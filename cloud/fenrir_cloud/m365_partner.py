"""Microsoft partner (GDAP) management: one partner sign-in, delegated access to every customer tenant.

How it works:

1. The MSP registers an app in its **partner** tenant (multi-tenant, public client flows allowed, delegated
   Graph permissions ``DelegatedAdminRelationship.ReadWrite.All``, ``Directory.Read.All`` and
   ``Group.ReadWrite.All``, plus whatever customer-side permissions administration needs) and enters its ID and
   secret. A partner admin signs in once with a device code; Fenrir keeps the encrypted refresh token.
2. **GDAP relationships** are created from Fenrir with a least-privilege role set (``RECOMMENDED_ROLES``), locked
   for approval, and the customer's Global Administrator approves them from the invitation link.
3. **Role groups**: one partner security group per role ("Fenrir GDAP - <role>"), and once a relationship is active
   each group is assigned its role in that relationship. Partner staff get customer access by group membership.
4. **Customer connections**: a GDAP customer is mapped to a Fenrir customer as an ``M365Connection`` with
   ``auth_mode="gdap"``. Its tokens are delegated tokens for the customer tenant, minted from the partner refresh
   token (``access_token_for``), so everything else (sync, standards, administration) works unchanged.

Graph v1.0: ``/tenantRelationships/delegatedAdminRelationships``, ``.../{id}/requests``,
``.../{id}/accessAssignments`` and ``/tenantRelationships/delegatedAdminCustomers``. Relationship approval always
stays with the customer; Fenrir never approves on a customer's behalf.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, crypto, m365
from .models import M365Connection, M365Partner, Tenant, utcnow

LOGIN = "https://login.microsoftonline.com"
GRAPH = m365.GRAPH
SCOPE = "https://graph.microsoft.com/.default offline_access"

# Least-privilege role set for day-to-day MSP administration. Global Administrator is deliberately absent:
# GDAP relationships containing it cannot auto-extend and should be the exception, not the default.
RECOMMENDED_ROLES: dict[str, str] = {
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "0526716b-113d-4c15-b2c8-68e3c22b9f80": "Authentication Policy Administrator",
    "892c5842-a9a6-463a-8041-72aa08ca3cf6": "Cloud App Security Administrator",
    "7698a772-787b-4ac8-901f-60d6b08affd2": "Cloud Device Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "8329153b-31d0-4727-b945-745eb3bc5f31": "Domain Name Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f2ef992c-3afb-46b9-b7cf-a126ee74c451": "Global Reader",
    "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "69091246-20e8-4a56-aa4d-066075b2a7a8": "Teams Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
}
GROUP_PREFIX = "Fenrir GDAP - "
EXPIRY_WARNING = timedelta(days=30)


class PartnerError(Exception):
    pass


def http_client() -> httpx.Client:
    return httpx.Client(timeout=20, follow_redirects=False)


def _aad(row: M365Partner) -> str:
    return f"m365-partner:{row.tenant_id}:{row.id}"


crypto.register_encrypted(M365Partner, "credentials_envelope", _aad)


def _secrets(row: M365Partner) -> dict:
    if not row.credentials_envelope:
        return {}
    import json

    return json.loads(crypto.decrypt(row.credentials_envelope, _aad(row)))


def _store_secrets(row: M365Partner, values: dict) -> None:
    import json

    row.credentials_envelope = crypto.encrypt(json.dumps(values), _aad(row))


def _error(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return f"HTTP {response.status_code}"
    error = body.get("error")
    if isinstance(error, dict):
        return str(error.get("message") or error.get("code"))[:300]
    return str(body.get("error_description") or error or response.status_code).split("\r\n")[0][:300]


def create(db: Session, msp_tenant_id: str, directory_id: str, client_id: str, client_secret: str, actor: str) -> M365Partner:
    UUID(directory_id), UUID(client_id)
    row = M365Partner(tenant_id=msp_tenant_id, partner_directory_id=directory_id, client_id=client_id, created_by=actor)
    db.add(row)
    db.flush()
    _store_secrets(row, {"clientSecret": client_secret})
    return row


# --------------------------------------------------------------------------- partner sign-in (device code)


def start_signin(row: M365Partner) -> dict:
    with http_client() as client:
        response = client.post(f"{LOGIN}/{row.partner_directory_id}/oauth2/v2.0/devicecode",
                               data={"client_id": row.client_id, "scope": SCOPE})
    if response.status_code != 200:
        raise PartnerError("Microsoft did not issue a sign-in code: " + _error(response))
    data = response.json()
    return {"deviceCode": data["device_code"], "userCode": data["user_code"],
            "verificationUri": data.get("verification_uri") or "https://microsoft.com/devicelogin",
            "expiresIn": int(data.get("expires_in") or 900), "interval": int(data.get("interval") or 5)}


def complete_signin(row: M365Partner, device_code: str) -> str:
    """Returns pending | ok; stores the refresh token on success."""
    secrets = _secrets(row)
    with http_client() as client:
        response = client.post(f"{LOGIN}/{row.partner_directory_id}/oauth2/v2.0/token",
                               data={"grant_type": "urn:ietf:params:oauth:grant-type:device_code", "client_id": row.client_id,
                                     "client_secret": secrets.get("clientSecret", ""), "device_code": device_code})
    if response.status_code == 200:
        data = response.json()
        if not data.get("refresh_token"):
            raise PartnerError("Microsoft returned no refresh token; the app needs the offline_access permission")
        _store_secrets(row, {**secrets, "refreshToken": data["refresh_token"]})
        row.status, row.last_error, row.refreshed_at = "connected", "", utcnow()
        row.signed_in_as = str(_claim(data.get("id_token") or data.get("access_token") or "", "upn") or "")[:320]
        return "ok"
    code = None
    try:
        code = response.json().get("error")
    except ValueError:
        pass
    if code in ("authorization_pending", "slow_down"):
        return "pending"
    raise PartnerError("Sign-in did not complete: " + _error(response))


def _claim(token: str, name: str):
    import base64
    import json

    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))).get(name)
    except (IndexError, ValueError):
        return None


def access_token_for(row: M365Partner, directory_id: str | None = None, client: httpx.Client | None = None) -> str:
    """A delegated Graph token for the partner tenant, or (through GDAP) for a customer tenant."""
    secrets = _secrets(row)
    if not secrets.get("refreshToken"):
        raise PartnerError("The partner connection has not been signed in")
    own = client is None
    client = client or http_client()
    try:
        response = client.post(f"{LOGIN}/{directory_id or row.partner_directory_id}/oauth2/v2.0/token",
                               data={"grant_type": "refresh_token", "client_id": row.client_id, "client_secret": secrets.get("clientSecret", ""),
                                     "refresh_token": secrets["refreshToken"], "scope": SCOPE})
    finally:
        if own:
            client.close()
    if response.status_code != 200:
        message = _error(response)
        if directory_id is None or directory_id == row.partner_directory_id:
            row.status, row.last_error = "error", message
        raise PartnerError("Microsoft refused a token: " + message)
    data = response.json()
    if data.get("refresh_token") and data["refresh_token"] != secrets["refreshToken"]:
        _store_secrets(row, {**secrets, "refreshToken": data["refresh_token"]})  # refresh tokens rotate
    row.refreshed_at = utcnow()
    return data["access_token"]


def partner_for(db: Session, tenant_id: str) -> M365Partner | None:
    """The partner connection of the MSP that owns a customer."""
    seen = set()
    while tenant_id and tenant_id not in seen:
        seen.add(tenant_id)
        row = db.execute(select(M365Partner).where(M365Partner.tenant_id == tenant_id)).scalars().first()
        if row is not None:
            return row
        tenant = db.get(Tenant, tenant_id)
        tenant_id = tenant.parent_id if tenant else None
    return None


# --------------------------------------------------------------------------- Graph calls in the partner tenant


def _graph(client: httpx.Client, token: str, method: str, path: str, body: dict | None = None) -> dict:
    response = client.request(method, GRAPH + path, headers={"Authorization": "Bearer " + token},
                              **({"json": body} if body is not None else {}))
    if response.status_code >= 400:
        raise PartnerError(f"Microsoft rejected {method} {path.split('?')[0]}: {_error(response)}")
    return response.json() if response.content else {}


def _when(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def relationship_view(rel: dict, assignments: list[dict] | None = None) -> dict:
    roles = {r.get("roleDefinitionId") for r in ((rel.get("accessDetails") or {}).get("unifiedRoles") or [])}
    end = _when(rel.get("endDateTime"))
    view = {"id": rel.get("id"), "displayName": rel.get("displayName"), "status": rel.get("status"),
            "customer": (rel.get("customer") or {}).get("displayName") or "", "customerTenantId": (rel.get("customer") or {}).get("tenantId"),
            "endDateTime": rel.get("endDateTime"), "autoExtendDuration": rel.get("autoExtendDuration"),
            "roles": sorted(RECOMMENDED_ROLES.get(r, r) for r in roles if r),
            "missingRoles": sorted(name for rid, name in RECOMMENDED_ROLES.items() if rid not in roles),
            "expiringSoon": bool(end and end - utcnow() < EXPIRY_WARNING and rel.get("status") == "active"),
            "invitationUrl": f"https://admin.microsoft.com/AdminPortal/Home#/partners/invitation/granularAdminRelationships/{rel.get('id')}"
            if rel.get("status") in ("created", "approvalPending") else None}
    if assignments is not None:
        assigned = set()
        for a in assignments:
            if a.get("status") in ("active", "pending"):
                assigned.update(r.get("roleDefinitionId") for r in ((a.get("accessDetails") or {}).get("unifiedRoles") or []))
        view["unassignedRoles"] = sorted(RECOMMENDED_ROLES.get(r, r) for r in roles - assigned if r)
    return view


def list_relationships(row: M365Partner) -> list[dict]:
    with http_client() as client:
        token = access_token_for(row, client=client)
        rows = m365.collect(client, GRAPH + "/tenantRelationships/delegatedAdminRelationships", token)
    return [relationship_view(r) for r in rows]


def list_customers(row: M365Partner) -> list[dict]:
    with http_client() as client:
        token = access_token_for(row, client=client)
        rows = m365.collect(client, GRAPH + "/tenantRelationships/delegatedAdminCustomers", token)
    return [{"tenantId": r.get("tenantId") or r.get("id"), "displayName": r.get("displayName") or ""} for r in rows]


def create_relationship(row: M365Partner, display_name: str, customer_tenant_id: str | None = None, duration_days: int = 730,
                        auto_extend: bool = True, roles: list[str] | None = None) -> dict:
    """Create and lock a relationship for approval; returns it with the customer's invitation link."""
    role_ids = roles or list(RECOMMENDED_ROLES)
    for rid in role_ids:
        UUID(rid)
    if not 1 <= duration_days <= 730:
        raise PartnerError("GDAP relationships last between 1 and 730 days")
    body = {"displayName": display_name[:50], "duration": f"P{duration_days}D",
            "accessDetails": {"unifiedRoles": [{"roleDefinitionId": rid} for rid in role_ids]}}
    if auto_extend:
        body["autoExtendDuration"] = "P180D"
    if customer_tenant_id:
        body["customer"] = {"tenantId": str(UUID(customer_tenant_id))}
    with http_client() as client:
        token = access_token_for(row, client=client)
        rel = _graph(client, token, "POST", "/tenantRelationships/delegatedAdminRelationships", body)
        _graph(client, token, "POST", f"/tenantRelationships/delegatedAdminRelationships/{rel['id']}/requests", {"action": "lockForApproval"})
        rel["status"] = "approvalPending"
    return relationship_view(rel)


def ensure_role_groups(row: M365Partner) -> dict:
    """One partner security group per recommended role; existing groups are reused by name."""
    groups = dict(row.role_groups or {})
    with http_client() as client:
        token = access_token_for(row, client=client)
        for rid, name in RECOMMENDED_ROLES.items():
            if rid in groups:
                continue
            display = GROUP_PREFIX + name
            found = m365.collect(client, GRAPH + "/groups?$filter=displayName eq '" + display.replace("'", "''") + "'&$select=id", token)
            if found:
                groups[rid] = found[0]["id"]
                continue
            nickname = "fenrir-gdap-" + name.lower().replace(" ", "-")
            created = _graph(client, token, "POST", "/groups", {"displayName": display, "mailEnabled": False, "mailNickname": nickname[:64],
                                                                  "securityEnabled": True,
                                                                  "description": f"Members get the {name} role in customer tenants through GDAP."})
            groups[rid] = created["id"]
    row.role_groups = groups
    return groups


def assign_access(row: M365Partner, relationship_id: str) -> dict:
    """Map each role group to its role in an active relationship. Existing assignments are left alone."""
    groups = row.role_groups or {}
    if not groups:
        raise PartnerError("Create the role groups first")
    assigned, skipped = [], []
    with http_client() as client:
        token = access_token_for(row, client=client)
        base = f"/tenantRelationships/delegatedAdminRelationships/{relationship_id}"
        rel = _graph(client, token, "GET", base)
        if rel.get("status") != "active":
            raise PartnerError("The customer has not approved this relationship yet")
        roles = {r.get("roleDefinitionId") for r in ((rel.get("accessDetails") or {}).get("unifiedRoles") or [])}
        existing = m365.collect(client, GRAPH + base + "/accessAssignments", token)
        covered = {(a.get("accessContainer") or {}).get("accessContainerId") for a in existing if a.get("status") != "deleted"}
        for rid in roles:
            group_id = groups.get(rid)
            if not group_id or group_id in covered:
                skipped.append(RECOMMENDED_ROLES.get(rid, rid))
                continue
            _graph(client, token, "POST", base + "/accessAssignments",
                   {"accessContainer": {"accessContainerId": group_id, "accessContainerType": "securityGroup"},
                    "accessDetails": {"unifiedRoles": [{"roleDefinitionId": rid}]}})
            assigned.append(RECOMMENDED_ROLES.get(rid, rid))
    return {"assigned": sorted(assigned), "skipped": sorted(skipped)}


def onboard_customer(db: Session, partner: M365Partner, customer_directory_id: str, fenrir_tenant_id: str, name: str,
                     actor: str) -> M365Connection:
    """Map a GDAP customer to a Fenrir customer. Uses delegated GDAP tokens: nothing is installed in the customer."""
    directory_id = str(UUID(customer_directory_id))
    existing = db.execute(select(M365Connection).where(M365Connection.tenant_id == fenrir_tenant_id,
                                                       M365Connection.directory_id == directory_id)).scalar_one_or_none()
    if existing is not None:
        raise PartnerError("This directory is already connected for this customer")
    access_token_for(partner, directory_id)  # proves GDAP access before the connection exists
    from .models import new_id

    row = M365Connection(id=new_id("m365"), tenant_id=fenrir_tenant_id, name=name[:200] or directory_id, directory_id=directory_id,
                         client_id=partner.client_id, credentials_envelope={}, auth_mode="gdap", tenant_name=name[:200],
                         consented_by=partner.signed_in_as, consented_at=utcnow())
    db.add(row)
    audit.record(db, actor, "m365.gdap.onboarded", directory_id, fenrir_tenant_id, partner=partner.id)
    return row


def view(row: M365Partner) -> dict:
    return {"id": row.id, "tenantId": row.tenant_id, "partnerDirectoryId": row.partner_directory_id, "clientId": row.client_id,
            "status": row.status, "lastError": row.last_error, "signedInAs": row.signed_in_as,
            "roleGroups": {RECOMMENDED_ROLES.get(k, k): v for k, v in (row.role_groups or {}).items()},
            "refreshedAt": row.refreshed_at.isoformat() + "Z" if row.refreshed_at else None}
