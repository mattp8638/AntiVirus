"""Microsoft partner (GDAP) management: one partner sign-in, delegated access to every customer tenant.

How it works:

1. The MSP registers an app in its **partner** tenant (multi-tenant, public client flows allowed, delegated
   Graph permissions ``DelegatedAdminRelationship.ReadWrite.All``, ``Directory.Read.All`` and
   ``Group.ReadWrite.All``, plus whatever customer-side permissions administration needs) and enters its ID.
   A partner admin signs in once with a device code; Fenrir keeps the encrypted refresh token. A client secret is
   only needed if public client flows are off (a confidential client); with them on, Microsoft rejects a secret.
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
# The partner sign-in names the permissions it needs (dynamic consent), so a Global Administrator approves them for the
# whole organisation on Microsoft's sign-in page ("Consent on behalf of your organization"): nothing has to be added
# to the app registration first. Partner Center is a separate API, so it is approved in a second, separate sign-in.
PARTNER_GRAPH_SCOPES = ("DelegatedAdminRelationship.ReadWrite.All", "Directory.Read.All", "Group.ReadWrite.All")
# Asked for at sign-in only so Fenrir can grant itself Partner Center access in the same step (one consent covers one
# API); setup_consents() removes it from Fenrir's grant straight afterwards.
SETUP_SCOPE = "DelegatedPermissionGrant.ReadWrite.All"
SIGNIN_SCOPES = {
    "graph": "openid profile offline_access " + " ".join(f"https://graph.microsoft.com/{p}" for p in (*PARTNER_GRAPH_SCOPES, SETUP_SCOPE)),
    "partner-center": "openid profile offline_access https://api.partnercenter.microsoft.com/user_impersonation",
}

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


# Microsoft only lets a partner admin into a customer tenant with an MFA-verified sign-in; otherwise every customer token
# fails with AADSTS50076 (or 50079 when the account has no MFA method yet). So the partner sign-in asks for MFA.
MFA_CLAIMS = '{"access_token":{"amr":{"essential":true,"values":["mfa"]}},"id_token":{"amr":{"essential":true,"values":["mfa"]}}}'
MFA_ERRORS = ("AADSTS50076", "AADSTS50079", "AADSTS50158")


def start_signin(row: M365Partner, purpose: str = "graph") -> dict:
    """Device-code sign-in. ``graph`` signs in and asks for the partner Graph permissions; ``partner-center`` asks for
    Partner Center access (needed to consent Fenrir's app in customer tenants). Both ask Microsoft for MFA."""
    if purpose not in SIGNIN_SCOPES:
        raise PartnerError("Unknown sign-in purpose")
    form = {"client_id": row.client_id, "scope": SIGNIN_SCOPES[purpose]}
    with http_client() as client:
        response = client.post(f"{LOGIN}/{row.partner_directory_id}/oauth2/v2.0/devicecode", data={**form, "claims": MFA_CLAIMS})
        if response.status_code != 200:  # a tenant that rejects the claims request still gets a sign-in code
            response = client.post(f"{LOGIN}/{row.partner_directory_id}/oauth2/v2.0/devicecode", data=form)
    if response.status_code != 200:
        raise PartnerError("Microsoft did not issue a sign-in code: " + _error(response))
    data = response.json()
    return {"deviceCode": data["device_code"], "userCode": data["user_code"],
            "verificationUri": data.get("verification_uri") or "https://microsoft.com/devicelogin",
            "expiresIn": int(data.get("expires_in") or 900), "interval": int(data.get("interval") or 5)}


# Device-code sign-in is a public-client flow when the app allows public client flows (the documented setup): Microsoft
# then binds the refresh token to a public client and rejects any client secret on it (AADSTS700025). With public
# client flows turned off the app is a confidential client and the secret is required (AADSTS7000218).
SECRET_REJECTED = "AADSTS700025"
SECRET_REQUIRED = "AADSTS7000218"


def _token_request(client: httpx.Client, row: M365Partner, directory_id: str, form: dict, secrets: dict) -> tuple[httpx.Response, str]:
    """POST to the token endpoint as the client type that worked last (public unless known otherwise), switching once
    if Microsoft says the app is the other type. Returns the response and the client type it was sent as."""
    client_type = secrets.get("clientType") or "public"
    secret = secrets.get("clientSecret") or ""
    response = None
    for _ in range(2):
        data = {**form, "client_id": row.client_id}
        if client_type == "confidential" and secret:
            data["client_secret"] = secret
        response = client.post(f"{LOGIN}/{directory_id}/oauth2/v2.0/token", data=data)
        if response.status_code == 200:
            break
        if client_type == "confidential" and SECRET_REJECTED in response.text:
            client_type = "public"
        elif client_type == "public" and secret and SECRET_REQUIRED in response.text:
            client_type = "confidential"
        else:
            break
    return response, client_type


def complete_signin(row: M365Partner, device_code: str) -> str:
    """Returns pending | ok; stores the refresh token on success."""
    secrets = _secrets(row)
    with http_client() as client:
        response, client_type = _token_request(client, row, row.partner_directory_id,
                                               {"grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": device_code},
                                               secrets)
    if response.status_code == 200:
        data = response.json()
        if not data.get("refresh_token"):
            raise PartnerError("Microsoft returned no refresh token; the app needs the offline_access permission")
        _store_secrets(row, {**secrets, "refreshToken": data["refresh_token"], "clientType": client_type})
        row.status, row.last_error, row.refreshed_at = "connected", "", utcnow()
        row.signed_in_as = _identity(data.get("id_token") or "", data.get("access_token") or "")[:320]
        amr = _claim(data.get("access_token") or "", "amr") or _claim(data.get("id_token") or "", "amr")
        row.settings = {**(row.settings or {}), "signInMfa": ("mfa" in amr) if isinstance(amr, list) else None, "mfaRequired": False,
                        "mfaRequiredFor": None}
        return "ok"
    code = None
    try:
        code = response.json().get("error")
    except ValueError:
        pass
    if code in ("authorization_pending", "slow_down"):
        return "pending"
    raise PartnerError("Sign-in did not complete: " + _error(response))


def _identity(*tokens: str) -> str:
    """The signed-in account: v2 ID tokens carry preferred_username, v1 access tokens upn or unique_name."""
    for token in tokens:
        for name in ("preferred_username", "upn", "unique_name", "email"):
            value = _claim(token, name) if token else None
            if value:
                return str(value)
    return ""


def _claim(token: str, name: str):
    import base64
    import json

    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))).get(name)
    except (IndexError, ValueError):
        return None


def access_token_for(row: M365Partner, directory_id: str | None = None, client: httpx.Client | None = None, scope: str = SCOPE) -> str:
    """A delegated Graph token for the partner tenant, or (through GDAP) for a customer tenant. ``scope`` selects
    another API for the same sign-in (Partner Center for application consent)."""
    secrets = _secrets(row)
    if not secrets.get("refreshToken"):
        raise PartnerError("The partner connection has not been signed in")
    own = client is None
    client = client or http_client()
    partner_itself = directory_id is None or directory_id == row.partner_directory_id
    try:
        response, client_type = _token_request(client, row, directory_id or row.partner_directory_id,
                                               {"grant_type": "refresh_token", "refresh_token": secrets["refreshToken"], "scope": scope},
                                               secrets)
    finally:
        if own:
            client.close()
    if response.status_code != 200:
        message = _error(response)
        if partner_itself:
            row.status, row.last_error = "error", message
        if any(code in response.text for code in MFA_ERRORS):
            row.settings = {**(row.settings or {}), "mfaRequired": True,
                            "mfaRequiredFor": None if partner_itself else directory_id}
            raise PartnerError("Microsoft requires multi-factor authentication for partner access" +
                               ("" if partner_itself else " to this customer") + ", and Fenrir's partner sign-in was not MFA-verified. "
                               "Click \"Sign in again\" and complete MFA when Microsoft asks (the account needs an MFA method in "
                               f"the partner tenant). Microsoft said: {message[:120]}")
        raise PartnerError("Microsoft refused a token: " + message)
    data = response.json()
    updated = {**secrets, "clientType": client_type}
    if data.get("refresh_token"):
        updated["refreshToken"] = data["refresh_token"]  # refresh tokens rotate
    if updated != secrets:
        _store_secrets(row, updated)
    if partner_itself:
        row.status, row.last_error = "connected", ""
    elif (row.settings or {}).get("mfaRequiredFor") == directory_id:
        row.settings = {**row.settings, "mfaRequired": False, "mfaRequiredFor": None, "mfaRequiredForName": None}
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


# Microsoft's answer when the signed-in account may not use the partner (GDAP) APIs.
RESTRICTED_HINT = ("Microsoft allows this only for an account that is a member (not a guest) of your partner tenant and is in the "
                   "Admin Agents group (Partner Center > Account settings > User management), signed in to an app with "
                   "DelegatedAdminRelationship.ReadWrite.All consented. Run the partner check, fix what it lists, then sign in again.")


def _refused(method: str, path: str, response: httpx.Response) -> PartnerError:
    message = _error(response)
    hint = f" {RESTRICTED_HINT}" if response.status_code == 403 and path.startswith(("/tenantRelationships", "/contracts")) else ""
    return PartnerError(f"Microsoft rejected {method} {path.split('?')[0]}: {message}.{hint}".replace("..", "."))


def _graph(client: httpx.Client, token: str, method: str, path: str, body: dict | None = None) -> dict:
    response = client.request(method, GRAPH + path, headers={"Authorization": "Bearer " + token},
                              **({"json": body} if body is not None else {}))
    if response.status_code >= 400:
        raise _refused(method, path, response)
    return response.json() if response.content else {}


def _list(client: httpx.Client, token: str, path: str) -> list[dict]:
    try:
        return m365.collect(client, GRAPH + path, token)
    except httpx.HTTPStatusError as exc:
        raise _refused("GET", path, exc.response) from exc


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
        rows = _list(client, token, "/tenantRelationships/delegatedAdminRelationships")
    return [relationship_view(r) for r in rows]


def list_customers(row: M365Partner) -> list[dict]:
    with http_client() as client:
        token = access_token_for(row, client=client)
        rows = _list(client, token, "/tenantRelationships/delegatedAdminCustomers")
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


# --------------------------------------------------------------------------- partner check, discovery and import

PARTNER_CENTER = "https://api.partnercenter.microsoft.com"
PARTNER_CENTER_SCOPE = "https://api.partnercenter.microsoft.com/user_impersonation offline_access"
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
# Delegated Graph permissions consented in each customer tenant (Partner Center application consent). What a technician
# can actually do is still limited by the GDAP roles of the groups they are in.
CUSTOMER_GRAPH_SCOPES = ("Directory.Read.All", "Organization.Read.All", "Domain.Read.All", "User.ReadWrite.All", "Group.ReadWrite.All",
                         "AuditLog.Read.All", "Reports.Read.All", "UserAuthenticationMethod.Read.All", "SecurityEvents.Read.All",
                         "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "Application.Read.All",
                         "DeviceManagementConfiguration.ReadWrite.All", "DeviceManagementManagedDevices.Read.All",
                         "SecurityAlert.Read.All")
REQUIRED_PARTNER_SCOPES = PARTNER_GRAPH_SCOPES
IMPORT_EVERY = timedelta(hours=6)


def check(row: M365Partner) -> dict:
    """Is this sign-in able to run GDAP? Permissions first (without Directory.Read.All Microsoft hides the partner type
    and group membership, so those are only judged once it is granted), then tenant, account and Partner Center.
    ``actions`` says which one-click approvals would fix what was found."""
    problems: list[str] = []
    actions = {"approveGraph": False, "approvePartnerCenter": False, "signInWithMfa": False}
    settings = row.settings or {}
    out: dict = {"partnerTenantId": row.partner_directory_id}
    with http_client() as client:
        token = access_token_for(row, client=client)
        out["tokenTenantId"] = _claim(token, "tid")
        # The access token carries how the original sign-in was authenticated, and every refresh keeps it.
        amr = _claim(token, "amr")
        out["mfa"] = ("mfa" in amr) if isinstance(amr, list) else settings.get("signInMfa")
        if out["mfa"] is False:
            actions["signInWithMfa"] = True
            problems.append("The partner sign-in was not MFA-verified (Microsoft recorded " + ", ".join(amr or ["no MFA"]) + "), and "
                            "Microsoft refuses partner access to customer tenants without MFA (AADSTS50076). Click \"Sign in again "
                            "with MFA\" and complete the MFA prompt. If Microsoft does not prompt, MFA was skipped for this device or "
                            "location: turn off \"remember MFA on trusted devices\" and trusted IPs for the account, or require MFA with "
                            "a Conditional Access policy, then sign in again.")
        elif settings.get("mfaRequired"):
            customer = settings.get("mfaRequiredForName") or settings.get("mfaRequiredFor") or "a customer"
            if out["mfa"]:
                problems.append(f"The partner sign-in is MFA-verified, but {customer} still asks for MFA (AADSTS50076), so that "
                                "customer's tenant does not accept MFA done in your partner tenant. In the customer's Entra admin centre, "
                                "open External Identities > Cross-tenant access settings, add your partner tenant and, under Inbound "
                                "access > Trust settings, tick \"Trust multifactor authentication from Microsoft Entra tenants\".")
            else:
                actions["signInWithMfa"] = True
                problems.append(f"{customer} requires MFA for partner access (AADSTS50076). Click \"Sign in again with MFA\" and "
                                "complete the MFA prompt.")
        scope_claim = _claim(token, "scp")
        scopes = set(str(scope_claim or "").split())
        out["scopes"] = sorted(scopes)
        missing = [p for p in REQUIRED_PARTNER_SCOPES if p not in scopes] if scope_claim is not None else []
        readable = "Directory.Read.All" in scopes or scope_claim is None
        if missing:
            actions["approveGraph"] = True
            problems.append("The signed-in token lacks the partner permissions (" + ", ".join(missing) + "). They must be Delegated "
                            "permissions: Application permissions only apply to app-only tokens and are ignored for a signed-in partner "
                            "admin. Click \"Approve Microsoft Graph permissions\", sign in as a Global Administrator of the partner tenant "
                            "and tick \"Consent on behalf of your organization\" (or add them under Microsoft Graph > Delegated "
                            "permissions in the app registration, grant admin consent and sign in again).")
        if out["tokenTenantId"] and str(out["tokenTenantId"]).lower() != row.partner_directory_id.lower():
            problems.append(f"The sign-in is for tenant {out['tokenTenantId']}, not the partner tenant {row.partner_directory_id}.")
        try:
            org = (_graph(client, token, "GET", "/organization?$select=id,displayName,partnerTenantType,verifiedDomains").get("value") or [{}])[0]
            out["organization"] = org.get("displayName") or ""
            out["partnerTenantType"] = org.get("partnerTenantType") or (None if readable else "not readable yet")
            out["domains"] = [d.get("name") for d in org.get("verifiedDomains") or []][:10]
            if readable and not org.get("partnerTenantType"):
                problems.append(f"{out['organization'] or 'This tenant'} is not registered as a Microsoft partner (CSP) tenant. Check that "
                                "the partner tenant ID is your Partner Center tenant.")
        except PartnerError as exc:
            problems.append(str(exc))
        try:
            me = _graph(client, token, "GET", "/me?$select=userPrincipalName,userType,displayName")
            out["user"], out["userType"] = me.get("userPrincipalName") or "", me.get("userType") or ""
            if out["user"] and not row.signed_in_as:
                row.signed_in_as = out["user"][:320]
            if out["userType"] == "Guest":
                problems.append(f"{out['user']} is a guest in the partner tenant. Sign in with an account that belongs to the partner tenant.")
        except PartnerError as exc:
            problems.append(str(exc))
        if readable:
            try:
                groups = {g.get("displayName") for g in _list(client, token, "/me/memberOf?$select=displayName,id")}
                out["adminAgent"] = "AdminAgents" in groups
                if not out["adminAgent"]:
                    problems.append("The signed-in account is not in the Admin Agents group. Add it in Partner Center (Account settings > "
                                    "User management > the user > Admin agent), wait a few minutes, then sign in again.")
            except PartnerError as exc:
                problems.append(str(exc))
        try:
            access_token_for(row, client=client, scope=PARTNER_CENTER_SCOPE)
            out["partnerCenter"] = True
        except PartnerError as exc:
            out["partnerCenter"] = False
            actions["approvePartnerCenter"] = True
            problems.append("Partner Center access is not approved, so Fenrir cannot consent its app in customer tenants. Click "
                            "\"Approve Partner Center access\" and sign in as a Global Administrator who is an Admin Agent, or add the "
                            "\"Microsoft Partner Center\" API's Delegated permission user_impersonation to the app and grant admin consent "
                            "(this is not the \"Partner Customer Delegated Administration\" API). "
                            f"Microsoft said: {str(exc).removeprefix('Microsoft refused a token: ')[:160]}")
    out["problems"], out["actions"] = problems, actions
    out["checkedAt"] = utcnow().isoformat() + "Z"
    row.settings = {**(row.settings or {}), "check": out}
    return out


PARTNER_CENTER_APP_ID = "fa3d9a0c-3fb0-42cc-9193-47c7ecd2edbd"  # the Microsoft Partner Center API


def _service_principal(client: httpx.Client, token: str, app_id: str) -> str | None:
    response = client.get(f"{GRAPH}/servicePrincipals(appId='{app_id}')?$select=id",
                          headers={"Authorization": "Bearer " + token})
    if response.status_code == 404:
        return None
    if response.status_code >= 400:
        raise _refused("GET", "/servicePrincipals", response)
    return response.json().get("id")


def _grants(client: httpx.Client, token: str, client_sp: str, resource_sp: str) -> list[dict]:
    return _list(client, token, f"/oauth2PermissionGrants?$filter=clientId eq '{client_sp}' and resourceId eq '{resource_sp}'")


def setup_consents(row: M365Partner) -> dict:
    """Right after the partner sign-in: grant Fenrir Partner Center access for the whole partner tenant (the one consent
    a sign-in cannot cover, because it is a second API), then drop the setup permission from Fenrir's own Graph grant
    so it does not keep the power to grant permissions. Best effort: what fails is reported, and the partner check
    offers the manual approval instead."""
    out: dict = {"partnerCenter": None, "setupPermissionRemoved": False}
    with http_client() as client:
        token = access_token_for(row, client=client)
        scopes = set(str(_claim(token, "scp") or "").split())
        if _claim(token, "scp") is not None and SETUP_SCOPE not in scopes:
            out["partnerCenter"] = "skipped: the sign-in was not granted " + SETUP_SCOPE
            return out
        try:
            fenrir_sp = _service_principal(client, token, row.client_id)
            partner_center_sp = _service_principal(client, token, PARTNER_CENTER_APP_ID)
            graph_sp = _service_principal(client, token, GRAPH_APP_ID)
            if not fenrir_sp:
                raise PartnerError("Fenrir's app has no service principal in the partner tenant yet")
            if not partner_center_sp:
                raise PartnerError("The Microsoft Partner Center API is not present in the partner tenant")
            existing = [g for g in _grants(client, token, fenrir_sp, partner_center_sp) if g.get("consentType") == "AllPrincipals"]
            if existing and "user_impersonation" in str(existing[0].get("scope") or "").split():
                out["partnerCenter"] = "already granted"
            elif existing:
                scope = " ".join(sorted(set(str(existing[0].get("scope") or "").split()) | {"user_impersonation"}))
                _graph(client, token, "PATCH", f"/oauth2PermissionGrants/{existing[0]['id']}", {"scope": scope})
                out["partnerCenter"] = "granted"
            else:
                _graph(client, token, "POST", "/oauth2PermissionGrants", {"clientId": fenrir_sp, "consentType": "AllPrincipals",
                                                                           "resourceId": partner_center_sp, "scope": "user_impersonation"})
                out["partnerCenter"] = "granted"
            for grant in _grants(client, token, fenrir_sp, graph_sp) if graph_sp else []:
                kept = [p for p in str(grant.get("scope") or "").split() if p != SETUP_SCOPE]
                if len(kept) != len(str(grant.get("scope") or "").split()):
                    _graph(client, token, "PATCH", f"/oauth2PermissionGrants/{grant['id']}", {"scope": " ".join(kept)})
                    out["setupPermissionRemoved"] = True
        except PartnerError as exc:
            out["partnerCenter"] = out["partnerCenter"] or f"failed: {exc}"[:300]
    row.settings = {**(row.settings or {}), "setup": {**out, "at": utcnow().isoformat() + "Z"}}
    return out


def discover(row: M365Partner) -> dict:
    """Every customer the partner tenant knows: CSP contracts, GDAP relationships and GDAP customers, merged by tenant ID.
    Each source fails on its own, so one refusal does not hide the others."""
    errors: dict[str, str] = {}
    customers: dict[str, dict] = {}

    def entry(tenant_id: str | None) -> dict | None:
        if not tenant_id:
            return None
        key = str(tenant_id).lower()
        return customers.setdefault(key, {"tenantId": key, "displayName": "", "defaultDomain": "", "sources": [], "gdap": "none",
                                           "relationships": [], "contractType": None})

    with http_client() as client:
        token = access_token_for(row, client=client)
        try:
            for c in _list(client, token, "/contracts?$select=customerId,defaultDomainName,displayName,contractType&$top=999"):
                item = entry(c.get("customerId"))
                if item:
                    item.update(displayName=item["displayName"] or c.get("displayName") or "", defaultDomain=c.get("defaultDomainName") or "",
                                contractType=c.get("contractType"))
                    item["sources"].append("contract")
        except (PartnerError, ValueError) as exc:
            errors["contracts"] = str(exc)
        try:
            for rel in _list(client, token, "/tenantRelationships/delegatedAdminRelationships"):
                view_ = relationship_view(rel)
                item = entry(view_["customerTenantId"])
                if item is None:
                    continue
                item["displayName"] = item["displayName"] or view_["customer"]
                item["relationships"].append({k: view_[k] for k in ("id", "displayName", "status", "endDateTime", "roles", "invitationUrl")})
                if "relationship" not in item["sources"]:
                    item["sources"].append("relationship")
        except (PartnerError, ValueError) as exc:
            errors["relationships"] = str(exc)
        try:
            for c in _list(client, token, "/tenantRelationships/delegatedAdminCustomers"):
                item = entry(c.get("tenantId") or c.get("id"))
                if item:
                    item["displayName"] = item["displayName"] or c.get("displayName") or ""
                    item["sources"].append("gdap")
        except (PartnerError, ValueError) as exc:
            errors["customers"] = str(exc)
    for item in customers.values():
        statuses = {r["status"] for r in item["relationships"]}
        item["gdap"] = ("active" if statuses & {"active", "expiring"} or "gdap" in item["sources"] else  # expiring still grants access
                        "pending" if statuses & {"created", "approvalPending", "approved", "activating"} else
                        "expired" if statuses & {"expired", "terminated", "terminating", "terminationRequested"} else "none")
    return {"customers": sorted(customers.values(), key=lambda c: c["displayName"].lower()), "errors": errors}


def consent_app(row: M365Partner, directory_id: str, client: httpx.Client | None = None) -> str:
    """Consent Fenrir's app in a customer tenant through Partner Center (what CSP partners use instead of asking each
    customer). Returns consented | already. Needs the Partner Center user_impersonation permission and Admin Agent."""
    own = client is None
    client = client or http_client()
    try:
        token = access_token_for(row, client=client, scope=PARTNER_CENTER_SCOPE)
        response = client.post(f"{PARTNER_CENTER}/v1/customers/{UUID(directory_id)}/applicationconsents",
                               headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
                               json={"applicationId": row.client_id, "displayName": "Fenrir",
                                     "applicationGrants": [{"enterpriseApplicationId": GRAPH_APP_ID, "scope": ",".join(CUSTOMER_GRAPH_SCOPES)}]})
    finally:
        if own:
            client.close()
    if response.status_code in (200, 201):
        return "consented"
    if response.status_code == 409:
        return "already"
    raise PartnerError(f"Partner Center refused the app consent: {_error(response)}")


def import_customers(db: Session, row: M365Partner, actor: str, directory_ids: list[str] | None = None,
                     create_relationships: bool = False) -> list[dict]:
    """Bring partner customers into Fenrir: a Fenrir customer per Microsoft customer (matched to an existing one by
    directory or name), app consent through Partner Center, and a GDAP Microsoft 365 connection where GDAP is active.
    Customers without GDAP get an invitation when ``create_relationships`` is set."""
    from . import services

    found = discover(row)
    wanted = {str(d).lower() for d in directory_ids} if directory_ids else None
    subtree = _subtree(db, row.tenant_id)
    linked = {c.directory_id.lower(): c for c in db.execute(select(M365Connection).where(M365Connection.tenant_id.in_(subtree))).scalars()}
    tenants = [t for t in db.execute(select(Tenant).where(Tenant.id.in_(subtree), Tenant.kind == "customer")).scalars()]
    results = []
    for customer in found["customers"]:
        directory_id = customer["tenantId"]
        if wanted is not None and directory_id not in wanted:
            continue
        name = customer["displayName"] or customer["defaultDomain"] or directory_id
        result = {"tenantId": directory_id, "displayName": name, "gdap": customer["gdap"]}
        if directory_id in linked:
            results.append({**result, "status": "already linked", "fenrirTenantId": linked[directory_id].tenant_id})
            continue
        tenant = next((t for t in tenants if str((t.settings or {}).get("m365DirectoryId", "")).lower() == directory_id), None) or \
            next((t for t in tenants if t.name.strip().lower() == name.strip().lower()), None)
        created = tenant is None
        if created:
            tenant = services.create_customer(db, name, row.tenant_id, actor)
            tenants.append(tenant)
        tenant.settings = {**(tenant.settings or {}), "m365DirectoryId": directory_id}
        result["fenrirTenantId"], result["createdCustomer"] = tenant.id, created
        if customer["gdap"] != "active":
            if create_relationships and customer["gdap"] in ("none", "expired"):
                try:
                    rel = create_relationship(row, f"Fenrir {name}"[:50], directory_id)
                    result.update(status="invitation created", invitationUrl=rel["invitationUrl"])
                except PartnerError as exc:
                    result.update(status="needs attention", error=str(exc))
            else:
                result["status"] = "awaiting GDAP" if customer["gdap"] == "pending" else "no GDAP relationship"
            results.append(result)
            continue
        try:
            result["consent"] = consent_app(row, directory_id)
        except (PartnerError, httpx.HTTPError) as exc:
            result["consent"] = "failed: " + str(exc)[:200]
        try:
            connection = onboard_customer(db, row, directory_id, tenant.id, name, actor)
            db.flush()
            result.update(status="linked", connectionId=connection.id)
        except PartnerError as exc:
            result.update(status="needs attention", error=str(exc))
            if (row.settings or {}).get("mfaRequiredFor") == directory_id:
                row.settings = {**row.settings, "mfaRequiredForName": name}  # the partner check names the customer
        results.append(result)
    row.settings = {**(row.settings or {}), "lastImportAt": utcnow().isoformat() + "Z"}
    audit.record(db, actor, "m365.gdap.imported", row.partner_directory_id, row.tenant_id,
                 linked=sum(1 for r in results if r["status"] == "linked"),
                 created=sum(1 for r in results if r.get("createdCustomer")))
    return results


def _subtree(db: Session, tenant_id: str) -> list[str]:
    from .deps import tenant_subtree

    return list(tenant_subtree(db, tenant_id))


def tick(db: Session) -> None:
    """Auto-import: link new GDAP customers for partners that turned it on (never creates relationships)."""
    import logging

    for row in db.execute(select(M365Partner).where(M365Partner.status == "connected")).scalars().all():
        settings = row.settings or {}
        if not settings.get("autoImport"):
            continue
        last = _when(settings.get("lastImportAt"))
        if last and utcnow() - last < IMPORT_EVERY:
            continue
        try:
            found = discover(row)
            ids = [c["tenantId"] for c in found["customers"] if c["gdap"] == "active"]
            if ids:
                import_customers(db, row, "system:gdap-import", ids)
            else:
                row.settings = {**settings, "lastImportAt": utcnow().isoformat() + "Z"}
            db.commit()
        except (PartnerError, httpx.HTTPError, ValueError) as exc:
            db.rollback()
            logging.getLogger("fenrir.m365").warning("GDAP auto-import failed for %s: %s", row.partner_directory_id, exc)


def view(row: M365Partner) -> dict:
    return {"id": row.id, "tenantId": row.tenant_id, "partnerDirectoryId": row.partner_directory_id, "clientId": row.client_id,
            "status": row.status, "lastError": row.last_error, "signedInAs": row.signed_in_as,
            "roleGroups": {RECOMMENDED_ROLES.get(k, k): v for k, v in (row.role_groups or {}).items()},
            "refreshedAt": row.refreshed_at.isoformat() + "Z" if row.refreshed_at else None,
            "autoImport": bool((row.settings or {}).get("autoImport")), "lastImportAt": (row.settings or {}).get("lastImportAt"),
            "check": (row.settings or {}).get("check")}
