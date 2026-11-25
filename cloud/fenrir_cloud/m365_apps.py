"""Enterprise apps, app registrations, consent and directory extensions of a Microsoft 365 tenant (M365-11).

The inventory reads from Microsoft Graph:

* app registrations (``/applications``) with their secrets and certificates, and the directory extension properties
  each one defines;
* service principals (enterprise apps): whether each is enabled, who publishes it (this tenant, Microsoft or
  another organisation), and its credentials;
* the application permissions each one holds (app role assignments) and the delegated permissions granted to it
  (OAuth2 permission grants, for all users or for one user);
* pending admin consent requests.

The permission contract is explicit. Every permission is listed as either *application* or *delegated*:

* an *application* permission works with no user signed in, across the whole tenant;
* a *delegated* permission only acts as the signed-in user, within that user's own rights.

High-privilege permissions are flagged on both kinds.

Credentials are rated ``expired``, ``expiring`` (within ``EXPIRY_WARNING``) or ``ok``. The daily check raises one
alert per expiring or expired credential of an app registration owned by the tenant.

Actions go through review, step-up and audit in the router:

* turn an enterprise app off or on;
* remove an expired secret or certificate;
* revoke a delegated consent grant.

A resource Microsoft will not return is recorded as unavailable with the reason, never treated as empty.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, m365
from .models import Alert, M365AppReport, M365Connection, utcnow

log = logging.getLogger("fenrir.m365.apps")

MICROSOFT_TENANTS = {"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"}
EXPIRY_WARNING = timedelta(days=30)
REPORT_EVERY = timedelta(hours=24)
MAX_ASSIGNMENT_LOOKUPS = 300
ALERT_RULE = "m365.app_credential_expiry"
HIGH_PRIVILEGE = {
    "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All", "Application.ReadWrite.All",
    "User.ReadWrite.All", "Group.ReadWrite.All", "Mail.ReadWrite", "Mail.Send", "Mail.Read", "Files.ReadWrite.All", "Sites.FullControl.All",
    "Sites.ReadWrite.All", "full_access_as_app", "Policy.ReadWrite.ConditionalAccess", "DeviceManagementConfiguration.ReadWrite.All",
    "Directory.AccessAsUser.All", "User.ManageIdentities.All", "UserAuthenticationMethod.ReadWrite.All",
}


class AppsError(Exception):
    pass


def _when(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "")[:26])
    except ValueError:
        return None


def credential_state(end: datetime | None, now: datetime | None = None) -> str:
    now = now or utcnow()
    if end is None:
        return "ok"
    if end <= now:
        return "expired"
    return "expiring" if end - now <= EXPIRY_WARNING else "ok"


def _credentials(obj: dict) -> list[dict]:
    out = []
    for kind, field in (("secret", "passwordCredentials"), ("certificate", "keyCredentials")):
        for c in obj.get(field) or []:
            end = _when(c.get("endDateTime"))
            out.append({"type": kind, "keyId": c.get("keyId"), "name": c.get("displayName") or "", "endDateTime": c.get("endDateTime"),
                        "state": credential_state(end), "hint": c.get("hint") or ""})
    return out


def _get(client, token, path: str) -> dict:
    r = client.get(m365.GRAPH + path, headers={"Authorization": "Bearer " + token})
    r.raise_for_status()
    return r.json()


def _list(client, token, path: str) -> list[dict]:
    return m365.collect(client, m365.GRAPH + path, token)


def _why(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        if code in (401, 403):
            return "Microsoft denied access: grant Application.Read.All and DelegatedPermissionGrant.Read.All"
        return f"Microsoft answered HTTP {code}"
    return f"{type(exc).__name__}: {str(exc)[:200]}"


def _client() -> httpx.Client:
    return httpx.Client(timeout=30, follow_redirects=False)


def inventory(conn: M365Connection) -> dict:
    unavailable: dict[str, str] = {}
    with _client() as client:
        token = m365.access_token(client, conn)
        try:
            apps = _list(client, token, "/applications?$select=id,appId,displayName,createdDateTime,signInAudience,"
                                        "passwordCredentials,keyCredentials,publisherDomain")
        except (httpx.HTTPError, ValueError) as exc:
            apps, unavailable["applications"] = [], _why(exc)
        try:
            sps = _list(client, token, "/servicePrincipals?$select=id,appId,displayName,accountEnabled,servicePrincipalType,"
                                       "appOwnerOrganizationId,publisherName,passwordCredentials,keyCredentials,appRoles,oauth2PermissionScopes")
        except (httpx.HTTPError, ValueError) as exc:
            sps, unavailable["servicePrincipals"] = [], _why(exc)
        try:
            grants = _list(client, token, "/oauth2PermissionGrants")
        except (httpx.HTTPError, ValueError) as exc:
            grants, unavailable["delegatedGrants"] = [], _why(exc)
        try:
            requests_ = _list(client, token, "/identityGovernance/appConsent/appConsentRequests?$filter=userConsentRequests/any(u:u/status eq 'InProgress')")
        except (httpx.HTTPError, ValueError) as exc:
            requests_, unavailable["consentRequests"] = [], _why(exc)
        by_sp = {s["id"]: s for s in sps}
        roles = {(s["id"], r["id"]): r.get("value") or r.get("displayName") for s in sps for r in s.get("appRoles") or []}
        extensions, assignments = {}, {}
        for app in apps[:MAX_ASSIGNMENT_LOOKUPS]:
            try:
                extensions[app["id"]] = [{"name": e.get("name"), "dataType": e.get("dataType"), "targetObjects": e.get("targetObjects") or []}
                                         for e in _get(client, token, f"/applications/{app['id']}/extensionProperties").get("value", [])]
            except (httpx.HTTPError, ValueError) as exc:
                unavailable.setdefault("extensions", _why(exc))
        lookups = [s for s in sps if s.get("appOwnerOrganizationId") not in MICROSOFT_TENANTS][:MAX_ASSIGNMENT_LOOKUPS]
        for sp in lookups:
            try:
                assignments[sp["id"]] = _get(client, token, f"/servicePrincipals/{sp['id']}/appRoleAssignments").get("value", [])
            except (httpx.HTTPError, ValueError) as exc:
                unavailable.setdefault("applicationPermissions", _why(exc))
    own_tenant = conn.directory_id
    delegated: dict[str, list] = {}
    for g in grants:
        resource = by_sp.get(g.get("resourceId"), {}).get("displayName", g.get("resourceId"))
        for scope in (g.get("scope") or "").split():
            delegated.setdefault(g.get("clientId"), []).append({
                "grantId": g.get("id"), "resource": resource, "permission": scope, "kind": "delegated",
                "consent": "admin (all users)" if g.get("consentType") == "AllPrincipals" else "one user",
                "principalId": g.get("principalId"), "highPrivilege": scope in HIGH_PRIVILEGE})
    service_principals = []
    for sp in sps:
        app_perms = [{"resource": by_sp.get(a.get("resourceId"), {}).get("displayName") or a.get("resourceDisplayName") or a.get("resourceId"),
                      "permission": roles.get((a.get("resourceId"), a.get("appRoleId"))) or a.get("appRoleId"), "kind": "application",
                      "highPrivilege": roles.get((a.get("resourceId"), a.get("appRoleId"))) in HIGH_PRIVILEGE}
                     for a in assignments.get(sp["id"], [])]
        owner = sp.get("appOwnerOrganizationId")
        publisher = "this tenant" if owner == own_tenant else "Microsoft" if owner in MICROSOFT_TENANTS else (sp.get("publisherName") or "another organisation")
        perms = app_perms + delegated.get(sp["id"], [])
        service_principals.append({
            "id": sp["id"], "appId": sp.get("appId"), "displayName": sp.get("displayName"), "enabled": sp.get("accountEnabled", True),
            "type": sp.get("servicePrincipalType"), "publisher": publisher, "credentials": _credentials(sp), "permissions": perms,
            "contract": "application and delegated" if app_perms and delegated.get(sp["id"]) else
                        "application (no signed-in user)" if app_perms else "delegated (as the signed-in user)" if perms else "none",
            "highPrivilege": sorted({p["permission"] for p in perms if p["highPrivilege"]}),
            "permissionsChecked": sp["id"] in assignments or owner in MICROSOFT_TENANTS})
    registrations = [{"id": a["id"], "appId": a.get("appId"), "displayName": a.get("displayName"), "createdDateTime": a.get("createdDateTime"),
                      "audience": a.get("signInAudience"), "credentials": _credentials(a), "extensions": extensions.get(a["id"], [])}
                     for a in apps]
    return {"registrations": registrations, "servicePrincipals": service_principals,
            "consentRequests": [{"id": r.get("id"), "appId": r.get("appId"), "appDisplayName": r.get("appDisplayName"),
                                 "scopes": [s.get("displayName") for s in r.get("pendingScopes") or []]} for r in requests_],
            "unavailable": unavailable,
            "summary": {"registrations": len(registrations), "servicePrincipals": len(service_principals),
                        "expired": sum(1 for a in registrations for c in a["credentials"] if c["state"] == "expired"),
                        "expiring": sum(1 for a in registrations for c in a["credentials"] if c["state"] == "expiring"),
                        "highPrivilegeApps": sum(1 for s in service_principals if s["highPrivilege"] and s["publisher"] != "Microsoft"),
                        "consentRequests": len(requests_)}}


def refresh(db: Session, conn: M365Connection, actor: str) -> M365AppReport:
    data = inventory(conn)
    report = M365AppReport(tenant_id=conn.tenant_id, connection_id=conn.id, data=data)
    db.add(report)
    db.flush()
    for old in db.scalars(select(M365AppReport).where(M365AppReport.connection_id == conn.id, M365AppReport.id != report.id)).all():
        db.delete(old)
    _alerts(db, conn, data)
    audit.record(db, actor, "m365.apps_inventoried", report.id, conn.tenant_id, summary=data["summary"], unavailable=sorted(data["unavailable"]))
    return report


def _alerts(db: Session, conn: M365Connection, data: dict) -> None:
    open_ = {(a.details or {}).get("key") for a in db.scalars(select(Alert).where(
        Alert.tenant_id == conn.tenant_id, Alert.rule_id == ALERT_RULE, Alert.status.in_(("new", "triaged")))).all()}
    for app in data["registrations"]:
        for c in app["credentials"]:
            if c["state"] == "ok":
                continue
            key = f"{conn.id}:{app['appId']}:{c['keyId']}:{c['state']}"
            if key in open_:
                continue
            what = f"{c['type']} '{c['name']}'" if c["name"] else c["type"]
            db.add(Alert(tenant_id=conn.tenant_id, rule_id=ALERT_RULE, severity="high" if c["state"] == "expired" else "medium",
                         title=f"App '{app['displayName']}': {what} {'expired' if c['state'] == 'expired' else 'expires soon'} ({(c['endDateTime'] or '')[:10]})"[:300],
                         mitre=[], event_ids=[], details={"category": "m365", "source": "Microsoft 365 apps", "key": key, "link": "/m365",
                                                          "description": "Integrations using this credential stop working when it expires. Add a new "
                                                                         "credential, move the integration to it, then remove the old one."}))


def latest(db: Session, connection_id: str) -> M365AppReport | None:
    return db.scalars(select(M365AppReport).where(M365AppReport.connection_id == connection_id)
                      .order_by(M365AppReport.taken_at.desc())).first()


# ---- actions -------------------------------------------------------------------------------------------------------

def act(conn: M365Connection, action: str, target: dict) -> dict:
    """Run one reviewed action. ``target`` is checked against the live tenant before anything is written."""
    with _client() as client:
        token = m365.access_token(client, conn)
        headers = {"Authorization": "Bearer " + token}

        def send(method, path, body=None):
            r = client.request(method, m365.GRAPH + path, headers=headers, **({"json": body} if body is not None else {}))
            if r.status_code >= 400:
                raise AppsError(f"Microsoft answered HTTP {r.status_code} to {method} {path.split('?')[0]}")
            return r.json() if r.content else {}

        if action in ("sp.disable", "sp.enable"):
            sp = _get(client, token, f"/servicePrincipals/{target['id']}?$select=id,displayName,appOwnerOrganizationId,appId")
            if sp.get("appId") == conn.client_id:
                raise AppsError("This is the app Fenrir itself signs in with; turning it off would cut Fenrir off from the tenant")
            send("PATCH", f"/servicePrincipals/{sp['id']}", {"accountEnabled": action == "sp.enable"})
            return {"message": f"'{sp.get('displayName')}' turned {'on' if action == 'sp.enable' else 'off'}"}
        if action == "credential.remove":
            app = _get(client, token, f"/applications/{target['id']}?$select=id,displayName,passwordCredentials,keyCredentials")
            cred = next((c for c in _credentials(app) if c["keyId"] == target.get("keyId")), None)
            if cred is None:
                raise AppsError("That credential no longer exists")
            if cred["state"] != "expired":
                raise AppsError("Only expired credentials can be removed here; a working one may still be in use")
            if cred["type"] == "secret":
                send("POST", f"/applications/{app['id']}/removePassword", {"keyId": cred["keyId"]})
            else:
                kept = [c for c in app.get("keyCredentials") or [] if c.get("keyId") != cred["keyId"]]
                send("PATCH", f"/applications/{app['id']}", {"keyCredentials": kept})
            return {"message": f"Expired {cred['type']} removed from '{app.get('displayName')}'"}
        if action == "grant.revoke":
            grant = _get(client, token, f"/oauth2PermissionGrants/{target['id']}")
            send("DELETE", f"/oauth2PermissionGrants/{grant['id']}")
            return {"message": f"Delegated consent ({grant.get('scope', '').strip()}) revoked"}
    raise AppsError("Unknown action")


def tick(db: Session, limit: int = 20) -> int:
    """Daily inventory (and credential expiry alerts) for each working connection, a few per hourly pass."""
    done = 0
    for conn in db.scalars(select(M365Connection)).all():
        if done >= limit:
            break
        if conn.status in ("error", "disconnected", "revoked"):
            continue
        last = latest(db, conn.id)
        if last is not None and last.taken_at > utcnow() - REPORT_EVERY:
            continue
        try:
            refresh(db, conn, "system:m365-apps")
            db.commit()
            done += 1
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            log.warning("app inventory of %s failed: %s", conn.id, exc)
    return done
