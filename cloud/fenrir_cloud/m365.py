"""Bounded, read-only Microsoft Graph v1.0 synchronisation."""
import re
from urllib.parse import urlparse
import httpx
from time import monotonic
from . import crypto

GRAPH = "https://graph.microsoft.com/v1.0"

def collect(client, url, token, deadline=None):
    deadline = deadline if deadline is not None else monotonic() + 120
    rows, seen = [], set()
    while url:
        if monotonic() >= deadline:
            raise ValueError("Graph synchronization exceeded its time budget")
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.netloc != "graph.microsoft.com" or not parsed.path.startswith("/v1.0/"):
            raise ValueError("Graph returned an invalid pagination URL")
        if url in seen or len(seen) >= 100:
            raise ValueError("Graph pagination exceeded its safety limit")
        seen.add(url)
        response = client.get(url, headers={"Authorization": "Bearer " + token})
        response.raise_for_status()
        data = response.json()
        page = data.get("value")
        if not isinstance(page, list) or not all(isinstance(row, dict) for row in page):
            raise ValueError("Invalid Graph response")
        rows.extend(page)
        if len(rows) > 50000:
            raise ValueError("Graph response exceeds 50000 records")
        url = data.get("@odata.nextLink")
    return rows

def synchronize(connection):
    deadline = monotonic() + 120
    with httpx.Client(timeout=20, follow_redirects=False) as client:
        token = access_token(client, connection)
        snapshot = {
            "users": collect(client, GRAPH + "/users?$select=id,displayName,userPrincipalName,mail,accountEnabled,assignedLicenses,userType,jobTitle&$top=999", token, deadline),
            "licenses": collect(client, GRAPH + "/subscribedSkus", token, deadline),
            "secureScores": collect(client, GRAPH + "/security/secureScores?$top=1", token, deadline),
        }
        # Optional collections: each needs its own permission (and some an Entra ID P1/P2 or Intune licence).
        # Sync carries on without them and records None, so callers can tell "not permitted" from "none".
        optional = {
            # AuditLog.Read.All
            "mfaRegistration": "/reports/authenticationMethods/userRegistrationDetails?$select=userPrincipalName,isAdmin,isMfaRegistered",
            # DeviceManagementManagedDevices.Read.All (Entra ID reconciliation against managed endpoints)
            "managedDevices": "/deviceManagement/managedDevices?$select=id,deviceName,serialNumber,operatingSystem,userPrincipalName,"
                              "complianceState,lastSyncDateTime",
            # Domain.Read.All
            "domains": "/domains?$select=id,isVerified,isDefault,authenticationType,supportedServices",
            # Organization.Read.All: the tenant's own name, country and directory sync state
            "organization": "/organization?$select=id,displayName,countryLetterCode,createdDateTime,onPremisesSyncEnabled,"
                            "onPremisesLastSyncDateTime,verifiedDomains",
            # RoleManagement.Read.Directory (or Directory.Read.All): who holds which admin role
            "directoryRoles": "/directoryRoles?$select=id,displayName,roleTemplateId&$expand=members",
            # ServiceHealth.Read.All: open Microsoft incidents and advisories
            "serviceIssues": "/admin/serviceAnnouncement/issues?$filter=isResolved%20eq%20false",
            # AuditLog.Read.All with Entra ID P1/P2: last sign-in per user (summarised below, not kept per user)
            "signInActivity": "/users?$select=id,userPrincipalName,accountEnabled,assignedLicenses,userType,createdDateTime,"
                              "signInActivity&$top=500",
            # SecurityAlert.Read.All (Defender for Endpoint or Business): open alerts, which become Fenrir alerts
            "defenderAlerts": "/security/alerts_v2?$filter=serviceSource%20eq%20'microsoftDefenderForEndpoint'%20and%20status%20ne%20'resolved'"
                              "&$top=200",
        }
        # The extra reads never fail the sync: each that Microsoft refuses, times out or answers oddly is recorded as
        # unavailable with its reason (shown on the tenant's Overview), and the next sync asks again.
        problems = {}
        for key, path in optional.items():
            try:
                snapshot[key] = collect(client, GRAPH + path, token, max(deadline, monotonic() + 30))
            except (httpx.HTTPError, ValueError) as exc:
                snapshot[key] = None
                problems[key] = describe_failure(exc)
        snapshot["unavailable"] = problems
        snapshot["inactiveUsers"] = inactive_users(snapshot.pop("signInActivity", None))
        snapshot["admins"] = admins(snapshot.pop("directoryRoles", None))
        snapshot["serviceIssues"] = service_issues(snapshot.get("serviceIssues"))
        snapshot["permissions"] = permission_check(token)
        snapshot["insights"] = insights(snapshot)
        return snapshot


def describe_failure(exc: Exception) -> str:
    """A short, safe account of a failed Microsoft call: Microsoft's own error code and message, never a secret."""
    if isinstance(exc, httpx.HTTPStatusError):
        response = exc.response
        where = "Microsoft sign-in" if response.request.url.host == "login.microsoftonline.com" else \
            f"Microsoft Graph ({response.request.url.path.removeprefix('/v1.0')})"
        try:
            data = response.json()
        except ValueError:
            data = {}
        error = data.get("error")
        if isinstance(error, dict):  # Graph
            said = ": ".join(str(x) for x in (error.get("code"), error.get("message")) if x)
        else:  # the token endpoint: AADSTS code and description, without Microsoft's trace and correlation IDs
            said = re.split(r"\s*(?:\r?\n|Trace ID:|Correlation ID:|Timestamp:)", str(data.get("error_description") or error or ""))[0]
        return f"{where} answered HTTP {response.status_code}" + (f": {said[:300]}" if said else "")
    if isinstance(exc, httpx.TimeoutException):
        try:
            return f"Microsoft did not answer in time ({exc.request.url.host}{exc.request.url.path})"
        except RuntimeError:
            return "Microsoft did not answer in time"
    if isinstance(exc, httpx.HTTPError):
        return f"Could not reach Microsoft: {type(exc).__name__}"
    return str(exc)[:300]


def permission_check(token: str) -> dict:
    """What this connection's own token allows, feature by feature (m365_permissions.py)."""
    from datetime import datetime, timezone

    from . import m365_permissions

    mode, granted = m365_permissions.granted_from_token(token)
    return {"mode": mode, "granted": granted, "features": m365_permissions.report(mode, granted),
            "checkedAt": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"}


INACTIVE_DAYS = 90


def inactive_users(rows: list | None) -> dict | None:
    """Enabled, licensed members with no sign-in for 90 days (or never, for accounts older than that): the licences an
    MSP can usually reclaim. None when Microsoft would not say (no P1/P2 or no permission)."""
    from datetime import datetime, timedelta, timezone

    if rows is None:
        return None
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=INACTIVE_DAYS)

    def when(value):
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else None
        except ValueError:
            return None

    found = []
    for row in rows:
        if not isinstance(row, dict) or row.get("accountEnabled") is False or not row.get("assignedLicenses"):
            continue
        if row.get("userType") == "Guest":
            continue
        activity = row.get("signInActivity") or {}
        last = max([d for d in (when(activity.get("lastSignInDateTime")), when(activity.get("lastNonInteractiveSignInDateTime"))) if d],
                   default=None)
        created = when(row.get("createdDateTime"))
        if (last and last < cutoff) or (last is None and created and created < cutoff):
            found.append({"userPrincipalName": row.get("userPrincipalName") or row.get("id") or "",
                          "lastSignIn": last.isoformat() if last else None,
                          "days": (now - last).days if last else None, "licences": len(row.get("assignedLicenses") or [])})
    found.sort(key=lambda r: (r["days"] is not None, -(r["days"] or 0)))
    return {"days": INACTIVE_DAYS, "count": len(found), "users": found[:500]}


def admins(roles: list | None) -> list | None:
    """Admin role holders: [{role, roleTemplateId, members: [{id, displayName, userPrincipalName, type}]}]."""
    if roles is None:
        return None
    out = []
    for role in roles:
        if not isinstance(role, dict):
            continue
        members = [{"id": m.get("id"), "displayName": m.get("displayName") or "", "userPrincipalName": m.get("userPrincipalName") or "",
                    "type": str(m.get("@odata.type") or "").rsplit(".", 1)[-1]} for m in role.get("members") or [] if isinstance(m, dict)]
        if members:
            out.append({"role": role.get("displayName") or "", "roleTemplateId": role.get("roleTemplateId") or "", "members": members})
    out.sort(key=lambda r: (r["roleTemplateId"] != GLOBAL_ADMIN, r["role"]))
    return out


GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"


def service_issues(rows: list | None) -> list | None:
    if rows is None:
        return None
    keep = ("id", "title", "service", "status", "classification", "feature", "startDateTime", "lastModifiedDateTime", "impactDescription")
    return [{k: row.get(k) for k in keep} for row in rows if isinstance(row, dict)][:100]


# Free, trial and self-service products Microsoft lists with thousands of seats (Power BI free, Power Automate free,
# Teams Exploratory...). Counting them would bury real unused licences.
FREE_SKUS = {"FLOW_FREE", "POWER_BI_STANDARD", "POWERAPPS_VIRAL", "POWERAPPS_DEV", "TEAMS_EXPLORATORY", "STREAM", "WINDOWS_STORE",
             "RIGHTSMANAGEMENT_ADHOC", "MCOPSTNC", "CCIBOTS_PRIVPREV_VIRAL", "POWER_PAGES_VTRIAL_FOR_MAKERS", "DEVELOPERPACK_E5",
             "MICROSOFT_BUSINESS_CENTER", "PROJECT_MADEIRA_PREVIEW_IW_SKU", "FORMS_PRO", "Microsoft_Teams_Exploratory_Dept"}


def paid_sku(sku: dict) -> bool:
    part = str(sku.get("skuPartNumber") or "")
    enabled = int(((sku.get("prepaidUnits") or {}).get("enabled")) or 0)
    return part not in FREE_SKUS and "FREE" not in part.upper() and "TRIAL" not in part.upper() and "VIRAL" not in part.upper() \
        and enabled < 10000


def insights(snapshot: dict) -> dict:
    """What an MSP acts on: licences paid for but unused, accounts without MFA, Secure Score."""
    users = [u for u in snapshot.get("users") or [] if isinstance(u, dict)]
    enabled = [u for u in users if u.get("accountEnabled") is not False]
    disabled_licensed = sorted(u.get("userPrincipalName") or u.get("id") or "" for u in users
                               if u.get("accountEnabled") is False and u.get("assignedLicenses"))
    purchased = assigned = 0
    for sku in snapshot.get("licenses") or []:
        if isinstance(sku, dict) and paid_sku(sku):
            purchased += int(((sku.get("prepaidUnits") or {}).get("enabled")) or 0)
            assigned += int(sku.get("consumedUnits") or 0)
    mfa = None
    registration = snapshot.get("mfaRegistration")
    if isinstance(registration, list):
        rows = [r for r in registration if isinstance(r, dict)]
        missing = [r for r in rows if not r.get("isMfaRegistered")]
        mfa = {"registered": len(rows) - len(missing), "notRegistered": len(missing),
               "percent": round(100 * (len(rows) - len(missing)) / len(rows)) if rows else None,
               "adminsWithoutMfa": sorted(r.get("userPrincipalName") or "" for r in missing if r.get("isAdmin"))[:50]}
    score = next((s for s in snapshot.get("secureScores") or [] if isinstance(s, dict)), None)
    secure = None
    if score and score.get("maxScore"):
        secure = {"current": score.get("currentScore"), "max": score.get("maxScore"),
                  "percent": round(100 * float(score.get("currentScore") or 0) / float(score["maxScore"]))}
    admin_roles = snapshot.get("admins")
    admin_info = None
    if isinstance(admin_roles, list):
        people = {m.get("id") for r in admin_roles for m in r.get("members") or []}
        admin_info = {"count": len(people),
                      "globalAdmins": sorted(m.get("userPrincipalName") or m.get("displayName") or "" for r in admin_roles
                                             if r.get("roleTemplateId") == GLOBAL_ADMIN for m in r.get("members") or [])[:50]}
    issues = snapshot.get("serviceIssues")
    inactive = snapshot.get("inactiveUsers")
    return {"users": len(users), "enabledUsers": len(enabled), "licencesPurchased": purchased, "licencesAssigned": assigned,
            "licencesUnused": max(purchased - assigned, 0), "disabledButLicensed": disabled_licensed[:100],
            "guests": sum(1 for u in users if u.get("userType") == "Guest"),
            "admins": admin_info, "serviceIssues": len(issues) if isinstance(issues, list) else None,
            "inactiveLicensed": inactive.get("count") if isinstance(inactive, dict) else None,
            "mfa": mfa, "secureScore": secure}


def access_token(client, connection, scope: str = "https://graph.microsoft.com/.default"):
    if connection.auth_mode == "gdap":
        # Delegated token for the customer tenant through the MSP's GDAP relationship (m365_partner.py). A rotated
        # partner refresh token is saved with the caller's own transaction.
        from sqlalchemy.orm import object_session

        from . import m365_partner
        from .db import session_factory

        db = object_session(connection)
        own = db is None
        db = db or session_factory()()
        try:
            partner = m365_partner.partner_for(db, connection.tenant_id)
            if partner is None:
                raise ValueError("No Microsoft partner connection is configured for GDAP")
            try:
                token = m365_partner.access_token_for(partner, connection.directory_id, client=client,
                                                      **({} if scope.startswith("https://graph.microsoft.com") else {"scope": scope}))
            except m365_partner.PartnerError as exc:
                raise ValueError(str(exc)) from exc
            if own:
                db.commit()
            return token
        finally:
            if own:
                db.close()
    if (connection.auth_mode or "app") == "platform":
        # The MSP's multi-tenant Fenrir app, consented by this tenant's admin.
        from .config import get_settings

        settings = get_settings()
        if not settings.m365_client_id or not settings.m365_client_secret:
            raise ValueError("The platform Microsoft 365 app is not configured")
        client_id, secret = settings.m365_client_id, settings.m365_client_secret
    else:
        client_id = connection.client_id
        secret = crypto.decrypt(connection.credentials_envelope, f"m365:{connection.tenant_id}:{connection.id}")
    response = client.post(f"https://login.microsoftonline.com/{connection.directory_id}/oauth2/v2.0/token",
        data={"client_id": client_id, "client_secret": secret,
              "grant_type": "client_credentials", "scope": scope})
    response.raise_for_status()
    return response.json()["access_token"]


MDE_SEVERITY = {"high": "high", "medium": "medium", "low": "low", "informational": "low"}


def ingest_defender_alerts(db, connection, alerts: list | None) -> dict:
    """Open Defender for Endpoint/Business alerts from Graph become Fenrir alerts on the matching device (by name), once
    each; an alert Microsoft no longer lists as open is resolved here too. None (no permission) changes nothing."""
    from sqlalchemy import select

    from .models import Alert, Device, utcnow

    if alerts is None:
        return {"raised": 0, "resolved": 0, "available": False}
    devices = {}
    for device in db.execute(select(Device).where(Device.tenant_id == connection.tenant_id)).scalars():
        devices[(device.hostname or "").lower().split(".")[0]] = device
    open_ids, raised = set(), 0
    existing = {a.rule_id: a for a in db.execute(select(Alert).where(Alert.tenant_id == connection.tenant_id,
                                                                    Alert.rule_id.like("mde:%"))).scalars()}
    for item in alerts:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        rule_id = f"mde:{item['id']}"[:64]
        open_ids.add(rule_id)
        if rule_id in existing:
            continue
        names = [str(e.get("deviceDnsName") or "") for e in item.get("evidence") or []
                 if isinstance(e, dict) and str(e.get("@odata.type", "")).endswith("deviceEvidence")]
        device = next((devices.get(n.lower().split(".")[0]) for n in names if devices.get(n.lower().split(".")[0])), None)
        db.add(Alert(tenant_id=connection.tenant_id, device_id=device.id if device else None, rule_id=rule_id,
                     title=f"Defender for Endpoint: {item.get('title') or 'alert'}"[:300],
                     severity=MDE_SEVERITY.get(str(item.get("severity") or "").lower(), "medium"),
                     mitre=[str(t) for t in item.get("mitreTechniques") or []][:10], event_ids=[],
                     details={"source": "Microsoft Defender for Endpoint", "mdeAlertId": item["id"], "category": item.get("category"),
                              "description": str(item.get("description") or "")[:2000],
                              "recommendedActions": str(item.get("recommendedActions") or "")[:2000],
                              "detectionSource": item.get("detectionSource"), "url": item.get("alertWebUrl"),
                              "devices": names[:5], "createdAt": item.get("createdDateTime")}))
        raised += 1
    resolved = 0
    for rule_id, alert in existing.items():
        if rule_id not in open_ids and alert.status in ("new", "triaged"):
            alert.status, alert.updated_at = "resolved", utcnow()
            alert.details = {**(alert.details or {}), "autoResolved": "Resolved in Microsoft Defender."}
            resolved += 1
    return {"raised": raised, "resolved": resolved, "available": True}
