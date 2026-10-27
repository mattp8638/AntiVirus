"""Bounded, read-only Microsoft Graph v1.0 synchronisation."""
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
            "users": collect(client, GRAPH + "/users?$select=id,displayName,userPrincipalName,accountEnabled,assignedLicenses&$top=999", token, deadline),
            "licenses": collect(client, GRAPH + "/subscribedSkus", token, deadline),
            "secureScores": collect(client, GRAPH + "/security/secureScores?$top=1", token, deadline),
        }
        # MFA registration needs AuditLog.Read.All (and Entra ID P1/P2); sync carries on without it.
        try:
            snapshot["mfaRegistration"] = collect(
                client, GRAPH + "/reports/authenticationMethods/userRegistrationDetails?$select=userPrincipalName,isAdmin,isMfaRegistered",
                token, deadline)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code not in (400, 401, 403, 404):
                raise
            snapshot["mfaRegistration"] = None
        snapshot["insights"] = insights(snapshot)
        return snapshot


def insights(snapshot: dict) -> dict:
    """What an MSP acts on: licences paid for but unused, accounts without MFA, Secure Score."""
    users = [u for u in snapshot.get("users") or [] if isinstance(u, dict)]
    enabled = [u for u in users if u.get("accountEnabled") is not False]
    disabled_licensed = sorted(u.get("userPrincipalName") or u.get("id") or "" for u in users
                               if u.get("accountEnabled") is False and u.get("assignedLicenses"))
    purchased = assigned = 0
    for sku in snapshot.get("licenses") or []:
        if isinstance(sku, dict):
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
    return {"users": len(users), "enabledUsers": len(enabled), "licencesPurchased": purchased, "licencesAssigned": assigned,
            "licencesUnused": max(purchased - assigned, 0), "disabledButLicensed": disabled_licensed[:100],
            "mfa": mfa, "secureScore": secure}


def access_token(client, connection):
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
              "grant_type": "client_credentials", "scope": "https://graph.microsoft.com/.default"})
    response.raise_for_status()
    return response.json()["access_token"]
