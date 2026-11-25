"""Google Workspace posture assessment and safe remediation (VULN-12).

**Connection.** Fenrir connects with a Google Cloud service account that the customer's super admin has authorised
for domain-wide delegation, and acts as a named admin. Two things are stored:

* The key, encrypted.
* The scopes, which are explicit. By default they are read-only (``READ_SCOPES``). The customer adds the write
  scope (``WRITE_SCOPES``) only if they want Fenrir to make the remediation changes; the connection records whether
  it was allowed.

**Checks**, read through the Admin SDK Directory API and public DNS:

* 2-Step Verification enrolment and enforcement, with administrators and super administrators separately;
* the number of super administrators (Google recommends a few, not one and not many);
* active accounts that have not signed in for ``STALE_DAYS`` days;
* SPF, DKIM (the ``google._domainkey`` selector) and DMARC for every verified domain;
* third-party apps with access to an administrator's data (OAuth tokens).

Each check is ``pass``, ``fail``, ``warn`` or ``unavailable``, and an unavailable check gives the reason. The
evidence names the accounts or records involved.

**Safe changes.** These are reviewed, need step-up and are audited, and Fenrir re-reads the user afterwards to verify
the change took effect:

* sign a user out of all sessions;
* require a new password at next sign-in;
* suspend a stale account.

Nothing that could lock out the organisation is offered. Fenrir never changes a super administrator, never turns
off 2-Step Verification and never deletes an account.
"""
from __future__ import annotations

import base64
import json
import time
from datetime import timedelta

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from sqlalchemy.orm import Session

from . import audit, crypto, m365_tools
from .models import GoogleWorkspaceConnection, GoogleWorkspacePosture, utcnow

TOKEN_URL = "https://oauth2.googleapis.com/token"
DIRECTORY = "https://admin.googleapis.com/admin/directory/v1"
READ_SCOPES = ["https://www.googleapis.com/auth/admin.directory.user.readonly",
               "https://www.googleapis.com/auth/admin.directory.domain.readonly",
               "https://www.googleapis.com/auth/admin.directory.user.security"]
WRITE_SCOPES = ["https://www.googleapis.com/auth/admin.directory.user"]
STALE_DAYS = 90
MAX_USERS = 20000


class WorkspaceError(Exception):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def parse_key(raw: str) -> dict:
    try:
        key = json.loads(raw)
    except ValueError:
        raise WorkspaceError("Paste the service account's JSON key file") from None
    if key.get("type") != "service_account" or not key.get("client_email") or not key.get("private_key"):
        raise WorkspaceError("This is not a service account key (type service_account with client_email and private_key)")
    try:
        serialization.load_pem_private_key(key["private_key"].encode(), password=None)
    except (ValueError, TypeError):
        raise WorkspaceError("The private key in the file could not be read") from None
    return {"client_email": key["client_email"], "private_key": key["private_key"], "token_uri": TOKEN_URL}


def _client() -> httpx.Client:
    return httpx.Client(timeout=20, follow_redirects=False)


def scopes(conn: GoogleWorkspaceConnection) -> list[str]:
    return READ_SCOPES + (WRITE_SCOPES if conn.allow_changes else [])


def access_token(client: httpx.Client, conn: GoogleWorkspaceConnection) -> str:
    key = json.loads(crypto.decrypt(conn.credentials_envelope, f"google-workspace:{conn.id}"))
    now = int(time.time())
    header = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    claims = _b64(json.dumps({"iss": key["client_email"], "sub": conn.admin_email, "scope": " ".join(scopes(conn)),
                              "aud": TOKEN_URL, "iat": now, "exp": now + 3600}).encode())
    private = serialization.load_pem_private_key(key["private_key"].encode(), password=None)
    signature = _b64(private.sign(f"{header}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256()))
    r = client.post(TOKEN_URL, data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": f"{header}.{claims}.{signature}"})
    if r.status_code >= 400:
        try:
            why = r.json().get("error_description") or r.json().get("error")
        except ValueError:
            why = r.text[:200]
        raise WorkspaceError(f"Google refused the service account ({why}). Check domain-wide delegation lists the client ID with these scopes: "
                             + ", ".join(scopes(conn)))
    return r.json()["access_token"]


def _get_all(client, token, path: str, field: str, params: dict | None = None) -> list[dict]:
    out, page = [], None
    while True:
        r = client.get(DIRECTORY + path, headers={"Authorization": "Bearer " + token}, params={**(params or {}), **({"pageToken": page} if page else {})})
        if r.status_code >= 400:
            raise WorkspaceError(f"Google answered HTTP {r.status_code} to {path}")
        data = r.json()
        out += data.get(field) or []
        page = data.get("nextPageToken")
        if not page or len(out) >= MAX_USERS:
            return out


def _when(value: str | None):
    from datetime import datetime

    if not value or value.startswith("1970"):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def assess(db: Session, conn: GoogleWorkspaceConnection, actor: str) -> GoogleWorkspacePosture:
    checks: list[dict] = []

    def add(key, title, status, detail, evidence=None, remedy=""):
        checks.append({"check": key, "title": title, "status": status, "detail": detail, "evidence": (evidence or [])[:50],
                       "count": len(evidence or []), "remedy": remedy})

    with _client() as client:
        token = access_token(client, conn)
        try:
            users = _get_all(client, token, "/users", "users", {"customer": "my_customer", "maxResults": 500, "projection": "basic"})
        except WorkspaceError as exc:
            users = None
            add("users", "Users", "unavailable", str(exc))
        if users is not None:
            active = [u for u in users if not u.get("suspended") and not u.get("archived")]
            admins = [u for u in active if u.get("isAdmin") or u.get("isDelegatedAdmin")]
            supers = [u for u in active if u.get("isAdmin")]
            no2sv = [u["primaryEmail"] for u in active if not u.get("isEnrolledIn2Sv")]
            unenforced = [u["primaryEmail"] for u in active if not u.get("isEnforcedIn2Sv")]
            admin_no2sv = [u["primaryEmail"] for u in admins if not u.get("isEnrolledIn2Sv")]
            add("2sv-admins", "Administrators use 2-Step Verification", "fail" if admin_no2sv else "pass",
                f"{len(admin_no2sv)} of {len(admins)} administrator(s) are not enrolled", admin_no2sv,
                "Enrol these administrators, then enforce 2-Step Verification for the admin organisational unit (Admin console > Security).")
            add("2sv-users", "Everyone uses 2-Step Verification", "warn" if no2sv else "pass",
                f"{len(no2sv)} of {len(active)} active user(s) are not enrolled", no2sv, "Enforce 2-Step Verification for all organisational units.")
            add("2sv-enforced", "2-Step Verification is enforced", "warn" if unenforced else "pass",
                f"Not enforced for {len(unenforced)} user(s)", unenforced,
                "Turn on enforcement in Admin console > Security > 2-Step Verification (Google offers no API to change it).")
            add("super-admins", "A small number of super administrators",
                "warn" if len(supers) == 1 or len(supers) > 4 else "pass" if supers else "fail",
                f"{len(supers)} super administrator(s); Google recommends more than one and only a few", [u["primaryEmail"] for u in supers],
                "Keep two to four super administrators, and use delegated roles for daily work.")
            cutoff = utcnow() - timedelta(days=STALE_DAYS)
            stale = [u["primaryEmail"] for u in active if not u.get("isAdmin")
                     and ((_when(u.get("lastLoginTime")) or _when(u.get("creationTime")) or utcnow()) < cutoff)]
            add("stale-accounts", f"No active accounts unused for {STALE_DAYS} days", "warn" if stale else "pass",
                f"{len(stale)} active account(s) have not signed in for {STALE_DAYS}+ days", stale,
                "Suspend accounts that are no longer needed (a safe change below).")
            granted = []
            for a in admins[:50]:
                try:
                    tokens = _get_all(client, token, f"/users/{a['primaryEmail']}/tokens", "items")
                except WorkspaceError:
                    continue
                granted += [f"{a['primaryEmail']}: {t.get('displayText') or t.get('clientId')}" for t in tokens if not t.get("nativeApp")]
            add("admin-oauth", "Third-party apps with access to administrators' data", "warn" if granted else "pass",
                f"{len(granted)} app grant(s) on administrator accounts", granted,
                "Review these apps; remove the ones that are not needed (Admin console > Security > API controls).")
        try:
            domains = [d["domainName"] for d in _get_all(client, token, "/customer/my_customer/domains", "domains") if d.get("verified")]
        except WorkspaceError as exc:
            domains = []
            add("domains", "Domains", "unavailable", str(exc))
    for domain in domains[:20]:
        try:
            result = m365_tools.domain_check(domain)
        except m365_tools.ToolError:
            continue
        by = {c["check"]: c for c in result["checks"]}
        dkim = _google_dkim(domain)
        for key in ("spf", "dmarc"):
            c = by.get(key)
            if c:
                add(f"{key}:{domain}", f"{key.upper()} for {domain}", c["status"] if c["status"] in ("pass", "warn", "fail") else "unavailable",
                    c["detail"], c["records"], "Publish SPF including _spf.google.com and DMARC with p=quarantine or p=reject.")
        add(f"dkim:{domain}", f"DKIM for {domain}", "pass" if dkim else "fail",
            "google._domainkey is published" if dkim else "No google._domainkey record: Gmail is not signing mail for this domain",
            dkim, "Generate the DKIM key in Admin console > Apps > Gmail > Authenticate email and publish it.")
    order = {"fail": 0, "warn": 1, "unavailable": 2, "pass": 3}
    checks.sort(key=lambda c: order[c["status"]])
    summary = {s: sum(1 for c in checks if c["status"] == s) for s in order}
    conn.status, conn.last_error = "ok", ""
    row = GoogleWorkspacePosture(tenant_id=conn.tenant_id, connection_id=conn.id, checks=checks, summary=summary, created_by=actor)
    db.add(row)
    db.flush()
    audit.record(db, actor, "google_workspace.assessed", row.id, conn.tenant_id, summary=summary)
    return row


def _google_dkim(domain: str) -> list[str]:
    with m365_tools._client() as client:
        try:
            return [t for t in m365_tools._dns(client, f"google._domainkey.{domain}", "TXT") if "v=DKIM1" in t][:1]
        except (httpx.HTTPError, ValueError):
            return []


ACTIONS = {"signout": "Sign out of all sessions", "require-password-change": "Require a new password at next sign-in",
           "suspend": "Suspend the account"}


def remediate(conn: GoogleWorkspaceConnection, action: str, email: str) -> dict:
    if action not in ACTIONS:
        raise WorkspaceError("Unknown action")
    if not conn.allow_changes:
        raise WorkspaceError("This connection is read-only. Add the write scope to domain-wide delegation and allow changes first.")
    with _client() as client:
        token = access_token(client, conn)
        h = {"Authorization": "Bearer " + token}
        r = client.get(f"{DIRECTORY}/users/{email}", headers=h)
        if r.status_code >= 400:
            raise WorkspaceError(f"Google could not find {email}")
        user = r.json()
        if user.get("isAdmin"):
            raise WorkspaceError("Fenrir does not change super administrators")
        if action == "signout":
            r = client.post(f"{DIRECTORY}/users/{email}/signOut", headers=h)
        elif action == "require-password-change":
            r = client.put(f"{DIRECTORY}/users/{email}", headers=h, json={"changePasswordAtNextLogin": True})
        else:
            r = client.put(f"{DIRECTORY}/users/{email}", headers=h, json={"suspended": True})
        if r.status_code >= 400:
            raise WorkspaceError(f"Google answered HTTP {r.status_code}")
        after = client.get(f"{DIRECTORY}/users/{email}", headers=h).json()
    verified = {"signout": True, "require-password-change": after.get("changePasswordAtNextLogin") is True,
                "suspend": after.get("suspended") is True}[action]
    return {"message": f"{ACTIONS[action]}: {email}", "verified": verified,
            "verification": "Google confirmed the change" if action != "signout" else "Google accepted the sign-out (it leaves no state to read back)"}
