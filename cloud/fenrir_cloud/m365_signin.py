"""Connect a Microsoft 365 tenant by signing in as one of its administrators, instead of typing IDs and secrets.

Two ways, both ending in an ordinary M365Connection that syncs with app-only (client credentials) tokens:

* Sign in with a code (device code flow, no setup): the admin enters a code at microsoft.com/devicelogin. With
  their delegated token Fenrir creates a single-tenant app registration *inside the customer's tenant* holding
  exactly the Graph application permissions Fenrir uses, grants admin consent to them, and stores a client
  secret (2 years). The admin's token is used only for that and never stored.
* Sign in with Microsoft (redirect, needs the MSP's multi-tenant Fenrir app in config): a normal Microsoft sign-in
  identifies the tenant, then Microsoft's admin-consent page grants the platform app access. The platform's
  secret is used for that tenant; nothing per-customer is stored.

Microsoft endpoints are reached through ``http_client()`` so tests can replace it.
"""
from __future__ import annotations

import base64
import json
from datetime import timedelta
from urllib.parse import urlencode

import httpx

from .config import get_settings
from .models import utcnow

LOGIN = "https://login.microsoftonline.com"
GRAPH = "https://graph.microsoft.com/v1.0"
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
MANAGED_TAG = "fenrir-managed"

# Application permissions Fenrir uses: sync (users, licences, Secure Score, MFA registration) and the allowlisted
# admin actions in m365_admin.CAPABILITIES. Nothing broader (no mail, files or directory-wide write).
APP_PERMISSIONS = [
    "User.Read.All", "Organization.Read.All", "Directory.Read.All", "Domain.Read.All", "SecurityEvents.Read.All",
    "AuditLog.Read.All", "Reports.Read.All", "User.ReadWrite.All", "User.RevokeSessions.All", "User.EnableDisableAccount.All",
    "LicenseAssignment.ReadWrite.All", "GroupMember.ReadWrite.All",
]
# What the signing-in admin must allow for the code flow (to create the app registration and consent to it).
DEVICE_SCOPES = ["https://graph.microsoft.com/Application.ReadWrite.All", "https://graph.microsoft.com/AppRoleAssignment.ReadWrite.All",
                 "https://graph.microsoft.com/Organization.Read.All", "https://graph.microsoft.com/User.Read"]


class SignInError(Exception):
    """A user-facing reason the sign-in or provisioning did not complete."""


def http_client() -> httpx.Client:
    return httpx.Client(timeout=20, follow_redirects=False)


def redirect_uris() -> dict:
    base = get_settings().public_base_url.rstrip("/")
    return {"callback": f"{base}/api/m365/oauth/callback", "consent": f"{base}/api/m365/oauth/consent"}


def platform_app_configured() -> bool:
    settings = get_settings()
    return bool(settings.m365_client_id and settings.m365_client_secret)


def _error(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return f"HTTP {response.status_code}"
    error = body.get("error")
    if isinstance(error, dict):
        return str(error.get("message") or error.get("code") or response.status_code)[:300]
    return str(body.get("error_description") or error or response.status_code).split("\r\n")[0][:300]


# --- device code ---------------------------------------------------------------------------------------------

def start_device_code() -> dict:
    with http_client() as client:
        response = client.post(f"{LOGIN}/organizations/oauth2/v2.0/devicecode",
                               data={"client_id": get_settings().m365_public_client_id, "scope": " ".join(DEVICE_SCOPES)})
    if response.status_code != 200:
        raise SignInError("Microsoft did not issue a sign-in code: " + _error(response))
    data = response.json()
    return {"deviceCode": data["device_code"], "userCode": data["user_code"], "verificationUri": data.get("verification_uri") or "https://microsoft.com/devicelogin",
            "expiresIn": int(data.get("expires_in") or 900), "interval": int(data["interval"]) if "interval" in data else 5}


def poll_device_code(device_code: str) -> dict:
    """{"status": "pending" | "slow_down" | "expired" | "denied" | "ok", "accessToken"?, "error"?}"""
    with http_client() as client:
        response = client.post(f"{LOGIN}/organizations/oauth2/v2.0/token",
                               data={"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                                     "client_id": get_settings().m365_public_client_id, "device_code": device_code})
    if response.status_code == 200:
        return {"status": "ok", "accessToken": response.json()["access_token"]}
    try:
        code = response.json().get("error")
    except ValueError:
        code = None
    if code == "authorization_pending":
        return {"status": "pending"}
    if code == "slow_down":
        return {"status": "slow_down"}
    if code == "expired_token":
        return {"status": "expired"}
    if code in ("access_denied", "authorization_declined"):
        return {"status": "denied", "error": "The sign-in was cancelled."}
    return {"status": "denied", "error": _error(response)}


# --- provisioning the customer-tenant app registration ---------------------------------------------------------

def _graph(client: httpx.Client, token: str, method: str, path: str, body: dict | None = None, ok=(200, 201, 204)) -> dict:
    response = client.request(method, GRAPH + path, headers={"Authorization": "Bearer " + token},
                              **({"json": body} if body is not None else {}))
    if response.status_code not in ok:
        if response.status_code == 403:
            raise SignInError("The account you signed in with cannot create app registrations or grant consent. Sign in as a "
                              "Global Administrator (or Privileged Role Administrator plus Application Administrator).")
        raise SignInError(f"Microsoft Graph refused {method} {path.split('?')[0]}: {_error(response)}")
    return response.json() if response.content else {}


def provision(access_token: str, app_name: str) -> dict:
    """Create (or reuse) Fenrir's app registration in the signed-in admin's tenant, consent to its permissions and
    add a client secret. Returns directoryId, tenantName, signedInAs, clientId, secret, secretExpires, granted, missing."""
    with http_client() as client:
        org = (_graph(client, access_token, "GET", "/organization?$select=id,displayName").get("value") or [{}])[0]
        if not org.get("id"):
            raise SignInError("Could not read the organisation you signed in to.")
        me = _graph(client, access_token, "GET", "/me?$select=userPrincipalName")
        graph_sp = (_graph(client, access_token, "GET", f"/servicePrincipals?$filter=appId eq '{GRAPH_APP_ID}'&$select=id,appRoles")
                    .get("value") or [None])[0]
        if not graph_sp:
            raise SignInError("Microsoft Graph's service principal was not found in this tenant.")
        roles = {r.get("value"): r.get("id") for r in graph_sp.get("appRoles") or [] if r.get("allowedMemberTypes") and "Application" in r["allowedMemberTypes"]}
        wanted = {name: roles[name] for name in APP_PERMISSIONS if name in roles}
        missing = [name for name in APP_PERMISSIONS if name not in roles]

        safe_name = app_name.replace("'", "")[:120]
        existing = [a for a in _graph(client, access_token, "GET",
                                      f"/applications?$filter=displayName eq '{safe_name}'&$select=id,appId,displayName,tags").get("value") or []
                    if MANAGED_TAG in (a.get("tags") or [])]
        access = [{"resourceAppId": GRAPH_APP_ID, "resourceAccess": [{"id": role_id, "type": "Role"} for role_id in wanted.values()]}]
        if existing:
            app = existing[0]
            _graph(client, access_token, "PATCH", f"/applications/{app['id']}", {"requiredResourceAccess": access})
        else:
            app = _graph(client, access_token, "POST", "/applications", {
                "displayName": safe_name, "signInAudience": "AzureADMyOrg", "tags": [MANAGED_TAG],
                "notes": "Created by Fenrir so it can monitor and manage this Microsoft 365 tenant. Delete this app to disconnect Fenrir.",
                "requiredResourceAccess": access})
        sps = _graph(client, access_token, "GET", f"/servicePrincipals?$filter=appId eq '{app['appId']}'&$select=id").get("value") or []
        sp = sps[0] if sps else _graph(client, access_token, "POST", "/servicePrincipals", {"appId": app["appId"], "tags": [MANAGED_TAG]})

        assigned = {a.get("appRoleId") for a in _graph(client, access_token, "GET", f"/servicePrincipals/{sp['id']}/appRoleAssignments").get("value") or []}
        granted = []
        for name, role_id in wanted.items():
            if role_id not in assigned:
                _graph(client, access_token, "POST", f"/servicePrincipals/{graph_sp['id']}/appRoleAssignedTo",
                       {"principalId": sp["id"], "resourceId": graph_sp["id"], "appRoleId": role_id}, ok=(200, 201, 409))
            granted.append(name)

        expires = utcnow().replace(microsecond=0) + timedelta(days=730)
        password = _graph(client, access_token, "POST", f"/applications/{app['id']}/addPassword",
                          {"passwordCredential": {"displayName": "Fenrir", "endDateTime": expires.isoformat() + "Z"}})
        if not password.get("secretText"):
            raise SignInError("Microsoft did not return a client secret for the Fenrir app.")
    return {"directoryId": org["id"], "tenantName": org.get("displayName") or "", "signedInAs": me.get("userPrincipalName") or "",
            "clientId": app["appId"], "secret": password["secretText"], "secretExpires": expires, "granted": granted, "missing": missing}


# --- redirect + admin consent (platform app) ---------------------------------------------------------------------

def authorize_url(state: str) -> str:
    query = {"client_id": get_settings().m365_client_id, "response_type": "code", "redirect_uri": redirect_uris()["callback"],
             "response_mode": "query", "scope": "openid profile email User.Read", "state": state, "prompt": "select_account"}
    return f"{LOGIN}/organizations/oauth2/v2.0/authorize?{urlencode(query)}"


def consent_url(directory_id: str, state: str) -> str:
    query = {"client_id": get_settings().m365_client_id, "scope": "https://graph.microsoft.com/.default",
             "redirect_uri": redirect_uris()["consent"], "state": state}
    return f"{LOGIN}/{directory_id}/v2.0/adminconsent?{urlencode(query)}"


def _claims(id_token: str) -> dict:
    try:
        payload = id_token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError):
        return {}


def redeem_code(code: str) -> dict:
    """Exchange the authorisation code (server to Microsoft over TLS, so the ID token's claims are trustworthy)."""
    settings = get_settings()
    with http_client() as client:
        response = client.post(f"{LOGIN}/organizations/oauth2/v2.0/token",
                               data={"client_id": settings.m365_client_id, "client_secret": settings.m365_client_secret,
                                     "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uris()["callback"],
                                     "scope": "openid profile email User.Read"})
    if response.status_code != 200:
        raise SignInError("Microsoft sign-in failed: " + _error(response))
    claims = _claims(response.json().get("id_token") or "")
    if not claims.get("tid"):
        raise SignInError("Microsoft did not say which tenant you signed in to.")
    return {"directoryId": claims["tid"], "signedInAs": claims.get("preferred_username") or claims.get("email") or claims.get("name") or ""}


def tenant_name(directory_id: str) -> str:
    """Display name of a consented tenant, through the platform app (best effort)."""
    settings = get_settings()
    try:
        with http_client() as client:
            token = client.post(f"{LOGIN}/{directory_id}/oauth2/v2.0/token",
                                data={"client_id": settings.m365_client_id, "client_secret": settings.m365_client_secret,
                                      "grant_type": "client_credentials", "scope": "https://graph.microsoft.com/.default"})
            if token.status_code != 200:
                return ""
            org = client.get(GRAPH + "/organization?$select=displayName", headers={"Authorization": "Bearer " + token.json()["access_token"]})
            return ((org.json().get("value") or [{}])[0].get("displayName") or "") if org.status_code == 200 else ""
    except (httpx.HTTPError, ValueError, KeyError):
        return ""
