"""Connecting Microsoft 365 by signing in as the tenant's admin: the device-code flow provisions Fenrir's app
registration in the customer tenant; the redirect flow consents the platform app. Microsoft is faked."""

import base64
import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from fenrir_cloud import crypto, db as database, m365, m365_signin
from fenrir_cloud.config import get_settings
from fenrir_cloud.models import AuditLog, M365Connection
from test_documentation_vault import stepup

TID = "11111111-2222-3333-4444-555555555555"
GRAPH_SP = "sp-graph"
ROLES = [{"value": name, "id": f"role-{i}", "allowedMemberTypes": ["Application"]} for i, name in enumerate(m365_signin.APP_PERMISSIONS)
         if name != "User.EnableDisableAccount.All"]  # pretend this tenant does not offer one of them


def fake_microsoft(monkeypatch, *, pending_polls=1, token_status=200):
    calls = {"polls": 0, "assigned": [], "apps": []}

    def handler(request: httpx.Request):
        url = str(request.url)
        body = request.content.decode() if request.content else ""
        if url.endswith("/organizations/oauth2/v2.0/devicecode"):
            return httpx.Response(200, json={"device_code": "dc-secret", "user_code": "ABCD-EFGH", "verification_uri": "https://microsoft.com/devicelogin",
                                             "expires_in": 900, "interval": 0})
        if url.endswith("/organizations/oauth2/v2.0/token") and "device_code" in body:
            calls["polls"] += 1
            if calls["polls"] <= pending_polls:
                return httpx.Response(400, json={"error": "authorization_pending"})
            return httpx.Response(token_status, json={"access_token": "delegated-admin-token"} if token_status == 200 else {"error": "access_denied"})
        if url.endswith("/organizations/oauth2/v2.0/token") and "authorization_code" in body:
            claims = base64.urlsafe_b64encode(json.dumps({"tid": TID, "preferred_username": "admin@contoso.example"}).encode()).decode().rstrip("=")
            return httpx.Response(200, json={"id_token": f"x.{claims}.y", "access_token": "a"})
        if f"/{TID}/oauth2/v2.0/token" in url:
            return httpx.Response(200, json={"access_token": "platform-token"})
        assert request.headers.get("Authorization", "").startswith("Bearer "), url
        path = request.url.path
        if path.endswith("/organization"):
            return httpx.Response(200, json={"value": [{"id": TID, "displayName": "Contoso Dental"}]})
        if path.endswith("/me"):
            return httpx.Response(200, json={"userPrincipalName": "admin@contoso.example"})
        if path.endswith("/servicePrincipals") and request.method == "GET":
            if "00000003-0000-0000-c000-000000000000" in url:
                return httpx.Response(200, json={"value": [{"id": GRAPH_SP, "appRoles": ROLES}]})
            return httpx.Response(200, json={"value": []})
        if path.endswith("/applications") and request.method == "GET":
            return httpx.Response(200, json={"value": calls["apps"]})
        if path.endswith("/applications") and request.method == "POST":
            app = {"id": "app-object", "appId": "99999999-0000-0000-0000-000000000001", **json.loads(body)}
            calls["apps"].append(app)
            assert app["signInAudience"] == "AzureADMyOrg" and "fenrir-managed" in app["tags"]
            return httpx.Response(201, json=app)
        if path.endswith("/applications/app-object") and request.method == "PATCH":
            return httpx.Response(204)
        if path.endswith("/servicePrincipals") and request.method == "POST":
            return httpx.Response(201, json={"id": "sp-fenrir"})
        if path.endswith("/appRoleAssignments"):
            return httpx.Response(200, json={"value": []})
        if path.endswith(f"/servicePrincipals/{GRAPH_SP}/appRoleAssignedTo"):
            calls["assigned"].append(json.loads(body)["appRoleId"])
            return httpx.Response(201, json={})
        if path.endswith("/addPassword"):
            return httpx.Response(200, json={"secretText": "generated-client-secret"})
        raise AssertionError(f"unexpected call {request.method} {url}")

    real = httpx.Client
    monkeypatch.setattr(m365_signin, "http_client", lambda: real(transport=httpx.MockTransport(handler)))
    return calls


def test_device_code_signin_provisions_the_app_and_connects(client, admin, tenant, monkeypatch):
    calls = fake_microsoft(monkeypatch)
    started = client.post("/api/console/m365/signin", headers=stepup(client, admin), json={"tenantId": tenant["id"], "mode": "device"})
    assert started.status_code == 200, started.text
    signin = started.json()
    assert signin["userCode"] == "ABCD-EFGH" and "dc-secret" not in started.text

    first = client.get(f"/api/console/m365/signin/{signin['id']}", headers=admin).json()
    assert first["status"] == "pending"
    done = client.get(f"/api/console/m365/signin/{signin['id']}", headers=admin).json()
    assert done["status"] == "completed", done
    assert done["signedInAs"] == "admin@contoso.example"
    assert len(calls["assigned"]) == len(ROLES)  # every permission the tenant offers was consented

    conn = client.get("/api/console/m365/connections", headers=admin).json()[0]
    assert conn["id"] == done["connectionId"] and conn["directoryId"] == TID and conn["authMode"] == "provisioned"
    assert conn["tenantName"] == "Contoso Dental" and conn["secretExpiresAt"]
    assert "generated-client-secret" not in json.dumps(conn)
    session = database.session_factory()()
    try:
        row = session.get(M365Connection, conn["id"])
        assert crypto.decrypt(row.credentials_envelope, f"m365:{row.tenant_id}:{row.id}") == "generated-client-secret"
        logged = session.query(AuditLog).filter(AuditLog.action == "m365.connected").one()
        assert "User.EnableDisableAccount.All" in json.dumps(logged.details)  # reported as not available
    finally:
        session.close()


def test_device_code_denied_and_needs_stepup(client, admin, tenant, monkeypatch):
    fake_microsoft(monkeypatch, pending_polls=0, token_status=400)
    assert client.post("/api/console/m365/signin", headers=admin, json={"tenantId": tenant["id"]}).status_code == 403
    signin = client.post("/api/console/m365/signin", headers=stepup(client, admin), json={"tenantId": tenant["id"]}).json()
    result = client.get(f"/api/console/m365/signin/{signin['id']}", headers=admin).json()
    assert result["status"] == "failed" and "cancelled" in result["error"]
    assert client.get("/api/console/m365/connections", headers=admin).json() == []


def test_redirect_signin_with_platform_app(client, admin, tenant, monkeypatch):
    fake_microsoft(monkeypatch)
    settings = get_settings()  # frozen dataclass: set and restore by hand
    original = (settings.m365_client_id, settings.m365_client_secret)
    object.__setattr__(settings, "m365_client_id", "aaaaaaaa-0000-0000-0000-00000000000a")
    object.__setattr__(settings, "m365_client_secret", "platform-secret")
    try:
        _redirect_flow(client, admin, tenant)
    finally:
        object.__setattr__(settings, "m365_client_id", original[0])
        object.__setattr__(settings, "m365_client_secret", original[1])


def _redirect_flow(client, admin, tenant):
    options = client.get("/api/console/m365/signin/options", headers=admin).json()
    assert options["redirect"] is True and options["redirectUris"][0].endswith("/api/m365/oauth/callback")

    started = client.post("/api/console/m365/signin", headers=stepup(client, admin), json={"tenantId": tenant["id"], "mode": "redirect"}).json()
    state = parse_qs(urlparse(started["authorizeUrl"]).query)["state"][0]
    back = client.get("/api/m365/oauth/callback", params={"state": state, "code": "auth-code"}, follow_redirects=False)
    assert back.status_code == 303 and f"/{TID}/v2.0/adminconsent" in back.headers["location"]

    # Consent claimed for another tenant is refused.
    wrong = client.get("/api/m365/oauth/consent", params={"state": state, "tenant": "00000000-0000-0000-0000-000000000000", "admin_consent": "True"},
                       follow_redirects=False)
    assert "signin=failed" in wrong.headers["location"]
    assert client.get("/api/console/m365/connections", headers=admin).json() == []

    started = client.post("/api/console/m365/signin", headers=stepup(client, admin), json={"tenantId": tenant["id"], "mode": "redirect"}).json()
    state = parse_qs(urlparse(started["authorizeUrl"]).query)["state"][0]
    client.get("/api/m365/oauth/callback", params={"state": state, "code": "auth-code"}, follow_redirects=False)
    done = client.get("/api/m365/oauth/consent", params={"state": state, "tenant": TID, "admin_consent": "True"}, follow_redirects=False)
    assert "signin=connected" in done.headers["location"]
    conn = client.get("/api/console/m365/connections", headers=admin).json()[0]
    assert conn["authMode"] == "platform" and conn["consentedBy"] == "admin@contoso.example" and conn["tenantName"] == "Contoso Dental"
    # Replaying the state does nothing.
    again = client.get("/api/m365/oauth/consent", params={"state": state, "tenant": TID, "admin_consent": "True"}, follow_redirects=False)
    assert "signin=expired" in again.headers["location"]

    # Sync uses the platform app's credentials for that tenant.
    seen = {}

    class Recorder:
        def post(self, url, data):
            seen.update(url=url, data=data)
            return httpx.Response(200, json={"access_token": "t"}, request=httpx.Request("POST", url))

    session = database.session_factory()()
    try:
        assert m365.access_token(Recorder(), session.get(M365Connection, conn["id"])) == "t"
    finally:
        session.close()
    assert seen["data"]["client_secret"] == "platform-secret" and TID in seen["url"]


def test_redirect_needs_platform_app(client, admin, tenant):
    reply = client.post("/api/console/m365/signin", headers=stepup(client, admin), json={"tenantId": tenant["id"], "mode": "redirect"})
    assert reply.status_code == 400 and "code instead" in reply.text
