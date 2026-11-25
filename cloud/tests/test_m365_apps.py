"""M365-11: enterprise apps, app registrations, consent, credential expiry and directory extensions."""
import json
from datetime import timedelta
from urllib.parse import unquote, urlparse

import httpx
import pytest

from test_documentation_vault import stepup
from test_msp_modules import connection
from fenrir_cloud import db as database, m365, m365_apps
from fenrir_cloud.models import Alert, AuditLog, utcnow

REAL = httpx.Client
GRAPH_SP = "sp-graph"
DIRECTORY = "00000000-0000-0000-0000-000000000001"


def iso(delta):
    return (utcnow() + delta).replace(microsecond=0).isoformat() + "Z"


def tenant():
    return {
        "applications": [{"id": "app1", "appId": "appid-1", "displayName": "Payroll sync", "signInAudience": "AzureADMyOrg",
                          "passwordCredentials": [{"keyId": "k-old", "displayName": "2024", "endDateTime": iso(-timedelta(days=3))},
                                                  {"keyId": "k-new", "displayName": "2026", "endDateTime": iso(timedelta(days=10))}],
                          "keyCredentials": [{"keyId": "c1", "displayName": "cert", "endDateTime": iso(timedelta(days=400))}]}],
        "extensions": {"app1": [{"name": "extension_appid1_costCentre", "dataType": "String", "targetObjects": ["User"]}]},
        "servicePrincipals": [
            {"id": "sp1", "appId": "appid-1", "displayName": "Payroll sync", "accountEnabled": True, "appOwnerOrganizationId": DIRECTORY},
            {"id": "sp2", "appId": "appid-2", "displayName": "Mail tool", "accountEnabled": True, "appOwnerOrganizationId": "other-org",
             "publisherName": "Contoso"},
            {"id": GRAPH_SP, "appId": "00000003-0000-0000-c000-000000000000", "displayName": "Microsoft Graph", "accountEnabled": True,
             "appOwnerOrganizationId": "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
             "appRoles": [{"id": "role-mail", "value": "Mail.ReadWrite"}, {"id": "role-users", "value": "User.Read.All"}]},
            {"id": "sp-fenrir", "appId": "00000000-0000-0000-0000-000000000002", "displayName": "Fenrir", "accountEnabled": True,
             "appOwnerOrganizationId": DIRECTORY}],
        "assignments": {"sp1": [{"resourceId": GRAPH_SP, "appRoleId": "role-users"}], "sp2": [{"resourceId": GRAPH_SP, "appRoleId": "role-mail"}]},
        "grants": [{"id": "grant1", "clientId": "sp2", "resourceId": GRAPH_SP, "consentType": "Principal", "principalId": "u1", "scope": "Mail.Send offline_access"}],
        "requests": [{"id": "req1", "appId": "appid-3", "appDisplayName": "Survey app", "pendingScopes": [{"displayName": "User.Read"}]}],
        "writes": [],
    }


@pytest.fixture
def graph(monkeypatch):
    t = tenant()

    def handler(request: httpx.Request):
        path = unquote(urlparse(str(request.url)).path)[len("/v1.0"):]
        body = json.loads(request.content) if request.content else None
        if request.method != "GET":
            t["writes"].append((request.method, path, body))
        if path == "/applications":
            return httpx.Response(200, json={"value": t["applications"]})
        if path.startswith("/applications/") and path.endswith("/extensionProperties"):
            return httpx.Response(200, json={"value": t["extensions"].get(path.split("/")[2], [])})
        if path.startswith("/applications/") and path.endswith("/removePassword"):
            app = next(a for a in t["applications"] if a["id"] == path.split("/")[2])
            app["passwordCredentials"] = [c for c in app["passwordCredentials"] if c["keyId"] != body["keyId"]]
            return httpx.Response(204)
        if path.startswith("/applications/"):
            return httpx.Response(200, json=next(a for a in t["applications"] if a["id"] == path.split("/")[2]))
        if path == "/servicePrincipals":
            return httpx.Response(200, json={"value": t["servicePrincipals"]})
        if path.endswith("/appRoleAssignments"):
            return httpx.Response(200, json={"value": t["assignments"].get(path.split("/")[2], [])})
        if path.startswith("/servicePrincipals/"):
            sp = next(s for s in t["servicePrincipals"] if s["id"] == path.split("/")[2])
            if request.method == "PATCH":
                sp.update(body)
                return httpx.Response(204)
            return httpx.Response(200, json=sp)
        if path == "/oauth2PermissionGrants":
            return httpx.Response(200, json={"value": t["grants"]})
        if path.startswith("/oauth2PermissionGrants/"):
            gid = path.split("/")[2]
            if request.method == "DELETE":
                t["grants"] = [g for g in t["grants"] if g["id"] != gid]
                return httpx.Response(204)
            return httpx.Response(200, json=next(g for g in t["grants"] if g["id"] == gid))
        if path == "/identityGovernance/appConsent/appConsentRequests":
            return httpx.Response(403, json={"error": {"code": "Authorization_RequestDenied"}}) if t.get("deny_requests") else \
                httpx.Response(200, json={"value": t["requests"]})
        return httpx.Response(404)

    monkeypatch.setattr(m365_apps, "_client", lambda: REAL(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(m365, "access_token", lambda client, conn, *a, **k: "token")
    return t


def test_inventory_contract_expiry_and_alerts(client, admin, tenant, graph):
    conn = connection(client, admin, tenant)
    out = client.post(f"/api/console/m365/connections/{conn['id']}/apps/refresh", headers=admin).json()
    reg = out["registrations"][0]
    assert {c["keyId"]: c["state"] for c in reg["credentials"]} == {"k-old": "expired", "k-new": "expiring", "c1": "ok"}
    assert reg["extensions"][0]["name"] == "extension_appid1_costCentre"
    sps = {s["id"]: s for s in out["servicePrincipals"]}
    assert sps["sp1"]["publisher"] == "this tenant" and sps["sp1"]["contract"] == "application (no signed-in user)"
    mail = sps["sp2"]
    assert mail["publisher"] == "Contoso" and mail["contract"] == "application and delegated"
    assert {(p["kind"], p["permission"]) for p in mail["permissions"]} == {("application", "Mail.ReadWrite"), ("delegated", "Mail.Send"),
                                                                            ("delegated", "offline_access")}
    assert mail["highPrivilege"] == ["Mail.ReadWrite", "Mail.Send"]
    assert next(p for p in mail["permissions"] if p["permission"] == "Mail.Send")["consent"] == "one user"
    assert out["consentRequests"][0]["appDisplayName"] == "Survey app"
    assert out["summary"] == {"registrations": 1, "servicePrincipals": 4, "expired": 1, "expiring": 1, "highPrivilegeApps": 1, "consentRequests": 1}
    with database.session_factory()() as db:
        alerts = db.query(Alert).filter_by(rule_id=m365_apps.ALERT_RULE).all()
        assert sorted(a.severity for a in alerts) == ["high", "medium"]
    client.post(f"/api/console/m365/connections/{conn['id']}/apps/refresh", headers=admin)
    with database.session_factory()() as db:
        assert db.query(Alert).filter_by(rule_id=m365_apps.ALERT_RULE).count() == 2  # not raised twice

    graph["deny_requests"] = True
    out = client.post(f"/api/console/m365/connections/{conn['id']}/apps/refresh", headers=admin).json()
    assert "denied" in out["unavailable"]["consentRequests"] and out["consentRequests"] == []


def test_actions_need_stepup_typed_name_and_refuse_unsafe_changes(client, admin, tenant, graph):
    conn = connection(client, admin, tenant)
    client.post(f"/api/console/m365/connections/{conn['id']}/apps/refresh", headers=admin)
    url = f"/api/console/m365/connections/{conn['id']}/apps/actions"
    body = {"action": "sp.disable", "id": "sp2", "confirmName": "Mail tool"}
    assert client.post(url, headers=admin, json=body).status_code == 403
    proof = stepup(client, admin)
    assert client.post(url, headers=proof, json={**body, "confirmName": "mail"}).status_code == 409
    assert client.post(url, headers=proof, json=body).json()["message"] == "'Mail tool' turned off"
    assert next(s for s in graph["servicePrincipals"] if s["id"] == "sp2")["accountEnabled"] is False

    # A working secret is never removed; an expired one is.
    r = client.post(url, headers=proof, json={"action": "credential.remove", "id": "app1", "keyId": "k-new", "confirmName": "Payroll sync"})
    assert r.status_code == 409 and "Only expired" in r.json()["detail"]
    r = client.post(url, headers=proof, json={"action": "credential.remove", "id": "app1", "keyId": "k-old", "confirmName": "Payroll sync"})
    assert r.status_code == 200 and [c["keyId"] for c in graph["applications"][0]["passwordCredentials"]] == ["k-new"]

    # Fenrir's own app cannot be switched off from here.
    r = client.post(url, headers=proof, json={"action": "sp.disable", "id": "sp-fenrir", "confirmName": "Fenrir"})
    assert r.status_code == 409 and "Fenrir itself" in r.json()["detail"]

    r = client.post(url, headers=proof, json={"action": "grant.revoke", "id": "grant1", "confirmName": "Mail tool"})
    assert r.status_code == 200 and graph["grants"] == []
    with database.session_factory()() as db:
        assert db.query(AuditLog).filter_by(action="m365.app_action").count() == 3
        assert db.query(AuditLog).filter_by(action="m365.app_action_refused").count() == 2
