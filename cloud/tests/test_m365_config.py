"""M365-14: tenant configuration backup, change history, comparison and restore, against an in-memory Graph."""
import copy
import json
import uuid
from datetime import timedelta
from urllib.parse import unquote, urlparse

import httpx
import pytest

from test_documentation_vault import stepup
from test_msp_modules import connection
from fenrir_cloud import db as database, m365, m365_config
from fenrir_cloud.models import AuditLog, M365ConfigRestore, M365ConfigSnapshot

REAL = httpx.Client
URL = "/api/console/m365/config"
COLLECTIONS = {"identity/conditionalAccess/namedLocations": "locations", "identity/conditionalAccess/policies": "policies",
               "deviceManagement/deviceCompliancePolicies": "compliance", "deviceManagement/deviceConfigurations": "profiles",
               "groups": "groups", "users": "users"}
SINGLETONS = {"policies/authorizationPolicy": "authz", "policies/identitySecurityDefaultsEnforcementPolicy": "defaults",
              "policies/authenticationMethodsPolicy": "methods"}


def tenant_a():
    return {
        "groups": [{"id": "gA1", "displayName": "Finance"}],
        "users": [{"id": "uA1", "userPrincipalName": "alice@shared.example"}],
        "locations": [{"id": "lA1", "displayName": "Office", "@odata.type": "#microsoft.graph.ipNamedLocation",
                       "ipRanges": [{"cidrAddress": "198.51.100.0/24"}], "isTrusted": True, "createdDateTime": "2026-01-01T00:00:00Z"}],
        "policies": [{"id": "pA1", "displayName": "Require MFA", "state": "enabled", "modifiedDateTime": "x",
                      "conditions": {"users": {"includeGroups": ["gA1"], "excludeUsers": ["uA1"], "includeUsers": []},
                                     "locations": {"includeLocations": ["lA1"], "excludeLocations": []},
                                     "applications": {"includeApplications": ["All"]}},
                      "grantControls": {"operator": "OR", "builtInControls": ["mfa"]}}],
        "compliance": [{"id": "cA1", "displayName": "Windows baseline", "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
                        "bitLockerEnabled": True, "version": 3}],
        "profiles": [{"id": "dA1", "displayName": "Office Wi-Fi", "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
                      "omaSettings": [{"omaUri": "./Vendor/MSFT/WiFi", "isEncrypted": True, "value": "****"}]}],
        "authz": {"id": "authorizationPolicy", "allowInvitesFrom": "adminsAndGuestInviters", "blockMsolPowerShell": True,
                  "defaultUserRolePermissions": {"allowedToCreateApps": False}},
        "defaults": {"id": "x", "isEnabled": False},
        "methods": {"id": "authenticationMethodsPolicy", "policyVersion": "1.5"},
    }


def tenant_b():
    return {"groups": [{"id": "gB1", "displayName": "Finance"}], "users": [], "locations": [], "policies": [], "compliance": [],
            "profiles": [], "authz": {"allowInvitesFrom": "everyone", "blockMsolPowerShell": False,
                                     "defaultUserRolePermissions": {"allowedToCreateApps": True}},
            "defaults": {"isEnabled": True}, "methods": {"policyVersion": "1.5"}}


@pytest.fixture
def graph(monkeypatch):
    tenants: dict[str, dict] = {}
    writes = []

    def handler(request: httpx.Request):
        t = tenants[request.headers["Authorization"][7:]]
        path = unquote(urlparse(str(request.url)).path)[len("/v1.0/"):]
        for prefix, key in SINGLETONS.items():
            if path == prefix:
                if request.method == "PATCH":
                    writes.append((request.method, path, json.loads(request.content)))
                    t[key].update(json.loads(request.content))
                    return httpx.Response(204)
                return httpx.Response(200, json=t[key])
        for prefix, key in sorted(COLLECTIONS.items(), key=lambda kv: -len(kv[0])):
            if path == prefix:
                if request.method == "POST":
                    body = json.loads(request.content)
                    writes.append(("POST", path, body))
                    body = {**body, "id": key[0] + uuid.uuid4().hex[:6]}
                    t[key].append(body)
                    return httpx.Response(201, json=body)
                return httpx.Response(200, json={"value": t[key]})
            if path.startswith(prefix + "/"):
                ident = path[len(prefix) + 1:]
                row = next((r for r in t[key] if ident in (r.get("id"), r.get("userPrincipalName"))), None)
                if row is None:
                    return httpx.Response(404, json={"error": {"code": "NotFound"}})
                if request.method == "PATCH":
                    body = json.loads(request.content)
                    writes.append(("PATCH", path, body))
                    row.update(body)
                    return httpx.Response(204)
                return httpx.Response(200, json=row)
        return httpx.Response(404)

    monkeypatch.setattr(m365_config, "_client", lambda: REAL(transport=httpx.MockTransport(handler), base_url="https://graph.microsoft.com"))
    monkeypatch.setattr(m365, "access_token", lambda client, conn, *a, **k: conn.id)
    return tenants, writes


def customer(client, admin, name):
    t = client.post("/api/console/tenants", json={"name": name, "template": "balanced"}, headers=admin).json()
    return t, connection(client, admin, t)


def test_backup_history_compare_and_cross_tenant_restore(client, admin, graph):
    tenants, writes = graph
    (ta, ca), (tb, cb) = customer(client, admin, "Alpha"), customer(client, admin, "Bravo")
    tenants[ca["id"]], tenants[cb["id"]] = tenant_a(), tenant_b()

    first = client.post(f"{URL}/connections/{ca['id']}/snapshots", headers=admin).json()
    assert first["created"] and first["counts"]["conditionalAccess"] == 1 and first["changes"] == {"first": True}
    assert client.post(f"{URL}/connections/{ca['id']}/snapshots", headers=admin).json()["created"] is False  # unchanged

    tenants[ca["id"]]["policies"][0]["state"] = "disabled"
    second = client.post(f"{URL}/connections/{ca['id']}/snapshots", headers=admin).json()
    change = second["changes"]["conditionalAccess"]["changed"][0]
    assert change["name"] == "Require MFA" and change["fields"] == [{"field": "state", "before": "enabled", "after": "disabled"}]
    history = client.get(f"{URL}/connections/{ca['id']}/snapshots", headers=admin).json()
    assert [h["id"] for h in history] == [second["id"], first["id"]]
    full = client.get(f"{URL}/snapshots/{first['id']}", headers=admin).json()
    assert full["verified"] and full["references"]["groups"] == {"gA1": "Finance"} and "modifiedDateTime" not in full["resources"]["conditionalAccess"][0]

    items = [{"resource": "conditionalAccess", "name": "Require MFA"}, {"resource": "namedLocations", "name": "Office"},
             {"resource": "authenticationMethods", "name": "authenticationMethods"}, {"resource": "intuneConfiguration", "name": "Office Wi-Fi"},
             {"resource": "intuneCompliance", "name": "Windows baseline"}, {"resource": "authorizationPolicy", "name": "authorizationPolicy"}]
    plan = client.post(f"{URL}/restores", headers=admin, json={"snapshotId": first["id"], "connectionId": cb["id"], "items": items}).json()
    by = {s["name"]: s for s in plan["plan"]}
    assert by["Require MFA"]["action"] == "blocked" and "alice@shared.example" in by["Require MFA"]["reasons"][0]
    assert by["authenticationMethods"]["action"] == "blocked" and by["Office Wi-Fi"]["action"] == "blocked"
    assert "encrypted" in by["Office Wi-Fi"]["reasons"][0]

    tenants[cb["id"]]["users"].append({"id": "uB1", "userPrincipalName": "alice@shared.example"})
    plan = client.post(f"{URL}/restores", headers=admin, json={"snapshotId": first["id"], "connectionId": cb["id"], "items": items}).json()
    by = {s["name"]: s for s in plan["plan"]}
    ca_step = by["Require MFA"]
    assert ca_step["action"] == "create" and ca_step["body"]["state"] == "enabledForReportingButNotEnforced"
    assert any("gA1 → gB1" in t for t in ca_step["translations"]) and any("restored first" in t for t in ca_step["translations"])
    assert by["Office"]["action"] == "create" and by["Windows baseline"]["action"] == "create"
    assert by["authorizationPolicy"]["action"] == "update" and {f["field"] for f in by["authorizationPolicy"]["fields"]} == {
        "allowInvitesFrom", "blockMsolPowerShell", "defaultUserRolePermissions.allowedToCreateApps"}
    assert writes == []  # planning writes nothing

    url = f"{URL}/restores/{plan['id']}/execute"
    assert client.post(url, headers=admin, json={"confirmCount": 4}).status_code == 403  # step-up first
    proof = stepup(client, admin)
    assert client.post(url, headers=proof, json={"confirmCount": 9}).status_code == 409
    done = client.post(url, headers=proof, json={"confirmCount": 4}).json()
    assert done["status"] == "completed", done["results"]
    b = tenants[cb["id"]]
    office = next(x for x in b["locations"] if x["displayName"] == "Office")
    policy = b["policies"][0]
    assert policy["conditions"]["users"]["includeGroups"] == ["gB1"] and policy["conditions"]["users"]["excludeUsers"] == ["uB1"]
    assert policy["conditions"]["locations"]["includeLocations"] == [office["id"]]
    assert "scheduledActionsForRule" in b["compliance"][0] and b["authz"]["blockMsolPowerShell"] is True
    assert [w[1] for w in writes][:2] == ["identity/conditionalAccess/namedLocations", "identity/conditionalAccess/policies"]
    assert client.post(url, headers=proof, json={"confirmCount": 4}).status_code == 409  # never runs twice

    # Compare across tenants: the only difference left in the policy is its state, because IDs compare by name.
    snap_b = client.post(f"{URL}/connections/{cb['id']}/snapshots", headers=admin).json()
    diff = client.get(f"{URL}/compare", headers=admin, params={"left": first["id"], "right": snap_b["id"]}).json()["differences"]
    assert diff["conditionalAccess"]["changed"] == [{"name": "Require MFA", "fields": [
        {"field": "state", "before": "enabled", "after": "enabledForReportingButNotEnforced"}]}]
    assert diff["intuneConfiguration"]["removed"] == ["Office Wi-Fi"]
    with database.session_factory()() as db:
        assert db.query(AuditLog).filter_by(action="m365.config_restored").count() == 1


def test_tampered_snapshot_and_stale_plan_are_refused(client, admin, graph):
    tenants, writes = graph
    (_, ca) = customer(client, admin, "Alpha")
    tenants[ca["id"]] = tenant_a()
    snap = client.post(f"{URL}/connections/{ca['id']}/snapshots", headers=admin).json()
    body = {"snapshotId": snap["id"], "connectionId": ca["id"], "items": [{"resource": "securityDefaults", "name": "securityDefaults"}]}
    tenants[ca["id"]]["defaults"]["isEnabled"] = True
    plan = client.post(f"{URL}/restores", headers=admin, json=body).json()
    assert plan["plan"][0]["action"] == "update"
    with database.session_factory()() as db:
        row = db.get(M365ConfigRestore, plan["id"])
        row.created_at = row.created_at - timedelta(hours=1)
        s = db.get(M365ConfigSnapshot, snap["id"])
        resources = copy.deepcopy(s.resources)
        resources["securityDefaults"][0]["isEnabled"] = True
        s.resources = resources
        db.commit()
    proof = stepup(client, admin)
    assert client.post(f"{URL}/restores/{plan['id']}/execute", headers=proof, json={"confirmCount": 1}).status_code == 409
    r = client.post(f"{URL}/restores", headers=admin, json=body)
    assert r.status_code == 400 and "SHA-256" in r.json()["detail"]
    assert writes == []


def test_unreadable_resources_are_recorded_and_scheduler_backs_up(client, admin, graph, monkeypatch):
    tenants, _ = graph
    (_, ca) = customer(client, admin, "Alpha")
    t = tenant_a()
    del t["methods"]  # the handler raises KeyError -> treat as unavailable via a 403 instead
    tenants[ca["id"]] = t
    real_read = m365_config._read

    def read(client_, token, resource):
        if resource == "authenticationMethods":
            raise httpx.HTTPStatusError("denied", request=httpx.Request("GET", "https://graph.microsoft.com/v1.0/x"),
                                        response=httpx.Response(403))
        return real_read(client_, token, resource)

    monkeypatch.setattr(m365_config, "_read", read)
    with database.session_factory()() as db:
        assert m365_config.tick(db) >= 1
        snap = m365_config.latest(db, ca["id"])
        assert "denied access" in snap.errors["authenticationMethods"] and "authenticationMethods" not in snap.resources
        assert m365_config.tick(db) == 0  # backed up less than a day ago


def test_other_customer_cannot_see_snapshots(client, admin, graph):
    tenants, _ = graph
    (_, ca) = customer(client, admin, "Alpha")
    tenants[ca["id"]] = tenant_a()
    snap = client.post(f"{URL}/connections/{ca['id']}/snapshots", headers=admin).json()
    other = client.post("/api/console/tenants", json={"name": "Other", "template": "balanced"}, headers=admin).json()
    client.post("/api/console/users", headers=admin, json={"tenantId": other["id"], "email": "boss@other.example",
                                                           "password": "other-password-123", "role": "tenant_admin"})
    from conftest import login
    boss = login(client, "boss@other.example", "other-password-123")
    assert client.get(f"{URL}/snapshots/{snap['id']}", headers=boss).status_code in (403, 404)
    assert client.get(f"{URL}/connections/{ca['id']}/snapshots", headers=boss).status_code in (403, 404)
