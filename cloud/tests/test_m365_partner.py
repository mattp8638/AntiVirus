"""GDAP partner lifecycle, multi-tenant identity standards and Entra ID reconciliation against a fake Microsoft."""

import json
import uuid

import httpx
import pytest

from conftest import enroll, login
from test_documentation_vault import stepup
from fenrir_cloud import m365_partner, m365_standards
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import Contact, M365Connection, M365Partner, Ticket

PARTNER_DIR = "11111111-1111-1111-1111-111111111111"
CLIENT_ID = "22222222-2222-2222-2222-222222222222"
CUSTOMER_DIR = "33333333-3333-3333-3333-333333333333"


class FakeMicrosoft:
    """Token endpoint plus the slice of Graph these features use. Records every write."""

    def __init__(self):
        self.writes = []
        self.relationships = {}
        self.groups = {}
        self.ca = []
        self.compliance = []
        self.security_defaults = False
        self.gdap_tenants = {CUSTOMER_DIR}
        self.refresh_tokens = []
        self.public_client = True  # "Allow public client flows" on, as documented
        self.secrets_sent = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url, method = request.url, request.method
        if url.host == "login.microsoftonline.com":
            form = dict(x.split("=", 1) for x in request.content.decode().split("&"))
            directory = url.path.split("/")[1]
            if url.path.endswith("/devicecode"):
                return httpx.Response(200, json={"device_code": "DEVICE-SECRET", "user_code": "ABCD-EFGH", "expires_in": 900, "interval": 1})
            self.secrets_sent += "client_secret" in form
            if self.public_client and "client_secret" in form:
                return httpx.Response(401, json={"error": "invalid_client", "error_description": (
                    "AADSTS700025: Client is public so neither 'client_assertion' nor 'client_secret' should be presented.")})
            if not self.public_client and form.get("client_secret") != "partner-secret":
                return httpx.Response(401, json={"error": "invalid_client", "error_description": (
                    "AADSTS7000218: The request body must contain the following parameter: 'client_assertion' or 'client_secret'.")})
            if form["grant_type"].endswith("device_code"):
                return httpx.Response(200, json={"access_token": "partner-token", "refresh_token": "rt-1"})
            self.refresh_tokens.append(form.get("refresh_token"))
            if directory not in self.gdap_tenants | {PARTNER_DIR}:
                return httpx.Response(400, json={"error": "invalid_grant", "error_description": "AADSTS: no GDAP relationship"})
            return httpx.Response(200, json={"access_token": f"token-{directory}", "refresh_token": "rt-2"})
        path = url.path.removeprefix("/v1.0")
        body = json.loads(request.content) if request.content else None
        if method != "GET":
            self.writes.append((method, path, body))
        if path == "/tenantRelationships/delegatedAdminRelationships":
            if method == "POST":
                rel = {**body, "id": str(uuid.uuid4()), "status": "created"}
                self.relationships[rel["id"]] = rel
                return httpx.Response(201, json=rel)
            return httpx.Response(200, json={"value": list(self.relationships.values())})
        if path.startswith("/tenantRelationships/delegatedAdminRelationships/"):
            rel_id = path.split("/")[3]
            rel = self.relationships[rel_id]
            if path.endswith("/requests"):
                rel["status"] = "approvalPending"
                return httpx.Response(201, json={"action": body["action"], "status": "created"})
            if path.endswith("/accessAssignments"):
                rel.setdefault("assignments", [])
                if method == "POST":
                    rel["assignments"].append({**body, "status": "pending"})
                    return httpx.Response(201, json=body)
                return httpx.Response(200, json={"value": rel["assignments"]})
            return httpx.Response(200, json=rel)
        if path == "/tenantRelationships/delegatedAdminCustomers":
            return httpx.Response(200, json={"value": [{"tenantId": CUSTOMER_DIR, "displayName": "Acme Ltd"}]})
        if path == "/groups":
            if method == "POST":
                group = {**body, "id": str(uuid.uuid4())}
                self.groups[group["displayName"]] = group
                return httpx.Response(201, json=group)
            name = url.params.get("$filter", "").split("'")[1] if "$filter" in url.params else ""
            return httpx.Response(200, json={"value": [g for g in self.groups.values() if g["displayName"] == name]})
        if path == "/policies/identitySecurityDefaultsEnforcementPolicy":
            return httpx.Response(200, json={"isEnabled": self.security_defaults})
        if path == "/identity/conditionalAccess/policies":
            if method == "POST":
                policy = {**body, "id": str(uuid.uuid4())}
                self.ca.append(policy)
                return httpx.Response(201, json=policy)
            return httpx.Response(200, json={"value": self.ca})
        if path.startswith("/identity/conditionalAccess/policies/"):
            policy = next(p for p in self.ca if p["id"] == path.rsplit("/", 1)[1])
            policy.update(body)
            return httpx.Response(204)
        if path == "/deviceManagement/deviceCompliancePolicies":
            if method == "POST":
                policy = {**body, "id": str(uuid.uuid4())}
                self.compliance.append(policy)
                return httpx.Response(201, json=policy)
            return httpx.Response(200, json={"value": self.compliance})
        if path.startswith("/deviceManagement/deviceCompliancePolicies/"):
            return httpx.Response(200, json={})
        return httpx.Response(404, json={"error": {"code": "NotFound", "message": path}})


@pytest.fixture
def microsoft(monkeypatch):
    fake = FakeMicrosoft()
    factory = lambda: httpx.Client(transport=httpx.MockTransport(fake))  # noqa: E731
    monkeypatch.setattr(m365_partner, "http_client", factory)
    monkeypatch.setattr(m365_standards, "http_client", factory)
    return fake


def connect_partner(client, admin):
    proof = stepup(client, admin)
    created = client.post("/api/console/m365/partner", headers=proof,
                          json={"directoryId": PARTNER_DIR, "clientId": CLIENT_ID, "clientSecret": "partner-secret"})
    assert created.status_code == 200, created.text
    code = client.post("/api/console/m365/partner/signin", headers=admin).json()
    assert code["userCode"] == "ABCD-EFGH" and "deviceCode" not in code  # the device code stays on the server
    polled = client.post("/api/console/m365/partner/signin/poll", headers=admin).json()
    assert polled["status"] == "ok" and polled["partner"]["status"] == "connected"
    return proof


def test_gdap_relationship_role_groups_and_assignment(client, admin, microsoft):
    proof = connect_partner(client, admin)
    rel = client.post("/api/console/m365/partner/relationships", headers=proof,
                      json={"displayName": "Acme GDAP", "customerTenantId": CUSTOMER_DIR}).json()
    assert rel["status"] == "approvalPending" and rel["invitationUrl"].endswith(rel["id"])
    created = next(b for m, p, b in microsoft.writes if p == "/tenantRelationships/delegatedAdminRelationships")
    roles = {r["roleDefinitionId"] for r in created["accessDetails"]["unifiedRoles"]}
    assert roles == set(m365_partner.RECOMMENDED_ROLES) and "62e90394-69f5-4237-9190-012177145e10" not in roles  # no Global Admin
    assert created["autoExtendDuration"] == "P180D" and created["duration"] == "P730D"

    # Assigning before the customer approves is refused.
    assert client.post(f"/api/console/m365/partner/relationships/{rel['id']}/assign", headers=admin).status_code == 502
    groups = client.post("/api/console/m365/partner/role-groups", headers=admin).json()["roleGroups"]
    assert len(groups) == 15 and len(microsoft.groups) == 15
    client.post("/api/console/m365/partner/role-groups", headers=admin)
    assert len(microsoft.groups) == 15  # idempotent

    microsoft.relationships[rel["id"]]["status"] = "active"
    assigned = client.post(f"/api/console/m365/partner/relationships/{rel['id']}/assign", headers=admin).json()
    assert len(assigned["assigned"]) == 15
    again = client.post(f"/api/console/m365/partner/relationships/{rel['id']}/assign", headers=admin).json()
    assert again["assigned"] == [] and len(again["skipped"]) == 15
    listed = client.get("/api/console/m365/partner/relationships", headers=admin).json()
    assert listed[0]["missingRoles"] == []


def test_gdap_onboarding_gives_delegated_customer_tokens(client, admin, tenant, microsoft, monkeypatch):
    proof = connect_partner(client, admin)
    customers = client.get("/api/console/m365/partner/customers", headers=admin).json()
    assert customers == [{"tenantId": CUSTOMER_DIR, "displayName": "Acme Ltd", "connectionId": None, "fenrirTenantId": None}]
    onboarded = client.post(f"/api/console/m365/partner/customers/{CUSTOMER_DIR}/onboard", headers=proof,
                            json={"tenantId": tenant["id"], "name": "Acme Ltd"})
    assert onboarded.status_code == 200, onboarded.text
    with session_factory()() as db:
        row = db.get(M365Connection, onboarded.json()["connectionId"])
        assert row.auth_mode == "gdap" and row.credentials_envelope == {}
        from fenrir_cloud import m365

        with httpx.Client(transport=httpx.MockTransport(microsoft)) as http:
            assert m365.access_token(http, row) == f"token-{CUSTOMER_DIR}"
        db.commit()
        partner = db.query(M365Partner).one()
        assert m365_partner._secrets(partner)["refreshToken"] == "rt-2"  # the rotated token was kept
    # A customer without a GDAP relationship cannot be onboarded.
    microsoft.gdap_tenants = set()
    other = "44444444-4444-4444-4444-444444444444"
    refused = client.post(f"/api/console/m365/partner/customers/{other}/onboard", headers=proof, json={"tenantId": tenant["id"]})
    assert refused.status_code == 502 and "GDAP" in refused.json()["detail"]


def test_partner_management_is_msp_only(client, admin, tenant, microsoft):
    client.post("/api/console/users", json={"email": "ta@acme.test", "name": "T", "role": "tenant_admin", "tenantId": tenant["id"],
                                            "password": "a-long-enough-password-1"}, headers=admin)
    tenant_admin = login(client, "ta@acme.test", "a-long-enough-password-1")
    assert client.get("/api/console/m365/partner", headers=tenant_admin).status_code == 403


def gdap_connection(client, admin, tenant, microsoft):
    proof = connect_partner(client, admin)
    return client.post(f"/api/console/m365/partner/customers/{CUSTOMER_DIR}/onboard", headers=proof,
                       json={"tenantId": tenant["id"], "name": "Acme"}).json()["connectionId"], proof


def test_standards_report_only_first_then_enforce_and_drift_alerts(client, admin, tenant, microsoft):
    connection_id, proof = gdap_connection(client, admin, tenant, microsoft)
    breakglass = "55555555-5555-5555-5555-555555555555"
    assert client.put("/api/console/m365/standards/assignments", headers=admin,
                      json={"tenantId": tenant["id"], "standard": "mfa.all-users", "mode": "alert",
                            "options": {"excludeUserIds": ["not-a-guid"]}}).status_code == 422
    client.put("/api/console/m365/standards/assignments", headers=admin,
               json={"tenantId": tenant["id"], "standard": "mfa.all-users", "mode": "alert", "options": {"excludeUserIds": [breakglass]}})
    evaluated = client.post("/api/console/m365/standards/evaluate", headers=admin, json={"tenantId": tenant["id"]}).json()
    assert evaluated == [{"standard": "mfa.all-users", "connectionId": connection_id, "status": "drifted"}]
    with session_factory()() as db:
        assert db.query(Ticket).filter(Ticket.source == "m365-standards").count() == 1

    # Deploy to the customer: report-only by default, break-glass excluded, matched by name on redeploy.
    other = client.post("/api/console/tenants", json={"name": "No M365 Co", "template": "balanced"}, headers=admin).json()
    deployed = client.post("/api/console/m365/standards/deploy", headers=proof,
                           json={"standard": "mfa.all-users", "tenantIds": [tenant["id"], other["id"]],
                                 "options": {"excludeUserIds": [breakglass]}}).json()["results"]
    assert {r["status"] for r in deployed} == {"deployed", "skipped"}
    policy = microsoft.ca[0]
    assert policy["state"] == "enabledForReportingButNotEnforced" and policy["conditions"]["users"]["excludeUsers"] == [breakglass]
    status = client.post("/api/console/m365/standards/evaluate", headers=admin, json={"tenantId": tenant["id"]}).json()[0]["status"]
    assert status == "drifted"  # report-only is not enforcement
    client.post("/api/console/m365/standards/deploy", headers=proof,
                json={"standard": "mfa.all-users", "tenantIds": [tenant["id"]], "options": {"enforce": True, "excludeUserIds": [breakglass]}})
    assert len(microsoft.ca) == 1 and microsoft.ca[0]["state"] == "enabled"
    assert client.post("/api/console/m365/standards/evaluate", headers=admin,
                       json={"tenantId": tenant["id"]}).json()[0]["status"] == "compliant"
    with session_factory()() as db:
        assert db.query(Ticket).filter(Ticket.source == "m365-standards").count() == 1  # no duplicate ticket


def test_security_defaults_and_intune_baseline(client, admin, tenant, microsoft):
    connection_id, proof = gdap_connection(client, admin, tenant, microsoft)
    microsoft.security_defaults = True
    with session_factory()() as db:
        row = db.get(M365Connection, connection_id)
        assert m365_standards.evaluate(row, "mfa.admins")["status"] == "compliant"
        with pytest.raises(m365_standards.StandardError, match="Security defaults"):
            m365_standards.deploy(row, "legacy-auth.block")
        assert m365_standards.evaluate(row, "intune.windows-compliance")["status"] == "drifted"
        result = m365_standards.deploy(row, "intune.windows-compliance")
        assert result["action"] == "created"
        assert ("POST", f"/deviceManagement/deviceCompliancePolicies/{result['policyId']}/assign",
                {"assignments": [{"target": {"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"}}]}) in microsoft.writes
        assert m365_standards.evaluate(row, "intune.windows-compliance")["status"] == "compliant"
        db.commit()
    assert client.post("/api/console/m365/standards/deploy", headers=admin, json={"standard": "mfa.admins",
                                                                                  "tenantIds": [tenant["id"]]}).status_code == 403  # step-up


def test_entra_reconciliation(client, admin, tenant):
    device = enroll(client, admin, tenant, hostname="ACME-LT-1", serial="SER-1")
    with session_factory()() as db:
        db.add(M365Connection(tenant_id=tenant["id"], name="Acme", directory_id=CUSTOMER_DIR, client_id=CLIENT_ID, credentials_envelope={},
                              snapshot={"users": [
                                  {"userPrincipalName": "new@acme.test", "displayName": "New Starter", "accountEnabled": True,
                                   "assignedLicenses": [{"skuId": "x"}], "userType": "Member"},
                                  {"userPrincipalName": "known@acme.test", "accountEnabled": True, "assignedLicenses": [{"skuId": "x"}]},
                                  {"userPrincipalName": "gone@acme.test", "accountEnabled": False, "assignedLicenses": [{"skuId": "x"}]}],
                                  "mfaRegistration": [{"userPrincipalName": "known@acme.test", "isMfaRegistered": False, "isAdmin": True}],
                                  "domains": [{"id": "acme.test", "isVerified": True}],
                                  "managedDevices": [{"deviceName": "ACME-LT-1", "serialNumber": "SER-1", "operatingSystem": "Windows"},
                                                     {"deviceName": "ACME-LT-2", "serialNumber": "SER-2", "operatingSystem": "Windows",
                                                      "complianceState": "noncompliant"}]}))
        from fenrir_cloud import services

        owner = services.msp_tenant_id(db, tenant["id"])
        for email in ("known@acme.test", "gone@acme.test", "left@acme.test", "accountant@outside.test"):
            db.add(Contact(tenant_id=owner, account_tenant_id=tenant["id"], name=email, email=email))
        db.commit()
    report = client.get("/api/console/m365/reconcile", params={"tenant_id": tenant["id"]}, headers=admin).json()
    assert [s["userPrincipalName"] for s in report["newStarters"]] == ["new@acme.test"]
    assert sorted(l["email"] for l in report["leavers"]) == ["gone@acme.test", "left@acme.test"]  # external address ignored
    assert report["disabledLicensed"] == ["gone@acme.test"] and report["withoutMfa"][0] == {"userPrincipalName": "known@acme.test", "admin": True}
    assert [d["deviceName"] for d in report["devicesWithoutAgent"]] == ["ACME-LT-2"]
    assert report["noncompliantDevices"][0]["deviceName"] == "ACME-LT-2"

    leaver = next(l for l in report["leavers"] if l["email"] == "left@acme.test")
    applied = client.post("/api/console/m365/reconcile/apply", headers=admin,
                          json={"tenantId": tenant["id"], "addContacts": ["new@acme.test", "not-in-report@acme.test"],
                                "retireContacts": [leaver["contactId"]]}).json()
    assert applied == {"added": ["new@acme.test"], "retired": ["left@acme.test"]}
    after = client.get("/api/console/m365/reconcile", params={"tenant_id": tenant["id"]}, headers=admin).json()
    assert after["newStarters"] == [] and [l["email"] for l in after["leavers"]] == ["gone@acme.test"]


def test_partner_token_requests_match_the_app_client_type(client, admin, microsoft):
    """Public client (the documented setup): never send the secret, even one stored from setup or an older version.
    Confidential client (public flows off): the secret is required, and is learned on the first refusal."""
    connect_partner(client, admin)
    with session_factory()() as db:
        partner = db.query(M365Partner).one()
        assert m365_partner._secrets(partner)["clientType"] == "public"
        m365_partner._store_secrets(partner, {**m365_partner._secrets(partner), "clientType": "confidential"})  # stale belief
        assert m365_partner.access_token_for(partner) == f"token-{PARTNER_DIR}"
        assert m365_partner._secrets(partner)["clientType"] == "public"
        before = microsoft.secrets_sent
        m365_partner.access_token_for(partner, CUSTOMER_DIR)
        assert microsoft.secrets_sent == before  # remembered: no secret, no refusal

        microsoft.public_client = False
        assert m365_partner.access_token_for(partner) == f"token-{PARTNER_DIR}"
        assert m365_partner._secrets(partner)["clientType"] == "confidential" and partner.status == "connected"
        db.commit()
