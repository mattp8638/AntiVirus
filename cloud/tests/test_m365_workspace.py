"""Microsoft 365 workspace: permission catalogue, richer sync, overview, log store (mocked Microsoft; see m365_fake.py)."""
import httpx
import pytest
from datetime import timedelta

from conftest import ADMIN_PASSWORD, login
from m365_fake import FakeTenant, token
from test_msp_modules import connection, post
from fenrir_cloud import db as database, m365_permissions, m365_workspace, m365_partner
from fenrir_cloud.models import M365Connection, M365LogEntry, utcnow


@pytest.fixture
def fake(monkeypatch):
    tenant = FakeTenant()
    monkeypatch.setattr(httpx, "Client", tenant.client)
    return tenant


def test_permission_report_reads_the_token_and_knows_supersets():
    mode, granted = m365_permissions.granted_from_token(token(["User.ReadWrite.All", "AuditLog.Read.All", "Directory.Read.All"]))
    assert mode == "app"
    rows = {r["key"]: r for r in m365_permissions.report(mode, granted)}
    # User.ReadWrite.All covers sign-in blocking, session revocation, licences and password profiles.
    for key in ("user.signin", "user.revoke_sessions", "license.assign", "user.reset_password", "logs.signins", "sync.admins"):
        assert rows[key]["available"], key
    assert rows["user.tap"]["missing"] == ["UserAuthenticationMethod.ReadWrite.All"]
    assert not rows["guest.invite"]["available"]

    mode, granted = m365_permissions.granted_from_token(token(scp="Directory.Read.All User.ReadWrite.All AuditLog.Read.All"))
    rows = {r["key"]: r for r in m365_permissions.report(mode, granted)}
    assert mode == "delegated"
    assert rows["user.out_of_office"]["unsupported"] and not rows["user.out_of_office"]["available"]
    assert rows["user.revoke_sessions"]["available"]


def test_new_permissions_reach_provisioning_and_gdap_consent():
    from fenrir_cloud import m365_signin

    for name in ("UserAuthenticationMethod.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "User.Invite.All",
                 "ServiceHealth.Read.All", "MailboxSettings.ReadWrite", "Group.ReadWrite.All"):
        assert name in m365_signin.APP_PERMISSIONS
    assert "MailboxSettings.ReadWrite" not in m365_partner.CUSTOMER_GRAPH_SCOPES  # only the user's own mailbox when delegated
    assert "Directory.AccessAsUser.All" in m365_partner.CUSTOMER_GRAPH_SCOPES
    assert len(set(m365_signin.APP_PERMISSIONS)) == len(m365_signin.APP_PERMISSIONS)


def test_sync_adds_admins_health_inactive_users_and_permissions(client, admin, tenant, fake):
    fake.users["00000000-0000-0000-0000-000000000010"]["signInActivity"] = {"lastSignInDateTime": "2020-01-01T00:00:00Z"}
    row = connection(client, admin, tenant)
    synced = post(client, admin, "m365/connections/" + row["id"] + "/sync", {})
    snap = synced["snapshot"]
    assert snap["admins"][0]["role"] == "Global Administrator"
    assert snap["insights"]["admins"]["globalAdmins"] == ["max@acme.example"]
    assert snap["serviceIssues"] == [{"id": "EX1", "title": "Mail delays", "service": "Exchange Online", "status": "serviceDegradation",
                                      "classification": "incident", "feature": None, "startDateTime": None, "lastModifiedDateTime": None,
                                      "impactDescription": None}]
    assert snap["inactiveUsers"]["count"] == 1 and snap["inactiveUsers"]["users"][0]["userPrincipalName"] == "jo@acme.example"
    assert "signInActivity" not in snap and "directoryRoles" not in snap
    assert snap["permissions"]["mode"] == "app" and synced["grantedPermissions"]

    overview = client.get("/api/console/m365/overview", headers=admin).json()
    assert overview["totals"]["tenants"] == 1 and overview["totals"]["serviceIssues"] == 1 and overview["totals"]["inactiveLicensed"] == 1
    assert overview["rows"][0]["customer"] == "Acme Dental" and overview["rows"][0]["permissionsMissing"] > 0

    check = post(client, admin, "m365/connections/" + row["id"] + "/permissions/check", {})
    assert {f["key"] for f in check["features"]} == set(m365_permissions.FEATURES)


def test_logs_are_copied_once_kept_and_searchable(client, admin, tenant, fake):
    row = connection(client, admin, tenant)
    first = post(client, admin, "m365/connections/" + row["id"] + "/logs/collect", {})["outcome"]
    assert first["signin"]["added"] == 7 and first["audit"]["added"] == 3
    again = post(client, admin, "m365/connections/" + row["id"] + "/logs/collect", {})["outcome"]
    assert again["signin"]["added"] == 0 and again["audit"]["added"] == 0  # the overlap window is deduplicated
    base = "/api/console/m365/connections/" + row["id"] + "/logs"
    failures = client.get(base, headers=admin, params={"kind": "signin", "result": "failure"}).json()
    assert failures["total"] == 2 and failures["rows"][0]["activity"] == "Invalid password"
    assert failures["rows"][0]["location"] == "Leeds, GB"
    found = client.get(base, headers=admin, params={"kind": "audit", "q": "add member"}).json()
    assert found["total"] == 3 and found["rows"][0]["details"]["changes"][0]["name"] == "Group.DisplayName"
    ws = client.get("/api/console/m365/connections/" + row["id"] + "/workspace", headers=admin).json()
    assert ws["logCounts"]["stored"] == {"signin": 7, "audit": 3} and ws["logCounts"]["signinFailures24h"] == 2

    # Retention drops what is older than the setting.
    with database.session_factory()() as db:
        db.query(M365LogEntry).filter(M365LogEntry.kind == "audit").update({"at": utcnow() - timedelta(days=800)})
        db.commit()
        assert m365_workspace.purge_logs(db, 730) == 3
        db.commit()


def test_a_tenant_without_premium_is_marked_and_not_asked_every_hour(client, admin, tenant, fake):
    fake.premium = False
    row = connection(client, admin, tenant)
    outcome = post(client, admin, "m365/connections/" + row["id"] + "/logs/collect", {})["outcome"]
    assert outcome["signin"]["available"] is False and "P1 or P2" in outcome["signin"]["error"]
    assert outcome["audit"]["added"] == 3
    with database.session_factory()() as db:
        conn = db.get(M365Connection, row["id"])
        before = len(fake.calls("GET", "/auditLogs/signIns"))
        assert m365_workspace.collect_logs(db, conn)["signin"].get("skipped")
        assert len(fake.calls("GET", "/auditLogs/signIns")) == before


def test_a_busy_tenant_catches_up_through_gaps(client, admin, tenant, fake, monkeypatch):
    monkeypatch.setattr(m365_workspace, "PER_RUN", 3)
    monkeypatch.setattr(m365_workspace, "OVERLAP", timedelta(seconds=0))
    row = connection(client, admin, tenant)
    # Microsoft pages of 1000 hold everything here, so make the fake page in threes to stop early.
    original = fake.route

    def small_pages(method, path, query, body):
        if path.startswith("/auditLogs/"):
            query = {**query, "$top": "3"}
        return original(method, path, query, body)

    fake.route = small_pages
    with database.session_factory()() as db:
        conn = db.get(M365Connection, row["id"])
        first = m365_workspace.collect_logs(db, conn, kinds=("signin",))
        db.commit()
        assert first["signin"]["added"] == 3 and first["signin"]["behind"]
        for _ in range(3):
            m365_workspace.collect_logs(db, conn, kinds=("signin",), force=True)
            db.commit()
        assert db.query(M365LogEntry).filter_by(connection_id=conn.id, kind="signin").count() == 7
        assert not (conn.log_state["signin"].get("gaps"))


def test_logs_and_workspace_respect_customer_boundaries(client, admin, tenant, fake):
    row = connection(client, admin, tenant)
    other = post(client, admin, "tenants", {"name": "Other"})
    post(client, admin, "users", {"tenantId": other["id"], "email": "tech@other.test", "password": ADMIN_PASSWORD, "role": "tenant_admin"})
    outsider = login(client, "tech@other.test")
    for path in ("/workspace", "/logs"):
        assert client.get("/api/console/m365/connections/" + row["id"] + path, headers=outsider).status_code in (403, 404)
    assert client.get("/api/console/m365/overview", headers=outsider).json()["rows"] == []


def test_update_permissions_per_connection_mode(client, admin, tenant, fake, monkeypatch):
    row = connection(client, admin, tenant)
    manual = post(client, admin, "m365/connections/" + row["id"] + "/permissions/update", {})
    assert manual["action"] == "manual" and "RoleManagement.ReadWrite.Directory" in manual["permissions"]
    with database.session_factory()() as db:
        db.get(M365Connection, row["id"]).auth_mode = "gdap"
        db.commit()
    assert client.post("/api/console/m365/connections/" + row["id"] + "/permissions/update", headers=admin).status_code == 409
    monkeypatch.setattr(m365_partner, "partner_for", lambda db, tenant_id: object())
    monkeypatch.setattr(m365_partner, "refresh_consent", lambda partner, directory: "consented")
    assert post(client, admin, "m365/connections/" + row["id"] + "/permissions/update", {})["action"] == "done"


def test_refresh_consent_replaces_an_existing_partner_center_consent(monkeypatch):
    calls = []

    def handle(request):
        calls.append((request.method, request.url.path))
        if request.method == "POST":
            return httpx.Response(409 if len([c for c in calls if c[0] == "POST"]) == 1 else 201, json={})
        return httpx.Response(204)

    monkeypatch.setattr(m365_partner, "access_token_for", lambda *a, **k: "pc-token")
    row = type("Partner", (), {"client_id": "00000000-0000-0000-0000-0000000000aa"})()
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        assert m365_partner.refresh_consent(row, "00000000-0000-0000-0000-000000000001", client=client) == "consented"
    assert [c[0] for c in calls] == ["POST", "DELETE", "POST"]
    assert calls[1][1].endswith("/applicationconsents/00000000-0000-0000-0000-0000000000aa")


def test_an_existing_database_gains_the_workspace_tables_and_column(client, admin, tenant, fake):
    """A server upgraded from before this release (migration 56) must not fail on m365_connections.log_state (it did: HTTP 500)."""
    from sqlalchemy import inspect, text

    row = connection(client, admin, tenant)
    with database.engine().begin() as conn:
        conn.execute(text("DROP TABLE m365_log_entries"))
        conn.execute(text("DROP TABLE m365_workflows"))
        conn.execute(text("ALTER TABLE m365_connections DROP COLUMN log_state"))
        conn.execute(text("DELETE FROM schema_migrations WHERE version=57"))
    with pytest.raises(Exception, match="log_state"):  # what the owner's server hit
        client.get("/api/console/m365/overview", headers=admin)
    assert database.migrate(database.engine()) == [57]
    found = inspect(database.engine())
    assert {"m365_log_entries", "m365_workflows"} <= set(found.get_table_names())
    assert "log_state" in {c["name"] for c in found.get_columns("m365_connections")}
    assert client.get("/api/console/m365/overview", headers=admin).status_code == 200
    assert post(client, admin, "m365/connections/" + row["id"] + "/logs/collect", {})["outcome"]["signin"]["added"] == 7
    assert database.migrate(database.engine()) == []


def test_extra_reads_never_fail_the_sync_and_failures_say_why(client, admin, tenant, fake):
    import httpx as _httpx

    row = connection(client, admin, tenant)
    fake.fail[("GET", r"^/directoryRoles$")] = 503
    original = fake.route

    def slow_health(method, path, query, body):
        if path == "/admin/serviceAnnouncement/issues":
            raise _httpx.ReadTimeout("timed out")
        return original(method, path, query, body)

    fake.route = slow_health
    synced = post(client, admin, "m365/connections/" + row["id"] + "/sync", {})
    assert synced["status"] == "synced" and synced["snapshot"]["admins"] is None
    ws = client.get("/api/console/m365/connections/" + row["id"] + "/workspace", headers=admin).json()
    assert "HTTP 503" in ws["unavailable"]["directoryRoles"] and "Insufficient privileges" in ws["unavailable"]["directoryRoles"]
    assert "did not answer in time" in ws["unavailable"]["serviceIssues"]

    # A refused sign-in fails the sync with Microsoft's reason, and never the secret.
    real_handle = fake.handle

    def refuse_token(request):
        if request.url.host == "login.microsoftonline.com":
            return _httpx.Response(401, json={"error": "invalid_client", "error_description":
                                              "AADSTS7000215: Invalid client secret provided. Trace ID: e646f18c Correlation ID: 1"})
        return real_handle(request)

    fake.handle = refuse_token
    failed = client.post("/api/console/m365/connections/" + row["id"] + "/sync", headers=admin)
    assert failed.status_code == 502 and "AADSTS7000215: Invalid client secret provided." in failed.json()["detail"]
    assert "Trace ID" not in failed.text and "private-client-secret" not in failed.text


def test_a_connection_can_be_corrected_or_removed_and_free_licences_do_not_count(client, admin, tenant, fake):
    from test_documentation_vault import stepup
    from fenrir_cloud import m365 as graph

    row = connection(client, admin, tenant)
    url = "/api/console/m365/connections/" + row["id"]
    assert client.patch(url, headers=admin, json={"clientSecret": "new"}).status_code == 403  # needs a fresh sign-in
    proof = stepup(client, admin)
    edited = client.patch(url, headers=proof, json={"name": "Palmer CSP", "clientId": "00000000-0000-0000-0000-0000000000ab",
                                                    "clientSecret": "the-secret-value"})
    assert edited.status_code == 200 and edited.json()["name"] == "Palmer CSP" and edited.json()["clientId"].endswith("ab")
    assert "the-secret-value" not in edited.text
    post(client, admin, "m365/connections/" + row["id"] + "/logs/collect", {})

    assert client.request("DELETE", url, headers=proof, json={"confirmName": "Customer M365"}).status_code == 422
    gone = client.request("DELETE", url, headers=proof, json={"confirmName": "Palmer CSP"})
    assert gone.status_code == 200 and gone.json()["removed"]["m365_log_entries"] == 10
    assert client.get("/api/console/m365/connections", headers=admin).json() == []
    with database.session_factory()() as db:
        assert db.query(M365LogEntry).count() == 0
    again = connection(client, admin, tenant)  # the same directory can be connected again
    assert again["id"] != row["id"]

    numbers = graph.insights({"users": [], "licenses": [
        {"skuPartNumber": "O365_BUSINESS_PREMIUM", "prepaidUnits": {"enabled": 5}, "consumedUnits": 3},
        {"skuPartNumber": "FLOW_FREE", "prepaidUnits": {"enabled": 10000}, "consumedUnits": 0},
        {"skuPartNumber": "POWER_BI_STANDARD", "prepaidUnits": {"enabled": 1000000}, "consumedUnits": 1},
        {"skuPartNumber": "SOMETHING_ODD", "prepaidUnits": {"enabled": 10000}, "consumedUnits": 0}]})
    assert (numbers["licencesPurchased"], numbers["licencesAssigned"], numbers["licencesUnused"]) == (5, 3, 2)
