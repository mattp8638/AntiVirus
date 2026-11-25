"""Microsoft 365 reports against the fake tenant, CSV export, and emailed schedules."""
import httpx
import pytest

from m365_fake import FakeTenant
from test_msp_modules import connection
from fenrir_cloud import mailer, m365_reports
from fenrir_cloud.db import session_factory


@pytest.fixture
def fake(monkeypatch):
    tenant = FakeTenant()
    monkeypatch.setattr(httpx, "Client", tenant.client)
    return tenant


def get(client, admin, conn, key):
    response = client.get(f"/api/console/m365/connections/{conn['id']}/reports/{key}", headers=admin)
    assert response.status_code == 200, response.text
    return response.json()


def test_every_report(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    assert {r["key"] for r in client.get("/api/console/m365/reports", headers=admin).json()} == set(m365_reports.REPORTS)
    licences = get(client, admin, conn, "licences")
    assert licences["rows"][0] == {"licence": "O365_BUSINESS_PREMIUM", "bought": 10, "assigned": 1, "free": 9, "heldByDisabledOrInactive": 0}
    mfa = get(client, admin, conn, "mfa")
    assert mfa["rows"][0]["signIn"] == "max@acme.example" and "1 of 2" in mfa["summary"] and "admins" in mfa["summary"]
    mailboxes = get(client, admin, conn, "mailboxes")
    assert mailboxes["rows"][0]["address"] == "jo@acme.example" and "1 near their quota" in mailboxes["summary"]
    assert get(client, admin, conn, "onedrive")["rows"][0]["usedMB"] == 2048.0
    guests = get(client, admin, conn, "guests")
    assert guests["rows"][0]["email"] == "gus@partner.example" and "1 inactive for 90+ days" in guests["summary"]
    admins = get(client, admin, conn, "admins")
    assert admins["rows"][0]["role"] == "Global Administrator" and "recommends 2 to 4" in admins["summary"]
    get(client, admin, conn, "inactive-users")
    csv_text = client.get(f"/api/console/m365/connections/{conn['id']}/reports/mfa/csv", headers=admin).text
    assert csv_text.splitlines()[0] == "user,signIn,admin,mfaRegistered,methods,passwordless"


def test_csv_never_starts_a_formula():
    out = m365_reports.to_csv({"columns": ["name"], "rows": [{"name": "=HYPERLINK(\"x\")"}]})
    assert out.splitlines()[1].startswith("\"'=")


def test_schedules_email_csv_attachments_once_per_period(client, admin, tenant, fake):
    connection(client, admin, tenant)
    bad = client.put("/api/console/m365/report-schedules", headers=admin, json={"tenantId": tenant["id"], "schedules": [
        {"reports": ["nonsense"], "every": "weekly", "to": ["boss@acme.example"]}]})
    assert bad.status_code == 422
    saved = client.put("/api/console/m365/report-schedules", headers=admin, json={"tenantId": tenant["id"], "schedules": [
        {"reports": ["mfa", "licences"], "every": "monthly", "to": ["boss@acme.example"]}]})
    assert saved.status_code == 200, saved.text
    mailer.OUTBOX.clear()
    with session_factory()() as db:
        assert m365_reports.send_schedules(db) == 1
        db.commit()
        assert m365_reports.send_schedules(db) == 0  # not again until next month
    [email] = [m for m in mailer.OUTBOX if m["to"] == "boss@acme.example"]
    assert sorted(email["attachments"])[0].startswith("licences-") and "MFA registration" in email["body"]


COPILOT = "c0000000-0000-0000-0000-00000000c0p1"


def test_copilot_licences_and_adoption(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    assert "No Microsoft 365 Copilot licences" in get(client, admin, conn, "copilot")["summary"]
    fake.extra_skus = [{"skuId": COPILOT, "skuPartNumber": "Microsoft_365_Copilot", "prepaidUnits": {"enabled": 5}, "consumedUnits": 2}]
    for user in fake.users.values():
        user["assignedLicenses"] = [*user.get("assignedLicenses", []), {"skuId": COPILOT}]
    fake.copilot_usage = [{"userPrincipalName": "jo@acme.example", "lastActivityDate": "2026-11-20",
                           "wordCopilotLastActivityDate": "2026-11-20", "microsoftTeamsCopilotLastActivityDate": "2026-11-18"}]
    report = get(client, admin, conn, "copilot")
    rows = {r["user"]: r for r in report["rows"]}
    assert rows["jo@acme.example"] == {"user": "jo@acme.example", "licence": "Microsoft_365_Copilot", "lastActivity": "2026-11-20",
                                       "apps": "Teams, Word", "status": "active"}
    assert rows["max@acme.example"]["status"] == "not used in 30 days"
    assert report["summary"].startswith("5 Copilot licence(s) bought, 2 assigned, 1 used in the last 30 days, 1 assigned but unused")
    fake.copilot_usage = None
    report = get(client, admin, conn, "copilot")
    assert "usage is unavailable" in report["summary"] and {r["status"] for r in report["rows"]} == {"usage unavailable"}
