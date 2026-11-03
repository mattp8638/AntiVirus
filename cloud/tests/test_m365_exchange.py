"""Exchange Online administration (batch 3) through the adminapi endpoint, against the fake tenant (m365_fake.py)."""
import httpx
import pytest

from m365_fake import USER, FakeTenant
from test_documentation_vault import stepup
from test_msp_modules import connection
from test_m365_lifecycle import plan, run
from fenrir_cloud import db as database
from fenrir_cloud.models import AuditLog


@pytest.fixture
def fake(monkeypatch):
    tenant = FakeTenant()
    monkeypatch.setattr(httpx, "Client", tenant.client)
    return tenant


def base(conn):
    return f"/api/console/m365/connections/{conn['id']}/exchange"


def test_mailboxes_permissions_and_suspicious_rules(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    boxes = client.get(base(conn) + "/mailboxes", headers=admin).json()
    assert [(b["address"], b["type"]) for b in boxes] == [("jo@acme.example", "user"), ("info@acme.example", "shared")]
    assert boxes[0]["aliases"] == ["joanne@acme.example"]
    shared = client.get(base(conn) + "/mailboxes/info@acme.example", headers=admin).json()
    assert shared["fullAccess"] == ["max@acme.example"] and shared["sendAs"] == ["max@acme.example"]  # SELF is left out
    jo = client.get(base(conn) + "/mailboxes/jo@acme.example", headers=admin).json()
    assert jo["rules"][0]["suspicious"] and "attacker@evil.example" in jo["rules"][0]["forwardsTo"][0]
    assert client.get(base(conn) + "/quarantine", headers=admin).json()[0]["type"] == "HighConfPhish"
    assert client.get(base(conn) + "/trace", headers=admin, params={"recipient": "jo@acme.example"}).json()[0]["status"] == "Delivered"
    assert client.get(base(conn) + "/trace", headers=admin).status_code == 400  # needs an address


def test_actions_preview_then_run_with_reauth_and_audit(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    preview = client.post(base(conn) + "/actions", headers=admin, json={
        "operation": "mailbox.forwarding", "parameters": {"mailbox": "jo@acme.example", "to": "max@acme.example", "keepCopy": True}})
    assert preview.status_code == 200 and "Forward jo@acme.example to max@acme.example" in preview.json()["description"]
    assert not [c for c in fake.exo_calls if c[0] == "Set-Mailbox"]  # previewing changes nothing
    assert client.post(base(conn) + "/actions", headers=admin, json={
        "operation": "mailbox.forwarding", "parameters": {"mailbox": "jo@acme.example", "to": "max@acme.example"}, "confirmed": True}).status_code in (403, 428)
    assert fake.mailboxes["jo@acme.example"]["ForwardingSmtpAddress"] is None  # refused without re-authentication
    done = client.post(base(conn) + "/actions", headers=stepup(client, admin), json={
        "operation": "mailbox.forwarding", "parameters": {"mailbox": "jo@acme.example", "to": "max@acme.example"}, "confirmed": True})
    assert done.status_code == 200, done.text
    assert fake.mailboxes["jo@acme.example"]["ForwardingSmtpAddress"] == "smtp:max@acme.example"
    with database.session_factory()() as db:
        assert db.query(AuditLog).filter(AuditLog.action == "m365.exchange.mailbox.forwarding").count() == 1

    released = client.post(base(conn) + "/actions", headers=stepup(client, admin), json={
        "operation": "quarantine.release", "parameters": {"messageId": fake.quarantined[0]["Identity"]}, "confirmed": True})
    assert released.status_code == 200 and fake.quarantined[0]["ReleaseStatus"] == "RELEASED"


def test_input_is_validated_and_only_listed_cmdlets_run(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    for body in ({"operation": "mailbox.forwarding", "parameters": {"mailbox": "jo@acme.example; Remove-Mailbox x", "to": "a@b.example"}},
                 {"operation": "mailbox.alias", "parameters": {"mailbox": "jo@acme.example", "alias": "not an address"}},
                 {"operation": "Remove-Mailbox", "parameters": {"mailbox": "jo@acme.example"}}):
        assert client.post(base(conn) + "/actions", headers=admin, json=body).status_code == 422


def test_missing_exchange_access_says_how_to_grant_it(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    fake.exo_denied = True
    response = client.get(base(conn) + "/mailboxes", headers=admin)
    assert response.status_code == 400 and "Exchange.ManageAsApp" in response.json()["detail"]


def test_offboarding_hands_over_the_mailbox_before_licences_go(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    flow = plan(client, admin, conn, "offboard", {"convertToShared": True, "mailboxDelegate": "max@acme.example",
                                                  "removeLicences": True, "markContact": False}, USER).json()
    keys = [s["key"] for s in flow["steps"]]
    assert keys.index("mailbox_handover") < keys.index("remove_licences")
    assert "kept because it is converted to shared" in next(s for s in flow["steps"] if s["key"] == "remove_licences")["warning"]
    done = run(client, admin, flow)["workflow"]
    assert done["status"] == "completed", done["steps"]
    assert fake.mailboxes["jo@acme.example"]["RecipientTypeDetails"] == "SharedMailbox"
    assert any(p["User"] == "max@acme.example" for p in fake.mailbox_permissions["jo@acme.example"])


def test_unexpected_failures_say_what_went_wrong_not_a_bare_500(client, admin, tenant, fake, monkeypatch):
    conn = connection(client, admin, tenant)
    from fenrir_cloud import m365_exchange

    def unreachable(*args, **kwargs):
        raise httpx.ConnectError("connection refused", request=httpx.Request("POST", "https://outlook.office365.com/adminapi"))

    monkeypatch.setattr(m365_exchange, "invoke", unreachable)
    response = client.get(base(conn) + "/mailboxes", headers=admin)
    assert response.status_code == 502 and "outlook.office365.com" in response.json()["detail"]

    def broken(*args, **kwargs):
        raise AttributeError("'list' object has no attribute 'get'")

    monkeypatch.setattr(m365_exchange, "invoke", broken)
    response = client.get(base(conn) + "/quarantine", headers=admin)
    assert response.status_code == 500 and "AttributeError" in response.json()["detail"]


def test_exchange_asks_for_uncompressed_replies(client, admin, tenant, fake, monkeypatch):
    conn = connection(client, admin, tenant)
    seen, handle = [], fake.handle

    def spy(request):
        if "adminapi" in str(request.url):
            seen.append(request.headers.get("Accept-Encoding"))
        return handle(request)

    monkeypatch.setattr(fake, "handle", spy)
    assert client.get(base(conn) + "/mailboxes", headers=admin).status_code == 200
    assert seen and set(seen) == {"identity"}
