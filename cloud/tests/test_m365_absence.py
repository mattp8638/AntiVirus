"""M365-09: scheduled absences (automatic replies, forwarding, calendar delegation) and their reversion."""
import json
import uuid
from contextlib import contextmanager
from datetime import timedelta
from urllib.parse import unquote, urlparse

import httpx
import pytest

from test_documentation_vault import stepup
from test_msp_modules import connection
from fenrir_cloud import db as database, m365, m365_absence, m365_admin
from fenrir_cloud.models import Alert, AuditLog, M365Absence, utcnow

REAL = httpx.Client
USER = "00000000-0000-0000-0000-0000000000a1"


@pytest.fixture
def mailbox(monkeypatch):
    box = {"automaticRepliesSetting": {"status": "disabled"}, "rules": [], "permissions": [
        {"id": "perm-existing", "emailAddress": {"address": "pa@example.test"}, "role": "write"}], "fail": set(), "calls": []}

    def handler(request: httpx.Request):
        path = unquote(urlparse(str(request.url)).path).split(f"/users/{USER}", 1)[1]
        box["calls"].append((request.method, path))
        if (request.method, path.split("/")[1] if path.count("/") else path) in box["fail"] or (request.method, path) in box["fail"]:
            return httpx.Response(503, json={"error": {"code": "ServiceUnavailable", "message": "try later"}})
        body = json.loads(request.content) if request.content else None
        if path == "/mailboxSettings":
            if request.method == "PATCH":
                box["automaticRepliesSetting"] = body["automaticRepliesSetting"]
                return httpx.Response(200, json={})
            return httpx.Response(200, json={"automaticRepliesSetting": box["automaticRepliesSetting"]})
        if path == "/mailFolders/inbox/messageRules" and request.method == "POST":
            rule = {**body, "id": "rule-" + uuid.uuid4().hex[:6]}
            box["rules"].append(rule)
            return httpx.Response(201, json=rule)
        if path.startswith("/mailFolders/inbox/messageRules/") and request.method == "DELETE":
            box["rules"] = [r for r in box["rules"] if r["id"] != path.rsplit("/", 1)[1]]
            return httpx.Response(204)
        if path == "/calendar/calendarPermissions":
            if request.method == "POST":
                perm = {**body, "id": "perm-" + uuid.uuid4().hex[:6]}
                box["permissions"].append(perm)
                return httpx.Response(201, json=perm)
            return httpx.Response(200, json={"value": box["permissions"]})
        if path.startswith("/calendar/calendarPermissions/") and request.method == "DELETE":
            box["permissions"] = [p for p in box["permissions"] if p["id"] != path.rsplit("/", 1)[1]]
            return httpx.Response(204)
        return httpx.Response(404)

    monkeypatch.setattr(m365_absence, "_client", lambda: REAL(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(m365, "access_token", lambda client, conn, *a, **k: "token")

    @contextmanager
    def session(conn):
        yield None, {}

    monkeypatch.setattr(m365_admin, "session", session)
    monkeypatch.setattr(m365_admin, "user", lambda c, h, ident: {"id": USER, "userPrincipalName": "sam@customer.example"})
    return box


def create(client, headers, conn, **extra):
    body = {"userId": USER, "startsAt": (utcnow() - timedelta(minutes=1)).isoformat() + "Z",
            "endsAt": (utcnow() + timedelta(days=7)).isoformat() + "Z",
            "autoReply": {"internal": "Away until Monday", "externalAudience": "contactsOnly"},
            "forwardTo": "cover@customer.example", "keepCopy": True,
            "delegates": [{"email": "cover@customer.example", "role": "write"}, {"email": "pa@example.test", "role": "read"}], **extra}
    return client.post(f"/api/console/m365/connections/{conn['id']}/absences", headers=headers, json=body)


def finish(absence_id):
    with database.session_factory()() as db:
        row = db.get(M365Absence, absence_id)
        row.ends_at = utcnow() - timedelta(seconds=1)
        db.commit()
        m365_absence.tick(db)
        db.refresh(row)
        return row.status, row.applied, row.log


def test_absence_applies_and_reverts_only_what_fenrir_changed(client, admin, tenant, mailbox):
    conn = connection(client, admin, tenant)
    assert create(client, admin, conn).status_code == 403  # forwarding needs step-up
    r = create(client, stepup(client, admin), conn)
    assert r.status_code == 200, r.text
    a = r.json()
    assert a["status"] == "active" and a["userLabel"] == "sam@customer.example"
    assert set(a["stillInPlace"]) == {"forwarding to cover@customer.example", "calendar access for cover@customer.example", "automatic replies"}
    reply = mailbox["automaticRepliesSetting"]
    assert reply["status"] == "scheduled" and reply["externalAudience"] == "contactsOnly" and reply["scheduledEndDateTime"]["timeZone"] == "UTC"
    assert mailbox["rules"][0]["actions"]["forwardTo"][0]["emailAddress"]["address"] == "cover@customer.example"
    assert "delete" not in mailbox["rules"][0]["actions"]
    assert {p["emailAddress"]["address"] for p in mailbox["permissions"]} == {"pa@example.test", "cover@customer.example"}

    status, applied, log = finish(a["id"])
    assert status == "ended" and m365_absence.still_in_place(type("A", (), {"applied": applied, "settings": {}})()) == []
    assert mailbox["rules"] == [] and mailbox["automaticRepliesSetting"] == {"status": "disabled"}
    # The delegate who already had access before the absence keeps it.
    assert [p["id"] for p in mailbox["permissions"]] == ["perm-existing"]
    with database.session_factory()() as db:
        assert db.query(AuditLog).filter_by(action="m365.absence_reverted").count() == 1


def test_failed_reversion_alerts_the_operator_with_what_is_still_in_place(client, admin, tenant, mailbox):
    conn = connection(client, admin, tenant)
    a = create(client, stepup(client, admin), conn, delegates=[]).json()
    mailbox["fail"].add(("DELETE", "mailFolders"))  # Microsoft keeps refusing to delete the forwarding rule
    for _ in range(m365_absence.MAX_ATTEMPTS):
        status, applied, _ = finish(a["id"])
    assert status == "revert_failed" and applied.get("ruleId")
    with database.session_factory()() as db:
        alert = db.query(Alert).filter_by(rule_id=m365_absence.ALERT_RULE).one()
        assert "forwarding to cover@customer.example" in alert.details["description"] and alert.severity == "high"
        assert db.query(AuditLog).filter_by(action="m365.absence_revert_failed").count() == 1
    # The operator fixes the cause and ends it again: it reverts and the forwarding rule is gone.
    mailbox["fail"].clear()
    out = client.post(f"/api/console/m365/absences/{a['id']}/end", headers=admin).json()
    assert out["status"] == "ended" and out["stillInPlace"] == [] and mailbox["rules"] == []


def test_scheduled_absence_starts_later_and_can_be_cancelled(client, admin, tenant, mailbox):
    conn = connection(client, admin, tenant)
    later = {"startsAt": (utcnow() + timedelta(days=1)).isoformat() + "Z", "endsAt": (utcnow() + timedelta(days=3)).isoformat() + "Z",
             "forwardTo": None, "delegates": []}
    a = create(client, admin, conn, **later).json()  # automatic replies only: no step-up needed
    assert a["status"] == "scheduled" and mailbox["calls"] == []
    assert create(client, admin, conn, **later).status_code == 409  # overlapping absence for the same user
    out = client.post(f"/api/console/m365/absences/{a['id']}/end", headers=admin).json()
    assert out["status"] == "cancelled"
    with database.session_factory()() as db:
        m365_absence.tick(db)
    assert mailbox["calls"] == []
    bad = create(client, admin, conn, autoReply=None, forwardTo=None, delegates=[])
    assert bad.status_code == 400 and "at least one" in bad.json()["detail"]


def test_partial_start_is_retried_without_repeating_steps(client, admin, tenant, mailbox):
    conn = connection(client, admin, tenant)
    mailbox["fail"].add(("POST", "/calendar/calendarPermissions"))
    a = create(client, stepup(client, admin), conn, delegates=[{"email": "cover@customer.example", "role": "read"}]).json()
    assert a["status"] == "scheduled"  # forwarding and replies applied; delegation failed and is retried
    mailbox["fail"].clear()
    with database.session_factory()() as db:
        m365_absence.tick(db)
        row = db.get(M365Absence, a["id"])
        assert row.status == "active"
    assert len(mailbox["rules"]) == 1  # the forwarding rule was not created twice
