"""ISMS tasks: generated from controls, completed with what was checked, reminders and escalation."""

from datetime import timedelta

import pytest
from conftest import login

PW = "a-long-password-123"


def person(client, admin, tenant_id, email, isms_role):
    user = client.post("/api/console/users", headers=admin, json={"tenantId": tenant_id, "email": email, "password": PW,
                                                                  "name": email.split("@")[0].title(),
                                                                  "role": "tenant_analyst"}).json()
    assert client.put("/api/console/isms/memberships", headers=admin,
                      json={"tenantId": tenant_id, "userId": user["id"], "role": isms_role}).status_code == 200
    return user


@pytest.fixture()
def prog(client, admin, tenant):
    person(client, admin, tenant["id"], "isms@acme.test", "isms_manager")
    h = login(client, "isms@acme.test", PW)
    client.put("/api/console/isms/programme/frameworks", headers=h, json={"tenantId": tenant["id"], "frameworks": {"iso27001": {}}})
    client.post("/api/console/isms/programme/apply", headers=h, json={"tenantId": tenant["id"], "answers": {"develops_software": False}})
    ctl = {c["ref"]: c for c in client.get(f"/api/console/isms/controls?tenant_id={tenant['id']}", headers=h).json()["controls"]}
    return h, tenant["id"], ctl


def tasks(client, h, tid, status="open"):
    return client.get(f"/api/console/isms/tasks?tenant_id={tid}&status={status}", headers=h).json()["tasks"]


def by_control(rows, ref):
    return {t["kind"]: t for t in rows if t["controlRef"] == ref}


def test_applying_creates_a_task_plan_for_applicable_controls_only(client, admin, prog):
    h, tid, ctl = prog
    rows = tasks(client, h, tid)
    applicable = [c for c in ctl.values() if c["applicable"]]
    assert len([t for t in rows if t["kind"] == "implement"]) == len(applicable)
    assert by_control(rows, "CC-DEV-01") == {}  # not applicable: no task
    impl = by_control(rows, "CC-BKP-01")["implement"]
    assert impl["title"].startswith("Put CC-BKP-01 in place") and impl["urgency"] == "later"


def test_implementing_closes_the_plan_task_and_opens_the_operating_task(client, admin, prog):
    h, tid, ctl = prog
    kim = person(client, admin, tid, "kim@acme.test", "control_owner")
    bkp = ctl["CC-BKP-01"]
    client.patch(f"/api/console/isms/controls/{bkp['id']}", headers=h, json={"ownerId": kim["id"]})
    assert by_control(tasks(client, h, tid), "CC-BKP-01")["implement"]["assigneeId"] == kim["id"]  # tasks follow the owner
    client.post(f"/api/console/isms/controls/{bkp['id']}/assessment", headers=h, json={"answer": "yes", "implementation": "Nightly"})
    mine = by_control(tasks(client, h, tid), "CC-BKP-01")
    assert set(mine) == {"operate"} and mine["operate"]["recurrence"] is not None
    done = by_control(tasks(client, h, tid, "done"), "CC-BKP-01")["implement"]
    assert done["completionNote"].startswith("Closed automatically")
    kim_h = login(client, "kim@acme.test", PW)
    op = mine["operate"]
    url = f"/api/console/isms/tasks/{op['id']}/complete"
    assert client.post(url, headers=kim_h, json={"note": " "}).status_code == 400  # what was checked?
    r = client.post(url, headers=kim_h, json={"note": "Restored a sample file"})
    assert r.status_code == 200 and r.json()["status"] == "done"
    nxt = by_control(tasks(client, h, tid), "CC-BKP-01")["operate"]
    assert nxt["id"] != op["id"] and nxt["dueOn"] > op["dueOn"]
    implement = next(t for t in tasks(client, h, tid) if t["kind"] == "implement")
    assert client.post(f"/api/console/isms/tasks/{implement['id']}/complete", headers=h,
                       json={"note": "x"}).status_code == 400  # closes itself


def test_staff_see_and_complete_only_their_own_tasks(client, admin, prog):
    h, tid, ctl = prog
    s = person(client, admin, tid, "sam@acme.test", "staff")
    sam = login(client, "sam@acme.test", PW)
    mine = client.post("/api/console/isms/tasks", headers=h, json={"tenantId": tid, "title": "Read the new policy",
                                                                   "dueOn": "2027-01-31", "assigneeId": s["id"]}).json()
    listing = client.get(f"/api/console/isms/tasks?tenant_id={tid}", headers=sam).json()
    assert listing["ownOnly"] is True and [t["id"] for t in listing["tasks"]] == [mine["id"]]
    other = client.post("/api/console/isms/tasks", headers=h, json={"tenantId": tid, "title": "Board pack",
                                                                    "dueOn": "2027-01-15"}).json()  # nobody's
    assert client.post(f"/api/console/isms/tasks/{other['id']}/complete", headers=sam, json={"note": "x"}).status_code == 403
    assert client.post(f"/api/console/isms/tasks/{mine['id']}/complete", headers=sam, json={"note": "Read it"}).status_code == 200
    assert client.post("/api/console/isms/tasks", headers=sam, json={"tenantId": tid, "title": "x", "dueOn": "2027-01-01"}).status_code == 403
    bad = client.post("/api/console/isms/tasks", headers=h, json={"tenantId": tid, "title": "x", "dueOn": "soon"})
    assert bad.status_code == 400


def test_reminders_and_escalation_are_sent_once_per_stage(client, admin, prog):
    from fenrir_cloud import db as database, mailer
    from fenrir_cloud.isms import tasks as isms_tasks
    from fenrir_cloud.isms.models import IsmsTask
    from fenrir_cloud.models import utcnow

    h, tid, ctl = prog
    kim = person(client, admin, tid, "kim@acme.test", "control_owner")
    today = utcnow().date()
    with database.session_factory()() as db:
        for title, days, who in (("Soon", 3, kim["id"]), ("Late", -2, kim["id"]), ("Very late", -20, kim["id"]),
                                 ("Nobody's", -2, None)):
            db.add(IsmsTask(tenant_id=tid, kind="manual", title=title, due_on=today + timedelta(days=days),
                            assignee_user_id=who))
        db.commit()
        mailer.OUTBOX.clear()
        counts = isms_tasks.send_reminders(db)
        assert counts["due_soon"] == 1 and counts["overdue"] == 1 and counts["escalated"] == 1
        sent = list(mailer.OUTBOX)
        kim_mail = [m for m in sent if m["to"] == "kim@acme.test"]
        assert any("due soon" in m["subject"] for m in kim_mail) and any("overdue" in m["subject"] for m in kim_mail)
        escalated = [m for m in sent if "escalated" in m["subject"]]
        assert escalated and escalated[0]["to"] == "isms@acme.test" and "Very late" in escalated[0]["body"]
        assert "/" in escalated[0]["body"].split("(due ")[1][:10]  # DD/MM/YYYY
        mailer.OUTBOX.clear()
        assert isms_tasks.send_reminders(db) == {"due_soon": 0, "overdue": 0, "escalated": 0}
        nobody = db.query(IsmsTask).filter_by(tenant_id=tid, title="Nobody's").one()
        assert nobody.overdue_notified_at is None  # kept for when someone is assigned


def test_tasks_are_isolated(client, admin, prog):
    h, tid, ctl = prog
    other = client.post("/api/console/tenants", json={"name": "Globex", "template": "balanced"}, headers=admin).json()
    person(client, admin, other["id"], "isms@globex.test", "isms_manager")
    g = login(client, "isms@globex.test", PW)
    t = tasks(client, h, tid)[0]
    assert client.post(f"/api/console/isms/tasks/{t['id']}/complete", headers=g, json={"note": "x"}).status_code == 404
    assert client.get(f"/api/console/isms/tasks?tenant_id={tid}", headers=g).status_code == 404
