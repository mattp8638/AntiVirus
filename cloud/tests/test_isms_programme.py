"""An ISMS programme: the content library, framework choice, onboarding answers, applicability and controls."""

import logging

from conftest import login
from sqlalchemy import select

PW = "a-long-password-123"


def person(client, admin, tenant_id, email, isms_role=None, fenrir_role="tenant_analyst"):
    user = client.post("/api/console/users", headers=admin, json={"tenantId": tenant_id, "email": email, "password": PW,
                                                                  "name": email.split("@")[0].title(),
                                                                  "role": fenrir_role}).json()
    if isms_role:
        r = client.put("/api/console/isms/memberships", headers=admin,
                       json={"tenantId": tenant_id, "userId": user["id"], "role": isms_role})
        assert r.status_code == 200, r.text
    return user


def manager(client, admin, tenant):
    person(client, admin, tenant["id"], "isms@acme.test", "isms_manager")
    return login(client, "isms@acme.test", PW)


def choose_iso(client, h, tid, **extra):
    r = client.put("/api/console/isms/programme/frameworks", headers=h,
                   json={"tenantId": tid, "frameworks": {"iso27001": {"status": "target_certification", **extra}}})
    assert r.status_code == 200, r.text
    return r.json()["frameworks"]


def apply(client, h, tid, answers=None):
    r = client.post("/api/console/isms/programme/apply", headers=h, json={"tenantId": tid, "answers": answers or {}})
    assert r.status_code == 200, r.text
    return r.json()


def controls(client, h, tid):
    return {c["ref"]: c for c in client.get(f"/api/console/isms/controls?tenant_id={tid}", headers=h).json()["controls"]}


def test_the_library_is_published_at_startup_and_never_changed(client, caplog):
    from fenrir_cloud import db as database
    from fenrir_cloud.isms import library
    from fenrir_cloud.isms.models import IsmsContentPack

    with database.session_factory()() as db:
        packs = {(p.pack_id, p.pack_version) for p in db.execute(select(IsmsContentPack)).scalars()}
        assert ("iso27001-2022", "1.1.0") in packs and ("common-controls", "1.0.0") in packs and len(packs) == 19
        assert library.publish_shipped(db) == []  # already there
        row = library.get(db, "iso27001-2022", "1.1.0")
        row.sha256 = "0" * 64  # as if the shipped pack were edited without a new pack_version
        db.commit()
        with caplog.at_level(logging.ERROR):
            assert library.publish_shipped(db) == []
        assert "changed without a new pack_version" in caplog.text
        assert library.get(db, "iso27001-2022", "1.1.0").sha256 == "0" * 64  # the stored version is kept


def test_frameworks_are_offered_certifiable_and_largest_first(client, admin, tenant):
    h = manager(client, admin, tenant)
    options = client.get(f"/api/console/isms/programme/frameworks?tenant_id={tenant['id']}", headers=h).json()["frameworks"]
    assert options[0]["framework"] == "iso27001" and options[0]["certifiable"] is True
    assert {o["framework"] for o in options} >= {"iso27001", "cyber-essentials", "ncsc-caf", "nist-csf", "uk-gdpr"}
    assert not any(o["selected"] for o in options)


def test_choosing_frameworks_pins_the_version_and_is_audited(client, admin, tenant):
    h = manager(client, admin, tenant)
    tid = tenant["id"]
    chosen = {o["framework"]: o for o in choose_iso(client, h, tid, targetDate="2027-06-30")}
    assert (chosen["iso27001"]["selected"], chosen["iso27001"]["pinnedVersion"], chosen["iso27001"]["targetDate"]) == (
        True, "1.1.0", "2027-06-30")
    bad = client.put("/api/console/isms/programme/frameworks", headers=h, json={"tenantId": tid, "frameworks": {"nope": {}}})
    assert bad.status_code == 400
    bad = client.put("/api/console/isms/programme/frameworks", headers=h,
                     json={"tenantId": tid, "frameworks": {"iso27001": {"status": "dreaming"}}})
    assert bad.status_code == 400
    client.put("/api/console/isms/programme/frameworks", headers=h, json={"tenantId": tid, "frameworks": {}})
    actions = [e["action"] for e in client.get("/api/console/audit?limit=100", headers=admin).json()]
    assert "isms.framework_added" in actions and "isms.framework_removed" in actions


def test_a_newer_pack_version_does_not_move_a_customer(client, admin, tenant):
    from fenrir_cloud import db as database
    from fenrir_cloud.isms import library
    from fenrir_cloud.isms.models import IsmsContentPack

    h = manager(client, admin, tenant)
    choose_iso(client, h, tenant["id"])
    with database.session_factory()() as db:
        old = library.get(db, "iso27001-2022", "1.1.0")
        db.add(IsmsContentPack(pack_id=old.pack_id, pack_version="1.2.0", kind=old.kind, framework=old.framework,
                               licence=old.licence, data={**old.data, "meta": {**old.data["meta"], "pack_version": "1.2.0"}},
                               sha256="1" * 64))
        db.commit()
    iso = next(o for o in client.get(f"/api/console/isms/programme/frameworks?tenant_id={tenant['id']}",
                                     headers=h).json()["frameworks"] if o["framework"] == "iso27001")
    assert (iso["packVersion"], iso["pinnedVersion"]) == ("1.2.0", "1.1.0")


def test_questions_come_from_the_chosen_frameworks_and_answers_are_checked(client, admin, tenant):
    h = manager(client, admin, tenant)
    tid = tenant["id"]
    assert client.get(f"/api/console/isms/programme/questions?tenant_id={tid}", headers=h).json()["questions"] == []
    choose_iso(client, h, tid)
    questions = {q["ref"]: q for q in client.get(f"/api/console/isms/programme/questions?tenant_id={tid}",
                                                 headers=h).json()["questions"]}
    assert questions["develops_software"]["type"] == "bool"
    for bad in ({"develops_software": "yes"}, {"hosting_model": "moon"}, {"no_such_question": True}):
        r = client.post("/api/console/isms/programme/apply", headers=h, json={"tenantId": tid, "answers": bad})
        assert r.status_code == 400, bad


def test_preview_writes_nothing_and_apply_creates_decisions_and_controls(client, admin, tenant):
    h = manager(client, admin, tenant)
    tid = tenant["id"]
    choose_iso(client, h, tid)
    p = client.post("/api/console/isms/programme/preview", headers=h,
                    json={"tenantId": tid, "answers": {"develops_software": False}}).json()
    assert any(c["key"] == "requirement:iso27001:A.8.25" and c["to"] is False for c in p["changes"])
    assert controls(client, h, tid) == {}
    assert client.get(f"/api/console/isms/programme/questions?tenant_id={tid}", headers=h).json()["questions"][0]["value"] is None

    result = apply(client, h, tid, {"develops_software": False})
    assert result["counts"]["requirement"]["applicable"] > 100
    decisions = {d["key"]: d for d in client.get(f"/api/console/isms/programme/applicability?tenant_id={tid}",
                                                 headers=h).json()["decisions"]}
    a825 = decisions["iso27001:A.8.25"]
    assert (a825["applicable"], a825["source"], a825["ruleRefs"]) == (False, "rule", ["R-DEV-01"])
    assert decisions["iso27001:6.1.3"]["source"] == "mandatory"
    ctl = controls(client, h, tid)
    assert ctl["CC-DEV-01"]["state"] == "not_applicable" and ctl["CC-BKP-01"]["state"] == "not_started"
    assert "iso27001:A.8.13" in ctl["CC-BKP-01"]["requirements"]
    assert apply(client, h, tid)["changes"] == []  # nothing changed, nothing to do


def test_controls_come_back_into_scope_with_their_owner_and_notes(client, admin, tenant):
    h = manager(client, admin, tenant)
    tid = tenant["id"]
    kim = person(client, admin, tid, "kim@acme.test", "control_owner")
    choose_iso(client, h, tid)
    apply(client, h, tid, {"develops_software": False})
    dev = controls(client, h, tid)["CC-DEV-01"]
    r = client.patch(f"/api/console/isms/controls/{dev['id']}", headers=h, json={"ownerId": kim["id"], "notes": "Ask Kim"})
    assert r.status_code == 200, r.text
    apply(client, h, tid, {"develops_software": True})
    dev = controls(client, h, tid)["CC-DEV-01"]
    assert (dev["state"], dev["ownerId"], dev["notes"], dev["ownerName"]) == ("not_started", kim["id"], "Ask Kim", "Kim")


def test_overrides_need_a_justification_and_cannot_exclude_mandatory_clauses(client, admin, tenant):
    h = manager(client, admin, tenant)
    tid = tenant["id"]
    choose_iso(client, h, tid)
    apply(client, h, tid)
    put = lambda **b: client.put("/api/console/isms/programme/overrides", headers=h, json={"tenantId": tid, **b})
    assert put(type="requirement", key="iso27001:6.1.3", applicable=False, justification="No").status_code == 400
    assert put(type="requirement", key="iso27001:A.7.4", applicable=False, justification="  ").status_code == 400
    assert put(type="requirement", key="iso27001:Z.9", applicable=False, justification="x").status_code == 404
    r = put(type="requirement", key="iso27001:A.7.4", applicable=False, justification="No premises we control")
    assert r.status_code == 200 and any(c["key"] == "requirement:iso27001:A.7.4" for c in r.json()["changes"])
    d = next(d for d in client.get(f"/api/console/isms/programme/applicability?tenant_id={tid}", headers=h).json()["decisions"]
             if d["key"] == "iso27001:A.7.4")
    assert (d["applicable"], d["source"], d["justification"]) == (False, "override", "No premises we control")
    r = client.delete(f"/api/console/isms/programme/overrides?tenant_id={tid}&type=requirement&key=iso27001:A.7.4", headers=h)
    assert any(c["key"] == "requirement:iso27001:A.7.4" and c["to"] is True for c in r.json()["changes"])


def test_control_edits_owners_and_states(client, admin, tenant):
    h = manager(client, admin, tenant)
    tid = tenant["id"]
    kim = person(client, admin, tid, "kim@acme.test", "control_owner")
    outsider = person(client, admin, tid, "out@acme.test")
    choose_iso(client, h, tid)
    apply(client, h, tid)
    bkp = controls(client, h, tid)["CC-BKP-01"]
    url = f"/api/console/isms/controls/{bkp['id']}"
    assert client.patch(url, headers=h, json={"ownerId": outsider["id"]}).status_code == 400
    assert client.patch(url, headers=h, json={"state": "implemented_evidenced"}).status_code == 400  # from evidence only
    kim_h = login(client, "kim@acme.test", PW)
    assert client.patch(url, headers=kim_h, json={"state": "in_progress"}).status_code == 403  # not hers yet
    client.patch(url, headers=h, json={"ownerId": kim["id"]})
    r = client.patch(url, headers=kim_h, json={"state": "in_progress"})
    assert r.status_code == 200 and r.json()["state"] == "in_progress"
    assert client.patch(url, headers=kim_h, json={"ownerId": None}).status_code == 403  # owners cannot hand it on
    assert client.patch(url, headers=kim_h, json={"notes": "Weekly restore test"}).json()["notes"] == "Weekly restore test"
    cleared = client.patch(url, headers=h, json={"ownerId": None}).json()
    assert (cleared["ownerId"], cleared["notes"]) == (None, "Weekly restore test")
    assert "isms.control_updated" in [e["action"] for e in client.get("/api/console/audit?limit=50", headers=admin).json()]


def test_programme_data_is_isolated(client, admin, tenant):
    h = manager(client, admin, tenant)
    other = client.post("/api/console/tenants", json={"name": "Globex", "template": "balanced"}, headers=admin).json()
    person(client, admin, other["id"], "isms@globex.test", "isms_manager")
    g = login(client, "isms@globex.test", PW)
    choose_iso(client, g, other["id"])
    apply(client, g, other["id"])
    their = next(iter(controls(client, g, other["id"]).values()))
    assert client.get(f"/api/console/isms/controls?tenant_id={other['id']}", headers=h).status_code == 404
    assert client.patch(f"/api/console/isms/controls/{their['id']}", headers=h, json={"notes": "x"}).status_code == 404
    assert client.post("/api/console/isms/programme/apply", headers=h, json={"tenantId": other["id"]}).status_code == 404


def test_deleting_a_customer_removes_its_isms_data_and_nothing_else(client, admin, tenant):
    from fenrir_cloud import db as database
    from fenrir_cloud.isms.scope import TENANT_TABLES
    from test_documentation_vault import stepup

    other = client.post("/api/console/tenants", json={"name": "Staying Ltd", "template": "balanced"}, headers=admin).json()
    for t in (tenant, other):
        me = client.get("/api/console/auth/me", headers=admin).json()["user"]
        client.put("/api/console/isms/memberships", headers=admin, json={"tenantId": t["id"], "userId": me["id"],
                                                                         "role": "isms_manager"})
        choose_iso(client, admin, t["id"])
        apply(client, admin, t["id"], {"develops_software": False})
        client.post("/api/console/isms/assets", headers=admin, json={"tenantId": t["id"], "type": "system", "name": "CRM"})
    preview = client.get(f"/api/console/tenants/{tenant['id']}/deletion", headers=admin)
    assert preview.status_code == 200 and preview.json()["blockers"] == []
    done = client.request("DELETE", f"/api/console/tenants/{tenant['id']}", headers=stepup(client, admin),
                          json={"confirmName": tenant["name"]})
    assert done.status_code == 200, done.text
    with database.session_factory()() as db:
        for model in TENANT_TABLES:
            assert db.query(model).filter_by(tenant_id=tenant["id"]).count() == 0, model.__tablename__
        assert db.query(TENANT_TABLES[0]).filter_by(tenant_id=other["id"]).count() == 1
    assert controls(client, admin, other["id"])["CC-DEV-01"]["state"] == "not_applicable"
