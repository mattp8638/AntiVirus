"""The customer's own controls (CUST-001): validation, requirement links that count in the Statement of
Applicability and audit checklists, tasks, deletion rules, pushing them to other customers, and the portfolio."""

import pytest
from conftest import login
from test_isms_soa import HALCYON, PW, person, programme

A = "/api/console/isms"


@pytest.fixture()
def ctx(client, admin, tenant):
    h = programme(client, admin, tenant, HALCYON)
    return h, tenant["id"]


def test_custom_controls_count_in_the_soa(client, admin, ctx):
    h, tid = ctx
    meta = client.get(f"{A}/custom-controls?tenant_id={tid}", headers=h).json()
    assert meta["controls"] == [] and any(r["key"] == "iso27001:A.5.1" for r in meta["requirements"])
    add = lambda **b: client.post(f"{A}/custom-controls", headers=h, json={"tenantId": tid, "title": "Clean desk walk-round", "statement": "Monthly check of desks", **b})  # noqa: E731
    assert add(title="ab").status_code == 400
    assert add(statement=" ").status_code == 400
    assert add(frequency="hourly").status_code == 400
    assert add(requirementKeys=["soc2-2017:CC1.1"]).json()["detail"] == "Link only to requirements of this customer's frameworks."
    c = add(frequency="monthly", testProcedure="Walk the office", requirementKeys=["iso27001:A.7.7"]).json()
    assert c["ref"] == "CUST-001" and c["requirementKeys"] == ["iso27001:A.7.7"]
    assert add(title="Second control").json()["ref"] == "CUST-002"
    soa = {r["ref"]: r for r in client.get(f"{A}/soa?tenant_id={tid}&framework=iso27001", headers=h).json()["rows"]}
    assert "CUST-001" in [x["ref"] for x in soa["A.7.7"]["controls"]]
    controls = {x["ref"]: x for x in client.get(f"{A}/controls?tenant_id={tid}", headers=h).json()["controls"]}
    assert controls["CUST-001"]["custom"] is True and controls["CUST-001"]["testProcedure"] == "Walk the office"
    # Library controls cannot be edited or deleted here.
    lib = controls["CC-BKP-01"]["id"]
    assert client.patch(f"{A}/custom-controls/{lib}", headers=h, json={"title": "x y z", "statement": "s"}).status_code == 400
    assert client.delete(f"{A}/custom-controls/{lib}", headers=h).status_code == 400
    # Linked into the audit checklist.
    prog = client.post(f"{A}/audit-programmes", headers=h, json={"tenantId": tid, "title": "Programme 2027", "periodStart": "2027-01-01", "periodEnd": "2027-12-31"}).json()
    a = client.post(f"{A}/audit-programmes/{prog['id']}/audits", headers=h, json={"title": "Physical", "frameworks": ["iso27001"], "plannedStart": "2027-02-01", "plannedEnd": "2027-02-01"}).json()
    a = client.post(f"{A}/audits/{a['id']}/checklist", headers=h, json={"groups": ["annex-a-7"]}).json()
    assert "CUST-001" in next(x for x in a["checks"] if x["ref"] == "A.7.7")["controls"]
    # Update and delete.
    c = client.patch(f"{A}/custom-controls/{c['id']}", headers=h, json={"title": "Clean desk check", "statement": "Monthly", "requirementKeys": []}).json()
    assert c["requirementKeys"] == []
    assert client.delete(f"{A}/custom-controls/{c['id']}", headers=h).json() == {"ok": True}
    kim = person(client, admin, tid, "kim@acme.test", "control_owner")  # noqa: F841
    assert client.post(f"{A}/custom-controls", headers=login(client, "kim@acme.test", PW),
                       json={"tenantId": tid, "title": "Nope nope", "statement": "s"}).status_code == 403


def test_controls_in_use_cannot_be_deleted(client, admin, ctx):
    h, tid = ctx
    c = client.post(f"{A}/custom-controls", headers=h, json={"tenantId": tid, "title": "Visitor log", "statement": "Sign in"}).json()
    r = client.post(f"{A}/risks", headers=h, json={"tenantId": tid, "title": "Tailgating at reception"}).json()
    linked = client.patch(f"{A}/risks/{r['id']}", headers=h, json={"title": r["title"], "controlIds": [c["id"]]})
    assert linked.status_code == 200, linked.text
    assert [x["ref"] for x in linked.json()["controls"]] == ["CUST-001"]
    assert client.delete(f"{A}/custom-controls/{c['id']}", headers=h).json()["detail"] == \
        "CUST-001 is linked to 0 evidence item(s) and 1 risk(s). Remove those links first."


def test_push_to_other_customers_and_portfolio(client, admin, ctx):
    h, tid = ctx
    client.post(f"{A}/custom-controls", headers=h, json={"tenantId": tid, "title": "MSP backup check", "statement": "Weekly restore test"})
    other = client.post("/api/console/tenants", json={"name": "Globex", "template": "balanced"}, headers=admin).json()
    third = client.post("/api/console/tenants", json={"name": "Initech", "template": "balanced"}, headers=admin).json()
    me = client.get("/api/console/auth/me", headers=h).json()
    uid = (me.get("user") or me)["id"]
    push = lambda targets: client.post(f"{A}/custom-controls/push", headers=h, json={"sourceTenantId": tid, "targetTenantIds": targets})  # noqa: E731
    assert push([tid]).status_code == 400
    # The ISMS manager cannot see Globex in Fenrir, so cannot be given a role there or push to it.
    assert client.put(f"{A}/memberships", headers=admin, json={"tenantId": other["id"], "userId": uid, "role": "isms_manager"}).status_code == 400
    assert push([other["id"]]).status_code in (403, 404)
    customers = client.get(f"{A}/portfolio", headers=h).json()["customers"]
    assert [c["name"] for c in customers] == ["Acme Dental"] and customers[0]["framework"].startswith("ISO")
    assert {"overdueTasks", "openNonconformities", "risksAboveAppetite", "documentsDueForReview", "nextAudit"} <= set(customers[0])
    # An MSP admin who holds ISMS roles in several customers sees each one and can push.
    from fenrir_cloud.isms.custom_controls import push_templates
    from fenrir_cloud import db as database
    with database.session_factory()() as db:
        assert push_templates(db, tid, other["id"], "test") == 1
        assert push_templates(db, tid, other["id"], "test") == 0  # titles it already has are skipped
        db.commit()
    ah = admin
    for t in (tid, other["id"]):
        me_admin = client.get("/api/console/auth/me", headers=ah).json()
        aid = (me_admin.get("user") or me_admin)["id"]
        client.put(f"{A}/memberships", headers=admin, json={"tenantId": t, "userId": aid, "role": "isms_manager"})
    r = client.post(f"{A}/custom-controls/push", headers=ah, json={"sourceTenantId": tid, "targetTenantIds": [other["id"], third["id"]]})
    assert r.status_code == 403  # no ISMS role in Initech
    assert client.put(f"{A}/memberships", headers=admin, json={"tenantId": third["id"], "userId": aid, "role": "isms_manager"}).status_code == 200
    assert client.post(f"{A}/custom-controls/push", headers=ah, json={"sourceTenantId": tid, "targetTenantIds": [other["id"], third["id"]]}).json()["added"] == {other["id"]: 0, third["id"]: 1}
    names = [c["name"] for c in client.get(f"{A}/portfolio", headers=ah).json()["customers"]]
    assert names == ["Acme Dental", "Globex", "Initech"]


def test_isolation(client, admin, ctx):
    h, tid = ctx
    c = client.post(f"{A}/custom-controls", headers=h, json={"tenantId": tid, "title": "Visitor log", "statement": "Sign in"}).json()
    other = client.post("/api/console/tenants", json={"name": "Globex", "template": "balanced"}, headers=admin).json()
    person(client, admin, other["id"], "isms@globex.test", "isms_manager")
    g = login(client, "isms@globex.test", PW)
    assert client.patch(f"{A}/custom-controls/{c['id']}", headers=g, json={"title": "x y z", "statement": "s"}).status_code == 404
    assert client.get(f"{A}/custom-controls?tenant_id={tid}", headers=g).status_code == 404
