"""Control assessment, the Statement of Applicability (with its Excel export) and readiness."""

import io

from conftest import login
from openpyxl import load_workbook

PW = "a-long-password-123"
HALCYON = {"develops_software": False, "outsources_development": False, "has_premises": True}


def person(client, admin, tenant_id, email, isms_role):
    user = client.post("/api/console/users", headers=admin, json={"tenantId": tenant_id, "email": email, "password": PW,
                                                                  "name": email.split("@")[0].title(),
                                                                  "role": "tenant_analyst"}).json()
    assert client.put("/api/console/isms/memberships", headers=admin,
                      json={"tenantId": tenant_id, "userId": user["id"], "role": isms_role}).status_code == 200
    return user


def programme(client, admin, tenant, answers=HALCYON):
    person(client, admin, tenant["id"], "isms@acme.test", "isms_manager")
    h = login(client, "isms@acme.test", PW)
    client.put("/api/console/isms/programme/frameworks", headers=h,
               json={"tenantId": tenant["id"], "frameworks": {"iso27001": {}}})
    r = client.post("/api/console/isms/programme/apply", headers=h, json={"tenantId": tenant["id"], "answers": answers})
    assert r.status_code == 200, r.text
    return h


def controls(client, h, tid):
    return {c["ref"]: c for c in client.get(f"/api/console/isms/controls?tenant_id={tid}", headers=h).json()["controls"]}


def soa(client, h, tid):
    return {r["ref"]: r for r in client.get(f"/api/console/isms/soa?tenant_id={tid}&framework=iso27001",
                                            headers=h).json()["rows"]}


def assess(client, h, control_id, **body):
    return client.post(f"/api/console/isms/controls/{control_id}/assessment", headers=h, json=body)


def test_readiness_matches_the_hand_calculation(client, admin, tenant):
    """The standalone app's Phase 1 acceptance figures (its docs/08-readiness-hand-calculation.md)."""
    from fenrir_cloud import db as database
    from fenrir_cloud.isms.models import IsmsTenantControl
    from sqlalchemy import select

    h = programme(client, admin, tenant)
    states = {**{c: "implemented_evidenced" for c in ("CC-BKP-01", "CC-MAL-01", "CC-WEB-01", "CC-CRY-01")},
              "CC-IAM-02": "implemented", "CC-END-01": "implemented", "CC-ACC-01": "in_progress"}
    with database.session_factory()() as db:
        for row in db.execute(select(IsmsTenantControl).where(IsmsTenantControl.ref.in_(states))).scalars():
            row.state = states[row.ref]
        db.commit()
    rows = soa(client, h, tenant["id"])
    excluded = sorted(r for r, v in rows.items() if not v["applicable"])
    assert excluded == ["A.8.25", "A.8.28", "A.8.29", "A.8.30", "A.8.31", "A.8.33", "A.8.4"]
    r = client.get(f"/api/console/isms/readiness?tenant_id={tenant['id']}", headers=h).json()["frameworks"][0]
    assert (r["applicable"], r["met"], r["partial"], r["notMet"], r["score"]) == (86, 4, 6, 76, 4.7)
    assert (r["coverage"]["applicable"], r["coverage"]["evidenced"], r["coverage"]["score"]) == (53, 4, 7.5)
    assert rows["A.8.13"]["status"] == "Implemented and evidenced"
    assert rows["A.8.5"]["status"] == "Implemented" and rows["A.5.15"]["status"] == "In progress"
    assert rows["A.8.25"]["status"] == "Not applicable" and len(rows) == 93


def test_assessment_sets_state_and_needs_a_description(client, admin, tenant):
    h = programme(client, admin, tenant)
    bkp = controls(client, h, tenant["id"])["CC-BKP-01"]
    r = assess(client, h, bkp["id"], answer="yes", implementation="")
    assert r.status_code == 400 and "Describe how" in r.json()["detail"]
    assert assess(client, h, bkp["id"], answer="maybe").status_code == 400
    r = assess(client, h, bkp["id"], answer="partly", implementation="Nightly backups; restores not yet tested")
    assert (r.json()["state"], r.json()["assessment"]) == ("in_progress", "partly")
    row = soa(client, h, tenant["id"])["A.8.13"]
    assert row["controls"][0]["implementation"] == "Nightly backups; restores not yet tested"
    assert assess(client, h, bkp["id"], answer="no").json()["state"] == "not_started"


def test_not_relevant_excludes_the_control_and_what_it_satisfies_until_answered_again(client, admin, tenant):
    h = programme(client, admin, tenant)
    tid = tenant["id"]
    phy = controls(client, h, tid)["CC-PHY-01"]
    assert phy["satisfies"]
    assert assess(client, h, phy["id"], answer="not_relevant").status_code == 400  # needs a justification
    r = assess(client, h, phy["id"], answer="not_relevant", justification="Fully remote; no offices")
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "not_applicable"
    rows = soa(client, h, tid)
    for key in phy["satisfies"]:
        row = rows[key.split(":", 1)[1]]
        assert (row["applicable"], row["source"], row["justification"]) == (False, "override", "Fully remote; no offices")
    r = assess(client, h, phy["id"], answer="yes", implementation="Badge access at the new office")
    assert r.json()["state"] == "implemented"
    rows = soa(client, h, tid)
    assert all(rows[k.split(":", 1)[1]]["applicable"] for k in phy["satisfies"])


def test_owners_assess_their_own_controls_but_cannot_exclude_them(client, admin, tenant):
    h = programme(client, admin, tenant)
    kim = person(client, admin, tenant["id"], "kim@acme.test", "control_owner")
    kim_h = login(client, "kim@acme.test", PW)
    bkp = controls(client, h, tenant["id"])["CC-BKP-01"]
    assert assess(client, kim_h, bkp["id"], answer="yes", implementation="x").status_code == 403
    client.patch(f"/api/console/isms/controls/{bkp['id']}", headers=h, json={"ownerId": kim["id"]})
    assert assess(client, kim_h, bkp["id"], answer="yes", implementation="Daily backups, monthly restore test").status_code == 200
    assert assess(client, kim_h, bkp["id"], answer="not_relevant", justification="x").status_code == 403


def test_soa_export_is_a_workbook_with_plain_text_and_is_audited(client, admin, tenant):
    h = programme(client, admin, tenant)
    bkp = controls(client, h, tenant["id"])["CC-BKP-01"]
    assess(client, h, bkp["id"], answer="yes", implementation='=HYPERLINK("http://evil.test","click")')
    client.put("/api/console/isms/programme/overrides", headers=h, json={
        "tenantId": tenant["id"], "type": "requirement", "key": "iso27001:A.7.4", "applicable": False,
        "justification": '=HYPERLINK("http://evil.test","No premises")'})
    r = client.get(f"/api/console/isms/soa/export?tenant_id={tenant['id']}&framework=iso27001", headers=h)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/vnd.openxmlformats")
    assert "Statement of Applicability" in r.headers["content-disposition"]
    wb = load_workbook(io.BytesIO(r.content))
    assert wb.sheetnames == ["About", "Statement of Applicability"]
    assert wb["About"]["B2"].value == "Acme Dental"
    sheet = wb["Statement of Applicability"]
    assert [c.value for c in sheet[1]][:4] == ["Control", "Title", "Theme", "Applicable"]
    assert sheet.max_row == 94
    a813 = next(row for row in sheet.iter_rows(min_row=2) if row[0].value == "A.8.13")
    assert a813[7].data_type == "s" and a813[7].value.startswith('CC-BKP-01: =HYPERLINK')
    a74 = next(row for row in sheet.iter_rows(min_row=2) if row[0].value == "A.7.4")
    assert (a74[4].value, a74[4].data_type) == ('=HYPERLINK("http://evil.test","No premises")', "s")
    for row in sheet.iter_rows():
        for cell in row:
            assert cell.data_type != "f"
    assert "isms.soa_exported" in [e["action"] for e in client.get("/api/console/audit?limit=20", headers=admin).json()]


def test_soa_needs_the_framework_in_the_programme(client, admin, tenant):
    h = programme(client, admin, tenant)
    r = client.get(f"/api/console/isms/soa?tenant_id={tenant['id']}&framework=cyber-essentials", headers=h)
    assert r.status_code == 404
