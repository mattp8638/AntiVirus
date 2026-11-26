"""The ISMS risk method and register: scoring, owners, treating controls, acceptance and snapshots."""

from conftest import login

PW = "a-long-password-123"


def person(client, admin, tenant_id, email, isms_role):
    user = client.post("/api/console/users", headers=admin, json={"tenantId": tenant_id, "email": email, "password": PW,
                                                                  "name": email.split("@")[0].title(),
                                                                  "role": "tenant_analyst"}).json()
    assert client.put("/api/console/isms/memberships", headers=admin,
                      json={"tenantId": tenant_id, "userId": user["id"], "role": isms_role}).status_code == 200
    return user


def setup(client, admin, tenant):
    person(client, admin, tenant["id"], "isms@acme.test", "isms_manager")
    return login(client, "isms@acme.test", PW)


def add(client, h, tid, **body):
    return client.post("/api/console/isms/risks", headers=h, json={"tenantId": tid, **body})


def actions(client, admin):
    return [e["action"] for e in client.get("/api/console/audit?limit=200", headers=admin).json()]


def test_the_default_method_until_one_is_saved_then_versions(client, admin, tenant):
    h = setup(client, admin, tenant)
    tid = tenant["id"]
    m = client.get(f"/api/console/isms/risk/method?tenant_id={tid}", headers=h).json()
    assert (m["saved"], m["version"], m["appetite"], m["maxScore"]) == (False, 0, 8, 25)
    body = {k: m[k] for k in ("likelihoodScale", "impactScale", "levels", "appetite", "acceptanceCriteria", "reviewMonths")}
    assert client.put("/api/console/isms/risk/method", headers=h, json={"tenantId": tid, **body}).json()["version"] == 1
    assert client.put("/api/console/isms/risk/method", headers=h, json={"tenantId": tid, **body}).json()["version"] == 1
    assert client.put("/api/console/isms/risk/method", headers=h, json={"tenantId": tid, **body, "appetite": 10}).json()["version"] == 2
    bad = client.put("/api/console/isms/risk/method", headers=h, json={"tenantId": tid, **body, "appetite": 99})
    assert bad.status_code == 400 and "Appetite must be between 1 and 25" in bad.json()["detail"]
    assert "isms.risk_method_saved" in actions(client, admin)


def test_risks_are_scored_banded_and_numbered(client, admin, tenant):
    h = setup(client, admin, tenant)
    tid = tenant["id"]
    asset = client.post("/api/console/isms/assets", headers=h, json={"tenantId": tid, "type": "system", "name": "CRM"}).json()
    assert add(client, h, tid, title=" ").status_code == 400
    assert add(client, h, tid, title="x", inherentLikelihood=6).status_code == 400
    assert add(client, h, tid, title="x", assetIds=["ias_nope"]).status_code == 400
    r1 = add(client, h, tid, title="Ransomware on the file server", inherentLikelihood=4, inherentImpact=4,
             assetIds=[asset["id"]]).json()
    assert (r1["ref"], r1["inherentScore"], r1["inherentLevel"], r1["status"], r1["withinAppetite"]) == (
        "R-001", 16, "Critical", "assessed", False)
    assert r1["assetNames"] == ["CRM"] and r1["nextReview"] is not None
    r2 = add(client, h, tid, title="Lost laptop").json()
    assert (r2["ref"], r2["status"], r2["inherentScore"]) == ("R-002", "identified", None)
    r1 = client.patch(f"/api/console/isms/risks/{r1['id']}", headers=h, json={
        "title": r1["title"], "inherentLikelihood": 4, "inherentImpact": 4, "treatment": "modify",
        "treatmentPlan": "Immutable backups", "residualLikelihood": 2, "residualImpact": 3}).json()
    assert (r1["status"], r1["residualScore"], r1["residualLevel"], r1["withinAppetite"]) == (
        "treatment_planned", 6, "Medium", True)
    listing = client.get(f"/api/console/isms/risks?tenant_id={tid}", headers=h).json()
    assert [r["ref"] for r in listing["risks"]] == ["R-001", "R-002"]
    assert listing["heatMap"]["grid"][2][1] == 1 and listing["heatMap"]["unrated"] == 1


def test_treating_controls_are_linked(client, admin, tenant):
    h = setup(client, admin, tenant)
    tid = tenant["id"]
    client.put("/api/console/isms/programme/frameworks", headers=h, json={"tenantId": tid, "frameworks": {"iso27001": {}}})
    client.post("/api/console/isms/programme/apply", headers=h, json={"tenantId": tid})
    ctl = {c["ref"]: c["id"] for c in client.get(f"/api/console/isms/controls?tenant_id={tid}", headers=h).json()["controls"]}
    r = add(client, h, tid, title="Ransomware", controlIds=[ctl["CC-BKP-01"], ctl["CC-MAL-01"]]).json()
    assert [c["ref"] for c in r["controls"]] == ["CC-BKP-01", "CC-MAL-01"]
    r = client.patch(f"/api/console/isms/risks/{r['id']}", headers=h, json={"title": "Ransomware", "controlIds": [ctl["CC-BKP-01"]]}).json()
    assert [c["ref"] for c in r["controls"]] == ["CC-BKP-01"]
    assert client.patch(f"/api/console/isms/risks/{r['id']}", headers=h,
                        json={"title": "Ransomware", "controlIds": ["itc_nope"]}).status_code == 400


def test_only_the_owner_accepts_and_a_rating_change_ends_the_acceptance(client, admin, tenant):
    h = setup(client, admin, tenant)
    tid = tenant["id"]
    kim = person(client, admin, tid, "kim@acme.test", "control_owner")
    kim_h = login(client, "kim@acme.test", PW)
    base = {"title": "Phishing", "ownerId": kim["id"], "inherentLikelihood": 5, "inherentImpact": 4}
    r = add(client, h, tid, **base).json()
    url = f"/api/console/isms/risks/{r['id']}"
    assert client.post(f"{url}/accept", headers=h, json={"rationale": "Fine"}).status_code == 403  # not the owner
    assert client.post(f"{url}/accept", headers=kim_h, json={"rationale": "Fine"}).json()["detail"].startswith("Choose a treatment")
    client.patch(url, headers=h, json={**base, "treatment": "retain"})
    short = client.post(f"{url}/accept", headers=kim_h, json={"rationale": "It is fine"})
    assert short.status_code == 400 and "above appetite" in short.json()["detail"]  # 20 > 8
    why = "Training and mail filtering are in place; the board accepted this at the March review."
    done = client.post(f"{url}/accept", headers=kim_h, json={"rationale": why}).json()
    assert done["status"] == "accepted" and done["acceptance"]["rationale"] == why
    assert (done["acceptance"]["acceptedBy"], done["acceptance"]["residualScore"]) == ("Kim", 20)
    kept = client.patch(url, headers=kim_h, json={**base, "treatment": "retain", "description": "Mostly email"}).json()
    assert kept["status"] == "accepted" and kept["acceptance"] is not None  # wording changes keep the acceptance
    moved = client.patch(url, headers=kim_h, json={**base, "treatment": "retain", "inherentImpact": 5}).json()
    assert (moved["status"], moved["acceptance"]) == ("treatment_planned", None)  # the accepted score changed
    client.post(f"{url}/accept", headers=kim_h, json={"rationale": why})
    # The owner can edit their own risk, but a new residual rating ends the acceptance.
    again = client.patch(url, headers=kim_h, json={**base, "treatment": "retain", "residualLikelihood": 3, "residualImpact": 3})
    assert again.status_code == 200 and (again.json()["status"], again.json()["acceptance"]) == ("treatment_planned", None)
    assert client.patch(url, headers=kim_h, json={**base, "ownerId": None}).status_code == 403
    assert "isms.risk_accepted" in actions(client, admin)


def test_snapshots_keep_a_dated_copy(client, admin, tenant):
    h = setup(client, admin, tenant)
    tid = tenant["id"]
    add(client, h, tid, title="Ransomware", inherentLikelihood=3, inherentImpact=3)
    snap = client.post("/api/console/isms/risks/snapshots", headers=h, json={"tenantId": tid, "reason": "Q4 review"}).json()
    assert snap["risks"] == 1
    add(client, h, tid, title="Flood")
    listing = client.get(f"/api/console/isms/risks/snapshots?tenant_id={tid}", headers=h).json()["snapshots"]
    assert [(s["reason"], s["risks"], s["takenBy"]) for s in listing] == [("Q4 review", 1, "Isms")]


def test_roles_and_isolation(client, admin, tenant):
    h = setup(client, admin, tenant)
    tid = tenant["id"]
    person(client, admin, tid, "exec@acme.test", "executive_viewer")
    ex = login(client, "exec@acme.test", PW)
    r = add(client, h, tid, title="Ransomware").json()
    assert client.get(f"/api/console/isms/risks?tenant_id={tid}", headers=ex).status_code == 200
    assert add(client, ex, tid, title="x").status_code == 403
    assert client.patch(f"/api/console/isms/risks/{r['id']}", headers=ex, json={"title": "x"}).status_code == 403
    other = client.post("/api/console/tenants", json={"name": "Globex", "template": "balanced"}, headers=admin).json()
    person(client, admin, other["id"], "isms@globex.test", "isms_manager")
    g = login(client, "isms@globex.test", PW)
    assert client.patch(f"/api/console/isms/risks/{r['id']}", headers=g, json={"title": "x"}).status_code == 404
    assert client.get(f"/api/console/isms/risks?tenant_id={tid}", headers=g).status_code == 404
