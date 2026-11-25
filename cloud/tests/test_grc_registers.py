"""Contextual registers (GRC-18), objectives and management reviews (GRC-13)."""



def test_registers_versions_and_exports(client, admin, tenant):
    tid = tenant["id"]
    url = "/api/console/grc/registers"
    assert {r["key"] for r in client.get(url, headers=admin).json()} >= {"risk", "opportunity", "interested_party", "issue", "pestel", "improvement"}
    assert client.post(f"{url}/pestel", headers=admin, json={"tenantId": tid, "title": "New data law", "category": "cosmic"}).status_code == 400
    assert client.post(f"{url}/issue", headers=admin, json={"tenantId": tid, "title": "Staff turnover", "likelihood": 3}).status_code == 400
    r = client.post(f"{url}/risk", headers=admin, json={
        "tenantId": tid, "title": "Ransomware stops order processing", "owner": "ops@acme.test", "likelihood": 4, "impact": 5,
        "treatment": "reduce", "treatmentPlan": "Immutable backups; tested recovery", "links": ["iso-27001:A.8.13"],
        "actions": [{"text": "Quarterly restore test", "owner": "ops@acme.test", "due": "2027-03-31"}], "reviewDue": "2027-01-15"})
    assert r.status_code == 200, r.text
    risk = r.json()
    assert risk["ref"] == "R-001" and risk["score"] == 20 and risk["level"] == "high" and risk["openActions"] == 1
    r = client.patch(f"{url}/risk/{risk['id']}", headers=admin, json={"residualLikelihood": 2, "residualImpact": 4, "reviewed": True, "note": "Q4 review"})
    assert r.json()["residualScore"] == 8 and r.json()["version"] == 2
    full = client.get(f"{url}/risk/{risk['id']}", headers=admin).json()
    assert [h["version"] for h in full["history"]] == [1, 2] and full["history"][1]["note"] == "Q4 review"
    assert client.post(f"{url}/interested_party", headers=admin, json={"tenantId": tid, "title": "Customers",
                                                                       "description": "Need orders shipped on time"}).json()["ref"] == "IP-001"
    client.post(f"{url}/pestel", headers=admin, json={"tenantId": tid, "title": "Data protection reform", "category": "legal"})
    imp = client.post(f"{url}/improvement", headers=admin, json={"tenantId": tid, "title": "Automate offboarding"}).json()

    x = client.post(f"{url}/risk/exports", headers=admin, json={"tenantId": tid}).json()
    assert x["rows"] == 1 and len(x["sha256"]) == 64
    client.patch(f"{url}/risk/{risk['id']}", headers=admin, json={"status": "treating"})
    listed = client.get("/api/console/grc/register-exports", headers=admin, params={"register": "risk", "tenantId": tid}).json()
    assert listed[0]["id"] == x["id"]
    csv_text = client.get(f"/api/console/grc/register-exports/{x['id']}.csv", headers=admin).text
    assert x["sha256"] in csv_text and "Ransomware" in csv_text and ",open," in csv_text, "the export is as it was"

    # Objectives with a KPI.
    o = client.post("/api/console/grc/objectives", headers=admin, json={
        "tenantId": tid, "title": "Patch critical vulnerabilities fast", "kpi": "Median days to patch critical", "unit": "days",
        "target": 7, "direction": "lower"}).json()
    o = client.post(f"/api/console/grc/objectives/{o['id']}/measurements", headers=admin, json={"value": 11, "note": "October"}).json()
    assert o["onTrack"] is False

    # Management review: pack from the current records, then held with decisions and actions.
    rv = client.post("/api/console/grc/reviews", headers=admin, json={"tenantId": tid, "title": "Q4 management review"}).json()
    assert client.post(f"/api/console/grc/reviews/{rv['id']}/held", headers=admin, json={"attendees": ["CEO"]}).status_code == 400
    rv = client.post(f"/api/console/grc/reviews/{rv['id']}/pack", headers=admin).json()
    pack = rv["pack"]
    assert pack["topRisks"][0]["ref"] == "R-001" and pack["registers"]["risk"]["open"] == 1
    assert pack["improvements"][0]["ref"] == imp["ref"] and pack["objectives"][0]["onTrack"] is False
    assert len(rv["packSha256"]) == 64
    held = client.post(f"/api/console/grc/reviews/{rv['id']}/held", headers=admin, json={
        "attendees": ["CEO", "IT manager"], "decisions": ["Fund immutable off-site copies"],
        "actions": [{"text": "Buy two rotation drives", "owner": "IT manager", "due": "2026-12-31"}]}).json()
    assert held["status"] == "held" and held["decisions"][0]["text"].startswith("Fund")
    assert client.post(f"/api/console/grc/reviews/{rv['id']}/pack", headers=admin).status_code == 400, "a held review keeps its pack"
    # The next review lists the previous one's open actions.
    nxt = client.post("/api/console/grc/reviews", headers=admin, json={"tenantId": tid, "title": "Q1 review"}).json()
    nxt = client.post(f"/api/console/grc/reviews/{nxt['id']}/pack", headers=admin).json()
    assert nxt["pack"]["previousReview"]["openActions"][0]["text"] == "Buy two rotation drives"
    done = client.patch(f"/api/console/grc/reviews/{rv['id']}/actions/{held['actions'][0]['id']}", headers=admin, json={"done": True})
    assert done.json()["actions"][0]["done"] is True
