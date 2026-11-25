"""AI governance (GRC-21): the answers suggest a tier, a person confirms it; approval waits for oversight, impact
assessment, the supplier and evidence; a change to use withdraws approval."""


def test_ai_inventory_assessment_and_approval(client, admin, tenant):
    tid = tenant["id"]
    qs = client.get("/api/console/grc/ai/questions", headers=admin).json()
    ids = [q["id"] for q in qs["questions"]]
    s = client.post("/api/console/grc/ai/systems", headers=admin, json={
        "tenantId": tid, "name": "CV screening assistant", "purpose": "Shortlists applicants", "owner": "hr@acme.test",
        "provider": "Hosted LLM", "deployment": "internal", "dataCategories": ["applicant CVs"]}).json()
    url = f"/api/console/grc/ai/systems/{s['id']}"
    answers = {i: False for i in ids}
    answers.update({"employment": True, "personal-data": True, "automated-decision": True, "customer-data-to-supplier": True})
    s = client.patch(url, headers=admin, json={"answers": answers}).json()
    assert s["suggestedTier"] == "high"
    s = client.patch(url, headers=admin, json={"tier": "minimal"}).json()
    assert any("lower than the answers suggest" in f for f in s["findings"])
    r = client.post(f"{url}/decision", headers=admin, json={"action": "approve"})
    assert r.status_code == 409
    vendor = client.post("/api/console/grc-assurance/vendors", headers=admin, json={"tenantId": tid, "name": "LLM Co"})
    assert vendor.status_code == 200, vendor.text
    vid = vendor.json()["id"]
    ev = client.post("/api/console/grc/evidence", headers=admin, json={"tenantId": tid, "title": "Bias test results", "kind": "note",
                                                                       "description": "Tested on 500 anonymised CVs"}).json()
    body = {"tier": "high", "impacts": "Risk of unfair rejection; mitigated by human review of every shortlist",
            "oversight": [{"measure": "A recruiter reviews every shortlist", "owner": "hr@acme.test"},
                          {"measure": "Quarterly bias audit", "owner": "dpo@acme.test", "frequency": "quarterly"}],
            "evidenceIds": [ev["id"]]}
    s = client.patch(url, headers=admin, json=body).json()
    assert s["findings"] == ["data goes to the supplier: link the supplier in third-party risk"]
    s = client.patch(url, headers=admin, json={"vendorId": vid}).json()
    assert s["findings"] == [], s["findings"]
    s = client.post(f"{url}/decision", headers=admin, json={"action": "approve"}).json()
    assert s["status"] == "approved" and s["approvedBy"]
    s = client.patch(url, headers=admin, json={"deployment": "customer-facing"}).json()
    assert s["status"] == "proposed", "a change of use needs a new approval"
    bad = client.post("/api/console/grc/ai/systems", headers=admin, json={"tenantId": tid, "name": "Mood scorer"}).json()
    bad = client.patch(f"/api/console/grc/ai/systems/{bad['id']}", headers=admin, json={"answers": {**{i: False for i in ids}, "social-scoring": True}, "tier": "unacceptable"}).json()
    assert bad["suggestedTier"] == "unacceptable" and "cannot be approved" in " ".join(bad["findings"])
