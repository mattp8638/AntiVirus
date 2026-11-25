"""Control gaps (FLOW-06): a failing control opens an owned gap with its devices, the work goes on a ticket,
treatment and evidence are recorded, and a review closes it only when the control passes again; it reopens if the
control fails later. Exceptions and risks raise gaps too."""

from conftest import enroll

from fenrir_cloud import grc_automation

STATE = {"passed": False}


def fake_status(db, tenant):
    host = STATE.get("host", "")
    sig = {"key": "edr", "label": "EDR running", "passed": STATE["passed"], "evidence": [f"{host}: agent stopped"] if host else []}
    return [{"id": "endpoint-protection", "title": "Endpoint protection", "description": "", "signals": [sig],
             "automated": "passing" if STATE["passed"] else "failing", "mappings": [], "adoptedRequirements": 0, "implemented": 0}]


def test_control_gap_lifecycle(client, admin, tenant, monkeypatch):
    monkeypatch.setattr(grc_automation, "status", fake_status)
    dev = enroll(client, admin, tenant, hostname="ACME-WS-77")
    STATE.update(passed=False, host="ACME-WS-77")
    tid = tenant["id"]
    assert client.post("/api/console/grc/gaps/scan", headers=admin, json={"tenantId": tid}).json() == {"opened": 1, "reopened": 0}
    assert client.post("/api/console/grc/gaps/scan", headers=admin, json={"tenantId": tid}).json()["opened"] == 0, "one open gap per control"
    g = client.get("/api/console/grc/gaps", headers=admin, params={"tenantId": tid}).json()[0]
    assert g["status"] == "open" and g["devices"] == [dev["deviceId"]] and "agent stopped" in g["description"]
    url = f"/api/console/grc/gaps/{g['id']}"

    assert client.post(f"{url}/submit", headers=admin).status_code == 400, "an owner first"
    g = client.patch(url, headers=admin, json={"owner": "ops@acme.test", "due": "2027-01-31", "treatment": "remediate"}).json()
    assert g["status"] == "treating"
    t = client.post(f"{url}/ticket", headers=admin).json()
    assert t["ticketId"] and t["ticketNumber"]
    tk = client.get(f"/api/console/tickets/{t['ticketId']}", headers=admin).json()
    assert "[GRC]" in tk["subject"]

    ev = client.post("/api/console/grc/evidence", headers=admin, json={"tenantId": tid, "title": "EDR reinstalled", "kind": "note",
                                                                       "description": "Reinstalled on ACME-WS-77"}).json()
    client.patch(url, headers=admin, json={"evidenceIds": [ev["id"]]})
    client.post(f"{url}/submit", headers=admin)
    r = client.post(f"{url}/review", headers=admin, json={"outcome": "close"})
    assert r.status_code == 409 and "still fails" in r.text, "not closed while the control fails"
    STATE["passed"] = True
    closed = client.post(f"{url}/review", headers=admin, json={"outcome": "close", "note": "Verified on the console"}).json()
    assert closed["status"] == "closed" and closed["review"]["outcome"] == "closed"

    # The control fails again: the gap reopens, with its history.
    STATE["passed"] = False
    assert client.post("/api/console/grc/gaps/scan", headers=admin, json={"tenantId": tid}).json() == {"opened": 0, "reopened": 1}
    g = client.get(url.replace(f"/{g['id']}", ""), headers=admin, params={"tenantId": tid}).json()[0]
    assert g["status"] == "open" and g["reopened"] == 1 and [e["kind"] for e in g["timeline"]][-1] == "reopened"


def test_accepted_risk_gap_needs_justification(client, admin, tenant):
    tid = tenant["id"]
    risk = client.post("/api/console/grc/registers/risk", headers=admin, json={"tenantId": tid, "title": "Legacy ERP unsupported",
                                                                               "likelihood": 3, "impact": 4, "treatment": "accept"}).json()
    g = client.post("/api/console/grc/gaps", headers=admin, json={"tenantId": tid, "source": "risk", "sourceRef": risk["id"]}).json()
    assert g["title"].startswith("Risk treatment: R-001")
    url = f"/api/console/grc/gaps/{g['id']}"
    client.patch(url, headers=admin, json={"owner": "cfo@acme.test", "treatment": "accept"})
    client.post(f"{url}/submit", headers=admin)
    r = client.post(f"{url}/review", headers=admin, json={"outcome": "close"})
    assert r.status_code == 409 and "justification" in r.text
    client.post(f"{url}/review", headers=admin, json={"outcome": "return", "note": "Justify it"})
    client.patch(url, headers=admin, json={"justification": "Replacement funded for Q3; isolated network segment meanwhile."})
    client.post(f"{url}/submit", headers=admin)
    assert client.post(f"{url}/review", headers=admin, json={"outcome": "close"}).json()["status"] == "closed"
