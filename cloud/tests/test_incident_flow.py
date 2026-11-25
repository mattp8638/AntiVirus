"""FLOW-03: an endpoint incident from correlated evidence to containment, restoration and governance evidence."""

import hashlib
import json

from test_detection import send, win_event

from fenrir_cloud.db import session_factory
from fenrir_cloud.models import GrcEvidence, GrcEvidenceLink


def test_incident_to_governance_evidence(client, admin, tenant, device):
    tid = tenant["id"]
    client.post("/api/console/grc/programmes", headers=admin, json={"tenantId": tid, "frameworkKey": "iso-27001"})
    send(client, device, [win_event("process.start", {
        "processImagePath": "C:\\Windows\\System32\\vssadmin.exe", "commandLine": "vssadmin delete shadows /all /quiet",
        "parentProcessImagePath": "C:\\Users\\bob\\AppData\\Local\\Temp\\locker.exe", "pid": 4242}, "f3-1")])
    inc = client.get("/api/console/incidents", headers=admin).json()[0]
    url = f"/api/console/incidents/{inc['id']}"
    client.patch(url, headers=admin, json={"status": "investigating", "note": "Bob's laptop; locker.exe from a phishing mail"})
    # The automated kill ran; the device reports its result.
    pending = client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device["headers"]).json()["items"]
    kill = next(i for i in pending if i["type"] == "process.tree.terminate")
    r = client.post(f"/api/v1/devices/{device['deviceId']}/commands/{kill['id']}/complete", headers=device["headers"],
                    json={"status": "completed", "resultJson": json.dumps({"terminated": [4242]})})
    assert r.status_code == 200, r.text
    client.patch(url, headers=admin, json={"status": "contained"})
    assert client.post(f"{url}/restoration", headers=admin, json={"text": "ok"}).status_code == 400
    client.post(f"{url}/restoration", headers=admin, json={"text": "Laptop reimaged from the 02:00 backup; Bob's password reset"})

    rep = client.get(f"{url}/report", headers=admin).json()
    assert rep["alerts"] and rep["devices"] == [device["deviceId"]]
    act = next(r for r in rep["response"] if r["action"] == "process.tree.terminate")
    assert act["status"] == "completed" and act["result"] == {"terminated": [4242]}
    assert rep["restoration"]["steps"][0]["text"].startswith("Laptop reimaged")

    detail = client.get(url, headers=admin).json()
    checklist = [{**c, "done": True} for c in detail["incident"]["checklist"]]
    client.patch(url, headers=admin, json={"checklist": checklist})
    r = client.patch(url, headers=admin, json={"status": "closed"})
    assert r.status_code == 200, r.text
    with session_factory()() as db:
        ev = db.query(GrcEvidence).filter(GrcEvidence.tenant_id == tid, GrcEvidence.control_id == "FC-INCIDENT").one()
        body = json.dumps(ev.data, sort_keys=True, separators=(",", ":"), default=str)
        assert hashlib.sha256(body.encode()).hexdigest() == ev.sha256
        links = {(l.framework_key, l.requirement_id) for l in db.query(GrcEvidenceLink).filter(GrcEvidenceLink.evidence_id == ev.id)}
        assert ("iso-27001", "A.5.26") in links
    timeline = client.get(url, headers=admin).json()["incident"]["timeline"]
    assert timeline[-1]["kind"] == "governance"
