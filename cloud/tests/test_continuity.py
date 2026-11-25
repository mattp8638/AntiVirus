"""Business continuity (GRC-17): plans with targets and dependencies, measured against backups and DR runs."""

import time

from test_device_backup import CAPS, agent_enroll, finish, heartbeat, image, link, ready_repo

from fenrir_cloud.db import session_factory
from fenrir_cloud.models import DrRun


def test_plan_assessment_exercises_and_report(client, admin, tenant):
    e = link(client, admin, tenant)
    agent_id, h = agent_enroll(client, e["token"])
    heartbeat(client, h)
    repo = ready_repo(client, admin, tenant, agent_id, h)
    r = client.post(f"/api/console/backup/agents/{agent_id}/jobs", headers=admin,
                    json={"kind": {"type": "backup_system"}, "repositoryId": repo})
    im = {**image(), "created_unix": int(time.time()) - 600}  # ten minutes ago
    while (jobs := heartbeat(client, h)["jobs"]):
        finish(client, h, jobs[0]["id"], **({"images": [im]} if jobs[0]["id"] == r.json()["id"] else {}))
    key = f"{agent_id}|"
    rb = client.post("/api/console/backup/runbooks", headers=admin, json={
        "tenantId": tenant["id"], "name": "Office", "groups": [{"name": "All", "machines": [{"key": key, "hostAgentId": agent_id}]}]})
    assert rb.status_code == 200, rb.text
    rb_id = rb.json()["id"]

    base = {"tenantId": tenant["id"], "name": "Acme continuity plan", "owner": "ops@acme.test"}
    cyc = [{"id": "a", "name": "A", "rtoMinutes": 60, "rpoMinutes": 60, "dependsOn": ["b"]},
           {"id": "b", "name": "B", "rtoMinutes": 60, "rpoMinutes": 60, "dependsOn": ["a"]}]
    assert "cycle" in client.post("/api/console/grc/continuity/plans", headers=admin, json={**base, "services": cyc}).text
    services = [
        {"id": "db", "name": "Database", "criticality": "critical", "rtoMinutes": 20, "rpoMinutes": 60,
         "machines": [key], "runbookId": rb_id},
        {"id": "erp", "name": "ERP", "criticality": "high", "rtoMinutes": 30, "rpoMinutes": 60, "dependsOn": ["db"],
         "machines": [key], "runbookId": rb_id},
        {"id": "crm", "name": "CRM", "criticality": "medium", "rtoMinutes": 10, "rpoMinutes": 5, "dependsOn": ["erp"]},
    ]
    r = client.post("/api/console/grc/continuity/plans", headers=admin, json={**base, "services": services})
    assert r.status_code == 200, r.text
    plan = r.json()
    url = f"/api/console/grc/continuity/plans/{plan['id']}"

    a = client.get(f"{url}/assessment", headers=admin).json()
    assert a["order"] == [["db"], ["erp"], ["crm"]]
    by = {s["serviceId"]: s for s in a["services"]}
    assert by["erp"]["capability"] == "gap" and any("never been run" in f for f in by["erp"]["findings"])
    assert any("ERP, whose RTO (30 min) is longer" in f for f in by["crm"]["findings"])
    assert any("no machines linked" in f for f in by["crm"]["findings"])

    # A DR run brought the machine up in 15 minutes.
    run = client.post(f"/api/console/backup/runbooks/{rb_id}/run", headers=admin, json={"mode": "test"})
    assert run.status_code == 200, run.text
    with session_factory()() as db:
        dr = db.query(DrRun).filter(DrRun.runbook_id == rb_id).one()
        dr.items = [{**i, "state": "up", "seconds": 900} for i in dr.items]
        dr.state = "succeeded"
        db.commit()
        run_id = dr.id
    by = {s["serviceId"]: s for s in client.get(f"{url}/assessment", headers=admin).json()["services"]}
    assert by["erp"]["capability"] == "measured" and by["erp"]["measuredRtoSeconds"] == 900
    assert by["db"]["capability"] == "measured"

    # A technical exercise takes its numbers from the run: 15 minutes meets both RTOs (20 and 30).
    bad = client.post(f"{url}/exercises", headers=admin, json={"kind": "technical", "title": "Q4 test", "drRunId": "nope"})
    assert bad.status_code == 400
    ex = client.post(f"{url}/exercises", headers=admin, json={
        "kind": "technical", "title": "Q4 recovery test", "drRunId": run_id, "services": ["db", "erp"],
        "participants": ["ops@acme.test"], "lessons": "DNS took longest",
        "actions": [{"text": "Pre-stage DNS records", "owner": "net@acme.test", "due": "2027-01-31"}]})
    assert ex.status_code == 200, ex.text
    ex = ex.json()
    assert ex["outcome"] == "passed" and ex["results"]["erp"]["met"] and ex["results"]["erp"]["measuredSeconds"] == 900
    by = {s["serviceId"]: s for s in client.get(f"{url}/assessment", headers=admin).json()["services"]}
    assert by["erp"]["capability"] == "exercised" and by["db"]["capability"] == "exercised"
    tt = client.post(f"{url}/exercises", headers=admin, json={"kind": "tabletop", "title": "Ransomware walk-through"})
    assert tt.status_code == 400, "a tabletop needs its outcome"

    # Approval versions the plan; a later change is visible until approved again.
    ok = client.post(f"{url}/approve", headers=admin).json()
    assert ok["status"] == "approved" and ok["approvedVersion"] == ok["version"] and len(ok["approvedSha256"]) == 64
    changed = client.patch(url, headers=admin, json={"scope": "Head office and the two shops"}).json()
    assert changed["changedSinceApproval"] is True

    rep = client.get(f"{url}/report", headers=admin).json()
    assert rep["approved"]["version"] == ok["version"] and rep["openActions"][0]["text"] == "Pre-stage DNS records"
    act = rep["openActions"][0]["id"]
    done = client.patch(f"/api/console/grc/continuity/exercises/{ex['id']}/actions/{act}", headers=admin, json={"done": True})
    assert done.json()["actions"][0]["done"] is True
    assert client.get(f"{url}/report", headers=admin).json()["openActions"] == []
