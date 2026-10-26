"""Problem and change management, technician workload, ticket links and the customer service report."""
from datetime import timedelta

from conftest import ADMIN_PASSWORD, login

from fenrir_cloud import db as database
from fenrir_cloud.models import Ticket, TimeEntry, Vulnerability, utcnow


def ticket(client, headers, tenant, subject, **extra):
    response = client.post("/api/console/tickets", headers=headers, json={"accountTenantId": tenant["id"], "subject": subject, **extra})
    assert response.status_code == 200, response.text
    return response.json()


def itil(client, headers, ticket_id, body, status=200):
    response = client.patch(f"/api/console/tickets/{ticket_id}/itil", headers=headers, json=body)
    assert response.status_code == status, response.text
    return response.json()


def test_problem_links_incidents_and_resolves_them(client, admin, tenant):
    problem = ticket(client, admin, tenant, "Outlook keeps crashing", recordType="problem")
    assert problem["recordType"] == "problem"
    first = ticket(client, admin, tenant, "Outlook crash - reception")
    second = ticket(client, admin, tenant, "Outlook crash - surgery")
    for incident in (first, second):
        itil(client, admin, incident["id"], {"problemId": problem["id"]})
    itil(client, admin, first["id"], {"problemId": second["id"]}, status=400)  # not a problem record
    itil(client, admin, problem["id"], {"rootCause": "Faulty add-in v2.1", "workaround": "Start Outlook in safe mode", "knownError": True})
    [row] = client.get("/api/console/psa/problems", headers=admin).json()
    assert row["linkedIncidents"] == 2 and row["openIncidents"] == 2 and row["knownError"]
    links = client.get(f"/api/console/tickets/{first['id']}/links", headers=admin).json()
    assert links["problem"]["workaround"] == "Start Outlook in safe mode"
    result = client.post(f"/api/console/tickets/{problem['id']}/problem/resolve-linked", headers=admin, json={}).json()
    assert result == {"resolved": 2}
    assert client.get("/api/console/psa/problems", headers=admin).json()[0]["openIncidents"] == 0
    resolved = client.get(f"/api/console/tickets/{first['id']}", headers=admin).json()
    assert resolved["resolvedAt"] and "Faulty add-in" in resolved["comments"][-2]["text"]


def _second_admin(client, admin):
    created = client.post("/api/console/users", headers=admin, json={"email": "cab@msp.example", "password": ADMIN_PASSWORD,
                                                                     "role": "msp_admin"})
    assert created.status_code == 200, created.text
    return login(client, "cab@msp.example")


def test_change_workflow_requires_plans_and_independent_approval(client, admin, tenant):
    change = ticket(client, admin, tenant, "Upgrade firewall firmware", recordType="change")
    assert change["changeState"] == "Draft"
    cid = change["id"]
    missing = client.post(f"/api/console/tickets/{cid}/change/submit", headers=admin, json={})
    assert missing.status_code == 400 and "backout plan" in missing.json()["detail"]
    start = (utcnow() + timedelta(days=2)).isoformat()
    itil(client, admin, cid, {"plannedStart": start, "plannedEnd": start}, status=400)  # empty window
    itil(client, admin, cid, {"changeRisk": "High", "implementationPlan": "Flash 7.4.3", "backoutPlan": "Reflash 7.2.8",
                              "plannedStart": start, "plannedEnd": (utcnow() + timedelta(days=2, hours=2)).isoformat()})
    assert client.post(f"/api/console/tickets/{cid}/change/submit", headers=admin, json={}).json()["changeState"] == "Submitted"
    # The submitter cannot approve their own change.
    assert client.post(f"/api/console/tickets/{cid}/change/approve", headers=admin, json={}).status_code == 403
    cab = _second_admin(client, admin)
    after_one = client.post(f"/api/console/tickets/{cid}/change/approve", headers=cab, json={}).json()
    assert after_one["changeState"] == "Submitted"  # high risk needs a second approver
    assert client.post(f"/api/console/tickets/{cid}/change/approve", headers=cab, json={}).status_code == 409
    # Editing the plan withdraws the approval.
    edited = itil(client, admin, cid, {"backoutPlan": "Reflash 7.2.8 and restore config backup"})
    assert edited["changeState"] == "Draft" and edited["changeApprovals"] == []
    client.post(f"/api/console/tickets/{cid}/change/submit", headers=admin, json={})
    itil(client, cab, cid, {"changeRisk": "Medium"})  # lower the risk: one approval is enough (and resets to Draft)
    client.post(f"/api/console/tickets/{cid}/change/submit", headers=admin, json={})
    approved = client.post(f"/api/console/tickets/{cid}/change/approve", headers=cab, json={"comment": "OK for Saturday"}).json()
    assert approved["changeState"] == "Approved"
    assert client.post(f"/api/console/tickets/{cid}/change/fail", headers=admin, json={}).status_code == 400  # needs a reason
    assert client.post(f"/api/console/tickets/{cid}/change/implement", headers=admin, json={}).json()["changeState"] == "Implemented"
    closed = client.post(f"/api/console/tickets/{cid}/change/close", headers=admin, json={}).json()
    assert closed["changeState"] == "Closed" and closed["resolvedAt"]
    report = client.get(f"/api/console/reports/executive?tenant_id={tenant['id']}", headers=admin).json()["service"]
    assert report["changesImplemented"] == 1
    plain = ticket(client, admin, tenant, "Mouse broken")
    assert client.post(f"/api/console/tickets/{plain['id']}/change/submit", headers=admin, json={}).status_code == 400


def test_workload_report_and_vulnerability_links(client, admin, tenant):
    me = client.get("/api/console/auth/me", headers=admin).json()["user"]["email"]
    urgent = ticket(client, admin, tenant, "Server down", priority="P1", assignee=me)
    ticket(client, admin, tenant, "New starter", priority="P4", assignee=me)
    ticket(client, admin, tenant, "Unassigned printer issue")
    session = database.session_factory()()
    try:
        row = session.get(Ticket, urgent["id"])
        row.sla_due_at = utcnow() - timedelta(hours=1)
        row.responded_at = row.created_at + timedelta(minutes=30)
        msp_id = row.tenant_id
        session.add(TimeEntry(tenant_id=msp_id, account_tenant_id=tenant["id"], member=me, hours=3, billable="Billable", started_at=utcnow()))
        session.add(Vulnerability(tenant_id=tenant["id"], device_id="dev_x", vuln_id="KB5040001", package="Windows", severity="critical",
                                  ticket_id=urgent["id"]))
        session.commit()
    finally:
        session.close()
    load = client.get("/api/console/psa/workload", headers=admin).json()
    mine = next(m for m in load["members"] if m["member"] == me)
    assert mine["openTickets"] == 2 and mine["p1p2"] == 1 and mine["overdue"] == 1
    assert mine["loggedHoursThisWeek"] == 3 and mine["utilisationPercent"] == 8
    assert load["unassignedOpen"] >= 1
    links = client.get(f"/api/console/tickets/{urgent['id']}/links", headers=admin).json()
    assert [v["vulnId"] for v in links["vulnerabilities"]] == ["KB5040001"]
    report = client.get(f"/api/console/reports/executive?tenant_id={tenant['id']}", headers=admin).json()["service"]
    assert report["byPriority"]["P1"]["tickets"] == 1 and report["hoursWorked"] == 3
    assert report["avgFirstResponseHours"] == 0.5
    page = client.get(f"/api/console/reports/executive.html?tenant_id={tenant['id']}", headers=admin)
    assert page.status_code == 200 and "By priority" in page.text and "Engineer time" in page.text
