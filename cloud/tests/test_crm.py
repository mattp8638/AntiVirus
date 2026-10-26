"""CRM: opportunities, activities, account owner, account 360, profitability and M365 licences."""
from datetime import timedelta

from fenrir_cloud import db as database
from fenrir_cloud.models import Contract, Invoice, M365Connection, TimeEntry, Ticket, utcnow


def post(client, headers, path, body):
    response = client.post(f"/api/console/{path}", headers=headers, json=body)
    assert response.status_code == 200, response.text
    return response.json()


def test_opportunities_validate_and_drive_weighted_pipeline(client, admin, tenant):
    opp = post(client, admin, "crm/opportunities", {"name": "Add backup", "kind": "Upsell", "accountTenantId": tenant["id"],
                                                    "value": 1000, "monthlyValue": 100, "stage": "Proposal"})
    assert opp["probability"] == 50 and opp["closedAt"] is None
    assert client.post("/api/console/crm/opportunities", headers=admin, json={"name": "x", "stage": "Maybe"}).status_code == 400
    assert client.post("/api/console/crm/opportunities", headers=admin,
                       json={"name": "x", "accountTenantId": "ten_not_mine"}).status_code == 400
    pipeline = client.get("/api/console/crm/opportunity-pipeline", headers=admin).json()
    assert pipeline["openValue"] == 2200 and pipeline["weightedValue"] == 1100
    won = client.patch(f"/api/console/crm/opportunities/{opp['id']}", headers=admin, json={"stage": "Won"}).json()
    assert won["probability"] == 100 and won["closedAt"]
    pipeline = client.get("/api/console/crm/opportunity-pipeline", headers=admin).json()
    assert pipeline["openValue"] == 0 and pipeline["wonLast90Days"] == 1 and pipeline["winRate"] == 100.0
    reopened = client.patch(f"/api/console/crm/opportunities/{opp['id']}", headers=admin, json={"stage": "Negotiation"}).json()
    assert reopened["closedAt"] is None and reopened["probability"] == 75


def test_activities_tasks_and_account_view(client, admin, tenant):
    contact = post(client, admin, "crm/contacts", {"name": "Jo Bloggs", "accountTenantId": tenant["id"]})
    call = post(client, admin, "crm/activities", {"kind": "call", "direction": "outbound", "subject": "Quarterly review",
                                                  "accountTenantId": tenant["id"], "contactId": contact["id"]})
    assert call["completedAt"] and call["createdBy"] == call["owner"]
    task = post(client, admin, "crm/activities", {"kind": "task", "subject": "Send renewal quote", "accountTenantId": tenant["id"],
                                                  "dueAt": "2030-01-05T09:00:00Z"})
    assert task["completedAt"] is None and task["dueAt"].startswith("2030-01-05")
    assert client.post("/api/console/crm/activities", headers=admin, json={"kind": "fax", "subject": "x"}).status_code == 400
    assert client.post("/api/console/crm/activities", headers=admin,
                       json={"kind": "note", "subject": "x", "contactId": "con_missing"}).status_code == 400
    open_tasks = client.get("/api/console/crm/activities?open_only=true", headers=admin).json()
    assert [t["id"] for t in open_tasks] == [task["id"]]
    client.patch(f"/api/console/crm/activities/{task['id']}", headers=admin, json={"done": True})
    assert client.get("/api/console/crm/activities?open_only=true", headers=admin).json() == []

    assert client.patch(f"/api/console/crm/accounts/{tenant['id']}", headers=admin,
                        json={"accountOwner": "sam@msp.example"}).json()["accountOwner"] == "sam@msp.example"
    accounts = client.get("/api/console/crm/accounts", headers=admin).json()
    row = next(a for a in accounts if a["id"] == tenant["id"])
    assert row["accountOwner"] == "sam@msp.example" and row["lastActivityAt"]

    session = database.session_factory()()
    try:
        from fenrir_cloud.models import Tenant
        msp = session.get(Tenant, session.get(Tenant, tenant["id"]).parent_id)
        msp.settings = {**(msp.settings or {}), "crm": {"labourCostPerHour": 50}}
        session.add(Contract(tenant_id=msp.id, account_tenant_id=tenant["id"], name="Managed", monthly_fee=300, active=True))
        session.add(Invoice(number="INV-1", tenant_id=msp.id, account_tenant_id=tenant["id"], subtotal=900, total=1080, status="Paid"))
        session.add(Invoice(number="INV-2", tenant_id=msp.id, account_tenant_id=tenant["id"], subtotal=500, total=600, status="Draft"))
        session.add(TimeEntry(tenant_id=msp.id, account_tenant_id=tenant["id"], member="tech", hours=6, started_at=utcnow() - timedelta(days=3)))
        session.add(Ticket(number=1, tenant_id=msp.id, account_tenant_id=tenant["id"], subject="Printer", status="Open"))
        session.add(M365Connection(tenant_id=tenant["id"], name="Acme", directory_id="d", client_id="c", credentials_envelope={},
                                   snapshot={"licenses": [{"skuPartNumber": "O365_BUSINESS_PREMIUM", "prepaidUnits": {"enabled": 20},
                                                           "consumedUnits": 14}]}))
        session.commit()
    finally:
        session.close()
    detail = client.get(f"/api/console/crm/accounts/{tenant['id']}", headers=admin).json()
    assert detail["account"]["accountOwner"] == "sam@msp.example"
    assert detail["mrr"] == 300 and detail["openTickets"] == 1
    money = detail["profitability"]
    assert money["revenue"] == 900 and money["labourCost"] == 300 and money["margin"] == 600 and money["marginPercent"] == 66.7
    assert detail["m365"]["skus"][0] == {"sku": "O365_BUSINESS_PREMIUM", "purchased": 20, "assigned": 14, "unused": 6, "overAssigned": 0}
    types = [item["type"] for item in detail["timeline"]]
    assert {"call", "task", "ticket", "invoice"} <= set(types)
    assert [c["name"] for c in detail["contacts"]] == ["Jo Bloggs"]


def test_lead_conversion_records_won_deal_and_owner(client, admin):
    lead = post(client, admin, "crm/leads", {"company": "Widget Co", "value": 12000, "seats": 10, "owner": "alex@msp.example"})
    result = post(client, admin, f"crm/leads/{lead['id']}/convert", {"template": "balanced"})
    account_id = result["tenant"]["id"]
    detail = client.get(f"/api/console/crm/accounts/{account_id}", headers=admin).json()
    assert detail["account"]["accountOwner"] == "alex@msp.example"
    [deal] = detail["opportunities"]
    assert deal["stage"] == "Won" and deal["monthlyValue"] == 1000 and deal["leadId"] == lead["id"]


def test_accounts_are_scoped(client, admin, tenant):
    assert client.get("/api/console/crm/accounts/ten_unknown", headers=admin).status_code == 404
    assert client.get("/api/console/crm/accounts").status_code == 401
