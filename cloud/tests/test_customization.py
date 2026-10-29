from conftest import login


def _user(client, admin, tenant_id, email, role):
    reply = client.post("/api/console/users", headers=admin, json={"tenantId": tenant_id, "email": email,
                                                                    "password": "long-password-123", "role": role})
    assert reply.status_code == 200, reply.text
    return login(client, email, "long-password-123")


def test_saved_views_are_private_unless_shared(client, admin, tenant):
    msp = client.get("/api/console/auth/me", headers=admin).json()["user"]["tenantId"]
    tech = _user(client, admin, msp, "tech@msp.test", "technician")
    customer = _user(client, admin, tenant["id"], "jo@acme.test", "tenant_analyst")
    views = "/api/console/saved-views"
    mine = client.post(views, headers=admin, json={"page": "tickets", "name": "My P1s", "filters": {"assignee": "me", "q": "P1"}}).json()
    shared = client.post(views, headers=admin, json={"page": "tickets", "name": "Past SLA", "filters": {"status": "active"}, "shared": True}).json()
    assert client.post(views, headers=admin, json={"page": "nowhere", "name": "x"}).status_code == 400
    assert client.post(views, headers=admin, json={"page": "tickets", "name": "x", "filters": {"a": {"nested": 1}}}).status_code == 400

    assert {v["name"] for v in client.get(views, headers=admin, params={"page": "tickets"}).json()} == {"My P1s", "Past SLA"}
    seen = client.get(views, headers=tech, params={"page": "tickets"}).json()
    assert [v["id"] for v in seen] == [shared["id"]] and not seen[0]["mine"]  # the private view stays private
    assert client.get(views, headers=customer, params={"page": "tickets"}).json() == []  # the MSP's views stay in the MSP
    assert client.delete(f"{views}/{mine['id']}", headers=tech).status_code == 404
    assert client.delete(f"{views}/{mine['id']}", headers=admin).json() == {"ok": True}


def test_custom_fields_are_defined_once_and_validated_per_record(client, admin, tenant, device):
    fields = "/api/console/custom-fields"
    tag = client.post(fields, headers=admin, json={"entity": "device", "label": "Asset tag"}).json()
    assert tag["key"] == "asset_tag" and tag["fieldType"] == "text"
    client.post(fields, headers=admin, json={"entity": "device", "label": "Warranty ends", "type": "date"})
    client.post(fields, headers=admin, json={"entity": "device", "label": "Tier", "type": "select", "options": ["Gold", "Silver"]})
    assert client.post(fields, headers=admin, json={"entity": "device", "label": "Asset tag"}).status_code == 409
    assert client.post(fields, headers=admin, json={"entity": "device", "label": "Tier 2", "type": "select"}).status_code == 400
    assert [f["key"] for f in client.get(fields, headers=admin, params={"entity": "device"}).json()] == ["asset_tag", "warranty_ends", "tier"]

    values = f"{fields}/values/device/{device['deviceId']}"
    assert client.put(values, headers=admin, json={"values": {"tier": "Bronze"}}).status_code == 400
    assert client.put(values, headers=admin, json={"values": {"warranty_ends": "next year"}}).status_code == 400
    assert client.put(values, headers=admin, json={"values": {"colour": "red"}}).status_code == 400
    saved = client.put(values, headers=admin, json={"values": {"asset_tag": "PT-00417", "warranty_ends": "2028-03-31", "tier": "Gold"}}).json()
    assert saved["customFields"] == {"asset_tag": "PT-00417", "warranty_ends": "2028-03-31", "tier": "Gold"}
    assert client.put(values, headers=admin, json={"values": {"tier": None}}).json()["customFields"] == {"asset_tag": "PT-00417", "warranty_ends": "2028-03-31"}

    listed = client.get("/api/console/devices", headers=admin, params={"q": "PT-00417"}).json()
    assert [d["id"] for d in listed] == [device["deviceId"]] and listed[0]["customFields"]["asset_tag"] == "PT-00417"

    ticket = client.post("/api/console/tickets", headers=admin, json={"accountTenantId": tenant["id"], "subject": "Laptop broken"}).json()
    client.post(fields, headers=admin, json={"entity": "ticket", "label": "Billable to project", "type": "checkbox"})
    assert client.put(f"{fields}/values/ticket/{ticket['id']}", headers=admin, json={"values": {"billable_to_project": "yes"}}).status_code == 400
    client.put(f"{fields}/values/ticket/{ticket['id']}", headers=admin, json={"values": {"billable_to_project": True}})
    assert client.get(f"/api/console/tickets/{ticket['id']}", headers=admin).json()["customFields"] == {"billable_to_project": True}


def test_other_customers_cannot_touch_custom_field_values(client, admin, tenant, device):
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Ltd", "template": "balanced"}).json()
    outsider = _user(client, admin, other["id"], "boss@other.test", "tenant_admin")
    client.post("/api/console/custom-fields", headers=admin, json={"entity": "device", "label": "Asset tag"})
    reply = client.put(f"/api/console/custom-fields/values/device/{device['deviceId']}", headers=outsider, json={"values": {"asset_tag": "X"}})
    assert reply.status_code in (400, 403, 404)
    assert client.post("/api/console/custom-fields", headers=outsider, json={"entity": "device", "label": "Sneaky"}).status_code in (403, 404)
