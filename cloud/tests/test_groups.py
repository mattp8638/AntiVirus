"""Device groups can be created, nested, renamed, given a policy, filled, emptied and deleted safely."""

from conftest import enroll, login
from fenrir_cloud import db as database
from fenrir_cloud.models import Device, DeviceGroup, EnrollmentToken


def group(client, admin, tenant, name, **extra):
    reply = client.post("/api/console/groups", headers=admin, json={"tenantId": tenant["id"], "name": name, **extra})
    assert reply.status_code == 200, reply.text
    return reply.json()


def groups(client, admin):
    return {g["name"]: g for g in client.get("/api/console/groups", headers=admin).json()}


def test_groups_nest_count_their_devices_and_can_be_renamed(client, admin, tenant):
    offices = group(client, admin, tenant, "Offices")
    leeds = group(client, admin, tenant, "Leeds", parentId=offices["id"])
    pc = enroll(client, admin, tenant)
    moved = client.post("/api/console/groups/members", headers=admin, json={"deviceIds": [pc["deviceId"]], "groupId": leeds["id"]})
    assert moved.status_code == 200 and moved.json()["moved"] == [pc["deviceId"]]
    listed = groups(client, admin)
    assert listed["Leeds"]["deviceCount"] == 1 and listed["Offices"]["childCount"] == 1
    renamed = client.patch(f"/api/console/groups/{leeds['id']}", headers=admin, json={"name": "Leeds office"})
    assert renamed.status_code == 200 and renamed.json()["name"] == "Leeds office"
    filtered = client.get("/api/console/devices", headers=admin, params={"group_id": leeds["id"]}).json()
    assert [d["id"] for d in filtered] == [pc["deviceId"]]


def test_a_group_cannot_sit_inside_itself(client, admin, tenant):
    top = group(client, admin, tenant, "Top")
    child = group(client, admin, tenant, "Child", parentId=top["id"])
    assert client.patch(f"/api/console/groups/{top['id']}", headers=admin, json={"parentId": child["id"]}).status_code == 400
    assert client.patch(f"/api/console/groups/{top['id']}", headers=admin, json={"parentId": top["id"]}).status_code == 400
    assert client.patch(f"/api/console/groups/{top['id']}", headers=admin, json={"name": " "}).status_code == 422


def test_deleting_moves_devices_sub_groups_and_codes_up_a_level(client, admin, tenant):
    offices = group(client, admin, tenant, "Offices")
    leeds = group(client, admin, tenant, "Leeds", parentId=offices["id"])
    floor = group(client, admin, tenant, "Floor 2", parentId=leeds["id"])
    pc = enroll(client, admin, tenant)
    client.post("/api/console/groups/members", headers=admin, json={"deviceIds": [pc["deviceId"]], "groupId": leeds["id"]})
    code = client.post("/api/console/enrollment-tokens", headers=admin, json={"tenantId": tenant["id"], "groupId": leeds["id"]})
    assert code.status_code == 200
    deleted = client.delete(f"/api/console/groups/{leeds['id']}", headers=admin)
    assert deleted.status_code == 200 and deleted.json() == {"ok": True, "devicesMoved": 1, "movedTo": offices["id"]}
    with database.session_factory()() as db:
        assert db.get(Device, pc["deviceId"]).group_id == offices["id"]
        assert db.get(DeviceGroup, floor["id"]).parent_id == offices["id"]
        assert db.query(EnrollmentToken).filter_by(id=code.json()["id"]).one().group_id == offices["id"]


def test_a_group_a_patch_policy_or_schedule_uses_is_not_deleted(client, admin, tenant):
    servers = group(client, admin, tenant, "Servers")
    policy = client.post("/api/console/rmm/patch-policies", headers=admin,
                         json={"tenantId": tenant["id"], "groupId": servers["id"], "name": "Server patching"})
    assert policy.status_code == 200, policy.text
    refused = client.delete(f"/api/console/groups/{servers['id']}", headers=admin)
    assert refused.status_code == 409 and "Server patching" in refused.json()["detail"]


def test_groups_and_members_stay_inside_one_customer(client, admin, tenant):
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Ltd", "template": "balanced"}).json()
    theirs = group(client, admin, other, "Theirs")
    ours = group(client, admin, tenant, "Ours")
    assert client.post("/api/console/groups", headers=admin, json={"tenantId": tenant["id"], "name": "x", "parentId": theirs["id"]}).status_code == 400
    assert client.post("/api/console/enrollment-tokens", headers=admin, json={"tenantId": tenant["id"], "groupId": theirs["id"]}).status_code == 400
    pc = enroll(client, admin, tenant)
    skipped = client.post("/api/console/groups/members", headers=admin, json={"deviceIds": [pc["deviceId"]], "groupId": theirs["id"]}).json()
    assert skipped["moved"] == [] and "another customer" in skipped["skipped"][0]["reason"]
    client.post("/api/console/users", headers=admin, json={"tenantId": other["id"], "email": "ops@other.example",
                                                           "password": "other-password-123", "role": "tenant_admin"})
    ops = login(client, "ops@other.example", "other-password-123")
    assert client.delete(f"/api/console/groups/{ours['id']}", headers=ops).status_code in (403, 404)
    assert client.patch(f"/api/console/groups/{ours['id']}", headers=ops, json={"name": "mine"}).status_code in (403, 404)
    assert client.post("/api/console/groups/members", headers=ops, json={"deviceIds": [pc["deviceId"]], "groupId": None}).json()["moved"] == []


def test_taking_devices_out_of_any_group(client, admin, tenant):
    leeds = group(client, admin, tenant, "Leeds")
    pc = enroll(client, admin, tenant)
    client.post("/api/console/groups/members", headers=admin, json={"deviceIds": [pc["deviceId"]], "groupId": leeds["id"]})
    out = client.post("/api/console/groups/members", headers=admin, json={"deviceIds": [pc["deviceId"]], "groupId": None})
    assert out.json()["moved"] == [pc["deviceId"]]
    with database.session_factory()() as db:
        assert db.get(Device, pc["deviceId"]).group_id is None
    ungrouped = client.get("/api/console/devices", headers=admin, params={"group_id": "none"}).json()
    assert [d["id"] for d in ungrouped] == [pc["deviceId"]]
