"""Group rules place devices automatically; a person's choice always wins until they hand the device back."""

import pytest

from conftest import enroll, login
from fenrir_cloud import db as database
from fenrir_cloud import group_rules
from fenrir_cloud.models import Device


def rule(*conditions, match="all", priority=100):
    return {"enabled": True, "match": match, "priority": priority,
            "conditions": [{"field": f, "op": o, "value": v} for f, o, v in conditions]}


def make_group(client, admin, tenant, name, rules=None, **extra):
    reply = client.post("/api/console/groups", headers=admin, json={"tenantId": tenant["id"], "name": name, "matchRules": rules, **extra})
    assert reply.status_code == 200, reply.text
    return reply.json()


def group_of(device_id):
    with database.session_factory()() as db:
        device = db.get(Device, device_id)
        return device.group_id, device.group_rule_id


def send_profile(client, device, os_name, role_kind=None):
    profile = {"os": {"name": os_name, "build": "1"}, "hardware": {"manufacturer": "Dell", "model": "R650"}}
    if role_kind:
        profile["role"] = {"kind": role_kind}
    reply = client.post(f"/api/v1/devices/{device['deviceId']}/profile", headers=device["headers"], json={"profile": profile})
    assert reply.status_code == 200, reply.text


def test_rules_are_checked_before_they_are_saved():
    with pytest.raises(group_rules.RuleError):
        group_rules.clean(rule(("colour", "is", "red")))
    with pytest.raises(group_rules.RuleError):
        group_rules.clean(rule(("hostname", "is", "x")))  # hostname takes "matches"
    with pytest.raises(group_rules.RuleError):
        group_rules.clean(rule(("ip", "in", "not-a-range")))
    with pytest.raises(group_rules.RuleError):
        group_rules.clean(rule(("role", "is", "mainframe")))
    assert group_rules.clean(None) == {}
    assert group_rules.clean({"conditions": []})["enabled"] is False


def test_a_hostname_rule_places_devices_as_they_enrol(client, admin, tenant):
    london = make_group(client, admin, tenant, "London", rule(("hostname", "matches", "LDN-*")))
    ldn = enroll(client, admin, tenant, hostname="LDN-PC1", serial="L1")
    other = enroll(client, admin, tenant, hostname="MAN-PC1", serial="M1")
    assert group_of(ldn["deviceId"]) == (london["id"], london["id"])
    assert group_of(other["deviceId"]) == (None, None)


def test_a_server_role_rule_places_the_device_when_its_inventory_arrives(client, admin, tenant):
    servers = make_group(client, admin, tenant, "Servers", rule(("platform", "is", "windows"), ("role", "is", "server")))
    srv = enroll(client, admin, tenant, hostname="FS01", os_version="Windows Server 2022", serial="S1")
    assert group_of(srv["deviceId"])[0] is None  # the role is not known until the inventory arrives
    send_profile(client, srv, "Windows Server 2022 Standard", "server")
    assert group_of(srv["deviceId"])[0] == servers["id"]
    listed = {g["name"]: g["deviceCount"] for g in client.get("/api/console/groups", headers=admin).json()}
    assert listed["Servers"] == 1


def test_saving_rules_places_existing_devices_and_a_device_that_stops_matching_leaves(client, admin, tenant):
    pc = enroll(client, admin, tenant, hostname="KIOSK-1", serial="K1")
    kiosks = make_group(client, admin, tenant, "Kiosks")
    saved = client.patch(f"/api/console/groups/{kiosks['id']}", headers=admin, json={"matchRules": rule(("tag", "has", "kiosk"))})
    assert saved.status_code == 200 and saved.json()["rulesMoved"] == 0
    client.patch(f"/api/console/devices/{pc['deviceId']}", headers=admin, json={"tags": ["kiosk"]})
    assert group_of(pc["deviceId"])[0] == kiosks["id"]
    client.patch(f"/api/console/devices/{pc['deviceId']}", headers=admin, json={"tags": []})
    assert group_of(pc["deviceId"]) == (None, None)


def test_a_persons_choice_wins_and_can_be_handed_back(client, admin, tenant):
    london = make_group(client, admin, tenant, "London", rule(("hostname", "matches", "LDN-*")))
    vip = make_group(client, admin, tenant, "VIP")
    pc = enroll(client, admin, tenant, hostname="LDN-CEO", serial="C1")
    assert group_of(pc["deviceId"])[0] == london["id"]
    client.post("/api/console/groups/members", headers=admin, json={"deviceIds": [pc["deviceId"]], "groupId": vip["id"]})
    with database.session_factory()() as db:
        group_rules.tick(db)
    assert group_of(pc["deviceId"]) == (vip["id"], "manual")
    client.post("/api/console/groups/members", headers=admin, json={"deviceIds": [pc["deviceId"]], "groupId": None})
    with database.session_factory()() as db:
        group_rules.tick(db)
    assert group_of(pc["deviceId"]) == (None, "manual")  # "no group" chosen by hand sticks too
    client.post("/api/console/groups/members", headers=admin, json={"deviceIds": [pc["deviceId"]], "groupId": "auto"})
    assert group_of(pc["deviceId"]) == (london["id"], london["id"])
    client.patch(f"/api/console/devices/{pc['deviceId']}", headers=admin, json={"groupId": vip["id"]})
    assert group_of(pc["deviceId"]) == (vip["id"], "manual")
    client.patch(f"/api/console/devices/{pc['deviceId']}", headers=admin, json={"groupId": "auto"})
    assert group_of(pc["deviceId"]) == (london["id"], london["id"])


def test_an_enrolment_codes_group_is_a_hand_placement(client, admin, tenant):
    make_group(client, admin, tenant, "London", rule(("hostname", "matches", "LDN-*")))
    reception = make_group(client, admin, tenant, "Reception")
    code = client.post("/api/console/enrollment-tokens", headers=admin, json={"tenantId": tenant["id"], "groupId": reception["id"]}).json()["token"]
    reply = client.post("/api/v1/enroll", json={"hostname": "LDN-DESK", "osVersion": "Windows 11", "serialNumber": "R1"},
                        headers={"X-Fenrir-Token": code})
    assert group_of(reply.json()["deviceId"]) == (reception["id"], "manual")


def test_the_lowest_priority_number_wins_when_several_groups_match(client, admin, tenant):
    make_group(client, admin, tenant, "All Windows", rule(("platform", "is", "windows"), priority=200))
    london = make_group(client, admin, tenant, "London", rule(("hostname", "matches", "ldn-*"), priority=10))
    pc = enroll(client, admin, tenant, hostname="LDN-PC9", serial="P9")
    assert group_of(pc["deviceId"])[0] == london["id"]


def test_deleting_a_rule_group_lets_the_other_rules_place_its_devices(client, admin, tenant):
    windows = make_group(client, admin, tenant, "All Windows", rule(("platform", "is", "windows"), priority=200))
    london = make_group(client, admin, tenant, "London", rule(("hostname", "matches", "LDN-*"), priority=10))
    pc = enroll(client, admin, tenant, hostname="LDN-PC2", serial="P2")
    assert group_of(pc["deviceId"])[0] == london["id"]
    assert client.delete(f"/api/console/groups/{london['id']}", headers=admin).status_code == 200
    assert group_of(pc["deviceId"])[0] == windows["id"]


def test_preview_shows_matches_and_hand_placed_devices(client, admin, tenant):
    vip = make_group(client, admin, tenant, "VIP")
    a = enroll(client, admin, tenant, hostname="LDN-A", serial="A")
    enroll(client, admin, tenant, hostname="LDN-B", serial="B")
    enroll(client, admin, tenant, hostname="MAN-C", serial="C")
    client.post("/api/console/groups/members", headers=admin, json={"deviceIds": [a["deviceId"]], "groupId": vip["id"]})
    preview = client.post("/api/console/groups/rules/preview", headers=admin,
                          json={"tenantId": tenant["id"], "matchRules": rule(("hostname", "matches", "LDN-*"))}).json()
    assert preview["count"] == 2 and preview["placedByHand"] == 1
    assert sorted(d["hostname"] for d in preview["devices"]) == ["LDN-A", "LDN-B"]
    bad = client.post("/api/console/groups/rules/preview", headers=admin, json={"tenantId": tenant["id"], "matchRules": rule(("ip", "in", "x"))})
    assert bad.status_code == 422


def test_ip_ranges_and_any_matching(client, admin, tenant):
    branch = make_group(client, admin, tenant, "Branch", rule(("ip", "in", "10.20.0.0/16"), ("hostname", "matches", "BR-*"), match="any"))
    pc = enroll(client, admin, tenant, hostname="BR-1", serial="BR1")
    assert group_of(pc["deviceId"])[0] == branch["id"]
    with database.session_factory()() as db:
        device = db.get(Device, pc["deviceId"])
        assert group_rules.matches(device, {"enabled": True, "match": "all", "conditions": [{"field": "ip", "op": "in", "value": "10.20.0.0/16"}]}) is False


def test_another_customer_cannot_preview_or_see_these_devices(client, admin, tenant):
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Ltd", "template": "balanced"}).json()
    client.post("/api/console/users", headers=admin, json={"tenantId": other["id"], "email": "ops@other.example",
                                                           "password": "other-password-123", "role": "tenant_admin"})
    ops = login(client, "ops@other.example", "other-password-123")
    enroll(client, admin, tenant, hostname="LDN-A", serial="A")
    reply = client.post("/api/console/groups/rules/preview", headers=ops, json={"tenantId": tenant["id"], "matchRules": rule(("hostname", "matches", "*"))})
    assert reply.status_code in (403, 404)
