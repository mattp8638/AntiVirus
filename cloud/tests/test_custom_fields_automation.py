"""Custom fields in automation: scripts read them as environment variables, set them with FENRIR-FIELD lines, and
monitors test them (numbers, yes/no, days until a date, text equality)."""

import json
from datetime import date, timedelta

from conftest import enroll

from fenrir_cloud import db as database, rmm
from fenrir_cloud.models import AuditLog, Device


def _poll(client, device):
    return client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device["headers"]).json()["items"]


def _complete(client, device, command_id, stdout):
    response = client.post(f"/api/v1/devices/{device['deviceId']}/commands/{command_id}/complete", headers=device["headers"],
                           json={"status": "completed", "resultJson": json.dumps({"exitCode": 0, "stdout": stdout})})
    assert response.status_code == 200, response.text


def _fields(client, admin):
    for body in ({"entity": "device", "label": "Asset tag"}, {"entity": "device", "label": "Warranty end", "type": "date"},
                 {"entity": "device", "label": "BitLocker on", "type": "checkbox"}, {"entity": "device", "label": "Disk GB", "type": "number"},
                 {"entity": "device", "label": "Tier", "type": "select", "options": ["Gold", "Silver"]}):
        assert client.post("/api/console/custom-fields", headers=admin, json=body).status_code == 200


def _script(client, admin, body="Write-Output hi"):
    return client.post("/api/console/rmm/scripts", headers=admin, json={
        "name": "Inventory fields", "language": "powershell", "body": body, "platforms": ["windows"]}).json()


def test_scripts_receive_the_devices_fields_as_environment_variables(client, admin, tenant):
    _fields(client, admin)
    device = enroll(client, admin, tenant)
    client.put(f"/api/console/custom-fields/values/device/{device['deviceId']}", headers=admin,
               json={"values": {"asset_tag": "AT-0042", "bitlocker_on": True}})
    script = _script(client, admin)
    client.post(f"/api/console/rmm/scripts/{script['id']}/run", headers=admin, json={"targets": {"deviceIds": [device["deviceId"]]}})
    [command] = _poll(client, device)
    env = json.loads(command["payloadJson"])["environment"]
    assert env["FENRIR_CF_ASSET_TAG"] == "AT-0042" and env["FENRIR_CF_BITLOCKER_ON"] == "true"
    assert env["FENRIR_CF_WARRANTY_END"] == "" and env["FENRIR_DEVICE_NAME"] == "ACME-WS-01" and env["FENRIR_CUSTOMER"] == "Acme Dental"


def test_scripts_set_fields_with_their_output_and_bad_values_are_skipped(client, admin, tenant):
    _fields(client, admin)
    device = enroll(client, admin, tenant)
    client.put(f"/api/console/custom-fields/values/device/{device['deviceId']}", headers=admin, json={"values": {"disk_gb": 100}})
    script = _script(client, admin)
    client.post(f"/api/console/rmm/scripts/{script['id']}/run", headers=admin, json={"targets": {"deviceIds": [device["deviceId"]]}})
    [command] = _poll(client, device)
    _complete(client, device, command["id"], "\n".join([
        "Checking...", "FENRIR-FIELD warranty_end=2027-03-01", "FENRIR-FIELD bitlocker_on=yes", "FENRIR-FIELD tier=Gold",
        "FENRIR-FIELD disk_gb=", "FENRIR-FIELD warranty_end_typo=2027-01-01", "FENRIR-FIELD tier=Platinum ",
        "  FENRIR-FIELD asset_tag = AT-9", "done"]))
    with database.session_factory()() as session:
        values = session.get(Device, device["deviceId"]).custom_fields
        assert values == {"warranty_end": "2027-03-01", "bitlocker_on": True, "tier": "Gold", "asset_tag": "AT-9"}  # disk_gb cleared
        entry = session.query(AuditLog).filter(AuditLog.action == "device.custom_fields.updated",
                                               AuditLog.actor == "script:Inventory fields").one()
        details = entry.details if isinstance(entry.details, dict) else json.loads(entry.details or "{}")
        assert "warranty_end_typo" in json.dumps(details) and "Platinum" not in json.dumps(values)


def test_output_from_scripts_outside_jobs_is_ignored(client, admin, tenant):
    _fields(client, admin)
    device = enroll(client, admin, tenant)
    queued = client.post(f"/api/console/devices/{device['deviceId']}/commands", headers=admin, json={
        "type": "script.run", "payload": {"language": "powershell", "body": "x"}, "reason": "test"})
    if queued.status_code != 200:  # direct script.run may be refused; nothing to check then
        return
    [command] = _poll(client, device)
    _complete(client, device, command["id"], "FENRIR-FIELD asset_tag=HACKED")
    with database.session_factory()() as session:
        assert (session.get(Device, device["deviceId"]).custom_fields or {}).get("asset_tag") is None


def test_monitors_test_fields(client, admin, tenant):
    _fields(client, admin)
    device = enroll(client, admin, tenant)
    soon = (date.today() + timedelta(days=12)).isoformat()
    client.put(f"/api/console/custom-fields/values/device/{device['deviceId']}", headers=admin,
               json={"values": {"warranty_end": soon, "bitlocker_on": False, "tier": "Gold", "disk_gb": 40}})
    for body in ({"name": "Warranty ending", "target": "warranty_end", "operator": "<", "threshold": 30},
                 {"name": "BitLocker off", "target": "bitlocker_on", "operator": "==", "threshold": 0},
                 {"name": "Gold customer", "target": "tier=gold", "operator": "==", "threshold": 1},
                 {"name": "Small disk", "target": "disk_gb", "operator": "<", "threshold": 20}):
        made = client.post("/api/console/rmm/conditions", headers=admin, json={
            **body, "metric": "custom_field", "durationMinutes": 0, "severity": "low", "tenantId": tenant["id"]})
        assert made.status_code == 200, made.text
    with database.session_factory()() as session:
        rmm.evaluate_device(session, session.get(Device, device["deviceId"]))
        session.commit()
    active = {a["condition"]: a["message"] for a in client.get("/api/console/rmm/monitoring", headers=admin).json()}
    assert set(active) == {"Warranty ending", "BitLocker off", "Gold customer"}  # 40 GB is not under 20
    assert "Warranty end is in 12 days" in active["Warranty ending"]
