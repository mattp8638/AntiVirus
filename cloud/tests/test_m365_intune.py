"""Intune through Graph against the fake tenant: devices and actions, BitLocker and LAPS, apps, Autopilot."""
import base64

import httpx
import pytest

from m365_fake import FakeTenant
from test_documentation_vault import stepup
from test_msp_modules import connection
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import AuditLog

LAPTOP, PHONE, APP = "11111111-aaaa-4aaa-8aaa-000000000001", "11111111-aaaa-4aaa-8aaa-000000000002", "33333333-cccc-4ccc-8ccc-000000000001"
GROUP = "44444444-dddd-4ddd-8ddd-000000000001"


@pytest.fixture
def fake(monkeypatch):
    tenant = FakeTenant()
    monkeypatch.setattr(httpx, "Client", tenant.client)
    return tenant


def base(conn):
    return f"/api/console/m365/connections/{conn['id']}/intune"


def test_devices_and_actions(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    devices = client.get(base(conn) + "/devices", headers=admin).json()
    assert devices[0]["name"] == "JO-LAPTOP" and devices[0]["compliance"] == "noncompliant"  # non-compliant first
    assert "restart" in devices[0]["actions"] and "restart" not in devices[1]["actions"] and "lock" in devices[1]["actions"]
    assert client.post(base(conn) + f"/devices/{LAPTOP}/action", headers=admin, json={"action": "sync"}).status_code == 200
    assert (LAPTOP, "syncDevice") in fake.device_actions
    # Wipe is destructive: refused without re-authentication, sent with it.
    assert client.post(base(conn) + f"/devices/{LAPTOP}/action", headers=admin, json={"action": "wipe"}).status_code in (403, 428)
    assert (LAPTOP, "wipe") not in fake.device_actions
    assert client.post(base(conn) + f"/devices/{LAPTOP}/action", headers=stepup(client, admin), json={"action": "wipe"}).status_code == 200
    assert (LAPTOP, "wipe") in fake.device_actions
    refused = client.post(base(conn) + f"/devices/{PHONE}/action", headers=admin, json={"action": "restart"})
    assert refused.status_code == 400 and "not available for iOS" in refused.json()["detail"]


def test_bitlocker_and_laps_are_revealed_once_with_reauth(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    assert client.post(base(conn) + f"/devices/{LAPTOP}/bitlocker", headers=admin).status_code in (403, 428)
    proof = stepup(client, admin)
    keys = client.post(base(conn) + f"/devices/{LAPTOP}/bitlocker", headers=proof)
    assert keys.status_code == 200 and keys.json()["keys"][0]["key"].startswith("111111-") and keys.headers["cache-control"] == "no-store"
    laps = client.post(base(conn) + f"/devices/{LAPTOP}/laps", headers=proof).json()
    assert laps == {"account": "LapsAdmin", "password": "S3cret-LAPS!", "backedUp": laps["backedUp"]}
    phone = client.post(base(conn) + f"/devices/{PHONE}/bitlocker", headers=proof)
    assert phone.status_code == 400 and "not joined to Entra ID" in phone.json()["detail"]
    with session_factory()() as db:
        logged = [a.action for a in db.query(AuditLog).filter(AuditLog.action.like("m365.intune.%"))]
        assert "m365.intune.bitlocker.revealed" in logged and "m365.intune.laps.revealed" in logged
        assert not any("S3cret-LAPS!" in str(a.details) for a in db.query(AuditLog))


def test_policies_apps_assignment_and_autopilot(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    assert client.get(base(conn) + "/policies", headers=admin).json()["compliance"][0]["assignments"] == 1
    apps = client.get(base(conn) + "/apps", headers=admin).json()
    assert apps[0]["assignments"] == [{"intent": "required", "target": "All users"}]
    done = client.post(base(conn) + f"/apps/{APP}/assign", headers=stepup(client, admin), json={"intent": "available", "groupId": GROUP})
    assert done.status_code == 200, done.text
    assert len(fake.mobile_apps[APP]["assignments"]) == 2  # the existing assignment is kept
    hashes = "Device Serial Number,Windows Product ID,Hardware Hash\nSN-NEW,,%s\n" % base64.b64encode(b"hardware").decode()
    imported = client.post(base(conn) + "/autopilot/import", headers=stepup(client, admin), json={"csv": hashes, "groupTag": "Sales"})
    assert imported.status_code == 200 and imported.json()["imported"] == 1
    assert fake.autopilot_imports[0]["serialNumber"] == "SN-NEW" and fake.autopilot_imports[0]["groupTag"] == "Sales"
    bad = client.post(base(conn) + "/autopilot/import", headers=stepup(client, admin), json={"csv": "nonsense"})
    assert bad.status_code == 400
    assert client.get(base(conn) + "/autopilot", headers=admin).json()[0]["serial"] == "SN1"
