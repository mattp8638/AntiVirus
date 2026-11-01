"""D-06: Protection health says what blocks programs before they run on Windows (Microsoft Defender, as Fenrir ships
no kernel driver), and never claims it when Defender is off or not yet checked."""
from conftest import enroll

from fenrir_cloud import db as database
from fenrir_cloud.models import DefenderState, Device


def set_defender(device_id, status):
    with database.session_factory()() as db:
        row = db.get(Device, device_id)
        db.merge(DefenderState(device_id=device_id, tenant_id=row.tenant_id, status=status))
        db.commit()


def test_pre_execution_blocking_per_windows_device(client, admin, tenant):
    on = enroll(client, admin, tenant, hostname="WIN-ON", serial="S1")
    passive = enroll(client, admin, tenant, hostname="WIN-PASSIVE", serial="S2")
    realtime_off = enroll(client, admin, tenant, hostname="WIN-RT-OFF", serial="S3")
    unchecked = enroll(client, admin, tenant, hostname="WIN-NEW", serial="S4")
    linux = enroll(client, admin, tenant, hostname="LNX-01", os_version="Ubuntu 24.04 LTS", serial="S5")
    set_defender(on["deviceId"], {"available": True, "mode": "Normal", "antivirus": True, "realTime": True})
    set_defender(passive["deviceId"], {"available": True, "mode": "Passive Mode", "antivirus": True, "realTime": True})
    set_defender(realtime_off["deviceId"], {"available": True, "mode": "Normal", "antivirus": True, "realTime": False})

    body = client.get("/api/console/protection/health", headers=admin).json()
    by_host = {d["hostname"]: d["preExecution"] for d in body["devices"]}
    assert by_host == {"WIN-ON": "defender", "WIN-PASSIVE": "none", "WIN-RT-OFF": "none", "WIN-NEW": "unknown", "LNX-01": None}
    assert body["totals"]["preExecution"] == {"defender": 1, "none": 2, "unknown": 1}
    assert unchecked and linux
