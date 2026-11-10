"""Server features the console now shows: disk-full forecasts, unusual resource use, monitoring history, the fleet-wide
remote action log, personal data discovery from the device page and file scoring."""

from datetime import timedelta

from conftest import enroll, login
from fenrir_cloud import db as database
from fenrir_cloud.models import Alert, DiskExhaustionPrediction, ResourceAnomaly, utcnow


def add_forecasts(device_id):
    with database.session_factory()() as db:
        db.add_all([
            DiskExhaustionPrediction(device_id=device_id, mount="C:", total_gb=256, current_used_gb=240, daily_growth_gb=2.5,
                                     days_remaining=3.2, status="critical", confidence_score=0.9),
            DiskExhaustionPrediction(device_id=device_id, mount="D:", total_gb=1000, current_used_gb=300, daily_growth_gb=0.5,
                                     days_remaining=900, status="ok", confidence_score=0.8),
            DiskExhaustionPrediction(device_id=device_id, mount="E:", total_gb=500, current_used_gb=480, daily_growth_gb=1,
                                     days_remaining=12, status="warning", confidence_score=0.7),
        ])
        db.add(ResourceAnomaly(device_id=device_id, metric="cpu", current_value=97, baseline_mean=12, baseline_std=4, z_score=21,
                               is_sustained=True, consecutive_spikes=4, top_processes=[{"name": "miner.exe", "cpu": 90}]))
        db.commit()


def test_disk_forecasts_list_the_urgent_drives_first_with_device_names(client, admin, tenant):
    pc = enroll(client, admin, tenant, hostname="FILE-SRV")
    add_forecasts(pc["deviceId"])
    urgent = client.get("/api/console/rmm/analytics/storage-exhaustion", headers=admin, params={"status": "attention"}).json()
    assert [(r["mount"], r["hostname"]) for r in urgent] == [("C:", "FILE-SRV"), ("E:", "FILE-SRV")]
    everything = client.get("/api/console/rmm/analytics/storage-exhaustion", headers=admin).json()
    assert [r["mount"] for r in everything] == ["C:", "E:", "D:"]
    device = client.get(f"/api/console/rmm/devices/{pc['deviceId']}/analytics/disk-predictions", headers=admin).json()
    assert {r["mount"] for r in device} == {"C:", "D:", "E:"}


def test_unusual_resource_use_carries_the_device_and_respects_the_customer_filter(client, admin, tenant):
    pc = enroll(client, admin, tenant, hostname="ACCOUNTS-PC")
    add_forecasts(pc["deviceId"])
    rows = client.get("/api/console/rmm/analytics/resource-anomalies", headers=admin, params={"tenant_id": tenant["id"]}).json()
    assert rows[0]["hostname"] == "ACCOUNTS-PC" and rows[0]["isSustained"] is True and rows[0]["topProcesses"][0]["name"] == "miner.exe"
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Ltd", "template": "balanced"}).json()
    assert client.get("/api/console/rmm/analytics/resource-anomalies", headers=admin, params={"tenant_id": other["id"]}).json() == []


def test_decommissioned_devices_drop_out_of_the_fleet_analytics(client, admin, tenant):
    pc = enroll(client, admin, tenant)
    add_forecasts(pc["deviceId"])
    client.delete(f"/api/console/devices/{pc['deviceId']}", headers=admin)
    assert client.get("/api/console/rmm/analytics/storage-exhaustion", headers=admin).json() == []


def test_another_customer_sees_none_of_it(client, admin, tenant):
    pc = enroll(client, admin, tenant)
    add_forecasts(pc["deviceId"])
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Ltd", "template": "balanced"}).json()
    client.post("/api/console/users", headers=admin, json={"tenantId": other["id"], "email": "ops@other.example",
                                                           "password": "other-password-123", "role": "tenant_admin"})
    ops = login(client, "ops@other.example", "other-password-123")
    assert client.get("/api/console/rmm/analytics/storage-exhaustion", headers=ops).json() == []
    assert client.get("/api/console/rmm/analytics/resource-anomalies", headers=ops).json() == []
    assert client.get(f"/api/console/rmm/devices/{pc['deviceId']}/analytics/anomalies", headers=ops).status_code == 404


def test_monitoring_history_names_the_device(client, admin, tenant):
    pc = enroll(client, admin, tenant, hostname="PRINT-SRV")
    with database.session_factory()() as db:
        db.add(Alert(tenant_id=tenant["id"], device_id=pc["deviceId"], rule_id="monitor:disk", title="Low disk on PRINT-SRV",
                     severity="medium", status="resolved", details={}, created_at=utcnow() - timedelta(hours=2)))
        db.commit()
    rows = client.get("/api/console/rmm/alerts", headers=admin, params={"tenant_id": tenant["id"]}).json()
    assert rows[0]["hostname"] == "PRINT-SRV" and rows[0]["status"] == "resolved"


def test_the_remote_action_log_filters_by_state_action_and_sender(client, admin, tenant):
    pc = enroll(client, admin, tenant, hostname="LAPTOP-7")
    for kind in ("scan.quick", "inventory.refresh"):
        assert client.post(f"/api/console/devices/{pc['deviceId']}/commands", headers=admin, json={"type": kind, "reason": "test"}).status_code == 200
    everything = client.get("/api/console/commands", headers=admin).json()
    assert {c["type"] for c in everything} >= {"scan.quick", "inventory.refresh"} and everything[0]["hostname"] == "LAPTOP-7"
    assert [c["type"] for c in client.get("/api/console/commands", headers=admin, params={"type": "scan.quick"}).json()] == ["scan.quick"]
    assert len(client.get("/api/console/commands", headers=admin, params={"status": "open", "issued_by": "me"}).json()) >= 2
    assert client.get("/api/console/commands", headers=admin, params={"issued_by": "someone@else.example"}).json() == []


def test_personal_data_discovery_from_the_device_page(client, admin, tenant):
    pc = enroll(client, admin, tenant, os_version="Ubuntu 24.04", serial="L1")
    queued = client.post(f"/api/console/devices/{pc['deviceId']}/pii-scan", headers=admin)
    assert queued.status_code == 200, queued.text
    assert any(c["type"] == "pii.scan" for c in client.get("/api/console/commands", headers=admin, params={"device_id": pc["deviceId"]}).json())


def test_file_scoring_needs_a_signed_in_user(client, admin):
    assert client.post("/api/console/ml/score", content=b"MZ").status_code == 401
    assert client.post("/api/console/ml/score", content=b"just text", headers=admin).status_code == 200
    assert client.get("/api/console/ml/model", headers=admin).status_code == 200
