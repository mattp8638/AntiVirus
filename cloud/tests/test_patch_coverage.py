from sqlalchemy import select

from fenrir_cloud import db as database, rmm
from fenrir_cloud.models import Device, DevicePatch
from conftest import enroll


def test_failed_provider_preserves_patches_and_cannot_report_fully_patched(client, admin, tenant, device):
    with database.session_factory()() as db:
        row = db.get(Device, device["deviceId"])
        rmm.ingest_patch_scan(db, row, {"patches": [
            {"id": "winget:Google.Chrome", "source": "winget", "title": "Chrome update"},
            {"id": "KB1234567", "source": "windows-update", "title": "Windows update"},
        ]})
        db.commit()
        last_success = row.metrics["patchScanAt"]
        rmm.ingest_patch_scan(db, row, {"patches": [], "coverage": {
            "windows-update": {"success": True},
            "winget": {"success": False, "error": "source unavailable"},
        }})
        db.commit()
        patches = {p.patch_key: p.status for p in db.scalars(select(DevicePatch).where(DevicePatch.device_id == row.id))}
        assert patches["winget:Google.Chrome"] == "missing"
        assert patches["KB1234567"] == "installed"
        assert row.metrics["patchScanStatus"] == "partial"
        assert row.metrics["patchScanAt"] == last_success
        rmm.record_heartbeat_metrics(db, row, {"cpuPercent": 10})
        db.commit()
        assert row.metrics["patchScanStatus"] == "partial"
        assert row.metrics["patchProviders"]["winget"]["error"] == "source unavailable"
    response = client.get("/api/console/rmm/patches/compliance", headers=admin).json()
    assert response["fullyPatched"] == 0
    assert response["incompleteScans"] == 1
    entry = next(d for d in response["devices_detail"] if d["id"] == device["deviceId"])
    assert entry["scanStatus"] == "partial" and not entry["providers"]["winget"]["success"]


def test_complete_scan_resolves_patches_and_restores_compliance(client, admin, tenant, device):
    with database.session_factory()() as db:
        row = db.get(Device, device["deviceId"])
        rmm.ingest_patch_scan(db, row, {"patches": [{"id": "winget:Google.Chrome", "source": "winget"}]})
        rmm.ingest_patch_scan(db, row, {"patches": [], "coverage": {
            "windows-update": {"success": True}, "winget": {"success": True},
        }})
        db.commit()
        assert row.metrics["patchScanStatus"] == "completed"
        assert db.scalar(select(DevicePatch).where(DevicePatch.device_id == row.id)).status == "installed"
    response = client.get("/api/console/rmm/patches/compliance", headers=admin).json()
    assert response["fullyPatched"] == 1 and response["incompleteScans"] == 0


def test_malformed_coverage_is_not_treated_as_success(client, admin, tenant, device):
    with database.session_factory()() as db:
        row = db.get(Device, device["deviceId"])
        rmm.ingest_patch_scan(db, row, {"patches": [{"id": "winget:Google.Chrome", "source": "winget"}]})
        rmm.ingest_patch_scan(db, row, {"patches": [], "coverage": {"winget": {"success": "true"}}})
        db.commit()
        assert row.metrics["patchScanStatus"] == "failed"
        assert db.scalar(select(DevicePatch).where(DevicePatch.device_id == row.id)).status == "missing"


def test_incomplete_device_remains_in_compliance_denominator(client, admin, tenant, device):
    other = enroll(client, admin, tenant, hostname="OTHER-PC", serial="SN-OTHER")
    with database.session_factory()() as db:
        rmm.ingest_patch_scan(db, db.get(Device, device["deviceId"]), {"patches": []})
        rmm.ingest_patch_scan(db, db.get(Device, other["deviceId"]), {"patches": [], "coverage": {
            "windows-update": {"success": True}, "winget": {"success": False},
        }})
        db.commit()
    response = client.get("/api/console/rmm/patches/compliance", headers=admin).json()
    assert response["devices"] == 2 and response["fullyPatched"] == 1
    assert response["compliancePercent"] == 50


def test_reboot_pending_is_not_verified_fully_patched(client, admin, tenant, device):
    with database.session_factory()() as db:
        rmm.ingest_patch_scan(db, db.get(Device, device["deviceId"]), {"patches": [], "rebootPending": True})
        db.commit()
    response = client.get("/api/console/rmm/patches/compliance", headers=admin).json()
    assert response["pendingReboot"] == 1 and response["fullyPatched"] == 0
