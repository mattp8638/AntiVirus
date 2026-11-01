"""Tests for predictive storage exhaustion and CPU/RAM anomaly detection features."""

from datetime import datetime, timedelta, timezone

from fenrir_cloud.analytics import (
    calculate_storage_exhaustion,
    evaluate_resource_anomaly,
    filter_disk_outliers,
    update_resource_baseline,
)


def test_filter_disk_outliers():
    # Normal data points with one huge spike (large download) and one huge drop (cleanup)
    points = [
        {"used_gb": 50.0},
        {"used_gb": 51.0},
        {"used_gb": 52.0},
        {"used_gb": 51.5},
        {"used_gb": 120.0},  # Temporary spike
        {"used_gb": 52.5},
        {"used_gb": 10.0},   # Temporary drop
        {"used_gb": 53.0},
    ]
    filtered = filter_disk_outliers(points, iqr_multiplier=1.5)
    used_list = [p["used_gb"] for p in filtered]

    assert 120.0 not in used_list
    assert 10.0 not in used_list
    assert 50.0 in used_list
    assert 53.0 in used_list


def test_calculate_storage_exhaustion_linear_growth():
    t0 = datetime(2026, 1, 1, 0, 0, 0)
    # Total disk 100 GB -> 95% threshold is 95 GB. OS baseline footprint is 30 GB.
    # Growth is 1 GB per day.
    points = [
        {"at": t0, "total_gb": 100.0, "used_gb": 30.0, "free_gb": 70.0},
        {"at": t0 + timedelta(days=5), "total_gb": 100.0, "used_gb": 35.0, "free_gb": 65.0},
        {"at": t0 + timedelta(days=10), "total_gb": 100.0, "used_gb": 40.0, "free_gb": 60.0},
        {"at": t0 + timedelta(days=15), "total_gb": 100.0, "used_gb": 45.0, "free_gb": 55.0},
    ]

    res = calculate_storage_exhaustion(points, capacity_threshold_pct=0.95)

    assert res["total_gb"] == 100.0
    assert res["current_used_gb"] == 45.0
    assert res["capacity_threshold_gb"] == 95.0
    assert res["baseline_os_gb"] == 30.0
    assert abs(res["daily_growth_gb"] - 1.0) < 0.05
    # Remaining before 95 GB threshold = 95 - 45 = 50 GB. At 1 GB/day => 50 days
    assert abs(res["days_remaining"] - 50.0) < 2.0
    assert res["status"] == "ok"


def test_calculate_storage_exhaustion_already_exhausted():
    t0 = datetime(2026, 1, 1, 0, 0, 0)
    # Disk usage is 96 GB out of 100 GB (exceeds 95 GB threshold)
    points = [
        {"at": t0, "total_gb": 100.0, "used_gb": 90.0, "free_gb": 10.0},
        {"at": t0 + timedelta(days=1), "total_gb": 100.0, "used_gb": 96.0, "free_gb": 4.0},
    ]

    res = calculate_storage_exhaustion(points, capacity_threshold_pct=0.95)

    assert res["days_remaining"] == 0.0
    assert res["status"] == "exhausted"


def test_calculate_storage_exhaustion_flat_or_shrinking():
    t0 = datetime(2026, 1, 1, 0, 0, 0)
    # Disk usage is decreasing
    points = [
        {"at": t0, "total_gb": 100.0, "used_gb": 60.0, "free_gb": 40.0},
        {"at": t0 + timedelta(days=5), "total_gb": 100.0, "used_gb": 55.0, "free_gb": 45.0},
    ]

    res = calculate_storage_exhaustion(points, capacity_threshold_pct=0.95)

    assert res["days_remaining"] is None
    assert res["status"] == "stable"


def test_update_resource_baseline():
    samples = [20.0, 22.0, 18.0, 25.0, 21.0]
    mean_val, std_val = update_resource_baseline(samples)

    assert abs(mean_val - 21.2) < 0.1
    assert std_val >= 1.0


def test_evaluate_resource_anomaly_zscore():
    # Normal baseline 20% CPU with std 2%
    # Current value 35% -> Z = (35 - 20) / 2 = 7.5 (statistical anomaly)
    res = evaluate_resource_anomaly(
        current_val=35.0,
        baseline_mean=20.0,
        baseline_std=2.0,
        top_processes=[{"pid": 101, "name": "runaway.exe", "cpuPercent": 35.0}],
        user_sessions=["alice"],
    )

    assert res["is_anomaly"] is True
    assert res["z_score"] >= 3.0
    assert len(res["top_processes"]) == 1
    assert res["top_processes"][0]["name"] == "runaway.exe"
    assert res["user_sessions"] == ["alice"]


def test_evaluate_resource_anomaly_sustained_load():
    # 85% CPU with mean 70% std 10%
    # Z = 1.5 (below Z=3.0 statistical threshold), but 3 consecutive check-ins => sustained bottleneck
    res = evaluate_resource_anomaly(
        current_val=85.0,
        baseline_mean=70.0,
        baseline_std=10.0,
        previous_consecutive_spikes=2,
    )

    assert res["consecutive_spikes"] == 3
    assert res["is_sustained"] is True
    assert res["is_anomaly"] is True


def test_analytics_api_endpoints(client, admin, tenant, device):
    # Send heartbeats with disk and process metrics to populate telemetry and baselines
    metrics_payload = {
        "cpuPercent": 95.0,
        "memoryPercent": 92.0,
        "disks": [
            {"mount": "C:", "totalGb": 100.0, "freeGb": 40.0, "freePercent": 40.0}
        ],
        "topProcesses": [
            {"pid": 404, "name": "miner.exe", "cpuPercent": 90.0, "memoryMb": 2048.0}
        ],
        "users": ["admin_user"],
    }

    hb_resp = client.post(
        f"/api/v1/devices/{device['deviceId']}/heartbeat",
        json={"metrics": metrics_payload},
        headers=device["headers"],
    )
    assert hb_resp.status_code == 200, hb_resp.text

    # Query device disk predictions
    pred_resp = client.get(
        f"/api/console/rmm/devices/{device['deviceId']}/analytics/disk-predictions",
        headers=admin,
    )
    assert pred_resp.status_code == 200, pred_resp.text

    # Query overall storage exhaustion predictions endpoint
    store_resp = client.get(
        "/api/console/rmm/analytics/storage-exhaustion",
        headers=admin,
    )
    assert store_resp.status_code == 200, store_resp.text

    # Query device resource anomalies
    dev_anom_resp = client.get(
        f"/api/console/rmm/devices/{device['deviceId']}/analytics/anomalies",
        headers=admin,
    )
    assert dev_anom_resp.status_code == 200, dev_anom_resp.text
    anomalies = dev_anom_resp.json()
    assert len(anomalies) > 0
    assert anomalies[0]["metric"] in ("cpu", "memory")

    # Query overall resource anomalies
    anom_resp = client.get(
        "/api/console/rmm/analytics/resource-anomalies",
        headers=admin,
    )
    assert anom_resp.status_code == 200, anom_resp.text
