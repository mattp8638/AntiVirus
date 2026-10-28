"""Core analytical engines for Fenrir RMM.

Includes:
1. Predictive Storage Exhaustion: Linear regression & smoothed rolling average with OS baseline
   exclusion, Hampel/IQR outlier filtering, and 95% capacity threshold prediction.
2. CPU and RAM Anomaly Detection: Rolling baseline estimation, Z-score statistical thresholding,
   sustained high-usage bottleneck detection, and context capture (top processes & user sessions).
3. Decoupled batch processing runner for scheduler integration.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import (
    Device,
    DeviceMetric,
    DiskExhaustionPrediction,
    DiskTelemetryHistory,
    ResourceAnomaly,
    ResourceBaseline,
    utcnow,
)


# --------------------------------------------------------------------------
# Feature 1: Predictive Storage Exhaustion Algorithms
# --------------------------------------------------------------------------

def filter_disk_outliers(
    data_points: list[dict[str, Any]],
    iqr_multiplier: float = 1.5,
) -> list[dict[str, Any]]:
    """Remove temporary spikes (e.g. large temporary downloads) and sudden drops

    (e.g. automated disk cleanups) using an Interquartile Range (IQR) filter.
    """
    if len(data_points) < 4:
        return data_points

    used_values = sorted(p["used_gb"] for p in data_points)
    n = len(used_values)
    q1 = used_values[n // 4]
    q3 = used_values[(3 * n) // 4]
    iqr = q3 - q1

    if iqr <= 0:
        return data_points

    lower_bound = q1 - (iqr_multiplier * iqr)
    upper_bound = q3 + (iqr_multiplier * iqr)

    filtered = [p for p in data_points if lower_bound <= p["used_gb"] <= upper_bound]
    return filtered if filtered else data_points


def calculate_storage_exhaustion(
    telemetry_points: list[dict[str, Any]],
    capacity_threshold_pct: float = 0.95,
) -> dict[str, Any]:
    """Calculate the daily storage growth rate and predict days remaining until 95% capacity.

    Steps:
    1. Filter temporary spikes/drops via IQR outlier filter.
    2. Exclude static baseline consumption (OS footprint baseline = min used space).
    3. Perform OLS linear regression on variable storage consumption vs time in days.
    4. Compute days remaining against 95% capacity threshold.
    """
    if not telemetry_points:
        return {
            "daily_growth_gb": 0.0,
            "days_remaining": None,
            "baseline_os_gb": 0.0,
            "current_used_gb": 0.0,
            "total_gb": 0.0,
            "capacity_threshold_gb": 0.0,
            "status": "unknown",
            "confidence_score": 0.0,
            "model_type": "linear_regression",
        }

    # Sort telemetry points by timestamp
    points = sorted(telemetry_points, key=lambda p: p["at"])
    latest = points[-1]
    total_gb = float(latest.get("total_gb", 0.0))
    current_used_gb = float(latest.get("used_gb", 0.0))
    threshold_gb = round(total_gb * capacity_threshold_pct, 2)

    if total_gb <= 0:
        return {
            "daily_growth_gb": 0.0,
            "days_remaining": None,
            "baseline_os_gb": 0.0,
            "current_used_gb": current_used_gb,
            "total_gb": total_gb,
            "capacity_threshold_gb": threshold_gb,
            "status": "invalid_total",
            "confidence_score": 0.0,
            "model_type": "linear_regression",
        }

    # Filter temporary spikes and sudden drops
    clean_points = filter_disk_outliers(points)

    # Exclude static baseline consumption (OS footprint baseline)
    min_used_gb = min(p["used_gb"] for p in clean_points)
    baseline_os_gb = round(min_used_gb, 2)

    if len(clean_points) < 2:
        remaining_gb = max(0.0, threshold_gb - current_used_gb)
        status = "exhausted" if current_used_gb >= threshold_gb else "stable"
        return {
            "daily_growth_gb": 0.0,
            "days_remaining": 0.0 if status == "exhausted" else None,
            "baseline_os_gb": baseline_os_gb,
            "current_used_gb": current_used_gb,
            "total_gb": total_gb,
            "capacity_threshold_gb": threshold_gb,
            "status": status,
            "confidence_score": 0.5,
            "model_type": "linear_regression",
        }

    # Convert timestamps to day offsets from t0
    t0 = clean_points[0]["at"]
    x: list[float] = []
    y: list[float] = []

    for p in clean_points:
        dt_days = (p["at"] - t0).total_seconds() / 86400.0
        # Variable storage = total used - static OS baseline
        var_used = max(0.0, p["used_gb"] - baseline_os_gb)
        x.append(dt_days)
        y.append(var_used)

    n = len(x)
    sum_x = sum(x)
    sum_y = sum(y)
    sum_xx = sum(xi * xi for xi in x)
    sum_xy = sum(xi * yi for xi, yi in zip(x, y))

    denom = (n * sum_xx) - (sum_x * sum_x)

    if abs(denom) < 1e-9:
        daily_growth = 0.0
        r_squared = 0.0
    else:
        slope = ((n * sum_xy) - (sum_x * sum_y)) / denom
        intercept = (sum_y - (slope * sum_x)) / n
        daily_growth = round(slope, 4)

        # R^2 calculation for confidence score
        y_mean = sum_y / n
        ss_tot = sum((yi - y_mean) ** 2 for yi in y)
        ss_res = sum((yi - (slope * xi + intercept)) ** 2 for xi, yi in zip(x, y))
        r_squared = round(1.0 - (ss_res / ss_tot), 4) if ss_tot > 1e-9 else 1.0
        r_squared = max(0.0, min(1.0, r_squared))

    remaining_gb = max(0.0, threshold_gb - current_used_gb)

    if current_used_gb >= threshold_gb:
        days_remaining = 0.0
        status = "exhausted"
    elif daily_growth <= 0.0001:
        # Disk usage is shrinking or flat
        days_remaining = None
        status = "stable"
    else:
        days_remaining = round(remaining_gb / daily_growth, 1)
        if days_remaining <= 7:
            status = "critical"
        elif days_remaining <= 30:
            status = "warning"
        else:
            status = "ok"

    return {
        "daily_growth_gb": daily_growth,
        "days_remaining": days_remaining,
        "baseline_os_gb": baseline_os_gb,
        "current_used_gb": current_used_gb,
        "total_gb": total_gb,
        "capacity_threshold_gb": threshold_gb,
        "status": status,
        "confidence_score": r_squared if r_squared > 0 else 0.5,
        "model_type": "linear_regression",
    }


# --------------------------------------------------------------------------
# Feature 2: CPU and RAM Anomaly Detection Algorithms
# --------------------------------------------------------------------------

def update_resource_baseline(
    historical_samples: list[float],
) -> tuple[float, float]:
    """Calculate rolling mean and standard deviation for resource utilization.

    Enforces a minimum standard deviation to avoid division by zero on idle hosts.
    """
    if not historical_samples:
        return 0.0, 1.0

    mean_val = sum(historical_samples) / len(historical_samples)
    if len(historical_samples) < 2:
        return round(mean_val, 2), 1.0

    variance = sum((x - mean_val) ** 2 for x in historical_samples) / (len(historical_samples) - 1)
    std_val = math.sqrt(variance)
    # Floor std at 1.0% to prevent zero-division
    std_val = max(1.0, std_val)

    return round(mean_val, 2), round(std_val, 2)


def evaluate_resource_anomaly(
    current_val: float,
    baseline_mean: float,
    baseline_std: float,
    previous_consecutive_spikes: int = 0,
    z_threshold: float = 3.0,
    high_util_threshold: float = 80.0,
    top_processes: list[dict] | None = None,
    user_sessions: list[str] | None = None,
) -> dict[str, Any]:
    """Evaluate whether current usage significantly deviates from norm or shows sustained bottleneck.

    Returns anomaly evaluation dict.
    """
    std = max(1.0, baseline_std)
    z_score = round((current_val - baseline_mean) / std, 2)

    is_statistical_anomaly = (z_score >= z_threshold) or (current_val >= 90.0)
    is_high_util = current_val >= high_util_threshold

    if is_statistical_anomaly or is_high_util:
        consecutive_spikes = previous_consecutive_spikes + 1
    else:
        consecutive_spikes = 0

    is_sustained = consecutive_spikes >= 3
    is_anomaly = is_statistical_anomaly or is_sustained

    return {
        "is_anomaly": is_anomaly,
        "z_score": z_score,
        "current_value": current_val,
        "baseline_mean": baseline_mean,
        "baseline_std": std,
        "consecutive_spikes": consecutive_spikes,
        "is_sustained": is_sustained,
        "top_processes": top_processes or [],
        "user_sessions": user_sessions or [],
    }


# --------------------------------------------------------------------------
# Decoupled Analytical Processing Runner (Runs in Scheduler Background)
# --------------------------------------------------------------------------

def process_disk_predictions(db: Session, device_id: str) -> list[DiskExhaustionPrediction]:
    """Decoupled background runner: calculates disk predictions for all mounts of a device."""
    predictions = []
    # Fetch distinct mounts for this device
    mounts = db.execute(
        select(DiskTelemetryHistory.mount)
        .where(DiskTelemetryHistory.device_id == device_id)
        .distinct()
    ).scalars().all()

    for mount in mounts:
        records = db.execute(
            select(DiskTelemetryHistory)
            .where(
                DiskTelemetryHistory.device_id == device_id,
                DiskTelemetryHistory.mount == mount,
            )
            .order_by(DiskTelemetryHistory.at.asc())
        ).scalars().all()

        points = [
            {
                "at": r.at,
                "total_gb": r.total_gb,
                "used_gb": r.used_gb,
                "free_gb": r.free_gb,
            }
            for r in records
        ]

        res = calculate_storage_exhaustion(points)

        pred = db.execute(
            select(DiskExhaustionPrediction).where(
                DiskExhaustionPrediction.device_id == device_id,
                DiskExhaustionPrediction.mount == mount,
            )
        ).scalars().first()

        if not pred:
            pred = DiskExhaustionPrediction(device_id=device_id, mount=mount)
            db.add(pred)

        pred.predicted_at = utcnow()
        pred.total_gb = res["total_gb"]
        pred.current_used_gb = res["current_used_gb"]
        pred.baseline_os_gb = res["baseline_os_gb"]
        pred.daily_growth_gb = res["daily_growth_gb"]
        pred.capacity_threshold_gb = res["capacity_threshold_gb"]
        pred.days_remaining = res["days_remaining"]
        pred.status = res["status"]
        pred.confidence_score = res["confidence_score"]
        pred.model_type = res["model_type"]

        predictions.append(pred)

    return predictions


def process_device_anomalies(
    db: Session,
    device: Device,
    metrics: dict[str, Any],
) -> list[ResourceAnomaly]:
    """Decoupled background worker: updates resource baselines and evaluates anomalies."""
    anomalies = []
    now = utcnow()
    since_7d = now - timedelta(days=7)

    top_procs = metrics.get("topProcesses", [])
    user_sess = metrics.get("users", [])

    for metric_key in ("cpu", "memory"):
        val_key = "cpuPercent" if metric_key == "cpu" else "memoryPercent"
        if val_key not in metrics or not isinstance(metrics[val_key], (int, float)):
            continue

        current_val = float(metrics[val_key])

        # Query recent metrics for rolling baseline calculation
        query = select(
            DeviceMetric.cpu if metric_key == "cpu" else DeviceMetric.memory
        ).where(
            DeviceMetric.device_id == device.id,
            DeviceMetric.at >= since_7d,
        )
        samples = db.execute(query).scalars().all()

        if not samples:
            samples = [current_val]

        mean_val, std_val = update_resource_baseline(samples)

        # Retrieve or create resource baseline record
        baseline = db.execute(
            select(ResourceBaseline).where(
                ResourceBaseline.device_id == device.id,
                ResourceBaseline.metric == metric_key,
            )
        ).scalars().first()

        if not baseline:
            baseline = ResourceBaseline(device_id=device.id, metric=metric_key)
            db.add(baseline)

        baseline.rolling_mean = mean_val
        baseline.rolling_std = std_val
        baseline.sample_count = len(samples)
        baseline.updated_at = now

        # Get previous anomaly record for tracking sustained spikes
        latest_anomaly = db.execute(
            select(ResourceAnomaly)
            .where(
                ResourceAnomaly.device_id == device.id,
                ResourceAnomaly.metric == metric_key,
            )
            .order_by(ResourceAnomaly.at.desc())
        ).scalars().first()

        prev_consecutive = (
            latest_anomaly.consecutive_spikes
            if latest_anomaly and (now - latest_anomaly.at) < timedelta(minutes=15)
            else 0
        )

        eval_res = evaluate_resource_anomaly(
            current_val=current_val,
            baseline_mean=mean_val,
            baseline_std=std_val,
            previous_consecutive_spikes=prev_consecutive,
            top_processes=top_procs,
            user_sessions=user_sess,
        )

        if eval_res["is_anomaly"]:
            anomaly_rec = ResourceAnomaly(
                device_id=device.id,
                at=now,
                metric=metric_key,
                current_value=current_val,
                baseline_mean=mean_val,
                baseline_std=std_val,
                z_score=eval_res["z_score"],
                is_sustained=eval_res["is_sustained"],
                consecutive_spikes=eval_res["consecutive_spikes"],
                top_processes=eval_res["top_processes"],
                user_sessions=eval_res["user_sessions"],
            )
            db.add(anomaly_rec)
            anomalies.append(anomaly_rec)

    return anomalies


def tick_analytics(db: Session) -> None:
    """Batch analytical pass executed periodically by the background scheduler thread."""
    devices = db.execute(select(Device).where(Device.approved.is_(True))).scalars().all()
    for dev in devices:
        process_disk_predictions(db, dev.id)
