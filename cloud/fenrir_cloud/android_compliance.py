"""Android phone compliance against the "android" policy section.

The phone checks itself (it is the only place the passcode strength, encryption, patch level or installed apps can be
read) and reports each check in its heartbeat metrics as ``compliance``: a list of ``{key, label, ok, detail,
enforced}``. ``managementMode`` says how it is managed: ``work_profile`` (Fenrir is the work profile's owner and
enforces the policy there) or ``device_admin`` (checked and reported only). This module keeps the latest report on
the device and raises one alert per phone that is not compliant, closed again when it is.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Alert, Device, utcnow

RULE = "android:noncompliant"
MODES = {"work_profile": "Work profile", "device_admin": "Device admin", "device_owner": "Company-owned"}


def _clean(report) -> list[dict]:
    items = []
    for row in report if isinstance(report, list) else []:
        if not isinstance(row, dict) or not row.get("key"):
            continue
        items.append({"key": str(row["key"])[:60], "label": str(row.get("label") or row["key"])[:120], "ok": bool(row.get("ok")),
                      "detail": str(row.get("detail") or "")[:300], "enforced": bool(row.get("enforced"))})
    return items[:60]


def record(db: Session, device: Device, metrics: dict, settings: dict) -> None:
    """Store the phone's compliance report and open or close its alert."""
    if device.platform != "android" or "compliance" not in metrics:
        return
    items = _clean(metrics.get("compliance"))
    failing = [i for i in items if not i["ok"]]
    device.metrics = {**(device.metrics or {}), "compliance": items,
                      "managementMode": str(metrics.get("managementMode") or (device.metrics or {}).get("managementMode") or "device_admin")[:20],
                      "compliant": not failing, "complianceAt": utcnow().isoformat() + "Z"}
    open_alert = db.execute(select(Alert).where(Alert.device_id == device.id, Alert.rule_id == RULE,
                                                Alert.status.in_(("new", "triaged")))).scalars().first()
    wanted = failing and bool((settings.get("android") or {}).get("alertOnNonCompliance", True))
    summary = "; ".join(f"{i['label']}: {i['detail']}" if i["detail"] else i["label"] for i in failing)
    if wanted and open_alert is None:
        db.add(Alert(tenant_id=device.tenant_id, device_id=device.id, rule_id=RULE, severity="medium", mitre=[],
                     title=f"{device.hostname} does not meet its phone policy"[:300], event_ids=[],
                     details={"category": "compliance", "source": "Android policy", "description": summary[:2000],
                              "failing": [i["key"] for i in failing]}))
    elif wanted and open_alert is not None:
        open_alert.details = {**(open_alert.details or {}), "description": summary[:2000], "failing": [i["key"] for i in failing]}
    elif not wanted and open_alert is not None:
        open_alert.status, open_alert.updated_at = "resolved", utcnow()
        open_alert.details = {**(open_alert.details or {}),
                              "autoResolved": "The phone meets its policy again." if not failing else "Compliance alerts were turned off."}


def summary(device: Device) -> dict:
    metrics = device.metrics or {}
    items = metrics.get("compliance") or []
    return {"mode": metrics.get("managementMode") or "device_admin", "modeLabel": MODES.get(metrics.get("managementMode") or "device_admin", "Device admin"),
            "compliant": metrics.get("compliant"), "checkedAt": metrics.get("complianceAt"), "items": items}
