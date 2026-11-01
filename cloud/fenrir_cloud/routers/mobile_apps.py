"""Phone app protection API (mobile_protection.py): a phone's apps with their verdicts, and trusting an app."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, intel, mobile_protection
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import MobileApp
from .fleet import _get_device

router = APIRouter(prefix="/api/console", tags=["Phone app protection"])
ORDER = {"malicious": 0, "suspicious": 1, "risky": 2, "review": 3, "clean": 4, "trusted": 5}


@router.get("/devices/{device_id}/mobile-apps")
def mobile_apps(device_id: str, include_removed: bool = False, principal: Principal = Depends(current_principal),
                db: Session = Depends(get_db)):
    principal.require("read")
    device = _get_device(db, principal, device_id)
    query = select(MobileApp).where(MobileApp.device_id == device.id)
    if not include_removed:
        query = query.where(MobileApp.removed_at.is_(None))
    rows = sorted(db.execute(query).scalars(), key=lambda r: (ORDER.get(r.verdict, 9), -r.risk_score, r.label.lower()))
    metrics = device.metrics or {}
    return {"apps": [mobile_protection.view(r) for r in rows], "deviceOwner": bool(metrics.get("deviceOwner")),
            "counts": {v: sum(1 for r in rows if r.verdict == v) for v in ORDER}}


@router.post("/devices/{device_id}/mobile-apps/trust")
def trust_app(device_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Not a threat: an allow indicator on this exact APK (or the app's package when there is no fingerprint), for the
    customer or, by a platform administrator, everywhere. Its alert resolves."""
    principal.require("respond")
    device = _get_device(db, principal, device_id)
    package = str(body.get("package") or "")
    row = db.execute(select(MobileApp).where(MobileApp.device_id == device.id, MobileApp.package == package)).scalars().first()
    if row is None:
        raise HTTPException(404, "That app is not on this phone")
    everywhere = body.get("scope") == "everywhere"
    if everywhere:
        principal.require("platform")
    kind, value = ("sha256", row.sha256) if row.sha256 else ("package", row.package)
    intel.upsert(db, kind, value, "allow", "trusted-app", f"trusted by {principal.actor}", None if everywhere else device.tenant_id,
                 100, f"Android app {row.label or row.package} ({row.package}) trusted from {device.hostname}")
    db.flush()
    changed = mobile_protection.reassess(db, None if everywhere else device.tenant_id)
    audit.record(db, principal.actor, "mobile.app_trusted", row.package, device.tenant_id, device=device.hostname,
                 scope="everywhere" if everywhere else "customer", by=kind)
    db.commit()
    return {"trusted": row.package, "reassessed": changed}
