"""Condition-based background remediation packages (detection + remediation scripts)."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .. import audit, condition_remediation as engine, script_review, services
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth, scoped_tenant
from ..models import ConditionPackage, ConditionResult, Device

router = APIRouter(prefix="/api/console/rmm/remediation-packages", tags=["Condition remediation"])

LANGUAGES = {"powershell": ["windows"], "bash": ["linux", "macos"], "sh": ["linux", "macos"], "zsh": ["macos"], "python": ["linux", "macos"]}


def _owned(db: Session, principal: Principal, package_id: str, allow_template: bool = False) -> ConditionPackage:
    row = db.get(ConditionPackage, package_id)
    if row is None or (row.tenant_id is None and not allow_template) or (row.tenant_id is not None and row.tenant_id not in principal.tenant_ids):
        raise HTTPException(404, "Not found")
    return row


def _apply(row: ConditionPackage, body: dict) -> None:
    for field, attr in (("name", "name"), ("description", "description"), ("detectionScript", "detection_script"),
                        ("remediationScript", "remediation_script")):
        if field in body:
            setattr(row, attr, str(body[field] or ""))
    if "language" in body:
        if body["language"] not in LANGUAGES:
            raise HTTPException(422, f"language must be one of {', '.join(LANGUAGES)}")
        row.language = body["language"]
    if "platforms" in body:
        platforms = [p for p in body["platforms"] or [] if p in ("windows", "linux", "macos")]
        row.platforms = platforms
    if set(row.platforms or []) - set(LANGUAGES[row.language]):
        raise HTTPException(422, f"{row.language} scripts cannot run on {', '.join(sorted(set(row.platforms) - set(LANGUAGES[row.language])))}")
    for field, attr, low, high in (("intervalHours", "interval_hours", 1, 720), ("timeoutSeconds", "timeout_seconds", 30, 3600)):
        if field in body:
            setattr(row, attr, max(low, min(int(body[field]), high)))
    for field, attr in (("autoRemediate", "auto_remediate"), ("ticketOnFailure", "ticket_on_failure"), ("enabled", "enabled")):
        if field in body:
            setattr(row, attr, bool(body[field]))
    if "targets" in body:
        row.targets = {k: [str(x) for x in v] for k, v in (body["targets"] or {}).items()
                       if k in ("deviceIds", "groupIds", "tenantIds", "platforms", "tags") and isinstance(v, list)}
    if not row.name.strip() or not row.detection_script.strip():
        raise HTTPException(422, "A name and a detection script are required")


@router.get("")
def list_packages(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    scope = scoped_tenant(principal, tenant_id)
    rows = db.execute(select(ConditionPackage).where(or_(ConditionPackage.tenant_id.is_(None), ConditionPackage.tenant_id.in_(scope)))
                      .order_by(ConditionPackage.tenant_id.is_(None), ConditionPackage.name)).scalars().all()
    results = db.execute(select(ConditionResult).where(ConditionResult.tenant_id.in_(scope))).scalars().all()
    by_package: dict[str, list] = {}
    for r in results:
        by_package.setdefault(r.package_id, []).append(r)
    return [engine.view(r, by_package.get(r.id, []) if r.tenant_id else None, db) for r in rows]


@router.post("")
def create_package(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """A custom package for one customer. Running scripts needs the scripts permission as well as configure."""
    principal.require("configure")
    principal.require("scripts")
    tenant_id = str(body.get("tenantId") or "")
    principal.check_tenant(tenant_id)
    row = ConditionPackage(tenant_id=tenant_id, name="", created_by=principal.actor, language=str(body.get("language") or "powershell"),
                           platforms=["windows"], review_editors=[principal.actor])
    _apply(row, body)
    db.add(row)
    db.flush()
    audit.record(db, principal.actor, "condition.package.created", row.name, tenant_id, package=row.id)
    db.commit()
    return engine.view(row, [], db)


@router.post("/{package_id}/enable")
def enable_template(package_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Copy a built-in package to a customer and turn it on."""
    principal.require("configure")
    principal.require("scripts")
    template = _owned(db, principal, package_id, allow_template=True)
    if template.tenant_id is not None:
        raise HTTPException(409, "Only built-in templates are enabled this way")
    tenant_id = str(body.get("tenantId") or "")
    principal.check_tenant(tenant_id)
    existing = db.execute(select(ConditionPackage).where(ConditionPackage.tenant_id == tenant_id,
                                                         ConditionPackage.builtin_key == template.builtin_key)).scalars().first()
    if existing is not None:
        existing.enabled = True
        row = existing
    else:
        row = engine.enable_for(db, template, tenant_id, principal.actor)
        _apply(row, {k: v for k, v in body.items() if k in ("intervalHours", "autoRemediate", "ticketOnFailure", "targets")})
    db.flush()
    audit.record(db, principal.actor, "condition.package.enabled", row.name, tenant_id, package=row.id)
    db.commit()
    return engine.view(row, [], db)


@router.patch("/{package_id}")
def update_package(package_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    principal.require("scripts")
    row = _owned(db, principal, package_id)
    before = script_review.before_edit(row)
    _apply(row, body)
    script_review.edited(row, principal.actor, before)
    audit.record(db, principal.actor, "condition.package.updated", row.name, row.tenant_id, package=row.id, fields=sorted(body))
    db.commit()
    return engine.view(row, None, db)


@router.post("/{package_id}/review")
def review_package(package_id: str, request: Request, body: dict = Body(...), principal: Principal = Depends(current_principal),
                   db: Session = Depends(get_db)):
    """A second person approves exactly the detection and remediation scripts they read (body.hash)."""
    row = _owned(db, principal, package_id)
    require_reauth(request, principal)
    script_review.approve(db, principal, row, str(body.get("hash") or ""))
    db.commit()
    return engine.view(row, None, db)


@router.delete("/{package_id}")
def delete_package(package_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    row = _owned(db, principal, package_id)
    for result in db.execute(select(ConditionResult).where(ConditionResult.package_id == row.id)).scalars():
        db.delete(result)
    audit.record(db, principal.actor, "condition.package.deleted", row.name, row.tenant_id, package=row.id)
    db.delete(row)
    db.commit()
    return {"deleted": package_id}


@router.post("/{package_id}/run")
def run_now(package_id: str, body: dict = Body(default={}), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Run detection now on every target (or the devices listed)."""
    principal.require("scripts")
    row = _owned(db, principal, package_id)
    try:
        script_review.check(db, row)
    except script_review.NotReviewed as exc:
        raise HTTPException(400, str(exc)) from None
    devices = engine.targets(db, row)
    if body.get("deviceIds"):
        wanted = set(body["deviceIds"])
        devices = [d for d in devices if d.id in wanted]
    queued, skipped = 0, []
    for device in devices:
        try:
            engine.queue(db, row, device, "detect", principal.actor)
            queued += 1
        except services.CommandError as exc:
            skipped.append({"deviceId": device.id, "reason": str(exc)})
    db.commit()
    return {"queued": queued, "skipped": skipped}


@router.get("/{package_id}/results")
def package_results(package_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    row = _owned(db, principal, package_id)
    results = db.execute(select(ConditionResult).where(ConditionResult.package_id == row.id)).scalars().all()
    hosts = dict(db.execute(select(Device.id, Device.hostname).where(Device.id.in_([r.device_id for r in results]))).all())
    return [{"deviceId": r.device_id, "hostname": hosts.get(r.device_id, ""), "status": r.status, "phase": r.phase,
             "detectOutput": r.detect_output, "remediateOutput": r.remediate_output, "attempts": r.attempts, "failures": r.failures,
             "lastDetectAt": r.last_detect_at.isoformat() + "Z" if r.last_detect_at else None,
             "lastRemediatedAt": r.last_remediated_at.isoformat() + "Z" if r.last_remediated_at else None, "ticketId": r.ticket_id}
            for r in sorted(results, key=lambda r: hosts.get(r.device_id, ""))]
