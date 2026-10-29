"""PII discovery and dark-web credential exposure: context that raises vulnerability priority."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, darkweb, datadiscovery, services
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import BreachExposure, DataDiscoveryScan, Device, Tenant

router = APIRouter(prefix="/api/console", tags=["Exposure intelligence"])


@router.post("/devices/{device_id}/pii-scan")
def request_pii_scan(device_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    device = db.get(Device, device_id)
    if device is None or device.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    try:
        scan = datadiscovery.request_scan(db, device, principal.actor)
    except services.CommandError as exc:
        raise HTTPException(409, str(exc)) from exc
    db.commit()
    return datadiscovery.view(scan, device.hostname)


@router.post("/pii/scans")
def request_pii_scans(body: dict = Body(default={}), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Scan every approved device of a customer (or the visible fleet)."""
    principal.require("respond")
    devices = db.execute(select(Device).where(Device.tenant_id.in_(scoped_tenant(principal, body.get("tenantId"))),
                                              Device.approved.is_(True))).scalars().all()
    queued, skipped = 0, []
    for device in devices:
        try:
            datadiscovery.request_scan(db, device, principal.actor)
            queued += 1
        except services.CommandError as exc:
            skipped.append({"deviceId": device.id, "reason": str(exc)})
    db.commit()
    return {"queued": queued, "skipped": skipped}


@router.get("/pii/scans")
def list_pii_scans(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The latest scan per device."""
    principal.require("read")
    rows = db.execute(select(DataDiscoveryScan).where(DataDiscoveryScan.tenant_id.in_(scoped_tenant(principal, tenant_id)))
                      .order_by(DataDiscoveryScan.requested_at.desc()).limit(2000)).scalars().all()
    latest: dict[str, DataDiscoveryScan] = {}
    for row in rows:
        latest.setdefault(row.device_id, row)
    hosts = dict(db.execute(select(Device.id, Device.hostname).where(Device.id.in_(latest))).all())
    order = {"high": 0, "low": 1, "none": 2}
    return sorted((datadiscovery.view(r, hosts.get(r.device_id, "")) for r in latest.values()),
                  key=lambda v: (order.get(v["sensitivity"], 3), v["hostname"]))


@router.get("/darkweb/settings")
def get_darkweb_settings(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    from ..config import get_settings

    principal.check_tenant(tenant_id)
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "Not found")
    return {**darkweb.settings_for(tenant), "providerConfigured": bool(get_settings().hibp_api_key)}


@router.put("/darkweb/settings")
def set_darkweb_settings(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    tenant_id = str(body.get("tenantId") or "")
    principal.check_tenant(tenant_id)
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "Not found")
    try:
        domains = darkweb.clean_domains(body.get("domains"))
    except darkweb.DarkWebError as exc:
        raise HTTPException(422, str(exc)) from exc
    config = {**darkweb.settings_for(tenant), "enabled": bool(body.get("enabled")), "domains": domains,
              "autoTicket": bool(body.get("autoTicket", True))}
    tenant.settings = {**(tenant.settings or {}), "darkWeb": config}
    audit.record(db, principal.actor, "darkweb.settings.updated", tenant.name, tenant.id, domains=domains, enabled=config["enabled"])
    db.commit()
    return config


@router.post("/darkweb/sync")
def sync_darkweb(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    tenant_id = str(body.get("tenantId") or "")
    principal.check_tenant(tenant_id)
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "Not found")
    try:
        result = darkweb.sync_tenant(db, tenant)
    except darkweb.DarkWebError as exc:
        db.commit()  # keep the recorded error
        raise HTTPException(502, str(exc)) from exc
    db.commit()
    return result


@router.get("/darkweb/exposures")
def list_exposures(tenant_id: str | None = None, status: str | None = "open", principal: Principal = Depends(current_principal),
                   db: Session = Depends(get_db)):
    principal.require("read")
    query = select(BreachExposure).where(BreachExposure.tenant_id.in_(scoped_tenant(principal, tenant_id)))
    if status:
        query = query.where(BreachExposure.status == status)
    rows = db.execute(query.order_by(BreachExposure.last_seen.desc()).limit(5000)).scalars().all()
    order = {"high": 0, "medium": 1, "low": 2}
    return sorted((darkweb.view(r) for r in rows), key=lambda v: (order.get(v["risk"], 3), v["email"]))


@router.patch("/darkweb/exposures/{exposure_id}")
def update_exposure(exposure_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                    db: Session = Depends(get_db)):
    principal.require("respond")
    row = db.get(BreachExposure, exposure_id)
    if row is None or row.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    try:
        darkweb.set_status(db, row, str(body.get("status") or ""), principal.actor)
    except darkweb.DarkWebError as exc:
        raise HTTPException(422, str(exc)) from exc
    db.commit()
    return darkweb.view(row)
