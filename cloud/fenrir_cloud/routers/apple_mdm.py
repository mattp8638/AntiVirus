"""Apple MDM: the device-facing check-in and command endpoints, and the console (MDM-02)."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import apple_mdm as mdm, audit
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth
from ..models import AppleDevice, AppleMdmCommand, AppleMdmConfig
from ..serialize import to_dict

device_router = APIRouter(prefix="/mdm", tags=["Apple MDM protocol"])
router = APIRouter(prefix="/api/console/apple-mdm", tags=["Apple MDM"])
MAX_BODY = 4 * 1024 * 1024


async def _body(request: Request) -> bytes:
    body = await request.body()
    if len(body) > MAX_BODY:
        raise HTTPException(413, "Too large")
    return body


@device_router.put("/checkin")
async def checkin(request: Request, db: Session = Depends(get_db)):
    body = await _body(request)
    try:
        mdm.checkin(db, body, request.headers.get("Mdm-Signature"))
    except (mdm.MdmError, ValueError) as exc:
        db.rollback()
        raise HTTPException(401 if isinstance(exc, mdm.MdmError) else 400, str(exc)) from None
    db.commit()
    return Response(status_code=200)


@device_router.put("/server")
async def server(request: Request, db: Session = Depends(get_db)):
    body = await _body(request)
    try:
        out = mdm.server(db, body, request.headers.get("Mdm-Signature"))
    except (mdm.MdmError, ValueError) as exc:
        db.rollback()
        raise HTTPException(401 if isinstance(exc, mdm.MdmError) else 400, str(exc)) from None
    db.commit()
    return Response(content=out, media_type="application/xml" if out else None, status_code=200)


def _config(db: Session, tenant_id: str) -> AppleMdmConfig:
    cfg = db.scalars(select(AppleMdmConfig).where(AppleMdmConfig.tenant_id == tenant_id)).first()
    if cfg is None:
        cfg = AppleMdmConfig(tenant_id=tenant_id)
        db.add(cfg)
        db.flush()
    return cfg


def _view(cfg: AppleMdmConfig) -> dict:
    return {"tenantId": cfg.tenant_id, "serverUrl": cfg.server_url, "pushTopic": cfg.push_topic, "pushExpiresAt": cfg.push_expires_at,
            "abmTokenExpiresAt": cfg.abm_token_expires_at, "caReady": bool(cfg.ca_cert_pem),
            "dependencies": {"apnsPushCertificate": bool(cfg.push_topic), "appleBusinessManager": bool(cfg.abm_token_expires_at),
                             "automatedDeviceEnrollment": False}}


class ConfigInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    serverUrl: str | None = Field(default=None, max_length=300, pattern=r"^https://[^/?#@]+$")
    pushCertificatePem: str | None = Field(default=None, max_length=20000)
    pushKeyPem: str | None = Field(default=None, max_length=20000)
    abmTokenExpiresAt: datetime | None = None


@router.get("/config/{tenant_id}")
def get_config(tenant_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    p.check_tenant(tenant_id)
    cfg = db.scalars(select(AppleMdmConfig).where(AppleMdmConfig.tenant_id == tenant_id)).first()
    return _view(cfg) if cfg else {"tenantId": tenant_id, "dependencies": {"apnsPushCertificate": False, "appleBusinessManager": False,
                                                                           "automatedDeviceEnrollment": False}}


@router.put("/config/{tenant_id}")
def save_config(tenant_id: str, body: ConfigInput, request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    p.check_tenant(tenant_id)
    require_reauth(request, p)
    cfg = _config(db, tenant_id)
    try:
        if body.serverUrl:
            cfg.server_url = body.serverUrl
        if body.pushCertificatePem or body.pushKeyPem:
            mdm.set_push_certificate(cfg, body.pushCertificatePem or "", body.pushKeyPem or "")
        if body.abmTokenExpiresAt:
            v = body.abmTokenExpiresAt
            cfg.abm_token_expires_at = v.astimezone(timezone.utc).replace(tzinfo=None) if v.tzinfo else v
        mdm.ensure_ca(cfg)
    except mdm.MdmError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from None
    cfg.updated_by = p.actor
    audit.record(db, p.actor, "apple_mdm.config_saved", cfg.id, tenant_id, pushTopic=cfg.push_topic,
                 pushExpires=str(cfg.push_expires_at or ""), abmExpires=str(cfg.abm_token_expires_at or ""))
    db.commit()
    return _view(cfg)


class EnrollInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str = Field(default="", max_length=200)


@router.post("/config/{tenant_id}/enrollments")
def enroll(tenant_id: str, body: EnrollInput, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """A one-device enrolment profile (.mobileconfig), valid for seven days."""
    p.require("configure")
    p.check_tenant(tenant_id)
    cfg = _config(db, tenant_id)
    try:
        enrollment, profile = mdm.enrollment_profile(db, cfg, body.label, p.actor)
    except mdm.MdmError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from None
    db.commit()
    return {"enrollmentId": enrollment.id, "expiresAt": enrollment.expires_at, "filename": "fenrir-mdm.mobileconfig",
            "profileBase64": base64.b64encode(profile).decode()}


@router.get("/devices")
def devices(tenantId: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    p.check_tenant(tenantId)
    rows = db.scalars(select(AppleDevice).where(AppleDevice.tenant_id == tenantId).order_by(AppleDevice.enrolled_at.desc()))
    return [{k: v for k, v in to_dict(d).items() if k != "unlockTokenEnvelope"} for d in rows]


@router.get("/devices/{device_id}/commands")
def commands(device_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    d = db.get(AppleDevice, device_id)
    if d is None or d.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "Device not found")
    return [to_dict(c) for c in db.scalars(select(AppleMdmCommand).where(AppleMdmCommand.device_id == d.id)
                                           .order_by(AppleMdmCommand.created_at.desc()).limit(100))]


class CommandInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    requestType: Literal["DeviceInformation", "ProfileList", "InstalledApplicationList", "SecurityInfo", "CertificateList",
                         "InstallProfile", "RemoveProfile", "InstallApplication", "DeviceLock", "EraseDevice"]
    payload: dict = Field(default_factory=dict)
    confirmSerial: str | None = None  # EraseDevice: the device's serial number, typed


@router.post("/devices/{device_id}/commands")
def send(device_id: str, body: CommandInput, request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("respond")
    d = db.get(AppleDevice, device_id)
    if d is None or d.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "Device not found")
    if body.requestType in ("EraseDevice", "DeviceLock", "InstallProfile", "RemoveProfile", "InstallApplication"):
        require_reauth(request, p)
    if body.requestType == "EraseDevice" and (body.confirmSerial or "").strip().upper() != (d.serial_number or "").upper():
        raise HTTPException(409, f"Type the device's serial number ({d.serial_number}) to confirm erasing it")
    try:
        cmd = mdm.queue(db, d, body.requestType, body.payload, p.actor)
        pushed = mdm.push(db, d)
    except mdm.MdmError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from None
    db.commit()
    return {**to_dict(cmd), "push": pushed}
