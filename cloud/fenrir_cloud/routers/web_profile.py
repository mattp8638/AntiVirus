"""Web protection for iPhone, iPad and Mac (web_profile.py): enrol with a phone code, download the profile, see it work."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, ratelimit, services, web_profile
from ..config import get_settings
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import Device, Tenant
from .agent_api import _resolve_enrollment_token, _sync_cmdb_from_agent, reinstatement_target
from .fleet import _get_device

router = APIRouter(tags=["Apple web protection"])
console = APIRouter(prefix="/api/console", tags=["Apple web protection"])


@router.post("/api/v1/enroll/apple")
def enrol_apple(request: Request, body: dict = Body(...), db: Session = Depends(get_db)):
    """The page an iPhone, iPad or Mac opens from the phone enrolment code: makes the device and returns its profile link."""
    ip = request.client.host if request.client else ""
    ratelimit.check(f"apple-enrol:{ip}", 60, 3600)  # an office enrolling its phones shares one address; the codes are the real gate
    kind = str(body.get("kind") or "")
    if kind not in web_profile.KINDS:
        raise HTTPException(422, "kind must be iphone, ipad or mac")
    raw = str(body.get("enrollmentToken") or "")
    if not raw:
        raise HTTPException(403, "An enrolment code is required")
    if reinstatement_target(raw) is not None:
        raise HTTPException(403, "This code reinstates a specific computer and cannot enrol a phone")
    token = _resolve_enrollment_token(db, raw)
    base = get_settings().public_base_url
    if not base.lower().startswith("https://"):
        raise HTTPException(409, "This Fenrir server is not on an https:// address, which Apple devices need. Ask IT to set FENRIR_PUBLIC_URL.")
    tenant = db.get(Tenant, token.tenant_id)
    if tenant is None:
        raise HTTPException(403, "Enrollment token is invalid or revoked")
    device = web_profile.enrol(db, tenant, token, str(body.get("name") or "")[:255], kind,
                               request.headers.get("user-agent", ""), ip)
    token.uses += 1
    _, policy_doc = services.effective_policy(db, device)
    device.applied_policy_revision = policy_doc["revision"]
    _sync_cmdb_from_agent(db, device)
    audit.record(db, f"device:{device.hostname}", "device.enrolled", device.id, tenant.id, platform=device.platform,
                 token=token.label, protection="dns-profile", kind=kind)
    db.commit()
    return {"deviceId": device.id, "hostname": device.hostname, "platform": device.platform,
            "profileUrl": f"/dns/{device.dns_token}/apple.mobileconfig", "signed": web_profile.signing_configured()}


@router.get("/dns/{token}/apple.mobileconfig", include_in_schema=False)
def download_profile(token: str, db: Session = Depends(get_db)):
    """The profile itself. The link holds the device's resolver secret, which is all the profile contains."""
    device = db.execute(select(Device).where(Device.dns_token == token)).scalar_one_or_none()
    if device is None or not web_profile.agentless(device) or web_profile.retired(device):
        raise HTTPException(404, "Unknown profile")
    try:
        content = web_profile.profile_bytes(device, db.get(Tenant, device.tenant_id), get_settings().public_base_url)
    except web_profile.ProfileError as exc:
        raise HTTPException(409, str(exc)) from exc
    return Response(content=content, media_type=web_profile.MEDIA_TYPE,
                    headers={"Content-Disposition": f'attachment; filename="{web_profile.FILENAME}"', "Cache-Control": "no-store"})


@console.get("/devices/{device_id}/web-protection")
def web_protection(device_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    device = _get_device(db, principal, device_id)
    if not web_profile.agentless(device):
        raise HTTPException(404, "This device is protected by its Fenrir agent, not a web protection profile")
    resolution, _ = services.effective_policy(db, device)
    return web_profile.view(db, device, get_settings().public_base_url, principal.can("configure"), resolution["settings"]["dns"])
