"""Agent deployment from an existing RMM, Group Policy or Intune (rmm_deploy.py)."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, deployment_installers, ratelimit, rmm_deploy
from ..config import get_settings
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import DeviceGroup, EnrollmentToken, Tenant, utcnow
from ..security import digest, new_secret

public = APIRouter(prefix="/api/v1/install", tags=["Agent deployment"])
router = APIRouter(prefix="/api/console", tags=["Agent deployment"])


def _token(db: Session, request: Request, raw: str | None) -> EnrollmentToken:
    client = request.client.host if request.client else "unknown"
    ratelimit.check(f"install-download:{client}", 60, 3600)
    if not raw or not raw.startswith("fet_") or len(raw) > 200:
        raise HTTPException(401, "Send the deployment token in the X-Fenrir-Token header")
    token = db.scalar(select(EnrollmentToken).where(EnrollmentToken.token_hash == digest(raw)))
    if token is None or token.revoked:
        raise HTTPException(403, "The deployment token is invalid or revoked")
    if token.expires_at and token.expires_at < utcnow():
        raise HTTPException(403, "The deployment token has expired")
    if token.max_uses is not None and token.uses >= token.max_uses:
        raise HTTPException(403, "The deployment token has no uses left")
    return token


def _base() -> str:
    return get_settings().public_base_url.rstrip("/")


@public.get("/windows.exe")
def windows_exe(request: Request, x_fenrir_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    _token(db, request, x_fenrir_token)
    data, filename, media = deployment_installers.build("windows", _base(), x_fenrir_token)
    return Response(data, media_type=media, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@public.get("/windows.msi")
def windows_msi(request: Request, x_fenrir_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    token = _token(db, request, x_fenrir_token)
    return _msi_response(db, token, x_fenrir_token)


def _msi_response(db: Session, token: EnrollmentToken, raw: str) -> Response:
    if not rmm_deploy.msi_available():
        raise HTTPException(409, "MSI packages need msitools (wixl) on the server; it is included in the Docker image")
    data, _, _ = deployment_installers.build("windows", _base(), raw)
    tenant = db.get(Tenant, token.tenant_id)
    try:
        msi = rmm_deploy.windows_msi(data, token.label, tenant.name if tenant else "Fenrir")
    except RuntimeError as exc:
        raise HTTPException(500, str(exc)) from None
    return Response(msi, media_type="application/x-msi", headers={"Content-Disposition": 'attachment; filename="FenrirAgent.msi"'})


@public.get("/linux.sh", response_class=PlainTextResponse)
def linux_sh(request: Request, x_fenrir_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    _token(db, request, x_fenrir_token)
    data, _, media = deployment_installers.build("linux", _base(), x_fenrir_token)
    return Response(data, media_type=media)


@public.get("/macos.sh", response_class=PlainTextResponse)
def macos_sh(request: Request, x_fenrir_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    _token(db, request, x_fenrir_token)
    data, _, media = deployment_installers.build("macos", _base(), x_fenrir_token)
    return Response(data, media_type=media)


@router.post("/deploy-scripts")
def create_deployment(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """A deployment token for one customer (and optional group) with the scripts and MSI instructions that use it."""
    principal.require("configure")
    ratelimit.check(f"deploy-scripts:{principal.user.id}", 20, 3600)
    tenant_id = str(body.get("tenantId") or "")
    if not tenant_id:
        raise HTTPException(422, "Choose the customer the devices belong to")
    principal.check_tenant(tenant_id)
    tenant = db.get(Tenant, tenant_id)
    if tenant is None or tenant.kind != "customer":
        raise HTTPException(404, "Customer not found")
    group_id = str(body.get("groupId") or "") or None
    if group_id:
        group = db.get(DeviceGroup, group_id)
        if group is None or group.tenant_id != tenant_id:
            raise HTTPException(422, "The device group belongs to another customer")
    try:
        days = int(body.get("expiresInDays", 90))
    except (TypeError, ValueError):
        raise HTTPException(422, "Expiry must be a whole number of days") from None
    if not 1 <= days <= 365:
        raise HTTPException(422, "Expiry must be between 1 and 365 days")
    label = str(body.get("label") or "RMM deployment").strip()[:200] or "RMM deployment"
    raw = new_secret("fet", 24)
    expires = utcnow() + timedelta(days=days)
    row = EnrollmentToken(tenant_id=tenant_id, group_id=group_id, label=label, token_hash=digest(raw), token_hint=raw[-6:],
                          max_uses=None, expires_at=expires)
    db.add(row)
    audit.record(db, principal.actor, "deployment_token.created", label, tenant_id, group=group_id or "", days=days)
    db.commit()
    base = _base()
    return {
        "id": row.id, "label": label, "tenantId": tenant_id, "groupId": group_id, "expiresAt": expires.isoformat() + "Z",
        "tokenHint": row.token_hint, "token": raw,  # shown once, like any new enrolment token; the scripts carry it too
        "windowsPowerShell": rmm_deploy.windows_script(base, raw, label, tenant.name, expires),
        "unixShell": rmm_deploy.unix_script(base, raw, label, tenant.name, expires),
        "msi": {"available": rmm_deploy.msi_available(), "downloadPath": f"deploy-scripts/{row.id}/msi",
                **rmm_deploy.intune_command()},
        "available": deployment_installers.available(),
    }


@router.post("/deploy-scripts/{token_id}/msi")
def deployment_msi(token_id: str, body: dict = Body(default={}), principal: Principal = Depends(current_principal),
                   db: Session = Depends(get_db)):
    """The MSI for a deployment created moments ago. The raw token is not stored, so the console sends it back."""
    principal.require("configure")
    row = db.get(EnrollmentToken, token_id)
    if row is None or row.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    raw = str(body.get("token") or "")
    if digest(raw) != row.token_hash:
        raise HTTPException(403, "That is not this deployment's token")
    if row.revoked or (row.expires_at and row.expires_at < utcnow()):
        raise HTTPException(403, "The deployment token is revoked or expired")
    ratelimit.check(f"deploy-msi:{principal.user.id}", 10, 3600)
    audit.record(db, principal.actor, "deployment_msi.downloaded", row.label, row.tenant_id)
    db.commit()
    return _msi_response(db, row, raw)
