"""Tenant-scoped Microsoft 365 connections and snapshots."""
from uuid import UUID
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from .. import audit, crypto, m365, ratelimit
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth, scoped_tenant
from ..models import M365Connection, new_id, utcnow
from ..serialize import to_dict
from .documentation import owned

router = APIRouter(prefix="/api/console/m365", tags=["Microsoft 365"])
crypto.register_encrypted(M365Connection, "credentials_envelope", lambda row: f"m365:{row.tenant_id}:{row.id}")

class ConnectionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str
    name: str = Field(min_length=1, max_length=200)
    directoryId: UUID
    clientId: UUID
    clientSecret: str = Field(min_length=1, max_length=10000)

class SecretInput(BaseModel):
    clientSecret: str = Field(min_length=1, max_length=10000)

@router.get("/connections")
def connections(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    return [to_dict(row) for row in db.scalars(select(M365Connection).where(M365Connection.tenant_id.in_(scoped_tenant(principal, tenant_id))).limit(1000))]

@router.post("/connections")
def create(body: ConnectionInput, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    principal.check_tenant(body.tenantId)
    require_reauth(request, principal)
    row = M365Connection(id=new_id("m365"), tenant_id=body.tenantId, name=body.name,
                         directory_id=str(body.directoryId), client_id=str(body.clientId))
    row.credentials_envelope = crypto.encrypt(body.clientSecret, f"m365:{row.tenant_id}:{row.id}")
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "This directory is already connected for this customer")
    audit.record(db, principal.actor, "m365.connected", row.id, row.tenant_id)
    db.commit()
    return to_dict(row)

@router.put("/connections/{connection_id}/secret")
def replace_secret(connection_id: str, body: SecretInput, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    row = owned(db, M365Connection, connection_id, principal)
    require_reauth(request, principal)
    row.credentials_envelope = crypto.encrypt(body.clientSecret, f"m365:{row.tenant_id}:{row.id}")
    row.updated_at = utcnow()
    audit.record(db, principal.actor, "m365.secret_replaced", row.id, row.tenant_id)
    db.commit()
    return {"ok": True}

@router.post("/connections/{connection_id}/sync")
def sync(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    row = owned(db, M365Connection, connection_id, principal)
    ratelimit.check(f"m365-sync:{row.id}", 3, 300)
    try:
        snapshot = m365.synchronize(row)
    except (httpx.HTTPError, ValueError, KeyError, crypto.VaultError):
        # Never return provider bodies, token URLs with secrets, or raw exceptions.
        row.status, row.last_error = "failed", "Sync failed. Check application credentials, Graph permissions and connectivity."
        audit.record(db, principal.actor, "m365.sync_failed", row.id, row.tenant_id)
        db.commit()
        raise HTTPException(502, row.last_error)
    defender = m365.ingest_defender_alerts(db, row, snapshot.pop("defenderAlerts", None))
    snapshot["defenderAlerts"] = defender
    row.snapshot, row.status, row.last_error, row.synced_at = snapshot, "synced", "", utcnow()
    audit.record(db, principal.actor, "m365.synced", row.id, row.tenant_id, users=len(snapshot["users"]), licenses=len(snapshot["licenses"]))
    db.commit()
    return to_dict(row)


# --- Admin sign-in ------------------------------------------------------------------------------------------------
import hashlib
import secrets as _secrets
from datetime import timedelta
from typing import Literal

from fastapi.responses import RedirectResponse

from .. import m365_signin
from ..config import get_settings
from ..models import M365SignIn

crypto.register_encrypted(M365SignIn, "secret_envelope", lambda row: f"m365-signin:{row.tenant_id}:{row.id}")
oauth = APIRouter(prefix="/api/m365/oauth", tags=["Microsoft 365"])
SIGNIN_MINUTES = 15


class SignInInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str
    name: str = Field(default="", max_length=200)
    mode: Literal["device", "redirect"] = "device"


def _hash(state: str) -> str:
    return hashlib.sha256(state.encode()).hexdigest()


def _signin_view(row: M365SignIn) -> dict:
    return {"id": row.id, "mode": row.mode, "status": row.status, "userCode": row.user_code, "verificationUri": row.verification_uri,
            "expiresAt": row.expires_at.isoformat() + "Z", "error": row.error, "connectionId": row.connection_id,
            "signedInAs": row.signed_in_as, "interval": row.interval}


def _store_connection(db: Session, row: M365SignIn, *, directory_id: str, tenant_name: str, mode: str, client_id: str,
                      secret: str | None, consented_by: str, granted: list, secret_expires=None) -> M365Connection:
    connection = db.execute(select(M365Connection).where(M365Connection.tenant_id == row.tenant_id,
                                                         M365Connection.directory_id == directory_id)).scalar_one_or_none()
    if connection is None:
        connection = M365Connection(id=new_id("m365"), tenant_id=row.tenant_id, directory_id=directory_id,
                                    name=row.name or tenant_name or "Microsoft 365")
        db.add(connection)
    connection.client_id, connection.auth_mode, connection.tenant_name = client_id, mode, tenant_name[:200]
    connection.consented_by, connection.consented_at = consented_by[:320], utcnow()
    connection.secret_expires_at, connection.granted_permissions = secret_expires, granted
    connection.credentials_envelope = crypto.encrypt(secret or "platform-app", f"m365:{connection.tenant_id}:{connection.id}")
    connection.status, connection.last_error, connection.updated_at = "connected", "", utcnow()
    db.flush()
    row.connection_id, row.status, row.directory_id = connection.id, "completed", directory_id
    return connection


@router.get("/signin/options")
def signin_options(principal: Principal = Depends(current_principal)):
    principal.require("configure")
    uris = m365_signin.redirect_uris()
    return {"redirect": m365_signin.platform_app_configured(), "device": True, "permissions": m365_signin.APP_PERMISSIONS,
            "redirectUris": [uris["callback"], uris["consent"]], "platformClientId": get_settings().m365_client_id or None}


@router.post("/signin")
def start_signin(body: SignInInput, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    principal.check_tenant(body.tenantId)
    require_reauth(request, principal)
    ratelimit.check(f"m365-signin:{principal.user.id}", 10, 600)
    row = M365SignIn(id=new_id("m365si"), tenant_id=body.tenantId, created_by=principal.user.id, mode=body.mode, name=body.name,
                     expires_at=utcnow() + timedelta(minutes=SIGNIN_MINUTES))
    out = {}
    if body.mode == "redirect":
        if not m365_signin.platform_app_configured():
            raise HTTPException(400, "Sign in with Microsoft needs the platform Microsoft 365 app (FENRIR_M365_CLIENT_ID and _SECRET). Use a code instead.")
        state = _secrets.token_urlsafe(32)
        row.state_hash = _hash(state)
        out["authorizeUrl"] = m365_signin.authorize_url(state)
    else:
        try:
            code = m365_signin.start_device_code()
        except (m365_signin.SignInError, httpx.HTTPError) as exc:
            raise HTTPException(502, str(exc) if isinstance(exc, m365_signin.SignInError) else "Could not reach Microsoft")
        row.user_code, row.verification_uri, row.interval = code["userCode"], code["verificationUri"], code["interval"]
        row.expires_at = utcnow() + timedelta(seconds=min(code["expiresIn"], SIGNIN_MINUTES * 60))
        db.add(row)
        db.flush()
        row.secret_envelope = crypto.encrypt(code["deviceCode"], f"m365-signin:{row.tenant_id}:{row.id}")
    db.add(row)
    audit.record(db, principal.actor, "m365.signin_started", row.id, row.tenant_id, mode=row.mode)
    db.commit()
    return {**_signin_view(row), **out}


@router.get("/signin/{signin_id}")
def poll_signin(signin_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The console polls this while the admin signs in. Device codes are checked with Microsoft at most once per interval."""
    principal.require("configure")
    row = db.get(M365SignIn, signin_id)
    if row is None or row.tenant_id not in principal.tenant_ids or row.created_by != principal.user.id:
        raise HTTPException(404, "Not found")
    if row.status in ("pending", "provisioning") and row.expires_at < utcnow():
        row.status, row.error = "expired", "The sign-in code expired. Start again."
        db.commit()
    if row.mode != "device" or row.status != "pending":
        return _signin_view(row)
    if row.last_polled_at and (utcnow() - row.last_polled_at).total_seconds() < row.interval:
        return _signin_view(row)
    row.last_polled_at = utcnow()
    try:
        result = m365_signin.poll_device_code(crypto.decrypt(row.secret_envelope, f"m365-signin:{row.tenant_id}:{row.id}"))
    except httpx.HTTPError:
        db.commit()
        return _signin_view(row)
    if result["status"] == "slow_down":
        row.interval = min(row.interval + 5, 30)
    elif result["status"] == "expired":
        row.status, row.error = "expired", "The sign-in code expired. Start again."
    elif result["status"] == "denied":
        row.status, row.error = "failed", result.get("error") or "The sign-in was not completed."
    elif result["status"] == "ok":
        row.status = "provisioning"
        db.commit()
        try:
            made = m365_signin.provision(result["accessToken"], f"Fenrir ({get_settings().public_base_url.split('//')[-1].split('/')[0]})")
        except (m365_signin.SignInError, httpx.HTTPError, KeyError) as exc:
            row.status = "failed"
            row.error = str(exc)[:500] if isinstance(exc, m365_signin.SignInError) else "Could not finish setting up the Fenrir app in Microsoft 365."
            audit.record(db, principal.actor, "m365.signin_failed", row.id, row.tenant_id)
            db.commit()
            return _signin_view(row)
        row.signed_in_as = made["signedInAs"]
        try:
            connection = _store_connection(db, row, directory_id=made["directoryId"], tenant_name=made["tenantName"], mode="provisioned",
                                           client_id=made["clientId"], secret=made["secret"], consented_by=made["signedInAs"],
                                           granted=made["granted"], secret_expires=made["secretExpires"])
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "This directory is already connected for this customer")
        row.secret_envelope = None  # the device code is spent
        audit.record(db, principal.actor, "m365.connected", connection.id, connection.tenant_id, mode="provisioned",
                     signedInAs=made["signedInAs"], missingPermissions=made["missing"])
    db.commit()
    return _signin_view(row)


def _console(path: str) -> RedirectResponse:
    return RedirectResponse(get_settings().public_base_url.rstrip("/") + path, status_code=303)


def _pending_redirect(db: Session, state: str) -> M365SignIn | None:
    if not state or len(state) > 200:
        return None
    row = db.execute(select(M365SignIn).where(M365SignIn.state_hash == _hash(state), M365SignIn.mode == "redirect")).scalar_one_or_none()
    if row is None or row.status != "pending" or row.expires_at < utcnow():
        return None
    return row


@oauth.get("/callback")
def oauth_callback(state: str = "", code: str = "", error: str = "", error_description: str = "", db: Session = Depends(get_db)):
    """Step 1 of "Sign in with Microsoft": the admin signed in; learn their tenant, then ask for admin consent."""
    row = _pending_redirect(db, state)
    if row is None:
        return _console("/m365?signin=expired")
    if error or not code:
        row.status, row.error = "failed", (error_description or error or "Sign-in cancelled")[:500]
        db.commit()
        return _console(f"/m365?signin=failed&id={row.id}")
    try:
        who = m365_signin.redeem_code(code)
    except (m365_signin.SignInError, httpx.HTTPError) as exc:
        row.status, row.error = "failed", str(exc)[:500] if isinstance(exc, m365_signin.SignInError) else "Could not reach Microsoft"
        db.commit()
        return _console(f"/m365?signin=failed&id={row.id}")
    row.directory_id, row.signed_in_as = who["directoryId"], who["signedInAs"]
    db.commit()
    return RedirectResponse(m365_signin.consent_url(who["directoryId"], state), status_code=303)


@oauth.get("/consent")
def oauth_consent(state: str = "", tenant: str = "", admin_consent: str = "", error: str = "", error_description: str = "",
                  db: Session = Depends(get_db)):
    """Step 2: Microsoft's admin-consent page sends the admin back here."""
    row = _pending_redirect(db, state)
    if row is None:
        return _console("/m365?signin=expired")
    if error or admin_consent.lower() != "true":
        row.status, row.error = "failed", (error_description or error or "Consent was not granted")[:500]
        db.commit()
        return _console(f"/m365?signin=failed&id={row.id}")
    if not row.directory_id or tenant.lower() != row.directory_id.lower():
        row.status, row.error = "failed", "Consent was granted in a different tenant from the one you signed in to."
        db.commit()
        return _console(f"/m365?signin=failed&id={row.id}")
    try:
        connection = _store_connection(db, row, directory_id=row.directory_id, tenant_name=m365_signin.tenant_name(row.directory_id),
                                       mode="platform", client_id=get_settings().m365_client_id, secret=None,
                                       consented_by=row.signed_in_as, granted=["(as consented on Microsoft's page)"])
    except IntegrityError:
        db.rollback()
        return _console("/m365?signin=duplicate")
    audit.record(db, f"user:{row.created_by}", "m365.connected", connection.id, connection.tenant_id, mode="platform",
                 signedInAs=row.signed_in_as)
    db.commit()
    return _console(f"/m365?signin=connected&id={connection.id}")
