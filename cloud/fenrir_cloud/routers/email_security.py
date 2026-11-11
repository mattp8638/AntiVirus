"""Email security: shadow-mode scanning of customers' Microsoft 365 mail (email_scan.py).

Seeing scanned messages and labelling them needs ``respond`` (the people who handle alerts); switching scanning on or
off for a customer needs ``configure``. Everything is limited to the customers the user can see.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .. import email_scan, ratelimit
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import EmailScan, EmailScanSetting, M365Connection
from .documentation import owned

router = APIRouter(prefix="/api/console/email-security", tags=["Email security"])


class SettingIn(BaseModel):
    mode: Literal["off", "shadow"]
    retentionDays: int | None = Field(default=None, ge=7, le=730)


class LabelIn(BaseModel):
    label: Literal["phish", "malware", "spam", "safe", ""]


@router.get("/overview")
def overview(tenant_id: str | None = None, days: int = Query(7, ge=1, le=90),
             principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    return email_scan.overview(db, scoped_tenant(principal, tenant_id), days)


@router.get("/connections")
def connections(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Every Microsoft 365 connection the user can see, with its email security setting."""
    principal.require("respond")
    tenants = scoped_tenant(principal, tenant_id)
    rows = db.execute(select(M365Connection).where(M365Connection.tenant_id.in_(tenants))).scalars().all()
    settings = {s.connection_id: s for s in db.execute(select(EmailScanSetting).where(
        EmailScanSetting.connection_id.in_([r.id for r in rows]))).scalars()} if rows else {}
    return [email_scan.setting_view(settings.get(r.id), r) for r in sorted(rows, key=lambda r: (r.tenant_name or r.name).lower())]


@router.put("/connections/{connection_id}")
def configure(connection_id: str, body: SettingIn, principal: Principal = Depends(current_principal),
              db: Session = Depends(get_db)):
    principal.require("configure")
    connection = owned(db, M365Connection, connection_id, principal)
    if body.mode == "shadow" and (connection.auth_mode or "app") == "gdap":
        raise HTTPException(409, "Reading mail needs an app connection (admin sign-in or the Fenrir app). Microsoft does "
                                 "not let a partner (GDAP) connection read mailboxes.")
    try:
        setting = email_scan.configure(db, connection, body.mode, body.retentionDays, principal.actor)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    db.commit()
    return email_scan.setting_view(setting, connection)


@router.post("/connections/{connection_id}/scan")
def scan_now(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Run one scan of this connection now (it also runs every five minutes on its own)."""
    principal.require("configure")
    connection = owned(db, M365Connection, connection_id, principal)
    setting = db.execute(select(EmailScanSetting).where(EmailScanSetting.connection_id == connection.id)).scalar_one_or_none()
    if setting is None or setting.mode != "shadow":
        raise HTTPException(409, "Turn on email security for this customer first.")
    ratelimit.check(f"email-scan:{connection.id}", 4, 300)
    from time import monotonic

    with httpx.Client(timeout=20, follow_redirects=False) as client:
        result = email_scan.run_one(db, setting, email_scan.load_intel(db), client, monotonic() + 45)
    return {**result, "setting": email_scan.setting_view(db.get(EmailScanSetting, setting.id), connection)}


@router.get("/messages")
def messages(tenant_id: str | None = None, verdict: str = "", agreement: str = "", label: str = "", q: str = "",
             since: datetime | None = None, limit: int = Query(100, ge=1, le=500),
             principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    query = select(EmailScan).where(EmailScan.tenant_id.in_(scoped_tenant(principal, tenant_id)))
    if verdict == "flagged":
        query = query.where(EmailScan.verdict.in_(("phish", "malware")))
    elif verdict:
        query = query.where(EmailScan.verdict == verdict)
    if agreement:
        query = query.where(EmailScan.agreement == agreement)
    if label == "any":
        query = query.where(EmailScan.label != "")
    elif label:
        query = query.where(EmailScan.label == label)
    if since:
        query = query.where(EmailScan.received_at >= since.replace(tzinfo=None))
    if q.strip():
        like = f"%{q.strip()[:100]}%"
        query = query.where(or_(EmailScan.subject.ilike(like), EmailScan.sender_address.ilike(like),
                                EmailScan.mailbox.ilike(like), EmailScan.sender_domain.ilike(like)))
    rows = db.execute(query.order_by(EmailScan.received_at.desc()).limit(limit)).scalars().all()
    return [email_scan.scan_view(r) for r in rows]


@router.get("/messages/{scan_id}")
def message(scan_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    return email_scan.scan_view(owned(db, EmailScan, scan_id, principal), full=True)


@router.put("/messages/{scan_id}/label")
def set_label(scan_id: str, body: LabelIn, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """A technician's call on a message: what it really was. These labels are what a model is trained on later."""
    principal.require("respond")
    row = owned(db, EmailScan, scan_id, principal)
    email_scan.label(db, row, body.label, principal.actor)
    db.commit()
    return email_scan.scan_view(row, full=True)
