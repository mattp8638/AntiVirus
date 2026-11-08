"""MSP branding (branding.py): the public brand for the sign-in page, and the MSP's settings and logo."""

from __future__ import annotations

import base64
import binascii

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from .. import audit, branding
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import Tenant

router = APIRouter(prefix="/api/console", tags=["Branding"])


@router.get("/auth/branding")
def public_branding(db: Session = Depends(get_db)):
    """Name, colours and logo for the sign-in page (no contact details): needs no sign-in."""
    return branding.public(branding.get(db))


@router.get("/auth/branding/logo")
def public_logo(db: Session = Depends(get_db)):
    data = branding.logo_bytes(branding.get(db))
    if not data:
        raise HTTPException(404, "No logo")
    return Response(data, media_type="image/png", headers={"Cache-Control": "public, max-age=3600",
                                                           "X-Content-Type-Options": "nosniff"})


def _msp(db: Session, principal: Principal) -> Tenant:
    msp = branding.msp_of(db, principal.user.tenant_id)
    if msp is None:
        raise HTTPException(404, "Not found")
    return msp


@router.get("/branding")
def get_branding(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The brand that applies to the signed-in user (their MSP's), with contact details."""
    principal.require("read")
    brand = branding.get(db, msp=_msp(db, principal))
    return {**{k: v for k, v in brand.items() if k != "logo"}, **branding.public(brand),
            "logoUrl": f"/api/console/branding/logo?v={brand['logoVersion']}" if brand["logo"] else None,
            # Inline copy for the settings page: an <img> cannot send the sign-in token the logo URL needs.
            "logoDataUrl": f"data:image/png;base64,{brand['logo']}" if brand["logo"] else None,
            "editable": principal.can("manage_tenants") and branding.msp_of(db, principal.user.tenant_id) is not None
            and principal.user.tenant_id == _msp(db, principal).id}


@router.get("/branding/logo")
def get_logo(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    data = branding.logo_bytes(branding.get(db, msp=_msp(db, principal)))
    if not data:
        raise HTTPException(404, "No logo")
    return Response(data, media_type="image/png", headers={"Cache-Control": "private, max-age=3600",
                                                           "X-Content-Type-Options": "nosniff"})


def _editable_msp(db: Session, principal: Principal) -> Tenant:
    principal.require("manage_tenants")
    msp = _msp(db, principal)
    if principal.user.tenant_id != msp.id:
        raise HTTPException(403, "Only the MSP's own staff can change its branding")
    return msp


@router.put("/branding")
def put_branding(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    msp = _editable_msp(db, principal)
    try:
        values = branding.validate(body)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    branding.save(msp, values)
    audit.record(db, principal.actor, "branding.updated", msp.name, msp.id, fields=sorted(values))
    db.commit()
    return get_branding(principal, db)


@router.put("/branding/logo")
def put_logo(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Upload a logo as base64 (``{"data": "..."}``); a data: URL prefix is accepted. PNG or JPEG, at most 2 MB."""
    msp = _editable_msp(db, principal)
    raw = body.get("data")
    if not isinstance(raw, str) or not raw:
        raise HTTPException(400, "Send the logo as base64 in data")
    if raw.startswith("data:"):
        raw = raw.partition(",")[2]
    if len(raw) > branding.MAX_UPLOAD * 4 // 3 + 8:
        raise HTTPException(400, "The logo must be at most 2 MB")
    try:
        data = base64.b64decode(raw, validate=True)
        logo = branding.normalise_logo(data)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(400, str(exc) if isinstance(exc, ValueError) and not isinstance(exc, binascii.Error)
                            else "The logo is not valid base64") from None
    branding.save(msp, {"logo": logo})
    audit.record(db, principal.actor, "branding.logo_updated", msp.name, msp.id)
    db.commit()
    return get_branding(principal, db)


@router.delete("/branding/logo")
def delete_logo(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    msp = _editable_msp(db, principal)
    branding.save(msp, {"logo": None})
    audit.record(db, principal.actor, "branding.logo_removed", msp.name, msp.id)
    db.commit()
    return get_branding(principal, db)
