"""Firewall and router configuration assessment from an uploaded export (VULN-13)."""
from __future__ import annotations

import base64
import binascii

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import firewall_config as fw, ratelimit
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import FirewallAssessment
from ..serialize import to_dict

router = APIRouter(prefix="/api/console/firewall-assessments", tags=["Firewall configuration assessment"])


@router.get("/capabilities")
def capabilities(principal: Principal = Depends(current_principal)):
    principal.require("read")
    return {"vendors": fw.CAPABILITIES, "checks": fw.CHECKS, "unsupported": fw.UNSUPPORTED_NOTE}


class Upload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str
    label: str = Field(default="", max_length=200)
    firmware: str = Field(default="", max_length=40)
    minimumFirmware: str = Field(default="", max_length=40)
    contentBase64: str = Field(max_length=fw.MAX_SIZE * 4 // 3 + 8)


@router.post("")
def upload(body: Upload, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Assess an exported configuration. The file is read in memory and never stored (it holds password hashes and keys)."""
    principal.require("configure")
    principal.check_tenant(body.tenantId)
    ratelimit.check(f"firewall-assessment:{principal.user.id}", 20, 3600)
    try:
        data = base64.b64decode(body.contentBase64, validate=True)
        row = fw.run(db, body.tenantId, body.label, data, body.firmware.strip(), body.minimumFirmware.strip(), principal.actor)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(400, str(exc) if isinstance(exc, fw.ConfigFormatError) else "The file could not be decoded") from None
    db.commit()
    return to_dict(row)


@router.get("")
def list_(tenantId: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    principal.check_tenant(tenantId)
    rows = db.scalars(select(FirewallAssessment).where(FirewallAssessment.tenant_id == tenantId)
                      .order_by(FirewallAssessment.created_at.desc()).limit(200))
    return [to_dict(r) for r in rows]
