"""Sign-in protection settings and findings for a customer's Microsoft 365 (m365_signin_security.py)."""
from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, m365_signin_security as protection
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import Alert, Tenant

router = APIRouter(prefix="/api/console/m365/signin-protection", tags=["Microsoft 365 sign-in protection"])


class Playbook(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revokeSessions: bool = True
    blockSignIn: bool = False
    openTicket: bool = True
    notifyEmail: str = Field(default="", max_length=254, pattern=r"^$|^[^@\s]+@[^@\s]+\.[^@\s]+$")


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str
    enabled: bool = False
    maxSpeedKmh: int = Field(default=900, ge=200, le=5000)
    minDistanceKm: int = Field(default=500, ge=50, le=10000)
    newCountry: bool = True
    sprayFailures: int = Field(default=10, ge=3, le=500)
    trustedCountries: list[str] = Field(default_factory=list, max_length=100)
    ignoreNetworks: list[str] = Field(default_factory=list, max_length=200)
    playbook: Playbook = Field(default_factory=Playbook)

    @field_validator("trustedCountries")
    @classmethod
    def countries(cls, value: list[str]) -> list[str]:
        out = [v.strip().upper() for v in value if v.strip()]
        if any(len(c) != 2 or not c.isalpha() for c in out):
            raise ValueError("Countries are two-letter codes, such as GB or US")
        return out

    @field_validator("ignoreNetworks")
    @classmethod
    def networks(cls, value: list[str]) -> list[str]:
        out = []
        for item in value:
            item = item.strip()
            if not item:
                continue
            try:
                out.append(str(ipaddress.ip_network(item, strict=False)))
            except ValueError:
                raise ValueError(f"'{item}' is not an IP address or range") from None
        return out


@router.get("")
def get_settings(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    principal.check_tenant(tenant_id)
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "Not found")
    findings = db.execute(select(Alert).where(Alert.tenant_id == tenant_id, Alert.rule_id.like("m365:%"))
                          .order_by(Alert.created_at.desc()).limit(100)).scalars().all()
    return {"settings": protection.settings_for(tenant),
            "findings": [{"id": a.id, "title": a.title, "severity": a.severity, "status": a.status, "at": a.created_at.isoformat() + "Z",
                          "kind": a.rule_id.removeprefix("m365:"), "summary": (a.details or {}).get("summary"),
                          "actions": (a.details or {}).get("actions") or []} for a in findings]}


@router.put("")
def put_settings(body: Settings, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("m365_admin")
    principal.check_tenant(body.tenantId)
    tenant = db.get(Tenant, body.tenantId)
    if tenant is None:
        raise HTTPException(404, "Not found")
    value = body.model_dump(exclude={"tenantId"})
    tenant.settings = {**(tenant.settings or {}), "signinProtection": value}
    audit.record(db, principal.actor, "m365.signin_protection.updated", tenant.name, tenant.id, enabled=value["enabled"],
                 playbook=value["playbook"])
    db.commit()
    return protection.settings_for(tenant)
