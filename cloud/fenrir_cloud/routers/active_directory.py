"""Active Directory per customer: domains found from domain controllers' agents, findings, privileged groups,
risky accounts, recent directory changes and AD alerts."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import activedirectory
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant

router = APIRouter(prefix="/api/console/ad", tags=["Active Directory"])


def _summary(entry: dict) -> dict:
    ad = entry.get("snapshot") or {}
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in entry["findings"]:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return {"tenantId": entry["tenantId"], "domain": entry["domain"], "netbios": (ad.get("domain") or {}).get("netbios"),
            "forest": (ad.get("domain") or {}).get("forest"), "mode": (ad.get("domain") or {}).get("mode"),
            "score": entry["score"], "findings": counts, "snapshotAt": entry["snapshotAt"], "counts": ad.get("counts") or {},
            "domainControllers": len(ad.get("domainControllers") or []), "agents": entry["agents"]}


@router.get("/domains")
def list_domains(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    return [_summary(e) for e in activedirectory.domains(db, scoped_tenant(principal, tenant_id))]


@router.get("/domains/{tenant_id}/{domain}")
def domain_detail(tenant_id: str, domain: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    principal.check_tenant(tenant_id)
    entry = next((e for e in activedirectory.domains(db, [tenant_id]) if e["domain"] == domain.lower()), None)
    if entry is None:
        raise HTTPException(404, "Domain not found")
    device_ids = [a["deviceId"] for a in entry["agents"]]
    ad = entry.get("snapshot") or {}
    enrolled = {a["hostname"].split(".")[0].upper(): a for a in entry["agents"]}
    controllers = [{**dc, "agent": enrolled.get(str(dc.get("name") or "").split(".")[0].upper())}
                   for dc in ad.get("domainControllers") or [] if isinstance(dc, dict)]
    return {**_summary(entry), "domainInfo": ad.get("domain") or {}, "controllers": controllers,
            "privilegedGroups": ad.get("privilegedGroups") or [], "passwordPolicy": ad.get("passwordPolicy") or {},
            "krbtgt": ad.get("krbtgt") or {}, "laps": ad.get("laps") or {}, "recycleBin": ad.get("recycleBin"),
            "risky": ad.get("risky") or {}, "gpos": (ad.get("gpos") or [])[:100], "trusts": ad.get("trusts") or [],
            "auditPolicy": entry.get("auditPolicy") or [], "findingsList": entry["findings"],
            "activity": activedirectory.recent_activity(db, tenant_id, device_ids),
            "alerts": activedirectory.alerts(db, tenant_id, device_ids)}
