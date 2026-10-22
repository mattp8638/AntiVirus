"""DNS protection, threat intel, vulnerabilities, attack surface, compliance."""

from __future__ import annotations

from collections import Counter
from datetime import timedelta

import dns.exception
import httpx
from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Query, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit, compliance, dnsfilter, exposure, intel, services
from ..config import get_settings
from ..db import get_db, session_factory
from ..deps import Principal, current_principal, scoped_tenant
from ..models import Device, DnsQueryLog, ExternalAsset, Indicator, Tenant, Vulnerability, YaraRule, utcnow
from ..serialize import apply_fields, to_dict

router = APIRouter(tags=["Protection"])
console = APIRouter(prefix="/api/console", tags=["Protection"])

DNS_MESSAGE = "application/dns-message"


# --------------------------------------------------------------------------- DNS over HTTPS


def _dns_device(db: Session, token: str) -> Device:
    device = db.execute(select(Device).where(Device.dns_token == token)).scalar_one_or_none()
    if device is None or device.api_key_hash.startswith("retired-"):
        raise HTTPException(404, "Unknown resolver")
    return device


def _doh(db: Session, device: Device, wire: bytes) -> Response:
    settings = get_settings()
    resolution, _ = services.effective_policy(db, device)
    dns_settings = resolution["settings"]["dns"]
    if not dns_settings["enabled"]:
        dns_settings = {**dns_settings, "blockedCategories": [], "blockDomains": [], "mode": "observe", "logQueries": "none"}
    try:
        answer, decision = dnsfilter.resolve(db, device, wire, dns_settings, settings.dns_upstream, settings.dns_sinkhole_ipv4)
    except dns.exception.DNSException as exc:
        raise HTTPException(400, f"Malformed DNS message: {exc}") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"Upstream resolver failed: {exc}") from exc
    db.commit()
    return Response(content=answer, media_type=DNS_MESSAGE, headers={"Cache-Control": "max-age=30",
                                                                     "X-Fenrir-Dns-Action": decision.action})


@router.get("/dns/{token}/dns-query", include_in_schema=False)
def doh_get(token: str, dns_param: str = Query(alias="dns"), db: Session = Depends(get_db)):
    try:
        wire = dnsfilter.decode_get_param(dns_param)
    except ValueError as exc:
        raise HTTPException(400, "dns parameter is not base64url") from exc
    return _doh(db, _dns_device(db, token), wire)


@router.post("/dns/{token}/dns-query", include_in_schema=False)
async def doh_post(token: str, request: Request, db: Session = Depends(get_db)):
    if request.headers.get("content-type", "").split(";")[0] != DNS_MESSAGE:
        raise HTTPException(415, f"Content-Type must be {DNS_MESSAGE}")
    wire = await request.body()
    if len(wire) > 4096:
        raise HTTPException(413, "DNS message too large")
    return _doh(db, _dns_device(db, token), wire)


@console.get("/dns/check")
def dns_check(domain: str, device_id: str | None = None, tenant_id: str | None = None,
              principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Explain what DNS protection would do for a domain."""
    if device_id:
        device = db.get(Device, device_id)
        if device is None:
            raise HTTPException(404, "Not found")
        principal.check_tenant(device.tenant_id)
        resolution, _ = services.effective_policy(db, device)
        tid = device.tenant_id
    else:
        tid = scoped_tenant(principal, tenant_id)[0] if tenant_id else principal.user.tenant_id
        from ..policy_schema import resolve

        resolution = resolve(services.policy_layers(db, db.get(Tenant, tid)))
    decision = dnsfilter.decide(domain, resolution["settings"]["dns"], dnsfilter.INTEL.domains(db, tid))
    return {"domain": domain, "action": decision.action, "reason": decision.reason or "no match", "category": decision.category,
            "rewrite": decision.rewrite, "dgaScore": dnsfilter.looks_like_dga(domain.lower())}


@console.get("/dns/log")
def dns_log(tenant_id: str | None = None, action: str | None = None, hours: int = 24,
            principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    scope = scoped_tenant(principal, tenant_id)
    query = select(DnsQueryLog).where(DnsQueryLog.tenant_id.in_(scope), DnsQueryLog.at >= utcnow() - timedelta(hours=hours))
    if action:
        query = query.where(DnsQueryLog.action == action)
    rows = db.execute(query.order_by(DnsQueryLog.at.desc()).limit(1000)).scalars().all()
    categories = Counter(r.category for r in rows if r.action == "block")
    domains = Counter(r.qname for r in rows if r.action == "block")
    return {"entries": [to_dict(r) for r in rows], "topCategories": categories.most_common(10), "topDomains": domains.most_common(10)}


# --------------------------------------------------------------------------- threat intel


@console.get("/intel/lookup")
def intel_lookup(value: str, tenant_id: str | None = None, principal: Principal = Depends(current_principal),
                 db: Session = Depends(get_db)):
    tid = scoped_tenant(principal, tenant_id)[0] if tenant_id else principal.user.tenant_id
    try:
        result = intel.lookup(db, value, tid)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    # Where has this been seen in our own telemetry?
    from ..models import Event
    from sqlalchemy import cast, String

    seen = db.execute(select(Event.device_id, func.count()).where(Event.tenant_id.in_(principal.tenant_ids),
                                                                  cast(Event.fields, String).contains(result["indicator"]))
                      .group_by(Event.device_id).limit(50)).all()
    result["sightings"] = [{"deviceId": d, "events": c} for d, c in seen]
    return result


@console.get("/intel/indicators")
def list_indicators(tenant_id: str | None = None, q: str | None = None, source: str | None = None, limit: int = 500,
                    principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    scope = scoped_tenant(principal, tenant_id)
    query = select(Indicator).where((Indicator.tenant_id.in_(scope)) | (Indicator.tenant_id.is_(None)))
    if q:
        query = query.where(Indicator.value.contains(q.lower()))
    if source:
        query = query.where(Indicator.source.like(f"{source}%"))
    return {"stats": intel.stats(db), "items": [to_dict(i) for i in db.execute(query.order_by(Indicator.created_at.desc())
                                                                               .limit(min(limit, 5000))).scalars()]}


@console.post("/intel/indicators")
def add_indicators(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Add one or many indicators. Accepts {values: [...]} or a newline-separated {text}."""
    principal.require("configure")
    tenant_id = body.get("tenantId")
    principal.check_tenant(tenant_id)
    verdict = str(body.get("verdict") or "malicious")
    if verdict not in {"malicious", "suspicious", "allow"}:
        raise HTTPException(400, "verdict must be malicious, suspicious or allow")
    values = list(body.get("values") or []) + [line for line in str(body.get("text") or "").splitlines()]
    added, rejected = 0, []
    for value in values:
        value = value.strip()
        if not value or value.startswith("#"):
            continue
        try:
            kind = intel.classify(value)
        except ValueError as exc:
            rejected.append(str(exc))
            continue
        intel.upsert(db, kind, value, verdict, str(body.get("category") or "malware"), str(body.get("source") or "manual"),
                     tenant_id, int(body.get("confidence") or 80), str(body.get("description") or ""))
        added += 1
    audit.record(db, principal.actor, "intel.indicators.added", f"{added} indicators", tenant_id, verdict=verdict)
    db.commit()
    dnsfilter.INTEL.invalidate()
    return {"added": added, "rejected": rejected[:50]}


@console.delete("/intel/indicators/{indicator_id}")
def delete_indicator(indicator_id: int, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    row = db.get(Indicator, indicator_id)
    if row is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(row.tenant_id)
    db.delete(row)
    audit.record(db, principal.actor, "intel.indicator.deleted", row.value, row.tenant_id)
    db.commit()
    dnsfilter.INTEL.invalidate()
    return {"ok": True}


@console.post("/intel/sync")
def intel_sync(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("platform")
    settings = get_settings()
    try:
        result = intel.sync_feed(db, settings.feed_url, settings.feed_token)
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"Feed sync failed: {exc}") from exc
    audit.record(db, principal.actor, "intel.feed.synced", settings.feed_url, None, **result)
    db.commit()
    return result


@console.get("/intel/yara")
def list_yara(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.execute(select(YaraRule).where((YaraRule.tenant_id.is_(None)) | (YaraRule.tenant_id.in_(principal.tenant_ids)))
                      .order_by(YaraRule.name).limit(5000)).scalars().all()
    return [to_dict(r) for r in rows]


@console.post("/intel/yara")
def add_yara(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    tenant_id = body.get("tenantId")
    principal.check_tenant(tenant_id)
    source = str(body.get("source") or "")
    if "rule " not in source or "condition:" not in source:
        raise HTTPException(400, "That does not look like a YARA rule (needs 'rule' and 'condition:')")
    row = YaraRule(tenant_id=tenant_id, name=str(body.get("name") or "custom rule"), source=source, origin="custom")
    db.add(row)
    audit.record(db, principal.actor, "intel.yara.added", row.name, tenant_id)
    db.commit()
    return to_dict(row)


@console.get("/ml/model")
def ml_model_info(principal: Principal = Depends(current_principal)):
    from .. import mlmodel

    bundle = mlmodel.current()
    if bundle is None:
        return {"available": False}
    return {"available": True, "version": bundle.version, "sha256": bundle.sha256, "size": bundle.size, "metrics": bundle.metrics}


@console.post("/ml/score")
async def ml_score(request: Request, principal: Principal = Depends(current_principal)):
    """Score an uploaded file (raw request body, max 64 MB) with the static model. Nothing is stored."""
    from .. import mlmodel

    data = await request.body()
    if not data:
        raise HTTPException(400, "Send the file as the request body")
    if len(data) > 64 * 1024 * 1024:
        raise HTTPException(413, "File larger than 64 MB")
    return mlmodel.score_bytes(data)


# --------------------------------------------------------------------------- vulnerabilities


@console.get("/vulnerabilities")
def list_vulnerabilities(tenant_id: str | None = None, status: str | None = "open", severity: str | None = None,
                         principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    query = select(Vulnerability).where(Vulnerability.tenant_id.in_(scoped_tenant(principal, tenant_id)))
    if status:
        query = query.where(Vulnerability.status == status)
    if severity:
        query = query.where(Vulnerability.severity == severity)
    rows = db.execute(query.order_by(Vulnerability.known_exploited.desc(), Vulnerability.cvss.desc().nullslast())
                      .limit(5000)).scalars().all()
    hosts = dict(db.execute(select(Device.id, Device.hostname).where(Device.id.in_({v.device_id for v in rows}))).all())
    by_cve: dict[str, dict] = {}
    for v in rows:
        entry = by_cve.setdefault(v.vuln_id, {"vulnId": v.vuln_id, "severity": v.severity, "cvss": v.cvss,
                                              "knownExploited": v.known_exploited, "summary": v.summary, "packages": set(),
                                              "fixedVersion": v.fixed_version, "devices": []})
        entry["packages"].add(v.package)
        entry["devices"].append({"deviceId": v.device_id, "hostname": hosts.get(v.device_id, ""), "installed": v.installed_version,
                                 "id": v.id, "status": v.status})
    out = sorted(by_cve.values(), key=lambda e: (not e["knownExploited"], -(e["cvss"] or 0), -len(e["devices"])))
    for entry in out:
        entry["packages"] = sorted(entry["packages"])
        entry["priority"] = ("P1" if entry["knownExploited"] else "P2" if entry["severity"] == "critical"
                             else "P3" if entry["severity"] == "high" else "P4")
    return out


@console.patch("/vulnerabilities/{vuln_pk}")
def update_vulnerability(vuln_pk: int, body: dict = Body(...), principal: Principal = Depends(current_principal),
                         db: Session = Depends(get_db)):
    principal.require("respond")
    row = db.get(Vulnerability, vuln_pk)
    if row is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(row.tenant_id)
    if body.get("status") not in {"open", "patching", "mitigated", "accepted", "fixed"}:
        raise HTTPException(400, "invalid status")
    row.status = body["status"]
    audit.record(db, principal.actor, "vulnerability.status", f"{row.vuln_id}@{row.device_id}", row.tenant_id, status=row.status,
                 reason=str(body.get("reason") or ""))
    db.commit()
    return to_dict(row)


def _scan_devices_job(device_ids: list[str]) -> None:
    db = session_factory()()
    try:
        for device_id in device_ids:
            device = db.get(Device, device_id)
            if device is not None:
                try:
                    exposure.scan_device(db, device)
                    db.commit()
                except httpx.HTTPError as exc:  # pragma: no cover - network dependent
                    db.rollback()
                    services.log.warning("vulnerability scan of %s failed: %s", device_id, exc)
    finally:
        db.close()


@console.post("/vulnerabilities/scan")
def scan_vulnerabilities(background: BackgroundTasks, body: dict = Body(default={}), principal: Principal = Depends(current_principal),
                         db: Session = Depends(get_db)):
    principal.require("respond")
    scope = scoped_tenant(principal, body.get("tenantId"))
    query = select(Device.id).where(Device.tenant_id.in_(scope))
    if body.get("deviceId"):
        query = query.where(Device.id == body["deviceId"])
    ids = [row[0] for row in db.execute(query).all()]
    background.add_task(_scan_devices_job, ids)
    return {"queued": len(ids)}


# --------------------------------------------------------------------------- attack surface


@console.get("/exposure/assets")
def list_assets(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.execute(select(ExternalAsset).where(ExternalAsset.tenant_id.in_(scoped_tenant(principal, tenant_id)))).scalars().all()
    return [to_dict(r) for r in rows]


@console.post("/exposure/assets")
def add_asset(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    tenant_id = body.get("tenantId")
    principal.check_tenant(tenant_id)
    if body.get("ownershipConfirmed") is not True:
        raise HTTPException(400, "Confirm you own or are authorised to scan this asset (ownershipConfirmed: true)")
    target = str(body.get("target") or "").strip().lower()
    if not target or "/" in target or " " in target:
        raise HTTPException(400, "target must be a single hostname or IP address")
    row = ExternalAsset(tenant_id=tenant_id, target=target, label=str(body.get("label") or ""), ownership_attested_by=principal.actor)
    db.add(row)
    audit.record(db, principal.actor, "exposure.asset.added", target, tenant_id, attested=True)
    db.commit()
    return to_dict(row)


def _scan_asset_job(asset_id: str) -> None:
    db = session_factory()()
    try:
        asset = db.get(ExternalAsset, asset_id)
        if asset is None:
            return
        asset.last_result = exposure.scan_external(asset)
        asset.last_scan_at = utcnow()
        db.commit()
    finally:
        db.close()


@console.post("/exposure/assets/{asset_id}/scan")
def scan_asset(asset_id: str, background: BackgroundTasks, principal: Principal = Depends(current_principal),
               db: Session = Depends(get_db)):
    principal.require("respond")
    asset = db.get(ExternalAsset, asset_id)
    if asset is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(asset.tenant_id)
    background.add_task(_scan_asset_job, asset.id)
    audit.record(db, principal.actor, "exposure.asset.scanned", asset.target, asset.tenant_id)
    db.commit()
    return {"queued": True}


# --------------------------------------------------------------------------- compliance


@console.get("/compliance")
def compliance_report(tenant_id: str | None = None, framework: str | None = None,
                      principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    tid = tenant_id or principal.user.tenant_id
    principal.check_tenant(tid)
    tenant = db.get(Tenant, tid)
    return {"tenant": tenant.name, "frameworks": compliance.evaluate(db, tenant, framework)}
