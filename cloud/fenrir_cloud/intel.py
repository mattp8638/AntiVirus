"""Threat intelligence: upstream feed sync, agent bundles, reputation lookups."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime

import httpx
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from .models import Indicator, YaraRule, utcnow

log = logging.getLogger("fenrir.intel")

HEX = {"md5": 32, "sha1": 40, "sha256": 64}


def classify(value: str) -> str:
    value = value.strip()
    lowered = value.lower()
    for kind, length in HEX.items():
        if len(lowered) == length and re.fullmatch(r"[0-9a-f]+", lowered):
            return kind
    if re.match(r"^[a-z][a-z0-9+.-]*://", lowered):
        return "url"
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", lowered) or ":" in lowered and re.fullmatch(r"[0-9a-f:]+", lowered):
        return "ip"
    if re.fullmatch(r"(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}", lowered.rstrip(".")):
        return "domain"
    raise ValueError(f"cannot tell what kind of indicator '{value[:80]}' is")


def normalise_value(kind: str, value: str) -> str:
    value = value.strip()
    if kind in HEX or kind == "domain":
        return value.lower().rstrip(".")
    return value


def _not_expired():
    return or_(Indicator.expires_at.is_(None), Indicator.expires_at > utcnow())


def lookup(db: Session, value: str, tenant_id: str | None) -> dict:
    kind = classify(value)
    value = normalise_value(kind, value)
    candidates = [value]
    if kind == "url":
        match = re.match(r"^[a-z]+://([^/:?#]+)", value.lower())
        if match:
            candidates.append(match.group(1))
    if kind in {"domain", "url"}:
        host = candidates[-1]
        parts = host.split(".")
        candidates += [".".join(parts[i:]) for i in range(1, len(parts) - 1)]
    rows = db.execute(
        select(Indicator).where(Indicator.value.in_(candidates), _not_expired(),
                                or_(Indicator.tenant_id.is_(None), Indicator.tenant_id == tenant_id))
    ).scalars().all()
    # Tenant entries beat global ones; allow beats malicious within the same scope.
    rows.sort(key=lambda r: (r.tenant_id is None, r.verdict != "allow", -r.confidence))
    top = rows[0] if rows else None
    verdict = top.verdict if top else "unknown"
    score = {"malicious": 95, "suspicious": 60, "allow": 0}.get(verdict, 10)
    return {
        "indicator": value, "type": kind, "verdict": verdict, "score": score,
        "category": top.category if top else "", "source": top.source if top else "",
        "matches": [{"value": r.value, "verdict": r.verdict, "source": r.source, "category": r.category,
                     "scope": "tenant" if r.tenant_id else "global"} for r in rows[:10]],
    }


def upsert(db: Session, kind: str, value: str, verdict: str = "malicious", category: str = "malware", source: str = "manual",
           tenant_id: str | None = None, confidence: int = 80, description: str = "", expires_at: datetime | None = None) -> Indicator:
    value = normalise_value(kind, value)
    row = db.execute(select(Indicator).where(Indicator.type == kind, Indicator.value == value,
                                             Indicator.tenant_id.is_(None) if tenant_id is None else Indicator.tenant_id == tenant_id,
                                             Indicator.source == source)).scalar_one_or_none()
    if row is None:
        row = Indicator(type=kind, value=value, tenant_id=tenant_id, source=source)
        db.add(row)
    row.verdict, row.category, row.confidence, row.description, row.expires_at = verdict, category, confidence, description, expires_at
    return row


# ---------------------------------------------------------------------------
# Upstream feed (signaturedb-fenrir worker)
# ---------------------------------------------------------------------------

FEED_SOURCE = "signaturedb-fenrir"


def sync_feed(db: Session, base_url: str, token: str = "", client: httpx.Client | None = None) -> dict:
    """Pull the worker's bundle and replace the global feed indicators and YARA rules."""
    own = client is None
    client = client or httpx.Client(timeout=60)
    try:
        headers = {"X-Fenrir-Token": token} if token else {}
        response = client.get(base_url.rstrip("/") + "/api/v1/agent/bundle", headers=headers)
        response.raise_for_status()
        bundle = response.json()
    finally:
        if own:
            client.close()

    db.execute(delete(Indicator).where(Indicator.source.like(f"{FEED_SOURCE}%"), Indicator.tenant_id.is_(None)))
    hashes = urls = rules = 0
    for item in bundle.get("hashes") or []:
        kind = str(item.get("type", "sha256")).lower()
        value = str(item.get("value", "")).lower()
        if kind in HEX and len(value) == HEX[kind]:
            db.add(Indicator(type=kind, value=value, verdict="malicious", category="malware",
                             source=f"{FEED_SOURCE}:{item.get('source', 'feed')}", confidence=90,
                             description=str(item.get("malwareFamily") or "")))
            hashes += 1
    for item in bundle.get("urls") or []:
        url = str(item.get("url", ""))
        if url:
            db.add(Indicator(type="url", value=url, verdict="malicious", category="malware",
                             source=f"{FEED_SOURCE}:{item.get('source', 'urlhaus')}", confidence=85,
                             description=str(item.get("threat") or "")))
            urls += 1
    db.execute(delete(YaraRule).where(YaraRule.origin == FEED_SOURCE))
    for item in bundle.get("rules") or []:
        if str(item.get("ruleType", "")).lower() == "yara" and item.get("content"):
            db.add(YaraRule(name=str(item.get("name") or item.get("id") or "feed-rule")[:200], source=str(item["content"]),
                            origin=FEED_SOURCE))
            rules += 1
    db.commit()
    from .dnsfilter import INTEL

    INTEL.invalidate()
    summary = bundle.get("summary") or {}
    return {"version": summary.get("version", ""), "hashes": hashes, "urls": urls, "yaraRules": rules, "syncedAt": utcnow().isoformat()}


# ---------------------------------------------------------------------------
# Agent bundle (the format the Windows ControlPlaneClient parses)
# ---------------------------------------------------------------------------


PUA_CATEGORIES = {"pua", "pup", "adware", "riskware", "grayware"}
_PUA_NAME = re.compile(r"(?i)(^|[^a-z])(pua|pup|adware|riskware|not-a-virus|grayware|toolbar|bundler|browsermodifier)([^a-z]|$)")


def is_pua(category: str | None, family: str | None) -> bool:
    """Potentially unwanted applications: by indicator category, or by the usual vendor naming (PUA:, Adware., not-a-virus:)."""
    return (category or "").lower() in PUA_CATEGORIES or bool(_PUA_NAME.search(family or ""))


def agent_bundle(db: Session, tenant_id: str | None, hashes_limit: int = 50000, urls_limit: int = 50000, rules_limit: int = 5000) -> dict:
    scope = or_(Indicator.tenant_id.is_(None), Indicator.tenant_id == tenant_id) if tenant_id else Indicator.tenant_id.is_(None)
    hash_rows = db.execute(
        select(Indicator).where(scope, Indicator.type.in_(tuple(HEX)), Indicator.verdict == "malicious", _not_expired())
        .order_by(Indicator.created_at.desc()).limit(hashes_limit)
    ).scalars().all()
    url_rows = db.execute(
        select(Indicator).where(scope, Indicator.type.in_(("url", "domain")), Indicator.verdict == "malicious", _not_expired())
        .order_by(Indicator.created_at.desc()).limit(urls_limit)
    ).scalars().all()
    rule_scope = or_(YaraRule.tenant_id.is_(None), YaraRule.tenant_id == tenant_id) if tenant_id else YaraRule.tenant_id.is_(None)
    yara_rows = db.execute(select(YaraRule).where(rule_scope, YaraRule.enabled.is_(True)).limit(rules_limit)).scalars().all()
    allow_rows = db.execute(select(Indicator).where(scope, Indicator.verdict == "allow", Indicator.type == "sha256")).scalars().all()

    hashes = [{"id": f"ind-{r.id}", "type": r.type, "value": r.value, "malwareFamily": r.description, "source": r.source,
               "category": "pua" if is_pua(r.category, r.description) else "malware",
               "firstSeen": r.created_at.isoformat()} for r in hash_rows]
    urls = []
    for r in url_rows:
        url = r.value if r.type == "url" else f"http://{r.value}/"
        host = re.sub(r"^[a-z]+://", "", url.lower()).split("/")[0]
        urls.append({"id": f"ind-{r.id}", "url": url, "host": host, "status": "online", "threat": r.category, "source": r.source,
                     "firstSeen": r.created_at.isoformat()})
    rules = [{"id": r.id, "ruleType": "yara", "name": r.name, "content": r.source, "source": r.origin} for r in yara_rows]

    digest = hashlib.sha256()
    for part in (hashes, urls, rules):
        digest.update(json.dumps([x["id"] if "id" in x else x for x in part], sort_keys=True).encode())
    version = digest.hexdigest()[:16]
    yara_version = hashlib.sha256("".join(r["content"] for r in rules).encode()).hexdigest()[:16]
    return {
        "checkedAt": utcnow().isoformat() + "Z",
        "signatureVersion": version,
        "version": version,
        "yaraVersion": yara_version,
        "hashes": hashes,
        "urls": urls,
        "rules": rules,
        "yaraRules": [r["content"] for r in rules],
        "allowSha256": [r.value for r in allow_rows],
        "summary": {"version": version, "counts": {"hashes": len(hashes), "urls": len(urls), "rules": len(rules)}},
    }


def stats(db: Session) -> dict:
    rows = db.execute(select(Indicator.type, Indicator.verdict, func.count()).group_by(Indicator.type, Indicator.verdict)).all()
    yara = db.execute(select(func.count()).select_from(YaraRule)).scalar() or 0
    return {"indicators": [{"type": t, "verdict": v, "count": c} for t, v, c in rows], "yaraRules": yara}


# ---------------------------------------------------------------------------
# High-Efficacy External DNS Blocklists (HaGeZi, Spydi/ThreatCull, OISD)
# ---------------------------------------------------------------------------

EXTERNAL_BLOCKLIST_SOURCES = {
    "hagezi-tif": {
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt",
        "category": "malware",
        "description": "HaGeZi Threat Intelligence Feed (TIF) - Malware, C2, Phishing, Cryptojacking",
    },
    "hagezi-multi-pro": {
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt",
        "category": "ads-trackers",
        "description": "HaGeZi Multi PRO - Balanced ad, tracker and malware blocklist",
    },
    "spydi-threatcull": {
        "url": "https://raw.githubusercontent.com/Spydi/ThreatIntel/main/domains.txt",
        "category": "malware",
        "description": "Spydi ThreatIntel / ThreatCull Honeypot & C2 tracker feed",
    },
    "oisd-big": {
        "url": "https://big.oisd.nl/domainswild",
        "category": "ads-trackers",
        "description": "OISD Big - Zero-breakage comprehensive blocklist",
    },
}


def parse_raw_blocklist(content: str) -> list[str]:
    """Parse raw text/Hosts/AdBlock format blocklist content and extract clean domains."""
    domains = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!", ";", "//")):
            continue
        if line.startswith("||") and line.endswith("^"):
            line = line[2:-1]
        parts = line.split()
        if len(parts) >= 2 and parts[0] in {"0.0.0.0", "127.0.0.1"}:
            domain = parts[1].strip()
        else:
            domain = parts[0].strip()

        domain = domain.lower().rstrip(".")
        if domain and not domain.startswith("#") and "." in domain:
            domains.add(domain)

    return sorted(domains)


def sync_external_blocklist_feed(
    db: Session,
    source_key: str,
    raw_content: str,
    category: str = "malware",
    tenant_id: str | None = None,
) -> int:
    """Import domain blocklist into Indicator database with deduplication."""
    domains = parse_raw_blocklist(raw_content)
    imported_count = 0

    for domain in domains:
        upsert(
            db=db,
            kind="domain",
            value=domain,
            verdict="malicious",
            category=category,
            source=source_key,
            tenant_id=tenant_id,
            confidence=85,
            description=f"Imported from {source_key}",
        )
        imported_count += 1

    return imported_count
