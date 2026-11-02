import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter()

FEED_DIR = Path("data") / "feeds"
FEED_STATE_FILE = FEED_DIR / "threat-feed-bundle.json"
FEED_DIR.mkdir(parents=True, exist_ok=True)

class HashIndicator(BaseModel):
    id: str
    source: str
    type: str
    value: str
    malware_family: Optional[str] = None
    first_seen: Optional[str] = None
    reporter: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

class UrlIndicator(BaseModel):
    id: str
    source: str
    url: str
    host: Optional[str] = None
    status: Optional[str] = None
    threat: Optional[str] = None
    first_seen: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

class FeedRule(BaseModel):
    id: str
    source: str
    rule_type: str
    name: str
    content: str
    sha256: str
    updated_at: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

class FeedBundle(BaseModel):
    version: str
    generated_at: str
    status: str
    hashes: List[HashIndicator] = Field(default_factory=list)
    urls: List[UrlIndicator] = Field(default_factory=list)
    rules: List[FeedRule] = Field(default_factory=list)
    sources: List[Dict[str, Any]] = Field(default_factory=list)

class LocalFeedImportRequest(BaseModel):
    source: str = "local"
    hashes: List[Dict[str, Any]] = Field(default_factory=list)
    urls: List[Dict[str, Any]] = Field(default_factory=list)
    rules: List[Dict[str, Any]] = Field(default_factory=list)


def now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def host_from_url(value: str) -> Optional[str]:
    try:
        return urlparse(value).hostname
    except Exception:
        return None


def load_bundle() -> FeedBundle:
    if not FEED_STATE_FILE.exists():
        return FeedBundle(version="bootstrap", generated_at=now(), status="empty")
    try:
        return FeedBundle(**json.loads(FEED_STATE_FILE.read_text(encoding="utf-8")))
    except Exception:
        return FeedBundle(version="recovered", generated_at=now(), status="degraded")


def save_bundle(bundle: FeedBundle) -> FeedBundle:
    material = json.dumps({"hashes": [item.id for item in bundle.hashes], "urls": [item.id for item in bundle.urls], "rules": [item.sha256 for item in bundle.rules]}, sort_keys=True)
    bundle.version = sha256(material)[:24]
    bundle.generated_at = now()
    bundle.status = "ready" if (bundle.hashes or bundle.urls or bundle.rules) else "empty"
    FEED_STATE_FILE.write_text(bundle.model_dump_json(indent=2), encoding="utf-8")
    return bundle


def dedupe_by_id(items):
    merged = {}
    for item in items:
        merged[item.id] = item
    return list(merged.values())


def normalise_hash(raw: Dict[str, Any], source: str) -> Optional[HashIndicator]:
    value = str(raw.get("value") or raw.get("sha256") or raw.get("sha256_hash") or raw.get("sha1") or raw.get("md5") or "").strip().lower()
    if not value:
        return None
    hash_type = raw.get("type") or ("sha256" if len(value) == 64 else "sha1" if len(value) == 40 else "md5" if len(value) == 32 else "unknown")
    return HashIndicator(
        id=str(raw.get("id") or f"{source}:{hash_type}:{value}"),
        source=source,
        type=hash_type,
        value=value,
        malware_family=raw.get("malware_family") or raw.get("malwareFamily") or raw.get("signature"),
        first_seen=raw.get("first_seen") or raw.get("firstSeen"),
        reporter=raw.get("reporter"),
        tags=list(raw.get("tags") or []),
    )


def normalise_url(raw: Dict[str, Any], source: str) -> Optional[UrlIndicator]:
    url = str(raw.get("url") or "").strip()
    if not url:
        return None
    return UrlIndicator(
        id=str(raw.get("id") or f"{source}:url:{sha256(url)}"),
        source=source,
        url=url,
        host=raw.get("host") or host_from_url(url),
        status=raw.get("status") or raw.get("url_status"),
        threat=raw.get("threat") or raw.get("signature"),
        first_seen=raw.get("first_seen") or raw.get("firstSeen") or raw.get("date_added"),
        tags=list(raw.get("tags") or []),
    )


def normalise_rule(raw: Dict[str, Any], source: str) -> Optional[FeedRule]:
    content = str(raw.get("content") or raw.get("rule") or raw.get("yara_rule") or "").strip()
    if not content:
        return None
    rule_type = str(raw.get("rule_type") or raw.get("ruleType") or "yara").lower()
    digest = sha256(content)
    return FeedRule(
        id=str(raw.get("id") or f"{source}:{rule_type}:{digest[:16]}"),
        source=source,
        rule_type=rule_type,
        name=str(raw.get("name") or raw.get("rule_name") or f"{source}-{rule_type}-{digest[:8]}"),
        content=content,
        sha256=digest,
        updated_at=raw.get("updated_at") or raw.get("updatedAt") or now(),
        tags=list(raw.get("tags") or []),
    )


@router.get("/summary")
def summary():
    bundle = load_bundle()
    return {
        "status": bundle.status,
        "version": bundle.version,
        "generated_at": bundle.generated_at,
        "counts": {
            "hashes": len(bundle.hashes),
            "urls": len(bundle.urls),
            "rules": len(bundle.rules),
            "yara_rules": len([rule for rule in bundle.rules if rule.rule_type == "yara"]),
            "suricata_rules": len([rule for rule in bundle.rules if rule.rule_type == "suricata"]),
            "clamav_rules": len([rule for rule in bundle.rules if rule.rule_type == "clamav"]),
        },
        "sources": bundle.sources,
        "state_file": str(FEED_STATE_FILE),
    }


@router.get("/bundle")
def bundle(hashes_limit: int = 500, urls_limit: int = 500, rules_limit: int = 200):
    current = load_bundle()
    return {
        "summary": summary(),
        "hashes": [item.model_dump() for item in current.hashes[:hashes_limit]],
        "urls": [item.model_dump() for item in current.urls[:urls_limit]],
        "rules": [item.model_dump() for item in current.rules[:rules_limit]],
    }


@router.post("/import/local")
def import_local(request: LocalFeedImportRequest):
    current = load_bundle()
    hashes = [normalise_hash(item, request.source) for item in request.hashes]
    urls = [normalise_url(item, request.source) for item in request.urls]
    rules = [normalise_rule(item, request.source) for item in request.rules]
    current.hashes = dedupe_by_id(current.hashes + [item for item in hashes if item])
    current.urls = dedupe_by_id(current.urls + [item for item in urls if item])
    current.rules = dedupe_by_id(current.rules + [item for item in rules if item])
    current.sources.append({"name": request.source, "enabled": True, "lastSuccessAt": now(), "fetchedItems": len(request.hashes) + len(request.urls) + len(request.rules)})
    saved = save_bundle(current)
    return {"status": "imported", "summary": summary(), "version": saved.version}


@router.get("/lookup")
def lookup(value: str):
    current = load_bundle()
    raw = value.strip().lower()
    hash_hits = [item.model_dump() for item in current.hashes if item.value.lower() == raw]
    url_hits = [item.model_dump() for item in current.urls if item.url.lower() == raw or (item.host and item.host.lower() == raw)]
    return {
        "status": "match" if hash_hits or url_hits else "no_match",
        "value": value,
        "hash_matches": hash_hits,
        "url_matches": url_hits,
        "match_count": len(hash_hits) + len(url_hits),
    }


@router.post("/sync/upstream")
def sync_upstream_placeholder():
    return {
        "status": "not_configured",
        "message": "The Python feed aggregator schema is imported. Upstream sync can now be wired using MalwareBazaar, URLhaus and YARAify credentials.",
        "expected_env": ["FENRIR_MALWARE_BAZAAR_AUTH_KEY", "FENRIR_URLHAUS_AUTH_KEY", "FENRIR_YARAIFY_AUTH_KEY", "FENRIR_SURICATA_URL", "FENRIR_CLAMAV_URL"],
    }
