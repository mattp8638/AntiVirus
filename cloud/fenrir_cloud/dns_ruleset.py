"""The Fenrir DNS ruleset: one list built from every feed and threat intel, scored by agreement.

A single feed is someone else's opinion. The ruleset combines them: each source that names a domain adds its weight,
so a domain on three independent lists (or confirmed by threat intel) scores higher than one on a single list.

- **Sources**: the external blocklists (HaGeZi, OISD, custom lists) with a weight each, plus Fenrir's threat intel
  (malicious domain indicators, global and from the feeds the server pulls).
- **Score** = the sum of the weights of the sources that list the domain or one of its parents, capped at 100.
- **Block threshold**: at or above it, the ruleset blocks (for malware-type categories always, for other categories
  where the policy blocks that category). **Monitor threshold**: kept and logged, never blocked.
- **Protected domains** (Microsoft, Apple, Google, certificate authorities, the Fenrir server...) are never in the
  ruleset, so a bad feed update cannot break sign-in or updates.
- Each build is versioned with statistics and the difference from the build before it (domains added and removed,
  with samples); any earlier build can be made active again. Builds run after the feeds refresh and on demand.

Policies choose how it is used (``dns.fenrirRuleset``: off / monitor / block) and whether the external lists still
block on their own or only through the ruleset (``dns.externalLists``: direct / ruleset).
"""
from __future__ import annotations

import logging
import threading
import time
import zlib
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import DnsBlocklist, DnsRuleset, Indicator, Tenant, utcnow

log = logging.getLogger("fenrir.dns.ruleset")

THREAT_CATEGORIES = ("malware", "phishing", "command-and-control", "cryptomining", "dga")
DEFAULT_WEIGHTS = {"hagezi-tif-mini": 50, "hagezi-tif": 35, "hagezi-pro": 30, "oisd-big": 30}
CUSTOM_WEIGHT = 30
PROTECTED = (
    "microsoft.com", "windows.com", "windowsupdate.com", "update.microsoft.com", "office.com", "office.net", "office365.com",
    "microsoftonline.com", "live.com", "outlook.com", "sharepoint.com", "onedrive.com", "msftauth.net", "msauth.net",
    "azure.com", "azureedge.net", "azurefd.net", "msedge.net", "bing.com", "teams.microsoft.com", "skype.com",
    "apple.com", "icloud.com", "mzstatic.com", "google.com", "googleapis.com", "gstatic.com", "gmail.com", "youtube.com",
    "amazon.com", "amazonaws.com", "cloudfront.net", "cloudflare.com", "akamai.net", "akamaiedge.net", "akamaized.net",
    "github.com", "githubusercontent.com", "digicert.com", "letsencrypt.org", "sectigo.com", "globalsign.com",
    "entrust.net", "godaddy.com", "verisign.com", "ocsp.digicert.com", "zoom.us", "slack.com", "dropbox.com",
)
DEFAULTS = {"blockThreshold": 60, "monitorThreshold": 50, "intelWeight": 60, "weights": {}, "protected": [], "autoBuild": True,
            "maxDomains": 3_000_000}


def config(db: Session) -> dict:
    msp = db.execute(select(Tenant).where(Tenant.kind == "msp").order_by(Tenant.created_at)).scalars().first()
    stored = ((msp.settings or {}) if msp else {}).get("dnsRuleset") or {}
    out = {**DEFAULTS, **{k: v for k, v in stored.items() if k in DEFAULTS}}
    out["weights"] = {**DEFAULT_WEIGHTS, **(stored.get("weights") or {})}
    out["explicit"] = tuple((stored.get("weights") or {}).keys())
    return out


def save_config(db: Session, body: dict) -> dict:
    current = config(db)
    for key in ("blockThreshold", "monitorThreshold", "intelWeight"):
        if key in body:
            current[key] = max(1, min(100, int(body[key])))
    if current["monitorThreshold"] > current["blockThreshold"]:
        raise ValueError("the monitor threshold cannot be above the block threshold")
    if "protected" in body:
        from .dns_rules import _clean_patterns

        current["protected"] = _clean_patterns("domain", body["protected"] or ["example.invalid"]) if body["protected"] else []
    if "autoBuild" in body:
        current["autoBuild"] = bool(body["autoBuild"])
    msp = db.execute(select(Tenant).where(Tenant.kind == "msp").order_by(Tenant.created_at)).scalars().first()
    if msp is not None:
        stored = dict((msp.settings or {}).get("dnsRuleset") or {})
        stored.update({k: current[k] for k in DEFAULTS if k != "weights"})
        if "weights" in body:  # only weights a person set are stored; the rest keep following the defaults
            stored["weights"] = {**(stored.get("weights") or {}),
                                 **{str(k)[:40]: max(0, min(100, int(v))) for k, v in dict(body["weights"]).items()}}
        msp.settings = {**(msp.settings or {}), "dnsRuleset": stored}
    return config(db)


def _protected(db: Session, cfg: dict) -> frozenset[str]:
    from .config import get_settings

    host = get_settings().public_base_url.split("://")[-1].split("/")[0].split(":")[0].lower()
    return frozenset({*PROTECTED, *cfg.get("protected", []), *([host] if host else [])})


def _is_protected(domain: str, protected: frozenset[str]) -> bool:
    parts = domain.split(".")
    return any(".".join(parts[i:]) in protected for i in range(len(parts) - 1))


def _intel_domains(db: Session) -> dict[str, str]:
    """Global malicious domain indicators (customer-specific intel stays with that customer's resolver)."""
    rows = db.execute(select(Indicator.value, Indicator.category).where(
        Indicator.type == "domain", Indicator.tenant_id.is_(None), Indicator.verdict == "malicious")).all()
    return {value.lower().strip("."): (category or "malware").lower() for value, category in rows if value}


def list_sources(db: Session, cfg: dict) -> list[dict]:
    """The blocklists that feed the ruleset: enabled lists with a weight, and disabled ones only when a weight was set
    for them explicitly (so an ads list can count towards agreement without blocking on its own)."""
    out = []
    for row in db.execute(select(DnsBlocklist).where(DnsBlocklist.domain_count > 0).order_by(DnsBlocklist.id)).scalars():
        explicit = row.id in (cfg.get("explicit") or ())
        weight = int(cfg["weights"].get(row.id, CUSTOM_WEIGHT if not row.builtin else 0))
        if weight <= 0 or (not row.enabled and not explicit):
            continue
        out.append({"id": row.id, "name": row.name, "category": row.category, "weight": weight, "kind": "list"})
    return out


def build(db: Session, actor: str = "system", activate: bool = True) -> DnsRuleset:
    """Score every domain the sources name and store a new build. Takes seconds for millions of domains."""
    from . import blocklists

    started = time.time()
    cfg = config(db)
    protected = _protected(db, cfg)
    active_lists = {entry.id: entry for entry in blocklists.CACHE.active(db)}
    sources = list_sources(db, cfg)
    sources.append({"id": "fenrir-intel", "name": "Fenrir threat intel", "category": "malware", "weight": int(cfg["intelWeight"]),
                    "kind": "intel"})
    sources = sources[:30]  # a bit per source in the packed value
    # One dict, packed: the weight sum in the low 12 bits, one bit per source above them (each source adds a name once).
    acc: dict[str, int] = {}
    contributed = []
    for index, source in enumerate(sources):
        bit, weight = 1 << index, source["weight"]
        if source["kind"] == "intel":
            names = _intel_domains(db)
        else:
            cached = active_lists.get(source["id"])
            names = cached.domains if cached else blocklists._unpack(
                db.execute(select(DnsBlocklist.domains).where(DnsBlocklist.id == source["id"])).scalar_one_or_none())
        count = 0
        add = weight + (bit << 12)
        for name in names:
            acc[name] = acc.get(name, 0) + add
            count += 1
        contributed.append(count)
        source["domains"] = count
    # Parents: a source naming example.com also scores sub.example.com when sub.example.com is in another source.
    threshold = int(cfg["monitorThreshold"])
    kept: dict[str, int] = {}
    by_category: dict[str, int] = {}
    blocking = 0
    for name, packed in acc.items():
        parts = name.split(".")
        total, bits = packed & 0xFFF, packed >> 12
        for i in range(1, len(parts) - 1):
            parent = acc.get(".".join(parts[i:]))
            if parent is not None and not (parent >> 12) & bits:
                total += parent & 0xFFF
                bits |= parent >> 12
        total = min(100, total)
        if total < threshold or _is_protected(name, protected):
            continue
        best = max((i for i in range(len(sources)) if bits >> i & 1), key=lambda i: sources[i]["weight"])
        category = sources[best]["category"]
        kept[name] = total | (best << 7) | (bits << 12)
        by_category[category] = by_category.get(category, 0) + 1
        if total >= cfg["blockThreshold"]:
            blocking += 1
        if len(kept) >= cfg["maxDomains"]:
            break
    previous = db.execute(select(DnsRuleset).where(DnsRuleset.active.is_(True))).scalars().first()
    diff = {"added": 0, "removed": 0, "addedSample": [], "removedSample": [], "previousVersion": previous.version if previous else None}
    if previous is not None and previous.domains:
        old = set(_decode(previous.domains))
        new = kept.keys()
        added = [d for d in new if d not in old]
        removed = [d for d in old if d not in kept]
        diff.update(added=len(added), removed=len(removed), addedSample=sorted(added)[:25], removedSample=sorted(removed)[:25])
    blob = zlib.compress("\n".join(f"{d}\t{v}" for d, v in kept.items()).encode(), 6)
    version = (db.execute(select(func.max(DnsRuleset.version))).scalar() or 0) + 1
    stats = {"domains": len(kept), "blocking": blocking, "monitorOnly": len(kept) - blocking, "byCategory": by_category,
             "scored": len(acc), "protectedSkipped": sum(1 for d in acc if _is_protected(d, protected)),
             "seconds": round(time.time() - started, 1), "bytes": len(blob)}
    row = DnsRuleset(version=version, created_by=actor, domain_count=len(kept), domains=blob, stats=stats, diff=diff,
                     settings={**{k: cfg[k] for k in ("blockThreshold", "monitorThreshold", "intelWeight")}, "sources": sources})
    db.add(row)
    db.flush()
    if activate:
        activate_build(db, row)
    # Keep the last 10 builds.
    old_rows = db.execute(select(DnsRuleset).where(DnsRuleset.active.is_(False)).order_by(DnsRuleset.version.desc()).offset(9)).scalars().all()
    for stale in old_rows:
        db.delete(stale)
    log.info("dns ruleset v%s: %s domains (%s blocking) in %.1fs", version, len(kept), blocking, time.time() - started)
    return row


def activate_build(db: Session, row: DnsRuleset) -> None:
    for other in db.execute(select(DnsRuleset).where(DnsRuleset.active.is_(True))).scalars():
        other.active = False
    row.active = True
    CACHE.invalidate()


def _decode(blob: bytes) -> dict[str, int]:
    out: dict[str, int] = {}
    for line in zlib.decompress(blob).decode().split("\n"):
        if "\t" in line:
            name, value = line.split("\t", 1)
            out[name] = int(value)
    return out


def view(row: DnsRuleset) -> dict:
    return {"id": row.id, "version": row.version, "active": row.active, "createdBy": row.created_by,
            "createdAt": row.created_at.isoformat() + "Z", "settings": row.settings, "stats": row.stats, "diff": row.diff,
            "domainCount": row.domain_count}


class Active:
    def __init__(self, row: DnsRuleset | None, entries: dict[str, int]):
        self.version = row.version if row else 0
        self.sources = (row.settings or {}).get("sources", []) if row else []
        self.block = int((row.settings or {}).get("blockThreshold", 60)) if row else 101
        self.entries = entries

    def lookup(self, candidates: list[str]) -> tuple[int, str, list[str]] | None:
        """(score, category, source names) for the most specific listed name, or None."""
        for name in candidates:
            value = self.entries.get(name)
            if value is not None:
                score, best, bits = value & 0x7F, (value >> 7) & 0x1F, value >> 12
                category = self.sources[best]["category"] if best < len(self.sources) else "malware"
                names = [s["name"] for i, s in enumerate(self.sources) if bits >> i & 1]
                return score, category, names
        return None


class RulesetCache:
    def __init__(self, ttl: int = 60):
        self.ttl = ttl
        self._lock = threading.Lock()
        self._checked = 0.0
        self._active = Active(None, {})
        self._id = ""

    def invalidate(self) -> None:
        with self._lock:
            self._checked = 0.0

    def active(self, db: Session) -> Active:
        with self._lock:
            if time.time() - self._checked < self.ttl:
                return self._active
            current = db.execute(select(DnsRuleset.id).where(DnsRuleset.active.is_(True))).scalar_one_or_none()
            if current != self._id:
                row = db.get(DnsRuleset, current) if current else None
                self._active = Active(row, _decode(row.domains) if row and row.domains else {})
                self._id = current or ""
            self._checked = time.time()
            return self._active


CACHE = RulesetCache()


def explain(db: Session, domain: str) -> dict:
    """Which sources name a domain (live, from the feeds as they are now) and what the active build says."""
    from . import blocklists

    domain = domain.lower().strip(".")
    parts = domain.split(".")
    candidates = [".".join(parts[i:]) for i in range(len(parts) - 1)]
    cfg = config(db)
    found = []
    active_lists = {entry.id: entry for entry in blocklists.CACHE.active(db)}
    for source in list_sources(db, cfg):
        cached = active_lists.get(source["id"])
        names = cached.domains if cached else blocklists._unpack(
            db.execute(select(DnsBlocklist.domains).where(DnsBlocklist.id == source["id"])).scalar_one_or_none())
        hit = next((c for c in candidates if c in names), None)
        if hit:
            found.append({"source": source["id"], "category": source["category"], "matched": hit, "weight": source["weight"]})
    intel = _intel_domains(db)
    hit = next((c for c in candidates if c in intel), None)
    if hit:
        found.append({"source": "fenrir-intel", "category": intel[hit], "matched": hit, "weight": int(cfg["intelWeight"])})
    current = CACHE.active(db).lookup(candidates)
    protected = _is_protected(domain, _protected(db, cfg))
    return {"domain": domain, "sources": found, "liveScore": min(100, sum(f["weight"] for f in found)), "protected": protected,
            "active": {"version": CACHE.active(db).version, "score": current[0], "category": current[1], "sources": current[2]}
            if current else None, "blockThreshold": cfg["blockThreshold"], "monitorThreshold": cfg["monitorThreshold"]}


def tick(db: Session) -> None:
    """After the feeds refresh (maintenance loop): rebuild when a feed changed since the active build, at most daily."""
    cfg = config(db)
    if not cfg["autoBuild"]:
        return
    active = db.execute(select(DnsRuleset).where(DnsRuleset.active.is_(True))).scalars().first()
    newest_feed = db.execute(select(func.max(DnsBlocklist.last_success_at))).scalar()
    if active is None or (newest_feed and newest_feed > active.created_at and utcnow() - active.created_at > timedelta(hours=20)):
        build(db, "scheduled build")
