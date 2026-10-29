"""External DNS blocklists (HaGeZi, OISD or any custom domain list) for the DoH resolver.

Lists are fetched on a schedule by the maintenance loop, parsed into normalised domain sets and
stored compressed in ``dns_blocklists``. The resolver consults them after the policy allow/block
lists and threat-intel indicators, so a policy allow entry or an intel "allow" always wins.

Safety rules for each refresh:

- an HTTP error, an empty parse or a body over ``MAX_BYTES`` keeps the previous copy;
- a list that shrinks by more than ``MAX_SHRINK`` in one refresh is held back (a truncated
  download must not silently unblock most of the list);
- ``ETag``/``If-None-Match`` avoids re-downloading unchanged lists.
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
import time
import zlib
from dataclasses import dataclass
from datetime import timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import DnsBlocklist, utcnow

log = logging.getLogger("fenrir.blocklists")

MAX_BYTES = 80 * 1024 * 1024
MAX_SHRINK = 0.5

# Verified list URLs. Only the malware feed is on by default; the others change browsing behaviour.
BUILTIN_LISTS: dict[str, dict] = {
    "hagezi-tif-mini": {
        "name": "HaGeZi Threat Intelligence Feeds (mini)",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt",
        "category": "malware", "enabled": True,
        "description": "Malware, phishing, scam, cryptojacking and C2 domains seen recently (about 200k domains).",
    },
    "hagezi-tif": {
        "name": "HaGeZi Threat Intelligence Feeds (full)",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt",
        "category": "malware", "enabled": False,
        "description": "The complete TIF list (over a million domains). Uses noticeably more server memory than the mini list.",
    },
    "hagezi-pro": {
        "name": "HaGeZi Multi PRO",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
        "category": "ads-trackers", "enabled": False,
        "description": "Ads, tracking, telemetry and badware. Applies where the policy blocks the ads-trackers category.",
    },
    "oisd-big": {
        "name": "OISD big",
        "url": "https://big.oisd.nl/domainswild2",
        "category": "ads-trackers", "enabled": False,
        "description": "Low false-positive ads/tracker/malware list. Applies where the policy blocks the ads-trackers category.",
    },
}

_DOMAIN = re.compile(r"(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}")
_SKIP_HOSTS = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback", "0.0.0.0"}


def parse(raw: str) -> list[str]:
    """Domains from hosts files, AdBlock ``||domain^`` rules, wildcard and plain domain lists."""
    domains: set[str] = set()
    for line in raw.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line[0] in "!;[" or line.startswith("@@"):
            continue  # comments, AdBlock headers and AdBlock exception rules
        parts = line.split()
        if len(parts) >= 2 and parts[0] in {"0.0.0.0", "127.0.0.1", "::", "::1"}:
            line = parts[1]
        else:
            line = parts[0]
        if line.startswith("||"):
            line = line[2:]
        line = line.split("^", 1)[0].split("$", 1)[0]
        line = line.removeprefix("*.").removeprefix(".").lower().rstrip(".")
        if line in _SKIP_HOSTS or not _DOMAIN.fullmatch(line):
            continue
        domains.add(line)
    return sorted(domains)


def _pack(domains: list[str]) -> bytes:
    return zlib.compress("\n".join(domains).encode(), 6)


def _unpack(blob: bytes | None) -> frozenset[str]:
    if not blob:
        return frozenset()
    return frozenset(zlib.decompress(blob).decode().split("\n")) - {""}


def ensure_builtin(db: Session) -> None:
    for key, spec in BUILTIN_LISTS.items():
        row = db.get(DnsBlocklist, key)
        if row is None:
            db.add(DnsBlocklist(id=key, name=spec["name"], url=spec["url"], category=spec["category"],
                                description=spec["description"], builtin=True, enabled=spec["enabled"]))
        elif row.builtin:
            # Keep URLs current with this release; operators control only enabled/refresh.
            row.url, row.name, row.description, row.category = spec["url"], spec["name"], spec["description"], spec["category"]


def store(db: Session, row: DnsBlocklist, raw: str) -> dict:
    """Parse ``raw`` into ``row`` unless it fails the safety checks. Returns a summary."""
    domains = parse(raw)
    row.last_attempt_at = utcnow()
    if not domains:
        row.last_error = "The download contained no domains; the previous copy was kept."
        return {"id": row.id, "updated": False, "error": row.last_error}
    if row.domain_count and len(domains) < row.domain_count * (1 - MAX_SHRINK):
        row.last_error = (f"The list shrank from {row.domain_count} to {len(domains)} domains in one refresh; "
                          "the previous copy was kept. Sync manually with force to accept it.")
        return {"id": row.id, "updated": False, "error": row.last_error}
    return _accept(row, domains)


def _accept(row: DnsBlocklist, domains: list[str]) -> dict:
    packed = _pack(domains)
    row.domains = packed
    row.domain_count = len(domains)
    row.content_sha256 = hashlib.sha256(packed).hexdigest()
    row.last_success_at = row.last_attempt_at = utcnow()
    row.last_error = ""
    CACHE.invalidate()
    return {"id": row.id, "updated": True, "domains": len(domains)}


def fetch(db: Session, row: DnsBlocklist, client: httpx.Client | None = None, force: bool = False) -> dict:
    own = client is None
    client = client or httpx.Client(timeout=120, follow_redirects=True)
    row.last_attempt_at = utcnow()
    try:
        headers = {"If-None-Match": row.etag} if row.etag and row.domains and not force else {}
        with client.stream("GET", row.url, headers=headers) as response:
            if response.status_code == 304:
                row.last_success_at, row.last_error = utcnow(), ""
                return {"id": row.id, "updated": False, "unchanged": True, "domains": row.domain_count}
            response.raise_for_status()
            chunks, size = [], 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > MAX_BYTES:
                    raise ValueError(f"list is larger than {MAX_BYTES // (1024 * 1024)} MB")
                chunks.append(chunk)
            etag = response.headers.get("etag", "")
        raw = b"".join(chunks).decode("utf-8", errors="replace")
    except (httpx.HTTPError, ValueError) as exc:
        row.last_error = f"Download failed: {exc}"[:500]
        log.warning("blocklist %s: %s", row.id, row.last_error)
        return {"id": row.id, "updated": False, "error": row.last_error}
    finally:
        if own:
            client.close()
    if force:
        domains = parse(raw)
        result = _accept(row, domains) if domains else store(db, row, raw)
    else:
        result = store(db, row, raw)
    if result.get("updated"):
        row.etag = etag[:200]
    return result


def due(row: DnsBlocklist) -> bool:
    if not row.enabled:
        return False
    if row.last_attempt_at is None:
        return True
    # Retry a failed list after an hour rather than waiting a full refresh period.
    period = timedelta(hours=max(1, row.refresh_hours)) if not row.last_error else timedelta(hours=1)
    return utcnow() - row.last_attempt_at >= period


def sync_due(db: Session, client: httpx.Client | None = None) -> list[dict]:
    ensure_builtin(db)
    db.commit()
    results = []
    for row in db.execute(select(DnsBlocklist).order_by(DnsBlocklist.id)).scalars().all():
        if due(row):
            results.append(fetch(db, row, client))
            db.commit()
    return results


@dataclass(frozen=True)
class ActiveList:
    id: str
    category: str
    domains: frozenset[str]


class BlocklistCache:
    """Decompressed enabled lists, reloaded only when a list's content hash changes."""

    def __init__(self, ttl_seconds: int = 60) -> None:
        self.ttl = ttl_seconds
        self._lock = threading.Lock()
        self._checked = 0.0
        self._lists: dict[str, tuple[str, ActiveList]] = {}

    def invalidate(self) -> None:
        with self._lock:
            self._checked = 0.0

    def active(self, db: Session) -> list[ActiveList]:
        with self._lock:
            if time.time() - self._checked < self.ttl:
                return [entry for _, entry in self._lists.values()]
            rows = db.execute(select(DnsBlocklist.id, DnsBlocklist.category, DnsBlocklist.content_sha256)
                              .where(DnsBlocklist.enabled.is_(True), DnsBlocklist.domain_count > 0)).all()
            fresh: dict[str, tuple[str, ActiveList]] = {}
            for key, category, sha in rows:
                cached = self._lists.get(key)
                if cached and cached[0] == sha and cached[1].category == category:
                    fresh[key] = cached
                    continue
                blob = db.execute(select(DnsBlocklist.domains).where(DnsBlocklist.id == key)).scalar_one_or_none()
                fresh[key] = (sha, ActiveList(key, category, _unpack(blob)))
            self._lists = fresh
            self._checked = time.time()
            return [entry for _, entry in fresh.values()]


CACHE = BlocklistCache()


def view(row: DnsBlocklist) -> dict:
    return {"id": row.id, "name": row.name, "url": row.url, "category": row.category, "description": row.description,
            "builtin": row.builtin, "enabled": row.enabled, "refreshHours": row.refresh_hours, "domainCount": row.domain_count,
            "lastAttemptAt": row.last_attempt_at.isoformat() if row.last_attempt_at else None,
            "lastSuccessAt": row.last_success_at.isoformat() if row.last_success_at else None,
            "lastError": row.last_error}
