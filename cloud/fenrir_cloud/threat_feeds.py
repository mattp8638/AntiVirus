"""Free threat-intelligence feeds the server pulls itself: no Fenrir-hosted service and no paid subscriptions.

Built in (all free; the abuse.ch data is CC0):

- MalwareBazaar recent samples (abuse.ch): SHA-256 hashes of malware seen in the last 48 hours.
- URLhaus recent URLs (abuse.ch): malware download links that are still online.
- URLhaus hostfile (abuse.ch): domains used only to spread malware (abuse.ch leaves out shared platforms).
- ThreatFox recent IOCs (abuse.ch): command-and-control domains, IPs, payload URLs and hashes from the last days.
- Feodo Tracker (abuse.ch): botnet command-and-control IPs (Emotet, QakBot, Dridex...).
- IPsum level 3 (stamparm, public domain): IPs listed by at least three public blocklists; kept as "suspicious",
  so they show up in lookups and sightings but are not firewall-blocked.

Each feed's indicators are stored with source ``feed:<id>`` and replaced on every successful sync, with an expiry a
few refreshes ahead, so a feed that stops updating ages out instead of blocking forever. Safety rules, as for the DNS
blocklists: an HTTP error, an empty parse or an oversized body keeps the previous copy, and a feed that shrinks by
more than 80% in one go is held back. abuse.ch may require a free Auth-Key (https://auth.abuse.ch): set
FENRIR_ABUSECH_AUTH_KEY and it is sent with every abuse.ch request.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
from datetime import timedelta

import httpx
from sqlalchemy import delete, insert, select
from sqlalchemy.orm import Session

from .models import Indicator, IntelFeed, utcnow

log = logging.getLogger("fenrir.feeds")

MAX_BYTES = 120 * 1024 * 1024
MAX_SHRINK = 0.8
SOURCE_PREFIX = "feed:"
USER_AGENT = "Fenrir-ThreatFeeds/1.0 (+self-hosted RMM)"

# id -> definition. "parser" names a function below.
BUILTIN: dict[str, dict] = {
    "malwarebazaar-recent": {
        "name": "MalwareBazaar: recent malware (abuse.ch)", "url": "https://bazaar.abuse.ch/export/csv/recent/",
        "parser": "malwarebazaar", "refresh_hours": 1, "enabled": True,
        "description": "SHA-256 hashes of malware samples shared in the last 48 hours. Agents block and quarantine matching files.",
    },
    "urlhaus-recent": {
        "name": "URLhaus: malware links (abuse.ch)", "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "parser": "urlhaus_csv", "refresh_hours": 1, "enabled": True,
        "description": "Malware download URLs from the last 30 days that are still online. Matched as exact links, never whole sites.",
    },
    "urlhaus-hosts": {
        "name": "URLhaus: malware domains (abuse.ch)", "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "parser": "hosts", "refresh_hours": 2, "enabled": True, "category": "malware",
        "description": "Domains used to spread malware, without shared platforms. Blocked by DNS protection and agents.",
    },
    "threatfox-recent": {
        "name": "ThreatFox: C2 and payload indicators (abuse.ch)", "url": "https://threatfox.abuse.ch/export/json/recent/",
        "parser": "threatfox", "refresh_hours": 1, "enabled": True,
        "description": "Command-and-control domains and IPs, payload URLs and malware hashes reported in the last days.",
    },
    "feodo-c2": {
        "name": "Feodo Tracker: botnet C2 IPs (abuse.ch)", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "parser": "feodo", "refresh_hours": 1, "enabled": True,
        "description": "Active command-and-control servers of Emotet, QakBot, Dridex and similar botnets. Firewall-blocked by agents.",
    },
    "ipsum-3": {
        "name": "IPsum: IPs on 3+ blocklists (stamparm)", "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        "parser": "ip_lines", "refresh_hours": 24, "enabled": True, "verdict": "suspicious", "category": "scanner",
        "description": "IPs that at least three public blocklists agree on. Shown in lookups and telemetry, not blocked.",
    },
}

# Shared platforms: a malware link hosted on one of these must never block the whole site.
SHARED_HOSTS = {
    "github.com", "githubusercontent.com", "github.io", "gitlab.com", "bitbucket.org", "sourceforge.net",
    "google.com", "googleapis.com", "googleusercontent.com", "goo.gl", "blogspot.com", "appspot.com", "web.app", "firebaseapp.com",
    "microsoft.com", "live.com", "1drv.ms", "sharepoint.com", "onedrive.com", "windows.net", "azurewebsites.net", "office.com",
    "dropbox.com", "dropboxusercontent.com", "box.com", "mega.nz", "mediafire.com", "wetransfer.com", "we.tl",
    "discord.com", "discordapp.com", "discordapp.net", "telegram.org", "t.me", "slack.com", "zoom.us",
    "amazonaws.com", "cloudfront.net", "s3.amazonaws.com", "akamaihd.net", "cloudflare.com", "r2.dev", "pages.dev", "workers.dev",
    "apple.com", "icloud.com", "facebook.com", "instagram.com", "whatsapp.com", "twitter.com", "x.com", "linkedin.com",
    "youtube.com", "archive.org", "pastebin.com", "paste.ee", "transfer.sh", "ngrok.io", "ngrok-free.app", "duckdns.org",
    "netlify.app", "vercel.app", "herokuapp.com", "glitch.me", "wordpress.com", "wixsite.com", "weebly.com", "000webhostapp.com",
    "bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "rebrand.ly", "linktr.ee", "notion.site", "canva.com", "docs.google.com",
}


def is_shared_host(host: str) -> bool:
    host = (host or "").lower().strip(".")
    parts = host.split(".")
    return any(".".join(parts[i:]) in SHARED_HOSTS for i in range(len(parts) - 1))


# --------------------------------------------------------------------------- parsers
# Each returns a list of (type, value, verdict, category, description, confidence).

Row = tuple[str, str, str, str, str, int]
HEX = re.compile(r"^[0-9a-f]{64}$")
IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$")


def _csv_rows(text: str, skipinitialspace: bool = False) -> list[list[str]]:
    lines = [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    return list(csv.reader(io.StringIO("\n".join(lines)), skipinitialspace=skipinitialspace))


def malwarebazaar(text: str, feed: dict) -> list[Row]:
    # "first_seen_utc", "sha256_hash", "md5_hash", "sha1_hash", "reporter", "file_name", "file_type_guess", "mime_type",
    # "signature", "clamav", "vtpercent", "imphash", "ssdeep", "tlsh"
    out = []
    for row in _csv_rows(text, skipinitialspace=True):
        if len(row) < 2:
            continue
        sha = row[1].strip().lower()
        if HEX.match(sha):
            family = row[8].strip() if len(row) > 8 and row[8].strip() not in ("", "n/a") else ""
            out.append(("sha256", sha, "malicious", "malware", family, 90))
    return out


def urlhaus_csv(text: str, feed: dict) -> list[Row]:
    # "id","dateadded","url","url_status","last_online","threat","tags","urlhaus_link","reporter"
    out = []
    for row in _csv_rows(text):
        if len(row) < 4 or not row[2].lower().startswith(("http://", "https://")):
            continue
        if row[3].strip().lower() != "online":
            continue
        threat = row[5].strip() if len(row) > 5 else ""
        out.append(("url", row[2].strip(), "malicious", "malware", threat, 85))
    return out


def hosts(text: str, feed: dict) -> list[Row]:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        host = (parts[1] if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1") else parts[0]).lower().strip(".")
        if DOMAIN.match(host) and not is_shared_host(host) and host != "localhost":
            out.append(("domain", host, feed.get("verdict", "malicious"), feed.get("category", "malware"), "", 85))
    return out


def threatfox(text: str, feed: dict) -> list[Row]:
    data = json.loads(text)
    items = []
    if isinstance(data, dict):
        for value in data.values():
            items.extend(value if isinstance(value, list) else [value])
    elif isinstance(data, list):
        items = data
    out = []
    for item in items:
        if not isinstance(item, dict):
            continue
        kind, value = str(item.get("ioc_type") or ""), str(item.get("ioc_value") or "").strip()
        family = str(item.get("malware_printable") or item.get("malware") or "")
        threat = str(item.get("threat_type") or "")
        category = "command-and-control" if threat == "botnet_cc" else "malware"
        try:
            confidence = max(50, min(100, int(item.get("confidence_level") or 75)))
        except (TypeError, ValueError):
            confidence = 75
        if kind == "ip:port":
            ip = value.rsplit(":", 1)[0]
            if IPV4.match(ip):
                out.append(("ip", ip, "malicious", category, family, confidence))
        elif kind == "domain":
            host = value.lower().strip(".")
            if DOMAIN.match(host) and not is_shared_host(host):
                out.append(("domain", host, "malicious", category, family, confidence))
        elif kind == "url" and value.lower().startswith(("http://", "https://")):
            out.append(("url", value, "malicious", category, family, confidence))
        elif kind == "sha256_hash" and HEX.match(value.lower()):
            out.append(("sha256", value.lower(), "malicious", "malware", family, confidence))
    return out


def feodo(text: str, feed: dict) -> list[Row]:
    data = json.loads(text)
    out = []
    for item in data if isinstance(data, list) else []:
        ip = str((item or {}).get("ip_address") or "").strip()
        if IPV4.match(ip) and str(item.get("status") or "online").lower() != "offline":
            out.append(("ip", ip, "malicious", "command-and-control", str(item.get("malware") or ""), 90))
    return out


def ip_lines(text: str, feed: dict) -> list[Row]:
    out = []
    for line in text.splitlines():
        ip = line.split("#", 1)[0].split()[0] if line.split("#", 1)[0].split() else ""
        if IPV4.match(ip):
            out.append(("ip", ip, feed.get("verdict", "suspicious"), feed.get("category", "scanner"), "", 60))
    return out


PARSERS = {"malwarebazaar": malwarebazaar, "urlhaus_csv": urlhaus_csv, "hosts": hosts, "threatfox": threatfox,
           "feodo": feodo, "ip_lines": ip_lines}


# --------------------------------------------------------------------------- sync


def seed(db: Session) -> None:
    """Add built-in feeds that are missing; never changes an existing row (so an admin's on/off choice stays)."""
    present = set(db.execute(select(IntelFeed.id)).scalars())
    for feed_id, item in BUILTIN.items():
        if feed_id not in present:
            db.add(IntelFeed(id=feed_id, name=item["name"], url=item["url"], description=item["description"],
                             enabled=item.get("enabled", True), refresh_hours=item.get("refresh_hours", 1)))


def _headers(feed: IntelFeed, auth_key: str) -> dict:
    headers = {"User-Agent": USER_AGENT}
    if feed.etag:
        headers["If-None-Match"] = feed.etag
    if auth_key and "abuse.ch" in feed.url:
        headers["Auth-Key"] = auth_key
    return headers


def sync_feed(db: Session, feed: IntelFeed, auth_key: str = "", client: httpx.Client | None = None) -> dict:
    """Download, parse and replace one feed's indicators. Never raises for network or parse problems."""
    definition = BUILTIN.get(feed.id, {})
    parser = PARSERS.get(definition.get("parser", ""))
    feed.last_attempt_at = utcnow()
    if parser is None:
        feed.last_error = "unknown feed format"
        return {"id": feed.id, "ok": False, "error": feed.last_error}
    own = client is None
    client = client or httpx.Client(timeout=90, follow_redirects=True)
    try:
        response = client.get(feed.url, headers=_headers(feed, auth_key))
        if response.status_code == 304:
            feed.last_success_at, feed.last_error = utcnow(), ""
            _extend_expiry(db, feed)
            return {"id": feed.id, "ok": True, "unchanged": True, "indicators": feed.indicator_count}
        if response.status_code in (401, 403) and "abuse.ch" in feed.url:
            feed.last_error = ("abuse.ch asked for an Auth-Key: create a free one at https://auth.abuse.ch and set "
                               "FENRIR_ABUSECH_AUTH_KEY on the server" if not auth_key else "abuse.ch refused the Auth-Key")
            return {"id": feed.id, "ok": False, "error": feed.last_error}
        response.raise_for_status()
        if len(response.content) > MAX_BYTES:
            raise ValueError(f"feed is larger than {MAX_BYTES // (1024 * 1024)} MB")
        text = response.text
        rows = parser(text, definition)
    except (httpx.HTTPError, ValueError, json.JSONDecodeError) as exc:
        feed.last_error = f"{type(exc).__name__}: {exc}"[:500]
        log.warning("feed %s failed: %s", feed.id, feed.last_error)
        return {"id": feed.id, "ok": False, "error": feed.last_error}
    finally:
        if own:
            client.close()

    unique: dict[tuple[str, str], Row] = {}
    for row in rows:
        unique.setdefault((row[0], row[1]), row)
    if not unique:
        feed.last_error = "the download parsed to no indicators; kept the previous copy"
        return {"id": feed.id, "ok": False, "error": feed.last_error}
    if feed.indicator_count >= 100 and len(unique) < feed.indicator_count * (1 - MAX_SHRINK):
        feed.last_error = (f"held back: {len(unique)} indicators against {feed.indicator_count} last time "
                           "(a truncated download must not unblock most of a feed)")
        return {"id": feed.id, "ok": False, "error": feed.last_error}

    source = SOURCE_PREFIX + feed.id
    expires = utcnow() + timedelta(hours=max(72, 6 * (feed.refresh_hours or 1)))
    db.execute(delete(Indicator).where(Indicator.source == source, Indicator.tenant_id.is_(None)))
    now = utcnow()
    batch = [{"tenant_id": None, "type": t, "value": v[:2048], "verdict": verdict, "category": category[:40], "source": source,
              "confidence": confidence, "description": description[:500], "expires_at": expires, "created_at": now}
             for t, v, verdict, category, description, confidence in unique.values()]
    for start in range(0, len(batch), 2000):
        db.execute(insert(Indicator), batch[start:start + 2000])
    feed.indicator_count = len(batch)
    feed.etag = (response.headers.get("etag") or "")[:200]
    feed.last_success_at, feed.last_error = utcnow(), ""
    return {"id": feed.id, "ok": True, "indicators": len(batch)}


def _extend_expiry(db: Session, feed: IntelFeed) -> None:
    from sqlalchemy import update

    expires = utcnow() + timedelta(hours=max(72, 6 * (feed.refresh_hours or 1)))
    db.execute(update(Indicator).where(Indicator.source == SOURCE_PREFIX + feed.id, Indicator.tenant_id.is_(None))
               .values(expires_at=expires))


def sync(db: Session, auth_key: str = "", only_due: bool = True, client: httpx.Client | None = None) -> list[dict]:
    """Sync enabled feeds (only those due, unless ``only_due`` is False). Commits after each feed."""
    seed(db)
    db.commit()
    results = []
    now = utcnow()
    for feed in db.execute(select(IntelFeed).where(IntelFeed.enabled.is_(True)).order_by(IntelFeed.id)).scalars().all():
        if only_due and feed.last_attempt_at and now - feed.last_attempt_at < timedelta(hours=feed.refresh_hours or 1):
            continue
        results.append(sync_feed(db, feed, auth_key, client))
        db.commit()
    if any(r.get("ok") and not r.get("unchanged") for r in results):
        from .dnsfilter import INTEL

        INTEL.invalidate()
    return results


def view(feed: IntelFeed) -> dict:
    return {"id": feed.id, "name": feed.name, "url": feed.url, "description": feed.description, "enabled": feed.enabled,
            "refreshHours": feed.refresh_hours, "indicators": feed.indicator_count,
            "lastAttemptAt": feed.last_attempt_at.isoformat() + "Z" if feed.last_attempt_at else None,
            "lastSuccessAt": feed.last_success_at.isoformat() + "Z" if feed.last_success_at else None,
            "lastError": feed.last_error}
