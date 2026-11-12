"""DNS protection: per-device DNS-over-HTTPS filtering resolver (RFC 8484).

Each device gets a private DoH URL (``/dns/<token>/dns-query``). The agent
points the OS resolver (or browser policy) at it, so filtering follows the
device off-network. Decisions, in order (each step is recorded in the decision's trail):

1. DNS rules and allow/block entries (dns_rules.py): device, group, customer, then MSP-wide; first match wins
2. policy allow list           -> allow
3. policy block list           -> block (reason "policy")
4. tenant/global indicators     -> allow if verdict allow, block if malicious (reason "threat-intel")
5. Fenrir DNS ruleset (dns_ruleset.py) -> block at or above its threshold, monitor below it (policy dns.fenrirRuleset)
6. external blocklists          -> "malware" lists always block; other lists block if their category is blocked
                                   (skipped when policy dns.externalLists is "ruleset")
7. category lists               -> block if the category is in policy.dns.blockedCategories
8. heuristics (DGA, DoH bypass) -> block if that category is blocked
9. otherwise forward upstream
"""

from __future__ import annotations

import base64
import logging
import math
import re
import time
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.rdatatype
import dns.rrset
import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Device, DnsQueryLog, Indicator

log = logging.getLogger("fenrir.dns")

# Small built-in category seeds. Production deployments add feed URLs; these
# make the feature useful out of the box and testable.
CATEGORY_DOMAINS: dict[str, set[str]] = {
    "doh-bypass": {"dns.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "dns.quad9.net", "doh.opendns.com",
                   "dns.nextdns.io", "doh.cleanbrowsing.org", "dns.adguard.com", "dns.adguard-dns.com", "chrome.cloudflare-dns.com"},
    "cryptomining": {"coinhive.com", "coin-hive.com", "minero.cc", "crypto-loot.com", "webminepool.com", "nanopool.org",
                     "supportxmr.com", "minexmr.com", "2miners.com", "moneroocean.stream"},
    "proxies-vpn": {"hidemyass.com", "torproject.org", "proxysite.com", "hide.me", "kproxy.com"},
    "ads-trackers": {"doubleclick.net", "googlesyndication.com", "adnxs.com", "taboola.com", "outbrain.com", "scorecardresearch.com"},
    "social-media": {"facebook.com", "instagram.com", "tiktok.com", "x.com", "twitter.com", "snapchat.com", "reddit.com"},
    "streaming": {"netflix.com", "twitch.tv", "disneyplus.com", "primevideo.com", "hulu.com"},
    "games": {"steampowered.com", "epicgames.com", "roblox.com", "miniclip.com"},
    "gambling": {"bet365.com", "williamhill.com", "paddypower.com", "pokerstars.com", "888casino.com", "betfair.com"},
    "dating": {"tinder.com", "bumble.com", "match.com", "hinge.co"},
}

SAFESEARCH = {
    "www.google.com": "forcesafesearch.google.com",
    "google.com": "forcesafesearch.google.com",
    "www.bing.com": "strict.bing.com",
    "duckduckgo.com": "safe.duckduckgo.com",
    "www.youtube.com": "restrict.youtube.com",
    "youtube.com": "restrict.youtube.com",
}

_VOWELS = set("aeiou")


def _parents(domain: str) -> list[str]:
    parts = domain.split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


def _entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values()) if text else 0.0


def looks_like_dga(domain: str) -> bool:
    """Cheap DGA heuristic: long, high-entropy, consonant-heavy leftmost label."""
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    label = labels[-2] if len(labels) == 2 else max(labels[:-1], key=len)
    if len(label) < 12 or not re.fullmatch(r"[a-z0-9]+", label):
        return False
    vowel_ratio = sum(1 for ch in label if ch in _VOWELS) / len(label)
    digit_ratio = sum(1 for ch in label if ch.isdigit()) / len(label)
    return _entropy(label) > 3.6 and (vowel_ratio < 0.25 or digit_ratio > 0.3)


@dataclass
class Decision:
    action: str  # allow | block
    reason: str = ""
    category: str = ""
    rewrite: str | None = None
    source: str = ""  # rule | entry | policy | intel | ruleset | blocklist | category | heuristic | safesearch
    rule_id: str = ""
    score: int | None = None
    monitor: bool = False  # a monitor rule, an audit rule or the ruleset's monitor band matched: log it
    trail: list = field(default_factory=list)
    audits: list = field(default_factory=list)


class IntelCache:
    """Short-lived cache of blocking indicators so DNS stays fast."""

    def __init__(self, ttl_seconds: int = 60) -> None:
        self.ttl = ttl_seconds
        self._loaded: dict[str | None, tuple[float, dict[str, tuple[str, str]]]] = {}

    def invalidate(self) -> None:
        self._loaded.clear()

    def domains(self, db: Session, tenant_id: str) -> dict[str, tuple[str, str]]:
        cached = self._loaded.get(tenant_id)
        if cached and time.time() - cached[0] < self.ttl:
            return cached[1]
        from .threat_feeds import SOURCE_PREFIX, is_shared_host

        rows = db.execute(
            select(Indicator.value, Indicator.verdict, Indicator.category, Indicator.type, Indicator.source).where(
                Indicator.type.in_(("domain", "url")), (Indicator.tenant_id.is_(None)) | (Indicator.tenant_id == tenant_id)
            )
        ).all()
        mapping: dict[str, tuple[str, str]] = {}
        for value, verdict, category, kind, source in rows:
            host = value.lower().strip(".")
            if kind == "url" and verdict != "allow" and (source or "").startswith(SOURCE_PREFIX):
                continue  # a malware link from a public feed blocks that link (agents), not its whole site
            if kind == "url":
                match = re.match(r"^[a-z]+://([^/:?#]+)", host)
                if match:
                    host = match.group(1)
            if host.startswith("||") and host.endswith("^"):
                host = host[2:-1]
            elif host.startswith("||"):
                host = host[2:]
            parts = host.split()
            if len(parts) >= 2 and parts[0] in {"0.0.0.0", "127.0.0.1"}:
                host = parts[1]
            host = host.strip(".^/ ")
            if not host or (verdict != "allow" and kind == "url" and is_shared_host(host)):
                continue
            # A tenant "allow" overrides a global "malicious".
            if verdict == "allow" or host not in mapping:
                mapping[host] = (verdict, category or "malware")
        self._loaded[tenant_id] = (time.time(), mapping)
        return mapping


INTEL = IntelCache()


THREAT = {"malware", "phishing", "command-and-control", "cryptomining", "dga"}


def decide(domain: str, dns_settings: dict, intel: dict[str, tuple[str, str]], blocklists: Iterable = (), *, rules=None,
           ruleset=None, qtype: str = "A", now=None) -> Decision:
    domain = domain.lower().rstrip(".")
    candidates = [domain, *_parents(domain)]
    allow = {d.lower().strip(".") for d in dns_settings.get("allowDomains", [])}
    block = {d.lower().strip(".") for d in dns_settings.get("blockDomains", [])}
    blocked_categories = set(dns_settings.get("blockedCategories", []))
    lists = list(blocklists)
    trail: list[str] = []
    audits: list[dict] = []
    monitor = False

    def finish(decision: Decision) -> Decision:
        decision.trail = trail + ([decision.reason] if decision.reason and decision.source not in ("rule", "entry") else [])
        decision.audits = audits
        decision.monitor = decision.monitor or monitor
        return decision

    def category_of() -> str:
        if ruleset is not None:
            hit = ruleset.lookup(candidates)
            if hit:
                return hit[1]
        for candidate in candidates:
            if candidate in intel and intel[candidate][0] != "allow":
                return (intel[candidate][1] or "malware").lower()
        for blocklist in lists:
            if any(c in blocklist.domains for c in candidates):
                return blocklist.category
        for category, domains in CATEGORY_DOMAINS.items():
            if any(c in domains for c in candidates):
                return category
        return "dga" if looks_like_dga(domain) else ""

    if rules is not None:
        outcome = rules.evaluate(domain, candidates, qtype, category_of, now)
        trail.extend(outcome.trail)
        audits.extend(outcome.audits)
        monitor = bool(outcome.audits)
        if outcome.rule is not None:
            source = "entry" if outcome.rule.kind == "entry" else "rule"
            label = "allow list" if source == "entry" and outcome.action == "allow" else "block list" if source == "entry" else "rule"
            return finish(Decision(outcome.action, f"{label}: {outcome.rule.name}", category_of() if outcome.action == "block" else "",
                                   source=source, rule_id=outcome.rule.id))
    if any(c in allow for c in candidates):
        return finish(Decision("allow", "allow-list", source="policy"))
    if any(c in block for c in candidates):
        return finish(Decision("block", "policy block list", "policy", source="policy"))
    for candidate in candidates:
        if candidate in intel:
            verdict, category = intel[candidate]
            if verdict == "allow":
                return finish(Decision("allow", "intel allow", source="intel"))
            if verdict in {"malicious", "suspicious"}:
                cat = (category or "malware").lower()
                if verdict == "malicious" or cat in blocked_categories or not blocked_categories:
                    return finish(Decision("block", f"threat intel ({verdict})", cat, source="intel"))
    ruleset_mode = dns_settings.get("fenrirRuleset", "block")
    if ruleset is not None and ruleset_mode != "off":
        hit = ruleset.lookup(candidates)
        if hit:
            score, category, sources = hit
            applies = category in THREAT or category in blocked_categories
            if ruleset_mode == "block" and score >= ruleset.block and applies:
                return finish(Decision("block", f"Fenrir ruleset v{ruleset.version}: score {score} ({', '.join(sources[:4])})",
                                       category, source="ruleset", score=score))
            trail.append(f"Fenrir ruleset v{ruleset.version}: score {score}, {category}"
                         + (" (monitor only)" if ruleset_mode == "monitor" or score < ruleset.block else " (category not blocked)"))
            monitor = monitor or (applies and ruleset_mode != "off")
    if dns_settings.get("externalLists", "direct") != "ruleset":
        for blocklist in lists:
            if blocklist.category == "malware" or blocklist.category in blocked_categories:
                if any(c in blocklist.domains for c in candidates):
                    return finish(Decision("block", f"blocklist {blocklist.id}", blocklist.category, source="blocklist"))
    for category, domains in CATEGORY_DOMAINS.items():
        if category in blocked_categories and any(c in domains for c in candidates):
            return finish(Decision("block", f"category {category}", category, source="category"))
    if "dga" in blocked_categories and looks_like_dga(domain):
        return finish(Decision("block", "algorithmically generated domain", "dga", source="heuristic"))
    if dns_settings.get("safeSearch") and domain in SAFESEARCH:
        return finish(Decision("allow", "safesearch", "safesearch", rewrite=SAFESEARCH[domain], source="safesearch"))
    return finish(Decision("allow"))


def blocked_response(query: dns.message.Message, action: str, sinkhole_ipv4: str) -> dns.message.Message:
    response = dns.message.make_response(query)
    response.flags |= dns.flags.RA
    if action == "nxdomain":
        response.set_rcode(dns.rcode.NXDOMAIN)
        return response
    if action == "refused":
        response.set_rcode(dns.rcode.REFUSED)
        return response
    question = query.question[0]
    if question.rdtype == dns.rdatatype.A:
        response.answer.append(dns.rrset.from_text(question.name, 60, "IN", "A", sinkhole_ipv4))
    elif question.rdtype == dns.rdatatype.AAAA:
        response.answer.append(dns.rrset.from_text(question.name, 60, "IN", "AAAA", "::"))
    return response


def forward(wire: bytes, upstream: str, client: httpx.Client | None = None) -> bytes:
    own = client is None
    client = client or httpx.Client(timeout=5)
    try:
        reply = client.post(upstream, content=wire, headers={"Content-Type": "application/dns-message",
                                                              "Accept": "application/dns-message"})
        reply.raise_for_status()
        return reply.content
    finally:
        if own:
            client.close()


def decode_get_param(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def resolve(
    db: Session,
    device: Device,
    wire: bytes,
    dns_settings: dict,
    upstream: str,
    sinkhole_ipv4: str,
    client: httpx.Client | None = None,
) -> tuple[bytes, Decision]:
    query = dns.message.from_wire(wire)
    if query.opcode() != dns.opcode.QUERY or len(query.question) != 1:
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.FORMERR)
        return response.to_wire(), Decision("allow", "malformed")
    question = query.question[0]
    qname = question.name.to_text().rstrip(".")
    from . import blocklists, dns_rules, dns_ruleset

    qtype = dns.rdatatype.to_text(question.rdtype)
    decision = decide(qname, dns_settings, INTEL.domains(db, device.tenant_id), blocklists.CACHE.active(db),
                      rules=dns_rules.CACHE.for_device(db, device), ruleset=dns_ruleset.CACHE.active(db), qtype=qtype)
    if dns_settings.get("mode") == "observe" and decision.action == "block":
        decision = Decision("allow", f"observe-only: {decision.reason}", decision.category, source=decision.source,
                            rule_id=decision.rule_id, score=decision.score, trail=decision.trail, audits=decision.audits)
    count(device, decision.action == "block")
    dns_rules.flush_hits(db)
    flush_counts(db)

    if decision.action == "block":
        answer = blocked_response(query, dns_settings.get("blockAction", "sinkhole"), sinkhole_ipv4).to_wire()
    elif decision.rewrite:
        rewritten = dns.message.make_query(decision.rewrite, question.rdtype)
        rewritten.id = query.id
        upstream_reply = dns.message.from_wire(forward(rewritten.to_wire(), upstream, client))
        response = dns.message.make_response(query)
        response.flags |= dns.flags.RA
        response.answer.append(dns.rrset.from_text(question.name, 300, "IN", "CNAME", decision.rewrite + "."))
        response.answer.extend(upstream_reply.answer)
        answer = response.to_wire()
    else:
        answer = forward(wire, upstream, client)

    log_mode = dns_settings.get("logQueries", "blocked")
    observed = decision.reason.startswith("observe")
    if log_mode == "all" or (log_mode == "blocked" and (decision.action == "block" or observed or decision.monitor)):
        action = "observe" if observed else "monitor" if decision.monitor and decision.action == "allow" else decision.action
        reason = decision.reason or ("; ".join(decision.trail) if decision.trail else "")
        db.add(DnsQueryLog(tenant_id=device.tenant_id, device_id=device.id, qname=qname[:255], qtype=qtype, action=action,
                           reason=reason[:200], category=decision.category[:40], source=decision.source[:20],
                           rule_id=(decision.rule_id or (decision.audits[0]["id"] if decision.audits else ""))[:32],
                           score=decision.score))
    return answer, decision


# Lookups and blocks per device per day, counted in memory and written at most every 30 seconds.
_COUNTS: dict[tuple[str, str, str], list[int]] = {}
_counts_lock = __import__("threading").Lock()
_counts_flushed = [time.time()]


def count(device: Device, blocked: bool) -> None:
    from datetime import datetime, timezone

    key = (device.tenant_id, device.id, datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    with _counts_lock:
        entry = _COUNTS.setdefault(key, [0, 0])
        entry[0] += 1
        entry[1] += int(blocked)


def flush_counts(db: Session, force: bool = False) -> None:
    from sqlalchemy import update

    from .models import DnsDeviceDay

    if not force and time.time() - _counts_flushed[0] < 30:
        return
    with _counts_lock:
        pending = dict(_COUNTS)
        _COUNTS.clear()
        _counts_flushed[0] = time.time()
    for (tenant_id, device_id, day), (queries, blocked) in pending.items():
        changed = db.execute(update(DnsDeviceDay).where(DnsDeviceDay.device_id == device_id, DnsDeviceDay.day == day).values(
            queries=DnsDeviceDay.queries + queries, blocked=DnsDeviceDay.blocked + blocked)).rowcount
        if not changed:
            db.add(DnsDeviceDay(tenant_id=tenant_id, device_id=device_id, day=day, queries=queries, blocked=blocked))
            db.flush()
