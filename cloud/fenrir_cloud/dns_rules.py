"""DNS rules and allow/block lists, like Defender custom indicators and Heimdal's DNS rules.

Two kinds of row in ``dns_rules``:

- **entry**: one allow or block line ("contoso.com", "*.ads.example"), optionally for one device or group, with an
  expiry. What a technician adds from the query log in one click.
- **rule**: the same plus conditions. Match type (domain and its subdomains, exact name, wildcard, safe regular
  expression, or a category), scope (the customer, device groups, single devices), query types, a weekly schedule,
  priority, and **audit mode**, which only records what the rule would have done.

Rules on the MSP's own tenant apply to every customer. Order of evaluation, first match wins:

1. scope: device rules, then group rules, then customer rules, then MSP-wide rules (the closest one decides);
2. priority (lower first);
3. at the same priority, allow before block (as Defender: an allow indicator wins).

Audit-mode rules and ``monitor`` rules never decide: they are recorded on the query (and the query is logged even
when the policy logs blocked lookups only). Every change is versioned in ``dns_rule_changes`` and can be restored.
"""
from __future__ import annotations

import re
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .models import Device, DeviceGroup, DnsRule, DnsRuleChange, Tenant, utcnow

ACTIONS = ("allow", "block", "monitor")
MATCHES = ("domain", "exact", "wildcard", "regex", "category")
SCOPES = ("tenant", "group", "device")
QTYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "HTTPS", "SVCB", "SRV", "PTR", "NS", "SOA", "ANY")
MAX_PATTERNS = 500
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
_WILDCARD = re.compile(r"^[a-z0-9_*.\-]{1,253}$")
_UNSAFE_REGEX = re.compile(r"\(\?[^:)]|\\[1-9]|(\+|\*|\})\s*(\+|\*|\{)|\([^)]*[+*}][^)]*\)\s*[+*{]")
_TIME = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_SCOPE_RANK = {"device": 0, "group": 1, "tenant": 2}
_ACTION_RANK = {"allow": 0, "block": 1, "monitor": 2}


class RuleError(ValueError):
    pass


def _clean_patterns(match: str, patterns) -> list[str]:
    from .policy_schema import DNS_CATEGORIES

    if isinstance(patterns, str):
        patterns = re.split(r"[\s,]+", patterns)
    if not isinstance(patterns, list):
        raise RuleError("patterns must be a list")
    out: list[str] = []
    for raw in patterns:
        value = str(raw or "").strip().lower().rstrip(".")
        if not value:
            continue
        if match in ("domain", "exact"):
            if value.startswith("*."):
                value = value[2:]
            value = re.sub(r"^[a-z]+://", "", value).split("/")[0].split(":")[0]
            if not _DOMAIN.match(value):
                raise RuleError(f"'{raw}' is not a domain name")
        elif match == "wildcard":
            if not _WILDCARD.match(value) or "*" not in value:
                raise RuleError(f"'{raw}': a wildcard uses letters, digits, dots, hyphens and * (for example *.ads.*.example)")
        elif match == "regex":
            if len(value) > 200:
                raise RuleError("a pattern can be at most 200 characters")
            if _UNSAFE_REGEX.search(value):
                raise RuleError(f"'{raw}' uses features not allowed in DNS rules (back-references, look-arounds, nested repeats)")
            try:
                re.compile(value)
            except re.error as exc:
                raise RuleError(f"'{raw}' is not a valid pattern: {exc}") from None
        elif match == "category":
            if value not in DNS_CATEGORIES:
                raise RuleError(f"unknown category '{raw}'")
        if value not in out:
            out.append(value)
    if not out:
        raise RuleError("add at least one domain, pattern or category")
    if len(out) > MAX_PATTERNS:
        raise RuleError(f"at most {MAX_PATTERNS} patterns in one rule")
    return out


def validate(db: Session, tenant_id: str, body: dict, principal_tenants: frozenset[str] | None = None) -> dict:
    """A clean rule from the console's JSON, or RuleError with a message a technician can act on."""
    kind = body.get("kind", "rule")
    if kind not in ("rule", "entry"):
        raise RuleError("kind must be rule or entry")
    action = body.get("action", "block")
    if action not in ACTIONS:
        raise RuleError("action must be allow, block or monitor")
    match = body.get("match", "domain")
    if match not in MATCHES or (kind == "entry" and match not in ("domain", "exact", "wildcard")):
        raise RuleError("unsupported match type")
    scope_type = body.get("scopeType", "tenant")
    if scope_type not in SCOPES:
        raise RuleError("scope must be tenant, group or device")
    scope_ids = [str(x) for x in (body.get("scopeIds") or []) if str(x).strip()]
    if scope_type != "tenant":
        if not scope_ids:
            raise RuleError(f"choose at least one {scope_type}")
        model = DeviceGroup if scope_type == "group" else Device
        found = {row.id: row.tenant_id for row in db.execute(select(model).where(model.id.in_(scope_ids))).scalars()}
        allowed = principal_tenants if principal_tenants is not None else frozenset({tenant_id})
        for item in scope_ids:
            if item not in found or found[item] not in allowed:
                raise RuleError(f"{scope_type} {item} not found")
    else:
        scope_ids = []
    qtypes = [str(q).upper() for q in (body.get("qtypes") or [])]
    if any(q not in QTYPES for q in qtypes):
        raise RuleError(f"query types must be from {', '.join(QTYPES)}")
    schedule = body.get("schedule") or {}
    if schedule:
        days = schedule.get("days") or []
        if not isinstance(days, list) or not days or any(not isinstance(d, int) or d < 0 or d > 6 for d in days):
            raise RuleError("schedule days are 0 (Monday) to 6 (Sunday)")
        start, end = schedule.get("start", "00:00"), schedule.get("end", "23:59")
        if not _TIME.match(str(start)) or not _TIME.match(str(end)):
            raise RuleError("schedule times look like 09:00")
        schedule = {"days": sorted(set(days)), "start": start, "end": end, "timezone": str(schedule.get("timezone") or "")[:64]}
    mode = body.get("mode", "enforce")
    if mode not in ("enforce", "audit"):
        raise RuleError("mode must be enforce or audit")
    expires = body.get("expiresAt")
    expires_at = None
    if expires:
        try:
            expires_at = datetime.fromisoformat(str(expires).replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            raise RuleError("expiry is not a date") from None
    patterns = _clean_patterns(match, body.get("patterns"))
    name = str(body.get("name") or "").strip()[:200] or f"{action.title()} {patterns[0]}{' +' + str(len(patterns) - 1) if len(patterns) > 1 else ''}"
    try:
        priority = max(0, min(10000, int(body.get("priority", 100))))
    except (TypeError, ValueError):
        raise RuleError("priority is a number") from None
    return {"kind": kind, "name": name, "action": action, "match": match, "patterns": patterns, "scope_type": scope_type,
            "scope_ids": scope_ids, "qtypes": qtypes, "schedule": schedule, "mode": mode if kind == "rule" else "enforce",
            "priority": priority, "enabled": bool(body.get("enabled", True)), "comment": str(body.get("comment") or "")[:500],
            "expires_at": expires_at}


FIELDS = ("kind", "name", "action", "match", "patterns", "scope_type", "scope_ids", "qtypes", "schedule", "mode", "priority",
          "enabled", "comment", "expires_at")


def snapshot(rule: DnsRule) -> dict:
    out = {f: getattr(rule, f) for f in FIELDS}
    out["expires_at"] = rule.expires_at.isoformat() + "Z" if rule.expires_at else None
    return out


def _changes(before: dict, after: dict) -> list[dict]:
    return [{"field": f, "from": before.get(f), "to": after.get(f)} for f in FIELDS if before.get(f) != after.get(f)]


def save(db: Session, tenant_id: str, clean: dict, actor: str, rule: DnsRule | None = None, comment: str = "",
         change: str | None = None) -> DnsRule:
    before = snapshot(rule) if rule else {}
    if rule is None:
        rule = DnsRule(tenant_id=tenant_id, created_by=actor, version=0)
        db.add(rule)
    for key, value in clean.items():
        setattr(rule, key, value)
    rule.version = (rule.version or 0) + 1
    rule.updated_at = utcnow()
    db.flush()
    after = snapshot(rule)
    db.add(DnsRuleChange(rule_id=rule.id, tenant_id=rule.tenant_id, version=rule.version, actor=actor, comment=comment[:500],
                         change=change or ("update" if before else "create"), snapshot=after, changes=_changes(before, after)))
    CACHE.invalidate()
    return rule


def delete(db: Session, rule: DnsRule, actor: str, comment: str = "") -> None:
    db.add(DnsRuleChange(rule_id=rule.id, tenant_id=rule.tenant_id, version=(rule.version or 0) + 1, actor=actor, change="delete",
                         comment=comment[:500], snapshot=snapshot(rule), changes=[]))
    db.delete(rule)
    CACHE.invalidate()


def view(rule: DnsRule, names: dict[str, str] | None = None) -> dict:
    now = utcnow()
    return {"id": rule.id, "tenantId": rule.tenant_id, "kind": rule.kind, "name": rule.name, "action": rule.action,
            "match": rule.match, "patterns": rule.patterns or [], "scopeType": rule.scope_type, "scopeIds": rule.scope_ids or [],
            "scopeNames": [(names or {}).get(i, i) for i in rule.scope_ids or []], "qtypes": rule.qtypes or [],
            "schedule": rule.schedule or {}, "mode": rule.mode, "priority": rule.priority, "enabled": rule.enabled,
            "comment": rule.comment, "expiresAt": rule.expires_at.isoformat() + "Z" if rule.expires_at else None,
            "expired": bool(rule.expires_at and rule.expires_at <= now), "hits": rule.hits or 0,
            "lastHitAt": rule.last_hit_at.isoformat() + "Z" if rule.last_hit_at else None, "version": rule.version,
            "createdBy": rule.created_by, "createdAt": rule.created_at.isoformat() + "Z",
            "updatedAt": rule.updated_at.isoformat() + "Z" if rule.updated_at else None}


# --------------------------------------------------------------------------- evaluation


@dataclass
class Compiled:
    id: str
    kind: str
    name: str
    action: str
    match: str
    scope_type: str
    scope_ids: frozenset[str]
    qtypes: frozenset[str]
    schedule: dict
    mode: str
    priority: int
    msp: bool
    exact: frozenset[str] = frozenset()
    suffixes: frozenset[str] = frozenset()
    regexes: tuple = ()
    categories: frozenset[str] = frozenset()

    @property
    def order(self) -> tuple:
        return (_SCOPE_RANK[self.scope_type] + (1 if self.msp and self.scope_type == "tenant" else 0), self.priority,
                _ACTION_RANK[self.action])

    def matches_name(self, domain: str, candidates: list[str], category_of) -> bool:
        if self.match == "exact":
            return domain in self.exact
        if self.match == "domain":
            return any(c in self.suffixes for c in candidates)
        if self.match == "category":
            return category_of() in self.categories
        return any(r.match(domain) for r in self.regexes)

    def in_schedule(self, now: datetime, tz_name: str) -> bool:
        if not self.schedule:
            return True
        try:
            from zoneinfo import ZoneInfo

            local = now.replace(tzinfo=ZoneInfo("UTC")).astimezone(ZoneInfo(self.schedule.get("timezone") or tz_name or "UTC"))
        except Exception:  # noqa: BLE001 - an unknown zone falls back to UTC
            local = now
        start, end, minute = self.schedule.get("start", "00:00"), self.schedule.get("end", "23:59"), local.strftime("%H:%M")
        if local.weekday() not in self.schedule.get("days", []):
            return False
        return start <= minute <= end if start <= end else (minute >= start or minute <= end)  # overnight windows


def compile_rule(rule: DnsRule, msp: bool) -> Compiled:
    base = dict(id=rule.id, kind=rule.kind, name=rule.name, action=rule.action, match=rule.match, scope_type=rule.scope_type,
                scope_ids=frozenset(rule.scope_ids or []), qtypes=frozenset(rule.qtypes or []), schedule=rule.schedule or {},
                mode=rule.mode, priority=rule.priority, msp=msp)
    patterns = rule.patterns or []
    if rule.match == "exact":
        return Compiled(**base, exact=frozenset(patterns))
    if rule.match == "domain":
        return Compiled(**base, suffixes=frozenset(patterns))
    if rule.match == "category":
        return Compiled(**base, categories=frozenset(patterns))
    if rule.match == "wildcard":
        regexes = tuple(re.compile("^" + re.escape(p).replace(r"\*", "[a-z0-9_.-]*") + "$") for p in patterns)
    else:
        regexes = tuple(re.compile(p) for p in patterns)
    return Compiled(**base, regexes=regexes)


@dataclass
class Outcome:
    action: str = ""  # allow | block when a rule decided
    rule: Compiled | None = None
    audits: list[dict] = field(default_factory=list)  # audit-mode and monitor rules that matched
    trail: list[str] = field(default_factory=list)


class DeviceRules:
    """The rules that apply to one device (or to a whole customer when no device is given), in evaluation order."""

    def __init__(self, rules: list[Compiled], device_id: str | None, group_ids: frozenset[str], tz_name: str):
        self.rules = rules
        self.device_id = device_id
        self.group_ids = group_ids
        self.tz_name = tz_name

    def evaluate(self, domain: str, candidates: list[str], qtype: str, category_of, now: datetime | None = None) -> Outcome:
        now = now or utcnow()
        outcome = Outcome()
        for rule in self.rules:
            if rule.scope_type == "device" and self.device_id not in rule.scope_ids:
                continue
            if rule.scope_type == "group" and not (rule.scope_ids & self.group_ids):
                continue
            if rule.qtypes and qtype not in rule.qtypes:
                continue
            if not rule.matches_name(domain, candidates, category_of) or not rule.in_schedule(now, self.tz_name):
                continue
            HITS[rule.id] += 1
            label = f"{'List entry' if rule.kind == 'entry' else 'Rule'} \"{rule.name}\""
            if rule.mode == "audit" or rule.action == "monitor":
                outcome.audits.append({"id": rule.id, "name": rule.name, "action": rule.action, "mode": rule.mode})
                outcome.trail.append(f"{label}: {'audit only, would ' + rule.action if rule.mode == 'audit' else 'monitored'}")
                continue
            outcome.action, outcome.rule = rule.action, rule
            outcome.trail.append(f"{label}: {rule.action}")
            return outcome
        return outcome


class RuleCache:
    """Compiled rules per customer (its own and the MSP's), reloaded every 30 seconds or when a rule changes."""

    def __init__(self, ttl: int = 30):
        self.ttl = ttl
        self._lock = threading.Lock()
        self._tenants: dict[str, tuple[float, list[Compiled], dict[str, str | None], str]] = {}

    def invalidate(self) -> None:
        with self._lock:
            self._tenants.clear()

    def _load(self, db: Session, tenant_id: str):
        with self._lock:
            cached = self._tenants.get(tenant_id)
            if cached and time.time() - cached[0] < self.ttl:
                return cached
        tenant = db.get(Tenant, tenant_id)
        chain = [tenant_id]
        parent = tenant.parent_id if tenant else None
        while parent and parent not in chain and len(chain) < 10:
            chain.append(parent)
            row = db.get(Tenant, parent)
            parent = row.parent_id if row else None
        now = utcnow()
        rows = db.execute(select(DnsRule).where(DnsRule.tenant_id.in_(chain), DnsRule.enabled.is_(True),
                                                (DnsRule.expires_at.is_(None)) | (DnsRule.expires_at > now))).scalars().all()
        compiled = sorted((compile_rule(r, r.tenant_id != tenant_id) for r in rows), key=lambda c: c.order)
        groups = {g.id: g.parent_id for g in db.execute(select(DeviceGroup).where(DeviceGroup.tenant_id == tenant_id)).scalars()}
        tz_name = str(((tenant.settings or {}) if tenant else {}).get("timezone") or "UTC")
        entry = (time.time(), compiled, groups, tz_name)
        with self._lock:
            self._tenants[tenant_id] = entry
        return entry

    def for_device(self, db: Session, device: Device) -> DeviceRules:
        _, compiled, groups, tz_name = self._load(db, device.tenant_id)
        chain, current = set(), device.group_id
        while current and current not in chain and len(chain) < 20:  # a rule for a group also covers its subgroups
            chain.add(current)
            current = groups.get(current)
        return DeviceRules(compiled, device.id, frozenset(chain), tz_name)

    def for_tenant(self, db: Session, tenant_id: str) -> DeviceRules:
        _, compiled, _, tz_name = self._load(db, tenant_id)
        return DeviceRules([c for c in compiled if c.scope_type == "tenant"], None, frozenset(), tz_name)


CACHE = RuleCache()
HITS: Counter = Counter()
_hits_lock = threading.Lock()
_last_flush = [time.time()]


def flush_hits(db: Session, force: bool = False) -> None:
    """Write buffered hit counts (at most every 30 seconds) so busy resolvers don't update a row per lookup."""
    if not force and time.time() - _last_flush[0] < 30:
        return
    with _hits_lock:
        pending = dict(HITS)
        HITS.clear()
        _last_flush[0] = time.time()
    now = utcnow()
    for rule_id, count in pending.items():
        db.execute(update(DnsRule).where(DnsRule.id == rule_id).values(hits=DnsRule.hits + count, last_hit_at=now))


def history(db: Session, rule_id: str) -> list[DnsRuleChange]:
    return list(db.execute(select(DnsRuleChange).where(DnsRuleChange.rule_id == rule_id)
                           .order_by(DnsRuleChange.version.desc())).scalars())


def restore_clean(snapshot_: dict) -> dict:
    clean = {k: snapshot_.get(k) for k in FIELDS}
    clean["expires_at"] = datetime.fromisoformat(snapshot_["expires_at"].replace("Z", "")) if snapshot_.get("expires_at") else None
    return clean


def expiring(db: Session, tenant_ids: list[str], days: int = 7) -> int:
    from sqlalchemy import func

    now = utcnow()
    return db.execute(select(func.count()).select_from(DnsRule).where(
        DnsRule.tenant_id.in_(tenant_ids), DnsRule.expires_at > now, DnsRule.expires_at <= now + timedelta(days=days))).scalar() or 0
