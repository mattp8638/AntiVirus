"""A self-contained Sigma rule engine.

Supports the parts of the Sigma specification that matter for endpoint
telemetry:

* selections as maps (AND) or lists of maps (OR), keyword lists
* value modifiers: contains, startswith, endswith, all, re, cidr, windash,
  exists, gt, gte, lt, lte, plus Sigma's case-insensitive ``*``/``?`` wildcards
* conditions with and / or / not / parentheses, ``1 of sel_*``, ``all of them``
* logsource matching on category and product
* correlation rules (Sigma v2): event_count, value_count, temporal

Rules compile once into closures, so evaluation is a dictionary walk.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Callable

import yaml

Predicate = Callable[[dict], bool]

# Sigma logsource categories -> normalised event categories (see normalize.py).
CATEGORY_MAP = {
    "process_creation": {"process"},
    "process_termination": {"process"},
    "image_load": {"image_load"},
    "network_connection": {"network"},
    "firewall": {"network"},
    "file_event": {"file"},
    "file_change": {"file"},
    "file_rename": {"file"},
    "file_delete": {"file"},
    "file_access": {"file"},
    "dns_query": {"dns"},
    "dns": {"dns"},
    "registry_event": {"registry"},
    "registry_set": {"registry"},
    "registry_add": {"registry"},
    "registry_delete": {"registry"},
    "ps_script": {"script"},
    "ps_module": {"script"},
    "amsi": {"script"},
    "antivirus": {"malware"},
    "authentication": {"auth"},
    "create_remote_thread": {"process_access"},
    "process_access": {"process_access"},
    "driver_load": {"image_load"},
    "webserver": {"web"},
    "endpoint_protection": {"protection"},
    "proxy": {"web"},
}


class SigmaError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Value matching
# ---------------------------------------------------------------------------


def _wildcard_regex(pattern: str, any_before: bool = False, any_after: bool = False) -> re.Pattern:
    # Sigma: * and ? are wildcards, backslash escapes them. Matching is case-insensitive.
    # contains/startswith/endswith add their wildcards here, outside the value, so a value ending in a
    # backslash ('\\Users\\Public\\') stays a literal backslash instead of escaping the added '*'.
    out = [".*"] if any_before else []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
        i += 1
    if any_after:
        out.append(".*")
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE | re.DOTALL)


def _to_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _windash_variants(value: str) -> list[str]:
    variants = {value}
    for prefix in ("-", "/", "–", "—", "―"):
        variants.add(re.sub(r"(^|\s)[-/–—―]", lambda m: m.group(1) + prefix, value))
    return sorted(variants)


def _value_matcher(raw: Any, modifiers: list[str]) -> Callable[[Any], bool]:
    if raw is None:
        return lambda actual: actual is None or actual == ""

    if "exists" in modifiers:
        want = bool(raw) if isinstance(raw, bool) else str(raw).lower() == "true"
        return lambda actual: (actual is not None) == want

    for op in ("gt", "gte", "lt", "lte"):
        if op in modifiers:
            threshold = float(raw)

            def numeric(actual: Any, op=op, threshold=threshold) -> bool:
                try:
                    number = float(actual)
                except (TypeError, ValueError):
                    return False
                return {"gt": number > threshold, "gte": number >= threshold, "lt": number < threshold, "lte": number <= threshold}[op]

            return numeric

    if "cidr" in modifiers:
        network = ipaddress.ip_network(str(raw), strict=False)

        def in_cidr(actual: Any) -> bool:
            try:
                return ipaddress.ip_address(str(actual)) in network
            except ValueError:
                return False

        return in_cidr

    if "re" in modifiers:
        flags = re.IGNORECASE if "i" in modifiers else 0
        if "m" in modifiers:
            flags |= re.MULTILINE
        if "s" in modifiers:
            flags |= re.DOTALL
        compiled = re.compile(str(raw), flags)
        return lambda actual: actual is not None and compiled.search(_to_text(actual)) is not None

    if isinstance(raw, (int, float)) and not isinstance(raw, bool) and not modifiers:
        return lambda actual: actual is not None and _to_text(actual) == _to_text(raw)

    text = _to_text(raw)
    patterns = _windash_variants(text) if "windash" in modifiers else [text]
    regexes = []
    contains, starts, ends = "contains" in modifiers, "startswith" in modifiers, "endswith" in modifiers
    for pattern in patterns:
        regexes.append(_wildcard_regex(pattern, any_before=contains or (ends and not starts),
                                       any_after=contains or (starts and not ends)))

    def match(actual: Any) -> bool:
        if actual is None:
            return False
        if isinstance(actual, list):
            return any(match(item) for item in actual)
        candidate = _to_text(actual)
        return any(regex.match(candidate) for regex in regexes)

    return match


# ---------------------------------------------------------------------------
# Field lookup
# ---------------------------------------------------------------------------


def lookup(event: dict, field_name: str) -> Any:
    if field_name in event:
        return event[field_name]
    lowered = field_name.lower()
    for key, value in event.items():
        if key.lower() == lowered:
            return value
    return None


def _all_values(event: dict) -> list[str]:
    values = []
    for value in event.values():
        if isinstance(value, (list, tuple)):
            values.extend(_to_text(item) for item in value)
        elif isinstance(value, dict):
            values.extend(_all_values(value))
        elif value is not None:
            values.append(_to_text(value))
    return values


# ---------------------------------------------------------------------------
# Selection compilation
# ---------------------------------------------------------------------------


def _compile_field(spec: str, raw: Any) -> Predicate:
    parts = spec.split("|")
    field_name, modifiers = parts[0], [m.lower() for m in parts[1:]]
    values = raw if isinstance(raw, list) else [raw]
    if not values:
        return lambda event: False
    matchers = [_value_matcher(value, modifiers) for value in values]
    require_all = "all" in modifiers

    def predicate(event: dict) -> bool:
        actual = lookup(event, field_name) if field_name else None
        if field_name == "":
            # "|contains: foo" with no field name = keyword search over all values.
            texts = _all_values(event)
            results = [any(m(text) for text in texts) for m in matchers]
        else:
            results = [m(actual) for m in matchers]
        return all(results) if require_all else any(results)

    return predicate


def _compile_map(selection: dict) -> Predicate:
    predicates = [_compile_field(str(key), value) for key, value in selection.items()]
    return lambda event: all(p(event) for p in predicates)


def _compile_selection(definition: Any) -> Predicate:
    if isinstance(definition, dict):
        return _compile_map(definition)
    if isinstance(definition, list):
        if all(isinstance(item, dict) for item in definition):
            maps = [_compile_map(item) for item in definition]
            return lambda event: any(p(event) for p in maps)
        # Keyword list: any keyword anywhere in the event (case-insensitive substring).
        keywords = [_wildcard_regex(f"*{_to_text(item)}*") for item in definition]
        return lambda event: any(regex.match(text) for regex in keywords for text in _all_values(event))
    if isinstance(definition, str):
        regex = _wildcard_regex(f"*{definition}*")
        return lambda event: any(regex.match(text) for text in _all_values(event))
    raise SigmaError(f"unsupported selection definition: {definition!r}")


# ---------------------------------------------------------------------------
# Condition parser
# ---------------------------------------------------------------------------

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*\-\.]+)")


def _tokenize(condition: str) -> list[str]:
    tokens = []
    pos = 0
    condition = condition.strip()
    while pos < len(condition):
        match = _TOKEN.match(condition, pos)
        if not match:
            raise SigmaError(f"bad condition near: {condition[pos:]!r}")
        tokens.append(match.group(1))
        pos = match.end()
    return tokens


class _ConditionParser:
    def __init__(self, tokens: list[str], selections: dict[str, Predicate]):
        self.tokens = tokens
        self.pos = 0
        self.selections = selections

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        token = self.peek()
        if token is None:
            raise SigmaError("unexpected end of condition")
        self.pos += 1
        return token

    def parse(self) -> Predicate:
        predicate = self.parse_or()
        if self.peek() is not None:
            raise SigmaError(f"unexpected token '{self.peek()}' in condition")
        return predicate

    def parse_or(self) -> Predicate:
        terms = [self.parse_and()]
        while (self.peek() or "").lower() == "or":
            self.take()
            terms.append(self.parse_and())
        return terms[0] if len(terms) == 1 else (lambda e, t=terms: any(p(e) for p in t))

    def parse_and(self) -> Predicate:
        terms = [self.parse_not()]
        while (self.peek() or "").lower() == "and":
            self.take()
            terms.append(self.parse_not())
        return terms[0] if len(terms) == 1 else (lambda e, t=terms: all(p(e) for p in t))

    def parse_not(self) -> Predicate:
        if (self.peek() or "").lower() == "not":
            self.take()
            inner = self.parse_not()
            return lambda e: not inner(e)
        return self.parse_atom()

    def parse_atom(self) -> Predicate:
        token = self.take()
        if token == "(":
            inner = self.parse_or()
            if self.take() != ")":
                raise SigmaError("missing ')' in condition")
            return inner
        lowered = token.lower()
        if lowered in {"1", "any", "all"} and (self.peek() or "").lower() == "of":
            self.take()
            target = self.take()
            if target.lower() == "them":
                names = [name for name in self.selections if not name.startswith("_")]
            else:
                names = [name for name in self.selections if fnmatch.fnmatchcase(name, target)]
            if not names:
                raise SigmaError(f"'{target}' matches no selection")
            group = [self.selections[name] for name in names]
            if lowered == "all":
                return lambda e: all(p(e) for p in group)
            return lambda e: any(p(e) for p in group)
        if token not in self.selections:
            raise SigmaError(f"condition references unknown selection '{token}'")
        return self.selections[token]


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

LEVELS = ("informational", "low", "medium", "high", "critical")


@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    tags: list[str]
    logsource: dict
    description: str = ""
    falsepositives: list[str] = field(default_factory=list)
    predicate: Predicate = field(default=lambda event: False, repr=False)

    @property
    def mitre(self) -> list[str]:
        out = []
        for tag in self.tags:
            if tag.lower().startswith("attack."):
                value = tag.split(".", 1)[1]
                out.append(value.upper() if value[:1].lower() == "t" and value[1:2].isdigit() else value)
        return out

    def applies_to(self, category: str, platform: str | None) -> bool:
        wanted = self.logsource.get("category")
        if wanted and category not in CATEGORY_MAP.get(wanted, {wanted}):
            return False
        product = self.logsource.get("product")
        if product and platform and product.lower() != platform.lower():
            return False
        return True

    def matches(self, event: dict, category: str, platform: str | None = None) -> bool:
        return self.applies_to(category, platform) and self.predicate(event)


@dataclass
class CorrelationRule:
    id: str
    title: str
    level: str
    tags: list[str]
    type: str  # event_count | value_count | temporal
    rules: list[str]
    group_by: list[str]
    timespan_seconds: int
    condition: dict
    value_field: str | None = None
    description: str = ""

    @property
    def mitre(self) -> list[str]:
        return SigmaRule(self.id, self.title, self.level, self.tags, {}).mitre

    def threshold_met(self, observed: int) -> bool:
        ops = {"gt": observed.__gt__, "gte": observed.__ge__, "lt": observed.__lt__, "lte": observed.__le__, "eq": observed.__eq__}
        return all(ops[op](int(value)) for op, value in self.condition.items() if op in ops)


def parse_timespan(value: str | int) -> int:
    if isinstance(value, int):
        return value
    match = re.fullmatch(r"(\d+)\s*([smhd])", str(value).strip())
    if not match:
        raise SigmaError(f"bad timespan '{value}'")
    return int(match.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]


def parse_rule(text: str) -> SigmaRule | CorrelationRule:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SigmaError(f"invalid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise SigmaError("rule must be a YAML mapping")
    rule_id = str(doc.get("id") or "").strip()
    title = str(doc.get("title") or "").strip()
    if not rule_id or not title:
        raise SigmaError("rule needs an id and a title")
    level = str(doc.get("level", "medium")).lower()
    if level not in LEVELS:
        raise SigmaError(f"level must be one of {', '.join(LEVELS)}")
    tags = [str(tag) for tag in doc.get("tags") or []]

    if "correlation" in doc:
        corr = doc["correlation"] or {}
        ctype = corr.get("type")
        if ctype not in {"event_count", "value_count", "temporal"}:
            raise SigmaError("correlation.type must be event_count, value_count or temporal")
        rules = corr.get("rules") or []
        if isinstance(rules, str):
            rules = [rules]
        if not rules:
            raise SigmaError("correlation needs at least one base rule")
        condition = corr.get("condition") or ({"gte": len(rules)} if ctype == "temporal" else {"gte": 1})
        value_field = condition.pop("field", None) if isinstance(condition, dict) else None
        if ctype == "value_count" and not value_field:
            raise SigmaError("value_count correlation needs condition.field")
        group_by = corr.get("group-by") or []
        if isinstance(group_by, str):
            group_by = [group_by]
        return CorrelationRule(
            id=rule_id, title=title, level=level, tags=tags, type=ctype, rules=[str(r) for r in rules],
            group_by=[str(g) for g in group_by], timespan_seconds=parse_timespan(corr.get("timespan", "5m")),
            condition=condition, value_field=value_field, description=str(doc.get("description", "")),
        )

    detection = doc.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        raise SigmaError("detection needs a condition")
    conditions = detection["condition"]
    if isinstance(conditions, str):
        conditions = [conditions]
    selections = {name: _compile_selection(value) for name, value in detection.items() if name not in {"condition", "timeframe"}}
    compiled = [_ConditionParser(_tokenize(cond), selections).parse() for cond in conditions]
    predicate = compiled[0] if len(compiled) == 1 else (lambda e: any(p(e) for p in compiled))
    return SigmaRule(
        id=rule_id, title=title, level=level, tags=tags, logsource=doc.get("logsource") or {},
        description=str(doc.get("description", "")), falsepositives=list(doc.get("falsepositives") or []),
        predicate=predicate,
    )
