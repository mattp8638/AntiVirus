"""Automatic group membership: a group's rules put matching devices into it.

A group's ``match_rules`` look like::

    {"enabled": true, "match": "all", "priority": 100,
     "conditions": [{"field": "platform", "op": "is", "value": "windows"},
                    {"field": "role", "op": "is", "value": "server"},
                    {"field": "hostname", "op": "matches", "value": "LDN-*"}]}

Fields: platform, role (workstation, server, domain-controller, phone, tablet, computer), hostname (a pattern with * and
?), os (text the OS name contains), tag (the device has the tag), ip (the address is inside a range such as 10.1.0.0/16).

``Device.group_rule_id`` says how a device got its group: the group's id when rules placed it, MANUAL when a person did
(including choosing no group), and None when nobody has yet (a device that already had a group before rules existed counts
as placed by hand). A device is placed by rules only while nobody has placed it by hand: moving it to a group in the console, the API or an
enrolment code's group is manual and wins for good, until someone hands it back to the rules ("Automatic"). Among the
groups whose rules match, the lowest priority number wins, then the deepest group, then the name. A device placed by a
rule that stops matching leaves the group again. Rules run when a device enrols, when its tags or inventory change, when
a group's rules are saved, and hourly.
"""

from __future__ import annotations

import fnmatch
import ipaddress

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Device, DeviceGroup

FIELDS = {"platform": ("is", "is not"), "role": ("is", "is not"), "hostname": ("matches", "does not match"),
          "os": ("contains", "does not contain"), "tag": ("has", "does not have"), "ip": ("in", "not in")}
ROLES = ("workstation", "server", "domain-controller", "phone", "tablet", "computer")
PLATFORMS = ("windows", "linux", "macos", "android", "ios")
MAX_CONDITIONS = 20
MANUAL = "manual"


class RuleError(ValueError):
    pass


def clean(rules: dict | None) -> dict:
    """Validated rules, or {} for none. Raises RuleError with a message for the console."""
    if not rules:
        return {}
    if not isinstance(rules, dict):
        raise RuleError("Rules must be an object")
    conditions = rules.get("conditions") or []
    if not isinstance(conditions, list) or len(conditions) > MAX_CONDITIONS:
        raise RuleError(f"A group can have up to {MAX_CONDITIONS} conditions")
    out = []
    for c in conditions:
        if not isinstance(c, dict):
            raise RuleError("Each condition needs a field, a test and a value")
        field, op, value = str(c.get("field") or ""), str(c.get("op") or ""), str(c.get("value") or "").strip()
        if field not in FIELDS:
            raise RuleError(f"Unknown field '{field}'")
        if op not in FIELDS[field]:
            raise RuleError(f"'{op}' does not apply to {field}")
        if not value:
            raise RuleError(f"Give a value for {field}")
        if field == "platform" and value.lower() not in PLATFORMS:
            raise RuleError(f"Platform must be one of {', '.join(PLATFORMS)}")
        if field == "role" and value.lower() not in ROLES:
            raise RuleError(f"Role must be one of {', '.join(ROLES)}")
        if field == "ip":
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise RuleError(f"'{value}' is not an address range such as 10.1.0.0/16") from exc
        out.append({"field": field, "op": op, "value": value[:200]})
    match = rules.get("match", "all")
    if match not in ("all", "any"):
        raise RuleError("match must be all or any")
    try:
        priority = int(rules.get("priority", 100))
    except (TypeError, ValueError) as exc:
        raise RuleError("Priority must be a whole number") from exc
    enabled = bool(rules.get("enabled", True)) and bool(out)
    return {"enabled": enabled, "match": match, "priority": max(0, min(priority, 10000)), "conditions": out}


def _value(device: Device, field: str):
    inventory = device.inventory or {}
    if field == "platform":
        return (device.platform or "").lower()
    if field == "role":
        # What the device reported; phones are phones. A computer whose inventory has not arrived yet matches no role.
        return str(inventory.get("role") or ("phone" if device.platform in ("android", "ios") else "")).lower()
    if field == "hostname":
        return (device.hostname or "").lower()
    if field == "os":
        return (device.os_version or "").lower()
    if field == "tag":
        return [str(t).lower() for t in device.tags or []]
    if field == "ip":
        return device.ip_address or ""
    return ""


def _test(device: Device, condition: dict) -> bool:
    field, op, wanted = condition["field"], condition["op"], condition["value"].lower()
    actual = _value(device, field)
    if field in ("platform", "role"):
        hit = actual == wanted
    elif field == "hostname":
        hit = fnmatch.fnmatchcase(actual, wanted)
    elif field == "os":
        hit = wanted in actual
    elif field == "tag":
        hit = wanted in actual
    else:  # ip
        try:
            hit = bool(actual) and ipaddress.ip_address(actual) in ipaddress.ip_network(wanted, strict=False)
        except ValueError:
            hit = False
    return hit if op in ("is", "matches", "contains", "has", "in") else not hit


def matches(device: Device, rules: dict) -> bool:
    if not rules or not rules.get("enabled") or not rules.get("conditions"):
        return False
    results = (_test(device, c) for c in rules["conditions"])
    return all(results) if rules.get("match", "all") == "all" else any(results)


def _depth(group: DeviceGroup, by_id: dict[str, DeviceGroup]) -> int:
    depth, seen, cursor = 0, set(), group
    while cursor.parent_id and cursor.parent_id in by_id and cursor.id not in seen:
        seen.add(cursor.id)
        cursor = by_id[cursor.parent_id]
        depth += 1
    return depth


def ranked_groups(db: Session, tenant_id: str) -> list[DeviceGroup]:
    groups = db.execute(select(DeviceGroup).where(DeviceGroup.tenant_id == tenant_id)).scalars().all()
    by_id = {g.id: g for g in groups}
    with_rules = [g for g in groups if (g.match_rules or {}).get("enabled")]
    return sorted(with_rules, key=lambda g: (int((g.match_rules or {}).get("priority", 100)), -_depth(g, by_id), g.name.lower()))


def target(device: Device, groups: list[DeviceGroup]) -> DeviceGroup | None:
    return next((g for g in groups if matches(device, g.match_rules or {})), None)


def evaluate(db: Session, device: Device, groups: list[DeviceGroup] | None = None) -> bool:
    """Place one device by the rules, unless someone placed it by hand. True when its group changed."""
    if device.api_key_hash == f"retired-{device.id}":
        return False
    if placed_by_hand(device):
        return False
    chosen = target(device, groups if groups is not None else ranked_groups(db, device.tenant_id))
    new_group = chosen.id if chosen else None
    if new_group == device.group_id:
        device.group_rule_id = new_group
        return False
    device.group_id, device.group_rule_id = new_group, new_group
    return True


def apply_tenant(db: Session, tenant_id: str) -> int:
    """Re-run the rules for every device of a customer. Returns how many moved."""
    groups = ranked_groups(db, tenant_id)
    moved = 0
    for device in db.execute(select(Device).where(Device.tenant_id == tenant_id)).scalars():
        moved += evaluate(db, device, groups)
    return moved


def placed_by_hand(device: Device) -> bool:
    return device.group_rule_id == MANUAL or (device.group_rule_id is None and device.group_id is not None)


def placed_by_rule(device: Device) -> bool:
    return device.group_rule_id not in (None, MANUAL) and device.group_rule_id == device.group_id


def place_by_hand(device: Device, group_id: str | None) -> None:
    """A person chose the group (or no group): rules leave the device alone from now on."""
    device.group_id, device.group_rule_id = group_id, MANUAL


def hand_back(db: Session, device: Device) -> bool:
    """Give a hand-placed device back to the rules."""
    device.group_id = device.group_rule_id = None
    return evaluate(db, device)


def preview(db: Session, tenant_id: str, rules: dict) -> list[Device]:
    retired = Device.api_key_hash == ("retired-" + Device.id)
    devices = db.execute(select(Device).where(Device.tenant_id == tenant_id, ~retired)).scalars().all()
    return [d for d in devices if matches(d, rules)]


def tick(db: Session) -> dict:
    """Hourly: catch devices whose details changed since they were last placed."""
    tenants = {t for (t,) in db.execute(select(DeviceGroup.tenant_id).distinct()).all()}
    moved = sum(apply_tenant(db, t) for t in tenants)
    db.commit()
    return {"moved": moved}
