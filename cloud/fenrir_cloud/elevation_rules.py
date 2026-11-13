"""Who gets admin access without waiting for a technician (privileged access management).

A request is granted straight away when, in this order:
1. an allowance a technician gave matches (this device or all of the customer's devices; the user or anyone; the kind of
   request; the program, when the allowance names programs);
2. the policy's admin access requests setting is auto-approve;
3. the user is on the policy's auto-approve users list;
4. the program (a "run" request) matches the auto-approve programs list (path, wildcard path or SHA-256) or its
   publisher, as verified on the device, is on the auto-approve publishers list.
Otherwise it waits for a technician when requests are set to approval, and is refused when they are off.
"""
from __future__ import annotations

import fnmatch
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from . import policy_schema
from .models import Device, ElevationAllowance, utcnow

_SHA256 = re.compile(r"[0-9a-fA-F]{64}")


@dataclass
class Decision:
    outcome: str  # "auto" | "pending" | "refused"
    actor: str = ""
    rule: str = ""  # what matched, shown on the request and in the audit log
    allowance: ElevationAllowance | None = None


def active_allowances(db: Session, device: Device, now: datetime | None = None) -> list[ElevationAllowance]:
    now = now or utcnow()
    rows = db.execute(select(ElevationAllowance).where(
        ElevationAllowance.tenant_id == device.tenant_id, ElevationAllowance.revoked_at.is_(None),
        or_(ElevationAllowance.device_id.is_(None), ElevationAllowance.device_id == device.id),
        or_(ElevationAllowance.expires_at.is_(None), ElevationAllowance.expires_at > now),
    ).order_by(ElevationAllowance.created_at)).scalars().all()
    return list(rows)


def _short(name: str) -> str:
    """jo from PC1\\jo, DOMAIN\\jo or jo@example.com."""
    name = name.strip().lower()
    name = name.rsplit("\\", 1)[-1]
    return name.split("@", 1)[0]


def user_matches(entry: str, user: str, sid: str = "", entry_sid: str = "") -> bool:
    if entry_sid:
        return entry_sid.strip().upper() == sid.strip().upper()
    entry = entry.strip().lower()
    if not entry:
        return True
    if "\\" in entry or "@" in entry:
        return entry == user.strip().lower()
    return entry == _short(user)


def program_matches(entry: str, target: str, sha256: str = "") -> bool:
    entry = entry.strip()
    if not entry or not target:
        return False
    if _SHA256.fullmatch(entry):
        return bool(sha256) and entry.lower() == sha256.lower()
    path = target.replace("/", "\\").lower()
    pattern = entry.replace("/", "\\").lower()
    if "*" in pattern or "?" in pattern:
        # [ and ] are ordinary characters in Windows paths, not character classes.
        pattern = pattern.replace("[", "[[]")
        return fnmatch.fnmatchcase(path, pattern)
    return path == pattern


def publisher_matches(entry: str, publisher: str) -> bool:
    return bool(entry.strip()) and bool(publisher) and entry.strip().lower() == publisher.strip().lower()


def allowance_matches(allowance: ElevationAllowance, user: str, sid: str, kind: str, target: str, sha256: str) -> bool:
    if allowance.kinds not in ("any", kind):
        return False
    if not user_matches(allowance.user, user, sid, allowance.user_sid):
        return False
    programs = [p for p in (allowance.programs or []) if str(p).strip()]
    if programs and kind == "run":
        return any(program_matches(str(p), target, sha256) for p in programs)
    if programs and kind == "session":
        return False  # an allowance for named programs does not give general admin access
    return True


def decide(db: Session, device: Device, resolution: dict, *, user: str, sid: str, kind: str, target: str = "",
           publisher: str = "", sha256: str = "") -> Decision:
    for allowance in active_allowances(db, device):
        if allowance_matches(allowance, user, sid, kind, target, sha256):
            return Decision("auto", f"allowance:{allowance.id}",
                            f"allowance from {allowance.created_by or 'a technician'}", allowance)
    mode = policy_schema.elevation_mode(resolution)
    privilege = resolution["settings"].get("privilege", {})
    if mode == "off":
        return Decision("refused")
    if mode == "auto-approve":
        return Decision("auto", "policy:auto-approve", "policy: auto-approve")
    for entry in privilege.get("autoApproveUsers") or []:
        if user_matches(str(entry), user, sid):
            return Decision("auto", "policy:auto-approve-user", f"policy: user {entry}")
    if kind == "run":
        for entry in privilege.get("autoApprovePrograms") or []:
            if program_matches(str(entry), target, sha256):
                return Decision("auto", "policy:auto-approve-program", f"policy: program {entry}")
        for entry in privilege.get("autoApprovePublishers") or []:
            if publisher_matches(str(entry), publisher):
                return Decision("auto", "policy:auto-approve-publisher", f"policy: publisher {entry}")
    return Decision("pending")


def adjust_agent_document(db: Session, device: Device, resolution: dict, doc: dict) -> None:
    """Tells a Windows agent whether its users can ask for admin access (the button in the agent window).

    The agent reads privilege.elevationRequests. It gets the effective setting, or "approval" when the policy has
    requests off but a technician has given an allowance on this device (the cloud then decides each request).
    Older agents also need privilege.enabled to accept requests; when it is forced on for that reason, removing
    standing admin rights keeps the value it had before (it only works with the switch on).
    """
    modules = doc.get("modules")
    if not isinstance(modules, dict) or not isinstance(modules.get("privilege"), dict):
        return
    privilege = modules["privilege"] = dict(modules["privilege"])  # shared with the resolution: never change that one
    mode = policy_schema.elevation_mode(resolution)
    allowances = active_allowances(db, device)
    if mode == "off" and allowances:
        mode = "auto-approve" if any(not a.user and not a.user_sid and not (a.programs or []) and a.kinds == "any"
                                     for a in allowances) else "approval"
    privilege["elevationRequests"] = mode
    if mode != "off" and not privilege.get("enabled"):
        privilege["enabled"] = True
        privilege["removeLocalAdmins"] = False
    if allowances or mode != str(resolution["settings"].get("privilege", {}).get("elevationRequests")):
        stamp = "|".join([mode] + [f"{a.id}:{a.expires_at.isoformat() if a.expires_at else ''}" for a in allowances])
        doc["revision"] = hashlib.sha256(f"{doc['revision']}|elevation|{stamp}".encode()).hexdigest()[:16]
