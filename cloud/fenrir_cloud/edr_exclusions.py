"""Strict EDR exclusions for RMM agents and other trusted tooling.

Name-only exclusions ("powershell.exe", "agent.exe") let any file with that name through. These rules are
bound to file content instead:

``process-chain``
    A child process is trusted only when its **parent's image path and SHA-256** both match. Typical use: an
    MSP's own RMM agent that runs PowerShell, cmd or bash scripts which would otherwise trip "suspicious
    child process" or obfuscated-script rules. Optional child path, child hash and command-line filters narrow
    it further.
``hash``
    One exact file (SHA-256), optionally also bound to its path.

Each rule lists the scopes it relaxes: ``behavior`` (attack-surface and application-control rules on the
agent), ``antimalware`` (signature/ML verdicts on the child image) and ``sigma`` (cloud detection alerts).

Matching is identical in the cloud (here), the Linux agent (``fleet/exclusions.go``) and the Windows
service (``BehaviorRules.cpp``): paths are compared case-insensitively with ``/`` and ``\\`` treated alike,
and ``*``/``?`` wildcards are allowed only in the final path component, so a rule cannot cover a whole
directory tree.
"""

from __future__ import annotations

import fnmatch
import re
from datetime import datetime

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .models import EdrExclusion, Tenant, utcnow

SCOPES = ("behavior", "antimalware", "sigma")
KINDS = ("process-chain", "hash")
MAX_RULES_PER_DEVICE = 500
_SHA256 = re.compile(r"[0-9a-f]{64}")

# Interpreters an RMM agent typically launches for scripts, per platform.
RMM_INTERPRETERS = {
    "windows": [r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"C:\Program Files\PowerShell\7\pwsh.exe",
                r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\cscript.exe", r"C:\Windows\System32\wscript.exe"],
    "linux": ["/bin/bash", "/usr/bin/bash", "/bin/sh", "/usr/bin/sh", "/usr/bin/python3", "/usr/bin/pwsh"],
    "macos": ["/bin/bash", "/bin/zsh", "/bin/sh", "/usr/bin/python3", "/usr/local/bin/pwsh"],
}


class ExclusionError(ValueError):
    pass


def normalise_path(path: str) -> str:
    return path.strip().replace("\\", "/").lower()


def _valid_pattern(pattern: str) -> bool:
    """An absolute path whose directory part has no wildcards."""
    path = normalise_path(pattern)
    if not path:
        return False
    absolute = path.startswith("/") or re.match(r"^[a-z]:/", path) is not None
    directory = path.rsplit("/", 1)[0] if "/" in path else ""
    return absolute and not any(ch in directory for ch in "*?[") and ".." not in path.split("/")


def path_matches(pattern: str, path: str) -> bool:
    if not pattern:
        return True
    want, have = normalise_path(pattern), normalise_path(path)
    if not have:
        return False
    want_dir, _, want_name = want.rpartition("/")
    have_dir, _, have_name = have.rpartition("/")
    return want_dir == have_dir and fnmatch.fnmatchcase(have_name, want_name.replace("[", "[[]"))


def _hashes(values) -> list[str]:
    if isinstance(values, str):
        values = re.split(r"[\s,;]+", values)
    out = []
    for value in values or []:
        value = str(value).strip().lower()
        if not value:
            continue
        if not _SHA256.fullmatch(value):
            raise ExclusionError(f"'{value[:20]}…' is not a SHA-256 hash")
        out.append(value)
    return sorted(set(out))


def validate(body: dict, existing: EdrExclusion | None = None) -> dict:
    """Return clean column values for a create/update body, or raise ExclusionError."""
    def pick(key: str, attr: str, default=None):
        if key in body:
            return body[key]
        return getattr(existing, attr) if existing is not None else default

    kind = str(pick("kind", "kind", "process-chain"))
    if kind not in KINDS:
        raise ExclusionError(f"kind must be one of {', '.join(KINDS)}")
    name = str(pick("name", "name", "") or "").strip()
    if not name:
        raise ExclusionError("A name is required")
    parent_image = str(pick("parentImage", "parent_image", "") or "").strip()
    child_image = str(pick("childImage", "child_image", "") or "").strip()
    parent_sha = _hashes(pick("parentSha256", "parent_sha256", []))
    child_sha = _hashes(pick("childSha256", "child_sha256", []))
    scopes = [str(s) for s in (pick("scopes", "scopes", None) or ["behavior", "sigma"])]
    if not scopes or any(s not in SCOPES for s in scopes):
        raise ExclusionError(f"scopes must be chosen from {', '.join(SCOPES)}")
    reason = str(pick("reason", "reason", "") or "").strip()
    if len(reason) < 10:
        raise ExclusionError("Explain why this exclusion is safe (at least 10 characters); it is shown to reviewers")
    if kind == "process-chain":
        if not parent_image or not _valid_pattern(parent_image):
            raise ExclusionError("parentImage must be the full path of the parent executable; a * is allowed only in the file name")
        if not parent_sha:
            raise ExclusionError("A process-chain exclusion needs at least one parent SHA-256 so a renamed copy is not trusted")
    else:
        if not child_sha:
            raise ExclusionError("A hash exclusion needs at least one SHA-256")
        parent_image, parent_sha = "", []
    if child_image and not _valid_pattern(child_image):
        raise ExclusionError("childImage must be a full path; a * is allowed only in the file name")
    if "antimalware" in scopes and not child_sha:
        raise ExclusionError("The antimalware scope skips file verdicts, so it needs the child's SHA-256")
    expires = pick("expiresAt", "expires_at", None)
    if isinstance(expires, str):
        try:
            expires = datetime.fromisoformat(expires.replace("Z", "+00:00")).replace(tzinfo=None) if expires else None
        except ValueError as exc:
            raise ExclusionError("expiresAt must be an ISO date") from exc
    return {"kind": kind, "name": name[:200], "parent_image": parent_image[:500], "parent_sha256": parent_sha,
            "child_image": child_image[:500], "child_sha256": child_sha,
            "command_line_contains": str(pick("commandLineContains", "command_line_contains", "") or "")[:500],
            "scopes": sorted(set(scopes)), "reason": reason[:1000], "enabled": bool(pick("enabled", "enabled", True)),
            "expires_at": expires}


def ancestors(db: Session, tenant_id: str | None) -> list[str]:
    chain, seen = [], set()
    while tenant_id and tenant_id not in seen:
        seen.add(tenant_id)
        chain.append(tenant_id)
        tenant = db.get(Tenant, tenant_id)
        tenant_id = tenant.parent_id if tenant else None
    return chain


def active_for(db: Session, tenant_id: str | None) -> list[EdrExclusion]:
    """Enabled, unexpired rules for a tenant: platform-wide ones plus the tenant's and its parents'."""
    scope = EdrExclusion.tenant_id.is_(None)
    chain = ancestors(db, tenant_id)
    if chain:
        scope = or_(scope, EdrExclusion.tenant_id.in_(chain))
    return db.execute(select(EdrExclusion).where(scope, EdrExclusion.enabled.is_(True),
                                                 or_(EdrExclusion.expires_at.is_(None), EdrExclusion.expires_at > utcnow()))
                      .order_by(EdrExclusion.created_at).limit(MAX_RULES_PER_DEVICE)).scalars().all()


def agent_rules(rules: list[EdrExclusion], scope: str | None = None) -> list[dict]:
    """The rule list agents receive under ``modules.edrExclusions``."""
    return [{"id": r.id, "kind": r.kind, "parentImage": r.parent_image, "parentSha256": list(r.parent_sha256 or []),
             "childImage": r.child_image, "childSha256": list(r.child_sha256 or []),
             "commandLineContains": r.command_line_contains, "scopes": list(r.scopes or [])}
            for r in rules if scope is None or scope in (r.scopes or [])]


def matches(rule: dict, *, image: str = "", sha256: str = "", parent_image: str = "", parent_sha256: str = "",
            command_line: str = "") -> bool:
    """Does one agent-format rule cover this process? Missing hashes never match (fail closed)."""
    if rule.get("childImage") and not path_matches(rule["childImage"], image):
        return False
    child_hashes = rule.get("childSha256") or []
    if child_hashes and (sha256 or "").lower() not in child_hashes:
        return False
    needle = (rule.get("commandLineContains") or "").lower()
    if needle and needle not in (command_line or "").lower():
        return False
    if rule.get("kind") == "hash":
        return bool(child_hashes)
    return (bool(rule.get("parentImage")) and path_matches(rule["parentImage"], parent_image)
            and (parent_sha256 or "").lower() in (rule.get("parentSha256") or []))


def first_match(rules: list[dict], fields: dict) -> dict | None:
    """The first rule covering a normalised telemetry event (Image, sha256, ParentImage, ParentSha256)."""
    def text(key: str) -> str:
        value = fields.get(key)
        return value if isinstance(value, str) else ""

    for rule in rules:
        if matches(rule, image=text("Image"), sha256=text("sha256"), parent_image=text("ParentImage"),
                   parent_sha256=text("ParentSha256"), command_line=text("CommandLine")):
            return rule
    return None


def record_hit(db: Session, rule_id: str, at: datetime | None = None) -> None:
    row = db.get(EdrExclusion, rule_id)
    if row is not None:
        row.hits = (row.hits or 0) + 1
        row.last_hit_at = at or utcnow()


def rmm_profile(body: dict) -> list[dict]:
    """Expand an RMM agent description into one process-chain rule per script interpreter.

    ``{"name", "platform", "agentImage", "agentSha256": [...], "interpreters": [...]?, "scopes"?, "reason"}``
    """
    platform = str(body.get("platform") or "windows")
    if platform not in RMM_INTERPRETERS:
        raise ExclusionError(f"platform must be one of {', '.join(RMM_INTERPRETERS)}")
    interpreters = [str(i) for i in (body.get("interpreters") or RMM_INTERPRETERS[platform]) if str(i).strip()]
    name = str(body.get("name") or "RMM agent").strip()
    rules = []
    for interpreter in interpreters:
        base = re.split(r"[\\/]", interpreter)[-1]
        rules.append({"kind": "process-chain", "name": f"{name}: {base}", "parentImage": body.get("agentImage"),
                      "parentSha256": body.get("agentSha256"), "childImage": interpreter,
                      "scopes": body.get("scopes") or ["behavior", "sigma"], "reason": body.get("reason") or "",
                      "expiresAt": body.get("expiresAt")})
    return rules


def view(row: EdrExclusion) -> dict:
    return {"id": row.id, "tenantId": row.tenant_id, "name": row.name, "kind": row.kind, "parentImage": row.parent_image,
            "parentSha256": row.parent_sha256 or [], "childImage": row.child_image, "childSha256": row.child_sha256 or [],
            "commandLineContains": row.command_line_contains, "scopes": row.scopes or [], "reason": row.reason,
            "profile": row.profile, "enabled": row.enabled,
            "expiresAt": row.expires_at.isoformat() if row.expires_at else None,
            "expired": bool(row.expires_at and row.expires_at <= utcnow()), "createdBy": row.created_by,
            "createdAt": row.created_at.isoformat() if row.created_at else None, "hits": row.hits or 0,
            "lastHitAt": row.last_hit_at.isoformat() if row.last_hit_at else None}
