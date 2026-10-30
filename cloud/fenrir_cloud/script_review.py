"""Second-person review of scripts before they reach devices.

With Settings > Platform > Security > "Require script review" on, a library script or a remediation package runs only
in a version someone reviewed who did not write or edit it since the last review. Any change to what runs (the script
text, its language, parameters or run-as account) needs a new review; renaming or re-describing it does not.
Scripts and packages shipped with Fenrir count as reviewed until someone changes them. Running a script that is not
part of the library (a bare "script.run" command) is refused while review is required.

The review is recorded on the item: the fingerprint of the content approved, who approved it and when, and a copy of
the approved text so the next reviewer sees what changed.
"""

from __future__ import annotations

import difflib
import hashlib
import json

from fastapi import HTTPException
from sqlalchemy.orm import Session

from . import audit, platform_security
from .models import Script, utcnow


class NotReviewed(ValueError):
    """Raised where a script would be sent; callers already turn ValueError into a refusal."""


def required(db: Session) -> bool:
    return bool(platform_security.get(db).get("scriptReview"))


def _content(item) -> dict:
    if isinstance(item, Script):
        return {"language": item.language, "body": item.body or "", "parameters": item.parameters or [], "runAs": item.run_as}
    return {"language": item.language, "detection": item.detection_script or "", "remediation": item.remediation_script or ""}


def content_hash(item) -> str:
    return hashlib.sha256(json.dumps(_content(item), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _shipped(item) -> bool:
    """Exactly as Fenrir shipped it: built-in library scripts nobody has edited, and packages matching their template."""
    if isinstance(item, Script):
        return bool(item.builtin) and item.updated_by == "system"
    if not item.builtin_key:
        return False
    from .condition_remediation import BUILTIN
    template = next((t for t in BUILTIN if t["key"] == item.builtin_key), None)
    return template is not None and (item.language, item.detection_script, item.remediation_script) == (
        template["language"], template["detection"], template["remediation"])


def _editors(item) -> list[str]:
    if item.review_editors:
        return list(item.review_editors)
    author = item.updated_by if isinstance(item, Script) else item.created_by
    return [author] if author and author != "system" else []


def status(item) -> str:
    """shipped | reviewed | pending"""
    if (item.review or {}).get("hash") == content_hash(item):
        return "reviewed"
    return "shipped" if _shipped(item) else "pending"


def view(db: Session, item) -> dict:
    review = item.review or {}
    state = status(item)
    return {"required": required(db), "status": state, "hash": content_hash(item), "editors": _editors(item) if state == "pending" else [],
            "reviewedBy": review.get("by"), "reviewedAt": review.get("at")}


def _name(item) -> str:
    return item.name or "This script"


def check(db: Session, item) -> None:
    if required(db) and status(item) == "pending":
        raise NotReviewed(f"{_name(item)} has changes that nobody else has reviewed yet. Someone with the approve permission "
                          "must review it before it can run.")


def before_edit(item) -> tuple[str, list[str], str]:
    return content_hash(item), _editors(item), status(item)


def edited(item, actor: str, before: tuple[str, list[str], str]) -> None:
    """Call after a change with before_edit(item) from before it. Everyone who changed an unreviewed version is
    remembered, so none of them can be its reviewer."""
    before_hash, before_editors, before_status = before
    current = content_hash(item)
    if current == before_hash:
        return
    if (item.review or {}).get("hash") == current:
        item.review_editors = None  # changed back to what was reviewed
        return
    carried = before_editors if before_status == "pending" else []
    item.review_editors = sorted(set(carried) | {actor})


def diff(item) -> str:
    """What changed since the last review, as a unified diff ("" when nothing was reviewed before)."""
    snapshot = (item.review or {}).get("content")
    if not snapshot:
        return ""
    current = _content(item)
    lines: list[str] = []
    for key in sorted(set(snapshot) | set(current)):
        old, new = snapshot.get(key), current.get(key)
        if old == new:
            continue
        as_text = lambda v: (v if isinstance(v, str) else json.dumps(v, indent=2, sort_keys=True)).splitlines()  # noqa: E731
        lines.extend(difflib.unified_diff(as_text(old), as_text(new), f"{key} (reviewed)", f"{key} (now)", lineterm=""))
    return "\n".join(lines)


def approve(db: Session, principal, item, seen_hash: str) -> None:
    principal.require("approve")
    principal.require("scripts")
    if seen_hash != content_hash(item):
        raise HTTPException(409, "It changed while you were reviewing it. Look at it again.")
    if principal.actor in _editors(item):
        raise HTTPException(403, "Someone who did not write or edit this version has to review it")
    if status(item) == "reviewed":
        return
    item.review = {"hash": content_hash(item), "by": principal.actor, "at": utcnow().isoformat(timespec="seconds") + "Z",
                   "content": _content(item)}
    item.review_editors = None
    kind = "rmm.script.reviewed" if isinstance(item, Script) else "condition.package.reviewed"
    audit.record(db, principal.actor, kind, item.name, item.tenant_id, id=item.id, hash=item.review["hash"][:16])


def guard_direct_run(db: Session) -> None:
    if required(db):
        raise HTTPException(400, "Scripts run from the library while script review is required, so a second person has "
                                 "reviewed them. Add it to Scripts and run it from there.")

