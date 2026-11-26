"""The customer's own controls beside the common control library (ported from the standalone app's
``packages/programme/src/custom-controls.ts``).

Each gets the next free CUST-nnn ref, its own statement and test procedure, and can be linked to requirements of
the customer's frameworks so it counts in the Statement of Applicability, readiness and audit checklists. An MSP can
push its own custom controls to its customers as templates (``push_templates``). Every change is audited.
"""

from __future__ import annotations

import re

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..models import utcnow
from .domain._js import js_trim
from .domain.tasks import RECURRENCES
from .models import IsmsControlRequirement, IsmsEvidenceLink, IsmsRiskControl, IsmsTenantControl
from .programme import pinned_packs

FREQUENCIES = (*RECURRENCES, "continuous")
CUSTOM_REF = re.compile(r"^CUST-\d{3,}$")


def _error(message: str, status: int = 400) -> HTTPException:
    return HTTPException(status, message)


def linkable_requirements(db: Session, tenant_id: str) -> list[dict]:
    out = []
    for pack in pinned_packs(db, tenant_id):
        meta = pack["meta"]
        out += [{"key": f"{meta['framework']}:{r['ref']}", "framework": meta["framework"],
                 "frameworkName": meta["name"], "ref": r["ref"], "title": r["short_title"]}
                for r in pack["requirements"]]
    return out


def links_by_requirement(db: Session, tenant_id: str, framework: str) -> dict[str, list[str]]:
    """Requirement ref to the refs of the customer's own controls linked to it."""
    rows = db.execute(select(IsmsControlRequirement, IsmsTenantControl.ref)
                      .join(IsmsTenantControl, IsmsTenantControl.id == IsmsControlRequirement.tenant_control_id)
                      .where(IsmsControlRequirement.tenant_id == tenant_id,
                             IsmsControlRequirement.framework == framework)).all()
    out: dict[str, list[str]] = {}
    for link, ref in rows:
        out.setdefault(link.requirement_ref, []).append(ref)
    return out


def control_view(db: Session, row: IsmsTenantControl) -> dict:
    links = db.execute(select(IsmsControlRequirement).where(
        IsmsControlRequirement.tenant_control_id == row.id)).scalars().all()
    return {"id": row.id, "ref": row.ref, "title": row.title, "statement": row.statement,
            "testProcedure": row.test_procedure or "", "frequency": row.frequency, "ownerId": row.owner_user_id,
            "requirementKeys": sorted(f"{lk.framework}:{lk.requirement_ref}" for lk in links)}


def custom_rows(db: Session, tenant_id: str) -> list[dict]:
    rows = db.execute(select(IsmsTenantControl).where(IsmsTenantControl.tenant_id == tenant_id,
                                                      IsmsTenantControl.common.is_(False))
                      .order_by(IsmsTenantControl.ref)).scalars().all()
    return [control_view(db, r) for r in rows]


def _validate(db: Session, tenant_id: str, data: dict, members: set[str]) -> dict:
    title = js_trim(str(data.get("title") or ""))
    statement = js_trim(str(data.get("statement") or ""))
    procedure = js_trim(str(data.get("testProcedure") or ""))
    if not 3 <= len(title) <= 120:
        raise _error("Give the control a title of 3 to 120 characters.")
    if not statement:
        raise _error("Describe what the control requires.")
    if len(statement) > 4000 or len(procedure) > 4000:
        raise _error("Keep the statement and test procedure under 4,000 characters each.")
    frequency = data.get("frequency") or None
    if frequency and frequency not in FREQUENCIES:
        raise _error("Choose a frequency from the list.")
    owner = data.get("ownerId") or None
    if owner and owner not in members:
        raise _error("The owner must have an ISMS role in this customer.")
    keys = list(dict.fromkeys(str(k) for k in (data.get("requirementKeys") or [])))
    if keys:
        allowed = {r["key"] for r in linkable_requirements(db, tenant_id)}
        if any(k not in allowed for k in keys):
            raise _error("Link only to requirements of this customer's frameworks.")
    return {"title": title, "statement": statement, "test_procedure": procedure or None, "frequency": frequency,
            "owner_user_id": owner, "keys": keys}


def _set_links(db: Session, row: IsmsTenantControl, keys: list[str], actor: str) -> None:
    current = {f"{lk.framework}:{lk.requirement_ref}": lk for lk in db.execute(select(IsmsControlRequirement).where(
        IsmsControlRequirement.tenant_control_id == row.id)).scalars()}
    for key, lk in current.items():
        if key not in keys:
            db.delete(lk)
    for key in keys:
        if key not in current:
            framework, ref = key.split(":", 1)
            db.add(IsmsControlRequirement(tenant_id=row.tenant_id, tenant_control_id=row.id, framework=framework,
                                          requirement_ref=ref, updated_by=actor))


def _next_ref(db: Session, tenant_id: str) -> str:
    refs = db.execute(select(IsmsTenantControl.ref).where(IsmsTenantControl.tenant_id == tenant_id)).scalars()
    n = max((int(r[5:]) for r in refs if CUSTOM_REF.match(r)), default=0) + 1
    return f"CUST-{n:03d}"


def create(db: Session, tenant_id: str, actor: str, data: dict, members: set[str]) -> IsmsTenantControl:
    from .tasks import sync_control_tasks
    v = _validate(db, tenant_id, data, members)
    keys = v.pop("keys")
    row = IsmsTenantControl(tenant_id=tenant_id, ref=_next_ref(db, tenant_id), common=False, state="not_started",
                            updated_by=actor, **v)
    db.add(row)
    db.flush()
    _set_links(db, row, keys, actor)
    db.flush()
    audit.record(db, actor, "isms.custom_control_created", row.ref, tenant_id, id=row.id, requirements=keys)
    sync_control_tasks(db, tenant_id, actor)
    return row


def update(db: Session, row: IsmsTenantControl, actor: str, data: dict, members: set[str]) -> None:
    from .tasks import sync_control_tasks
    if row.common:
        raise _error("Library controls are changed through the content packs, not here.")
    v = _validate(db, row.tenant_id, data, members)
    keys = v.pop("keys")
    for k, val in v.items():
        setattr(row, k, val)
    row.updated_at, row.updated_by = utcnow(), actor
    _set_links(db, row, keys, actor)
    db.flush()
    audit.record(db, actor, "isms.custom_control_updated", row.ref, row.tenant_id, id=row.id, requirements=keys)
    sync_control_tasks(db, row.tenant_id, actor)


def delete(db: Session, row: IsmsTenantControl, actor: str) -> None:
    """Refused while evidence or risks point at it, so nothing loses its link silently."""
    if row.common:
        raise _error("Library controls cannot be deleted; mark them not applicable instead.")
    evidence = db.execute(select(func.count()).select_from(IsmsEvidenceLink)
                          .where(IsmsEvidenceLink.tenant_control_id == row.id)).scalar()
    risks = db.execute(select(func.count()).select_from(IsmsRiskControl)
                       .where(IsmsRiskControl.tenant_control_id == row.id)).scalar()
    if evidence or risks:
        raise _error(f"{row.ref} is linked to {evidence} evidence item(s) and {risks} risk(s). Remove those links first.")
    from .models import IsmsTask
    for t in db.execute(select(IsmsTask).where(IsmsTask.tenant_control_id == row.id,
                                               IsmsTask.status == "open")).scalars():
        t.status, t.updated_by = "cancelled", actor
    for t in db.execute(select(IsmsTask).where(IsmsTask.tenant_control_id == row.id)).scalars():
        t.tenant_control_id = None
    for lk in db.execute(select(IsmsControlRequirement).where(
            IsmsControlRequirement.tenant_control_id == row.id)).scalars():
        db.delete(lk)
    db.flush()
    db.delete(row)
    audit.record(db, actor, "isms.custom_control_deleted", row.ref, row.tenant_id, id=row.id)


def push_templates(db: Session, source_tenant_id: str, target_tenant_id: str, actor: str,
                   control_ids: list[str] | None = None) -> int:
    """Copies the source customer's own controls into a target customer, skipping titles the target already has.
    Requirement links are not copied (the target's frameworks may differ); owners are not copied either."""
    sources = [r for r in db.execute(select(IsmsTenantControl).where(
        IsmsTenantControl.tenant_id == source_tenant_id, IsmsTenantControl.common.is_(False))).scalars()
        if not control_ids or r.id in control_ids]
    have = {t.lower() for t in db.execute(select(IsmsTenantControl.title).where(
        IsmsTenantControl.tenant_id == target_tenant_id, IsmsTenantControl.common.is_(False))).scalars()}
    added = 0
    for s in sources:
        if s.title.lower() in have:
            continue
        row = IsmsTenantControl(tenant_id=target_tenant_id, ref=_next_ref(db, target_tenant_id), common=False,
                                title=s.title, statement=s.statement, test_procedure=s.test_procedure,
                                frequency=s.frequency, state="not_started", updated_by=actor)
        db.add(row)
        db.flush()
        have.add(s.title.lower())
        added += 1
    audit.record(db, actor, "isms.custom_controls_pushed", f"{added} added", target_tenant_id,
                 source_tenant_id=source_tenant_id, added=added)
    return added
