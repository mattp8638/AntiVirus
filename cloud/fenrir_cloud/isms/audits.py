"""Internal audit (ISO 27001 9.2): programmes, audits, checklists generated from the customer's frameworks and
applicability, results, and findings raised as nonconformities.

Ported from the standalone app's ``packages/programme/src/audit.ts``. The rules for checklists, coverage and
completion are the pure functions in ``domain/audit.py``. A completed audit and its checklist are frozen by the guard
in ``models.py`` as well as by the checks here. Every change is audited.
"""

from __future__ import annotations

from datetime import date

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..models import User, utcnow
from .domain._js import js_trim
from .domain.audit import (AuditableRequirement, AuditForCompletion, audit_completion_blockers, build_checklist,
                           checklist_key, draw_sample, programme_coverage, result_counts, suggested_sample_size)
from .models import IsmsApplicability, IsmsAudit, IsmsAuditCheck, IsmsAuditProgramme, IsmsNonconformity
from .custom_controls import links_by_requirement
from .programme import controls, pinned_packs, tenant_frameworks

CHECK_RESULTS = ("conforms", "observation", "minor", "major", "not_assessed")
FINDINGS = ("observation", "minor", "major")


def _error(message: str, status: int = 400) -> HTTPException:
    return HTTPException(status, message)


def _date(value, what: str) -> date:
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError):
        raise _error(f"Give {what} as a date like 2027-03-31.") from None


def _names(db: Session, ids) -> dict[str, str]:
    ids = {i for i in ids if i}
    if not ids:
        return {}
    return {u.id: (u.name or u.email) for u in db.execute(select(User).where(User.id.in_(ids))).scalars()}


def auditable_requirements(db: Session, tenant_id: str, frameworks: list[str] | None = None) -> list[AuditableRequirement]:
    """Requirements of the customer's frameworks with applicability and the controls that implement them."""
    decisions = {(r.target_key): r.applicable for r in db.execute(select(IsmsApplicability).where(
        IsmsApplicability.tenant_id == tenant_id, IsmsApplicability.target_type == "requirement")).scalars()}
    live = {c.ref for c in controls(db, tenant_id) if c.state != "not_applicable"}
    out = []
    for pack in pinned_packs(db, tenant_id):
        slug = pack["meta"]["framework"]
        if frameworks and slug not in frameworks:
            continue
        groups = {g["ref"]: g["title"] for g in pack["groups"]}
        mapped: dict[str, set[str]] = {}
        for m in pack["mappings"]:
            if m["strength"] != "related" and m["control"] in live:
                mapped.setdefault(m["requirement"], set()).add(m["control"])
        for ref, custom in links_by_requirement(db, tenant_id, slug).items():
            mapped.setdefault(ref, set()).update(c for c in custom if c in live)
        for i, r in enumerate(pack["requirements"]):
            mandatory = bool(r.get("mandatory"))
            applicable = mandatory or decisions.get(f"{slug}:{r['ref']}", True)
            out.append(AuditableRequirement(slug, r["ref"], r["short_title"], r["group"], groups.get(r["group"], ""),
                                            mandatory, bool(applicable), tuple(sorted(mapped.get(r["ref"], ()))), i))
    out.sort(key=lambda r: (r.framework, r.sort))
    return out


def auditable_groups(db: Session, tenant_id: str) -> list[dict]:
    out = []
    for pack in pinned_packs(db, tenant_id):
        used = {r["group"] for r in pack["requirements"]}
        out += [{"framework": pack["meta"]["framework"], "ref": g["ref"], "title": g["title"]}
                for g in pack["groups"] if g["ref"] in used]
    return out


# Programmes -------------------------------------------------------------------------------------------------------

def _findings_by_check(db: Session, check_ids: list[str]) -> dict[str, list[IsmsNonconformity]]:
    out: dict[str, list[IsmsNonconformity]] = {}
    if check_ids:
        for n in db.execute(select(IsmsNonconformity).where(IsmsNonconformity.audit_finding_id.in_(check_ids))
                            .order_by(IsmsNonconformity.ref)).scalars():
            out.setdefault(n.audit_finding_id, []).append(n)
    return out


def programme_rows(db: Session, tenant_id: str, programme_id: str | None = None) -> list[dict]:
    q = select(IsmsAuditProgramme).where(IsmsAuditProgramme.tenant_id == tenant_id)
    if programme_id:
        q = q.where(IsmsAuditProgramme.id == programme_id)
    progs = db.execute(q.order_by(IsmsAuditProgramme.period_start.desc())).scalars().all()
    if not progs:
        return []
    audits = db.execute(select(IsmsAudit).where(IsmsAudit.tenant_id == tenant_id)
                        .order_by(IsmsAudit.planned_start, IsmsAudit.ref)).scalars().all()
    checks = db.execute(select(IsmsAuditCheck).where(IsmsAuditCheck.tenant_id == tenant_id)).scalars().all()
    findings = _findings_by_check(db, [c.id for c in checks])
    by_audit: dict[str, list[IsmsAuditCheck]] = {}
    for c in checks:
        by_audit.setdefault(c.audit_id, []).append(c)
    names = _names(db, [a.lead_auditor_id for a in audits])
    reqs = auditable_requirements(db, tenant_id)
    out = []
    for p in progs:
        mine = [a for a in audits if a.programme_id == p.id]
        covered = {checklist_key(c.framework, c.requirement_ref) for a in mine for c in by_audit.get(a.id, [])
                   if c.result in ("conforms", *FINDINGS)}
        cov = programme_coverage(reqs, covered)
        out.append({"id": p.id, "title": p.title, "periodStart": p.period_start.isoformat(),
                    "periodEnd": p.period_end.isoformat(), "objectives": p.objectives,
                    "audits": [{"id": a.id, "ref": a.ref, "title": a.title, "status": a.status,
                                "plannedStart": a.planned_start.isoformat(), "plannedEnd": a.planned_end.isoformat(),
                                "leadAuditorName": names.get(a.lead_auditor_id),
                                "checks": len(by_audit.get(a.id, [])),
                                "findings": sum(len(findings.get(c.id, [])) for c in by_audit.get(a.id, []))}
                               for a in mine],
                    "coverage": {"required": cov.required, "covered": cov.covered, "percent": cov.percent,
                                 "missing": cov.missing[:200]}})
    return out


def save_programme(db: Session, tenant_id: str, actor: str, data: dict,
                   row: IsmsAuditProgramme | None = None) -> IsmsAuditProgramme:
    title = js_trim(str(data.get("title") or ""))
    if len(title) < 3:
        raise _error("Give the programme a title.")
    start, end = _date(data.get("periodStart"), "the start"), _date(data.get("periodEnd"), "the end")
    if end <= start:
        raise _error("The period must end after it starts.")
    clash = db.execute(select(IsmsAuditProgramme.id).where(IsmsAuditProgramme.tenant_id == tenant_id,
                                                           IsmsAuditProgramme.title == title)).scalar()
    if clash and (row is None or clash != row.id):
        raise _error("A programme with that title already exists.")
    values = {"title": title[:160], "period_start": start, "period_end": end,
              "objectives": js_trim(str(data.get("objectives") or ""))[:8000]}
    if row is None:
        row = IsmsAuditProgramme(tenant_id=tenant_id, updated_by=actor, **values)
        db.add(row)
        db.flush()
        audit.record(db, actor, "isms.audit_programme_created", row.title, tenant_id, id=row.id)
    else:
        for k, v in values.items():
            setattr(row, k, v)
        row.updated_by, row.updated_at = actor, utcnow()
        audit.record(db, actor, "isms.audit_programme_updated", row.title, tenant_id, id=row.id)
    return row


# Audits -----------------------------------------------------------------------------------------------------------

def _validate(db: Session, tenant_id: str, data: dict, members: set[str], programme: IsmsAuditProgramme) -> dict:
    title = js_trim(str(data.get("title") or ""))
    if len(title) < 3:
        raise _error("Give the audit a title.")
    start, end = _date(data.get("plannedStart"), "the start"), _date(data.get("plannedEnd"), "the end")
    if end < start:
        raise _error("The audit must end on or after its start date.")
    if not (programme.period_start <= start <= programme.period_end):
        raise _error("Plan the audit inside the programme period.")
    selected = {f.framework for f in tenant_frameworks(db, tenant_id)}
    frameworks = list(dict.fromkeys(str(f) for f in (data.get("frameworks") or [])))
    if not frameworks:
        raise _error("Choose at least one framework to audit.")
    if any(f not in selected for f in frameworks):
        raise _error("Audit only frameworks in this customer's programme.")
    lead = data.get("leadAuditorId") or None
    if lead and lead not in members:
        raise _error("The lead auditor must have an ISMS role in this customer.")
    return {"title": title[:160], "scope": js_trim(str(data.get("scope") or ""))[:8000], "frameworks": frameworks,
            "planned_start": start, "planned_end": end, "lead_auditor_id": lead,
            "other_auditors": js_trim(str(data.get("otherAuditors") or ""))[:2000],
            "independence_note": js_trim(str(data.get("independenceNote") or ""))[:4000]}


def create_audit(db: Session, programme: IsmsAuditProgramme, actor: str, data: dict, members: set[str]) -> IsmsAudit:
    values = _validate(db, programme.tenant_id, data, members, programme)
    refs = db.execute(select(IsmsAudit.ref).where(IsmsAudit.tenant_id == programme.tenant_id)).scalars()
    n = max((int(r[4:]) for r in refs if r[4:].isdigit()), default=0) + 1
    row = IsmsAudit(tenant_id=programme.tenant_id, programme_id=programme.id, ref=f"AUD-{n:03d}", updated_by=actor,
                    **values)
    db.add(row)
    db.flush()
    audit.record(db, actor, "isms.audit_planned", row.ref, row.tenant_id, id=row.id, frameworks=row.frameworks)
    return row


def _not_completed(row: IsmsAudit) -> None:
    if row.status == "completed":
        raise _error("A completed audit cannot change.")


def update_audit(db: Session, row: IsmsAudit, actor: str, data: dict, members: set[str]) -> None:
    _not_completed(row)
    programme = db.get(IsmsAuditProgramme, row.programme_id)
    for k, v in _validate(db, row.tenant_id, data, members, programme).items():
        setattr(row, k, v)
    row.updated_by, row.updated_at = actor, utcnow()
    audit.record(db, actor, "isms.audit_updated", row.ref, row.tenant_id, id=row.id)


def _checks(db: Session, audit_id: str) -> list[IsmsAuditCheck]:
    return db.execute(select(IsmsAuditCheck).where(IsmsAuditCheck.audit_id == audit_id)
                      .order_by(IsmsAuditCheck.sort)).scalars().all()


def audit_view(db: Session, row: IsmsAudit) -> dict:
    checks = _checks(db, row.id)
    findings = _findings_by_check(db, [c.id for c in checks])
    names = _names(db, [row.lead_auditor_id, *[c.checked_by_user_id for c in checks]])
    programme = db.get(IsmsAuditProgramme, row.programme_id)
    results = [c.result for c in checks]
    return {
        "id": row.id, "ref": row.ref, "programmeId": row.programme_id, "programmeTitle": programme.title,
        "title": row.title, "scope": row.scope, "frameworks": list(row.frameworks or []),
        "plannedStart": row.planned_start.isoformat(), "plannedEnd": row.planned_end.isoformat(),
        "leadAuditorId": row.lead_auditor_id, "leadAuditorName": names.get(row.lead_auditor_id),
        "otherAuditors": row.other_auditors, "independenceNote": row.independence_note, "status": row.status,
        "summary": row.summary, "startedAt": row.started_at.isoformat() + "Z" if row.started_at else None,
        "completedAt": row.completed_at.isoformat() + "Z" if row.completed_at else None,
        "checks": [{"id": c.id, "framework": c.framework, "ref": c.requirement_ref, "title": c.requirement_title,
                    "groupTitle": c.group_title, "mandatory": c.mandatory, "controls": c.controls, "result": c.result,
                    "notes": c.notes, "evidenceSeen": c.evidence_seen,
                    "checkedAt": c.checked_at.isoformat() + "Z" if c.checked_at else None,
                    "checkedByName": names.get(c.checked_by_user_id),
                    "findings": [{"id": n.id, "ref": n.ref, "status": n.status} for n in findings.get(c.id, [])]}
                   for c in checks],
        "counts": result_counts(results),
        "blockers": audit_completion_blockers(AuditForCompletion(row.status, row.independence_note, row.summary,
                                                                 tuple(results))),
    }


def generate_checklist(db: Session, row: IsmsAudit, actor: str, groups: list[str] | None = None) -> int:
    """Builds or refreshes the checklist: adds items now in scope and drops untouched items no longer in scope.
    Items with a result are kept."""
    _not_completed(row)
    items = build_checklist(auditable_requirements(db, row.tenant_id, list(row.frameworks or [])), groups or None)
    if not items:
        raise _error("Nothing to audit in that selection.")
    keep = {checklist_key(i.framework, i.ref): i for i in items}
    existing = {checklist_key(c.framework, c.requirement_ref): c for c in _checks(db, row.id)}
    for key, c in existing.items():
        if c.result is None and key not in keep:
            db.delete(c)
    for key, i in keep.items():
        c = existing.get(key)
        if c is None:
            db.add(IsmsAuditCheck(tenant_id=row.tenant_id, audit_id=row.id, framework=i.framework,
                                  requirement_ref=i.ref, requirement_title=i.title[:300],
                                  group_title=i.group_title[:300], mandatory=i.mandatory, controls=i.controls,
                                  sort=i.sort, updated_by=actor))
        elif c.sort != i.sort:
            c.sort = i.sort
    audit.record(db, actor, "isms.audit_checklist_generated", row.ref, row.tenant_id, id=row.id, items=len(items),
                 groups=groups or [])
    return len(items)


def start_audit(db: Session, row: IsmsAudit, actor: str) -> None:
    if row.status != "planned":
        return
    if not _checks(db, row.id):
        raise _error("Generate the checklist before starting.")
    row.status, row.started_at, row.updated_by = "in_progress", utcnow(), actor
    audit.record(db, actor, "isms.audit_started", row.ref, row.tenant_id, id=row.id)


def record_check(db: Session, check: IsmsAuditCheck, actor: str, user_id: str, data: dict) -> IsmsAudit:
    result = data.get("result")
    if result not in CHECK_RESULTS:
        raise _error("Choose a result.")
    parent = db.get(IsmsAudit, check.audit_id)
    if parent.status != "in_progress":
        raise _error("Start the audit to record results.")
    notes = js_trim(str(data.get("notes") or ""))
    if result in FINDINGS and not notes:
        raise _error("Describe what was found.")
    check.result, check.notes = result, notes[:8000]
    check.evidence_seen = js_trim(str(data.get("evidenceSeen") or ""))[:8000]
    check.checked_at, check.checked_by_user_id, check.updated_by = utcnow(), user_id, actor
    audit.record(db, actor, "isms.audit_check_recorded", f"{parent.ref} {check.requirement_ref}", parent.tenant_id,
                 id=check.id, result=result)
    return parent


def raise_finding(db: Session, check: IsmsAuditCheck, actor: str, user_id: str, owner_id: str | None,
                  members: set[str]) -> IsmsNonconformity:
    """Raises a checklist item's finding as a nonconformity (minor or major) or an improvement (observation)."""
    from .management import raise_nc

    if check.result not in FINDINGS:
        raise _error("Only observations and nonconformities become findings.")
    if db.execute(select(func.count()).select_from(IsmsNonconformity)
                  .where(IsmsNonconformity.audit_finding_id == check.id)).scalar():
        raise _error("A finding has already been raised for this item.")
    parent = db.get(IsmsAudit, check.audit_id)
    _not_completed(parent)
    opportunity = check.result == "observation"
    return raise_nc(db, check.tenant_id, actor, user_id, {
        "kind": "opportunity" if opportunity else "nonconformity",
        "title": f"{parent.ref}: {check.requirement_ref} {check.requirement_title}"[:200],
        "description": check.notes, "source": "internal_audit",
        "severity": None if opportunity else check.result, "requirementRef": check.requirement_ref,
        "ownerId": owner_id}, members, audit_finding_id=check.id)


def complete_audit(db: Session, row: IsmsAudit, actor: str, summary: str) -> None:
    checks = _checks(db, row.id)
    blockers = audit_completion_blockers(AuditForCompletion(row.status, row.independence_note, summary,
                                                            tuple(c.result for c in checks)))
    if blockers:
        raise _error(" ".join(blockers))
    findings = _findings_by_check(db, [c.id for c in checks])
    unraised = [c.requirement_ref for c in checks if c.result in ("minor", "major") and not findings.get(c.id)]
    if unraised:
        raise _error(f"Raise a nonconformity for every minor or major finding first ({', '.join(unraised)}).")
    row.summary, row.status, row.completed_at, row.updated_by = js_trim(summary)[:8000], "completed", utcnow(), actor
    audit.record(db, actor, "isms.audit_completed", row.ref, row.tenant_id, id=row.id,
                 counts=result_counts([c.result for c in checks]))


def delete_audit(db: Session, row: IsmsAudit, actor: str) -> None:
    if row.status != "planned":
        raise _error("Only a planned audit can be deleted.")
    for c in _checks(db, row.id):
        db.delete(c)
    db.flush()
    db.delete(row)
    audit.record(db, actor, "isms.audit_deleted", row.ref, row.tenant_id, id=row.id)


def sample(population: list[str], size: int | None, seed: str) -> dict:
    """A reproducible sample for testing a control: the same population, size and seed always give the same items."""
    items = [js_trim(str(p)) for p in population if js_trim(str(p))]
    if not items:
        raise _error("List the population to sample from, one item per line.")
    if len(items) > 10000:
        raise _error("The population can have up to 10,000 items.")
    seed = js_trim(seed)
    if not seed:
        raise _error("Give a seed so the sample can be drawn again.")
    n = suggested_sample_size(len(items)) if size is None else size
    if n < 1:
        raise _error("The sample size must be at least 1.")
    return {"population": len(items), "size": min(n, len(items)), "suggested": suggested_sample_size(len(items)),
            "seed": seed, "items": draw_sample(items, n, seed, lambda x: x)}


def next_audit(db: Session, tenant_id: str) -> dict | None:
    a = db.execute(select(IsmsAudit).where(IsmsAudit.tenant_id == tenant_id, IsmsAudit.status != "completed")
                   .order_by(IsmsAudit.planned_start).limit(1)).scalar()
    return {"id": a.id, "ref": a.ref, "title": a.title, "plannedStart": a.planned_start.isoformat(),
            "status": a.status} if a else None
