"""A customer's ISMS programme: chosen frameworks, onboarding answers, applicability and the customer's controls.

Frameworks are pinned to the pack version chosen. Applicability is computed by the pure engine
(``domain/applicability.py``) from those pinned versions, the newest common control library and templates, the
customer's answers and manual overrides. Applying writes the decisions and keeps one tenant control per common
control, switched to not applicable when nothing needs it (owners, state and notes are kept). Every change is audited.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any

from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .. import audit
from ..models import utcnow
from . import library
from .domain._js import js_trim
from .domain.applicability import (
    ApplicabilityInput, Change, Decision, GroupInput, MappingInput, OverrideInput, RejectedOverride,
    RequirementInput, RuleInput, Target, compute_applicability, diff_applicability, item_key,
)
from .models import (IsmsApplicability, IsmsApplicabilityOverride, IsmsProfileAnswer, IsmsTenantControl,
                     IsmsTenantFramework)

STATUSES = ("in_scope", "target_certification", "certified")
TARGET_TYPES = ("requirement", "control", "template_section")


def _error(message: str, status: int = 400) -> HTTPException:
    return HTTPException(status, message)


# Frameworks -----------------------------------------------------------------------------------------------------

def tenant_frameworks(db: Session, tenant_id: str) -> list[IsmsTenantFramework]:
    return list(db.execute(select(IsmsTenantFramework).where(IsmsTenantFramework.tenant_id == tenant_id)).scalars())


def framework_options(db: Session, tenant_id: str) -> list[dict]:
    """The newest version of every framework, with the customer's choice. Certifiable frameworks come first, largest
    first: the first chosen one is the primary framework for the dashboard, Statement of Applicability and documents."""
    chosen = {f.framework: f for f in tenant_frameworks(db, tenant_id)}
    out = []
    for pack in library.latest_frameworks(db):
        meta = pack.data["meta"]
        mine = chosen.get(meta["framework"])
        out.append({"framework": meta["framework"], "packId": pack.pack_id, "name": meta["name"],
                    "version": meta["version"], "packVersion": pack.pack_version,
                    "certifiable": meta["certifiable"], "licence": pack.licence,
                    "requirementCount": len(pack.data["requirements"]), "selected": mine is not None,
                    "status": mine.status if mine else None,
                    "pinnedVersion": mine.pack_version if mine else None,
                    "targetDate": mine.target_date.isoformat() if mine and mine.target_date else None})
    return sorted(out, key=lambda f: (not f["certifiable"], -f["requirementCount"], f["name"]))


def set_frameworks(db: Session, tenant_id: str, actor: str, selected: dict[str, dict]) -> None:
    """Makes the customer's framework choice exactly ``selected`` ({framework: {status, targetDate}}). A framework
    already chosen keeps its pinned pack version."""
    latest = {p.data["meta"]["framework"]: p for p in library.latest_frameworks(db)}
    for slug, choice in selected.items():
        if slug not in latest:
            raise _error(f"Unknown framework {slug!r}")
        if choice.get("status", "target_certification") not in STATUSES:
            raise _error(f"Status must be one of: {', '.join(STATUSES)}")
    current = {f.framework: f for f in tenant_frameworks(db, tenant_id)}
    for slug, row in current.items():
        if slug not in selected:
            audit.record(db, actor, "isms.framework_removed", slug, tenant_id, packVersion=row.pack_version)
            db.delete(row)
    for slug, choice in selected.items():
        status = choice.get("status", "target_certification")
        target = _date(choice.get("targetDate"))
        row = current.get(slug)
        if row is None:
            pack = latest[slug]
            db.add(IsmsTenantFramework(tenant_id=tenant_id, framework=slug, pack_id=pack.pack_id,
                                       pack_version=pack.pack_version, status=status, target_date=target,
                                       updated_by=actor))
            audit.record(db, actor, "isms.framework_added", slug, tenant_id, packVersion=pack.pack_version,
                         status=status)
        elif (row.status, row.target_date) != (status, target):
            audit.record(db, actor, "isms.framework_changed", slug, tenant_id, status=status,
                         targetDate=target.isoformat() if target else None)
            row.status, row.target_date, row.updated_at, row.updated_by = status, target, utcnow(), actor
    db.flush()


def _date(value: Any) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        raise _error("Dates must look like 2027-03-31") from None


def pinned_packs(db: Session, tenant_id: str) -> list[dict]:
    out = []
    for f in tenant_frameworks(db, tenant_id):
        pack = library.get(db, f.pack_id, f.pack_version)
        if pack is not None:
            out.append(pack.data)
    return out


# Questions and answers ------------------------------------------------------------------------------------------

def answers(db: Session, tenant_id: str) -> dict[str, Any]:
    rows = db.execute(select(IsmsProfileAnswer).where(IsmsProfileAnswer.tenant_id == tenant_id)).scalars()
    return {r.question_ref: r.value for r in rows}


def questions(db: Session, tenant_id: str) -> list[dict]:
    """Onboarding questions contributed by the customer's framework packs, with saved answers."""
    saved = answers(db, tenant_id)
    seen: dict[str, dict] = {}
    for pack in pinned_packs(db, tenant_id):
        for q in pack["questions"]:
            seen.setdefault(q["ref"], q)
    return [{"ref": q["ref"], "text": q["text"], "help": q.get("help"), "type": q["type"],
             "options": q.get("options", []), "value": saved.get(q["ref"])} for q in sorted(seen.values(),
                                                                                           key=lambda q: q["ref"])]


def _valid_answer(q: dict, value: Any) -> Any:
    kind = q["type"]
    options = {o["value"] for o in q.get("options", [])}
    if kind == "bool" and isinstance(value, bool):
        return value
    if kind == "number" and isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
        return value
    if kind == "single" and value in options:
        return value
    if kind == "multi" and isinstance(value, list) and all(v in options for v in value):
        return sorted(set(value), key=list(o["value"] for o in q["options"]).index)
    raise _error(f"That is not a valid answer to {q['ref']!r}")


def save_answers(db: Session, tenant_id: str, actor: str, changes: dict[str, Any]) -> None:
    """Saves answers (None removes one). Unchanged values are not rewritten."""
    known = {q["ref"]: q for q in questions(db, tenant_id)}
    current = {r.question_ref: r for r in db.execute(select(IsmsProfileAnswer)
                                                     .where(IsmsProfileAnswer.tenant_id == tenant_id)).scalars()}
    for ref, value in changes.items():
        if ref not in known:
            raise _error(f"Unknown question {ref!r}")
        row = current.get(ref)
        if value is None:
            if row is not None:
                db.delete(row)
                audit.record(db, actor, "isms.answer_removed", ref, tenant_id)
            continue
        value = _valid_answer(known[ref], value)
        if row is None:
            db.add(IsmsProfileAnswer(tenant_id=tenant_id, question_ref=ref, value=value, updated_by=actor))
        elif row.value == value:
            continue
        else:
            row.value, row.updated_at, row.updated_by = value, utcnow(), actor
        audit.record(db, actor, "isms.answer_saved", ref, tenant_id, value=value)
    db.flush()


# Applicability ----------------------------------------------------------------------------------------------

def overrides(db: Session, tenant_id: str) -> list[IsmsApplicabilityOverride]:
    return list(db.execute(select(IsmsApplicabilityOverride)
                           .where(IsmsApplicabilityOverride.tenant_id == tenant_id)).scalars())


def engine_input(db: Session, tenant_id: str, answer_changes: dict[str, Any] | None = None) -> ApplicabilityInput:
    packs = pinned_packs(db, tenant_id)
    if not packs:
        return ApplicabilityInput({}, [], [], [], [], [], [], [])
    groups, requirements, mappings, rules = [], [], [], []
    for p in packs:
        fw = p["meta"]["framework"]
        groups += [GroupInput(fw, g["ref"], g.get("parent")) for g in p["groups"]]
        requirements += [RequirementInput(fw, r["ref"], r["group"], r.get("mandatory", False))
                         for r in p["requirements"]]
        mappings += [MappingInput(fw, m["requirement"], m["control"], m["strength"]) for m in p["mappings"]]
        rules += [RuleInput(r["ref"], fw, r.get("when"), r["effect"],
                            tuple(Target(t["type"], t["ref"]) for t in r["targets"]), r["reason"])
                  for r in sorted(p["rules"], key=lambda r: r["ref"])]
    merged = {**answers(db, tenant_id), **(answer_changes or {})}
    merged = {k: v for k, v in merged.items() if v is not None}
    return ApplicabilityInput(
        answers=merged, groups=groups, requirements=requirements,
        controls=sorted({m.control for m in mappings}), template_sections=library.template_sections(db),
        mappings=mappings, rules=rules,
        overrides=[OverrideInput(o.target_type, o.target_key, o.applicable, o.justification)
                   for o in overrides(db, tenant_id)])


def current_decisions(db: Session, tenant_id: str) -> dict[str, Decision]:
    rows = db.execute(select(IsmsApplicability).where(IsmsApplicability.tenant_id == tenant_id)).scalars()
    return {item_key(r.target_type, r.target_key): Decision(r.target_type, r.target_key, r.applicable, r.source,
                                                            r.reason, tuple(r.rule_refs or ()), r.locked,
                                                            r.justification) for r in rows}


@dataclass
class Preview:
    decisions: dict[str, Decision]
    changes: list[Change]
    rejected: list[RejectedOverride]


def preview(db: Session, tenant_id: str, answer_changes: dict[str, Any] | None = None) -> Preview:
    """What applying would change, without writing anything. Show this before applying."""
    result = compute_applicability(engine_input(db, tenant_id, answer_changes))
    return Preview(result.decisions, diff_applicability(current_decisions(db, tenant_id), result.decisions),
                   result.rejected_overrides)


def apply(db: Session, tenant_id: str, actor: str, answer_changes: dict[str, Any] | None = None) -> Preview:
    """Saves answers, recomputes applicability and writes the decisions and the customer's controls."""
    if answer_changes:
        save_answers(db, tenant_id, actor, answer_changes)
    result = preview(db, tenant_id)
    existing = {item_key(r.target_type, r.target_key): r for r in db.execute(
        select(IsmsApplicability).where(IsmsApplicability.tenant_id == tenant_id)).scalars()}
    now = utcnow()
    for key, d in result.decisions.items():
        values = {"applicable": d.applicable, "source": d.source, "rule_refs": list(d.rule_refs),
                  "reason": d.reason, "justification": d.justification, "locked": d.locked}
        row = existing.pop(key, None)
        if row is None:
            db.add(IsmsApplicability(tenant_id=tenant_id, target_type=d.type, target_key=d.key, updated_by=actor,
                                     **values))
        elif any(getattr(row, k) != v for k, v in values.items()):
            for k, v in values.items():
                setattr(row, k, v)
            row.updated_at, row.updated_by = now, actor
    for row in existing.values():  # items no longer in the programme
        db.delete(row)
    _sync_controls(db, tenant_id, actor, result.decisions)
    audit.record(db, actor, "isms.applicability_applied", f"{len(result.changes)} change(s)", tenant_id,
                 changes=[{"key": c.key, "from": c.before, "to": c.after} for c in result.changes[:200]])
    db.flush()
    return result


def _sync_controls(db: Session, tenant_id: str, actor: str, decisions: dict[str, Decision]) -> None:
    """One tenant control per common control in the programme; not applicable ones keep their owner and notes."""
    library_controls = library.common_controls(db)
    rows = {c.ref: c for c in db.execute(select(IsmsTenantControl)
                                         .where(IsmsTenantControl.tenant_id == tenant_id)).scalars()}
    now = utcnow()
    for d in decisions.values():
        if d.type != "control":
            continue
        row = rows.get(d.key)
        if row is None:
            cc = library_controls.get(d.key)
            if cc is None:
                continue
            db.add(IsmsTenantControl(tenant_id=tenant_id, ref=cc["ref"], common=True, title=cc["title"],
                                     statement=cc["statement"], frequency=cc["default_frequency"],
                                     state="not_started" if d.applicable else "not_applicable", updated_by=actor))
            continue
        if not row.common:
            continue
        state = ("not_started" if row.state == "not_applicable" else row.state) if d.applicable else "not_applicable"
        if row.state != state:
            row.state, row.updated_at, row.updated_by = state, now, actor


def set_override(db: Session, tenant_id: str, actor: str, target_type: str, target_key: str, applicable: bool,
                 justification: str) -> IsmsApplicabilityOverride:
    if target_type not in TARGET_TYPES:
        raise _error(f"Type must be one of: {', '.join(TARGET_TYPES)}")
    justification = js_trim(justification or "")
    if not justification:
        raise _error("A justification is required.")
    keys = {item_key(d.type, d.key): d for d in compute_applicability(engine_input(db, tenant_id)).decisions.values()}
    decision = keys.get(item_key(target_type, target_key))
    if decision is None:
        raise _error("No such item in the programme.", 404)
    if decision.locked and decision.source != "override" and not applicable:
        raise _error("Mandatory requirements cannot be excluded." if decision.source == "mandatory"
                     else f"Required by {', '.join(decision.rule_refs)}.")
    row = db.execute(select(IsmsApplicabilityOverride).where(
        IsmsApplicabilityOverride.tenant_id == tenant_id, IsmsApplicabilityOverride.target_type == target_type,
        IsmsApplicabilityOverride.target_key == target_key)).scalar_one_or_none()
    if row is None:
        row = IsmsApplicabilityOverride(tenant_id=tenant_id, target_type=target_type, target_key=target_key,
                                        applicable=applicable, justification=justification[:4000], updated_by=actor)
        db.add(row)
    else:
        row.applicable, row.justification, row.updated_at, row.updated_by = (applicable, justification[:4000], utcnow(),
                                                                             actor)
    audit.record(db, actor, "isms.override_set", f"{target_type}:{target_key}", tenant_id, applicable=applicable,
                 justification=justification[:4000])
    db.flush()
    return row


def remove_override(db: Session, tenant_id: str, actor: str, target_type: str, target_key: str) -> None:
    gone = db.execute(delete(IsmsApplicabilityOverride).where(
        IsmsApplicabilityOverride.tenant_id == tenant_id, IsmsApplicabilityOverride.target_type == target_type,
        IsmsApplicabilityOverride.target_key == target_key))
    if gone.rowcount:
        audit.record(db, actor, "isms.override_removed", f"{target_type}:{target_key}", tenant_id)


# Controls ---------------------------------------------------------------------------------------------------

CONTROL_STATES = ("not_started", "in_progress", "implemented", "implemented_evidenced", "not_applicable")


def controls(db: Session, tenant_id: str) -> list[IsmsTenantControl]:
    return list(db.execute(select(IsmsTenantControl).where(IsmsTenantControl.tenant_id == tenant_id)
                           .order_by(IsmsTenantControl.ref)).scalars())
MANUAL_STATES = ("not_started", "in_progress", "implemented")  # implemented_evidenced comes from current evidence


def control_rows(db: Session, tenant_id: str) -> list[dict]:
    """The customer's controls with their applicability, owner and the requirements they serve."""
    decisions = {r.target_key: r for r in db.execute(select(IsmsApplicability).where(
        IsmsApplicability.tenant_id == tenant_id, IsmsApplicability.target_type == "control")).scalars()}
    serves: dict[str, set[str]] = {}
    satisfies: dict[str, set[str]] = {}
    for pack in pinned_packs(db, tenant_id):
        fw = pack["meta"]["framework"]
        mandatory = {r["ref"] for r in pack["requirements"] if r.get("mandatory")}
        for m in pack["mappings"]:
            if m["strength"] == "related":
                continue
            serves.setdefault(m["control"], set()).add(f"{fw}:{m['requirement']}")
            if m["strength"] == "satisfies" and m["requirement"] not in mandatory:
                satisfies.setdefault(m["control"], set()).add(f"{fw}:{m['requirement']}")
    library_controls = library.common_controls(db)
    out = []
    for c in controls(db, tenant_id):
        d = decisions.get(c.ref)
        out.append({"id": c.id, "ref": c.ref, "title": c.title, "statement": c.statement, "state": c.state,
                    "frequency": c.frequency, "ownerId": c.owner_user_id, "notes": c.notes, "custom": not c.common,
                    "applicable": d.applicable if d else c.state != "not_applicable",
                    "reason": d.reason if d else ("Added by your organization." if not c.common else ""),
                    "requirements": sorted(serves.get(c.ref, ())), "satisfies": sorted(satisfies.get(c.ref, ())),
                    "testProcedure": (library_controls.get(c.ref) or {}).get("test_procedure"),
                    "assessment": c.assessment, "implementation": c.implementation,
                    "assessedAt": c.assessed_at.isoformat() + "Z" if c.assessed_at else None})
    return out


def update_control(db: Session, row: IsmsTenantControl, actor: str, owner_id: str | None, state: str | None,
                   notes: str | None, owner_members: set[str]) -> IsmsTenantControl:
    """Sets a control's owner, manual state and notes. Not applicable controls keep their state.

    ``owner_id`` None leaves the owner as it is; an empty string clears it. ``state`` and ``notes`` None leave them."""
    if owner_id and owner_id not in owner_members:
        raise _error("The owner must be a member of this organization.")
    changes: dict[str, Any] = {}
    if owner_id is not None and (owner_id or None) != row.owner_user_id:
        changes["owner_user_id"] = owner_id or None
    if state is not None:
        if state not in MANUAL_STATES:
            raise _error(f"State must be one of: {', '.join(MANUAL_STATES)}")
        if row.state != "not_applicable" and not (row.state == "implemented_evidenced" and state == "implemented") \
                and row.state != state:
            changes["state"] = state
    if notes is not None and (js_trim(notes) or None) != row.notes:
        changes["notes"] = js_trim(notes)[:4000] or None
    if changes:
        for k, v in changes.items():
            setattr(row, k, v)
        row.updated_at, row.updated_by = utcnow(), actor
        audit.record(db, actor, "isms.control_updated", row.ref, row.tenant_id, **{
            {"owner_user_id": "ownerId"}.get(k, k): v for k, v in changes.items()})
    return row


# Control assessment: "is this in place today?" ------------------------------------------------------------------

ASSESSMENTS = ("yes", "partly", "no", "not_relevant")
_ASSESSED_STATE = {"yes": "implemented", "partly": "in_progress", "no": "not_started"}


def assess_control(db: Session, row: IsmsTenantControl, actor: str, user_id: str, answer: str, implementation: str,
                   justification: str | None, owner_id: str | None, members: set[str]) -> None:
    """Records the answer for a control.

    * yes, partly, no: sets the state (implemented, in progress, not started) and how it is done. Evidenced controls
      stay evidenced while the answer is yes.
    * not_relevant: excludes the control and every requirement it fully satisfies, with the same justification, so
      the Statement of Applicability shows the decision. A later answer removes those exclusions again.

    The caller rolls back on error: a rejected exclusion (a mandatory clause, or a rule requirement) changes nothing.
    """
    if answer not in ASSESSMENTS:
        raise _error("Choose an answer.")
    implementation = js_trim(implementation or "")[:4000]
    if answer in ("yes", "partly") and not implementation:
        raise _error("Describe how this is done today. The description appears in your Statement of Applicability.")
    if owner_id and owner_id not in members:
        raise _error("The owner must be a member of this organization.")
    tenant_id = row.tenant_id
    had = db.execute(delete(IsmsApplicabilityOverride).where(
        IsmsApplicabilityOverride.tenant_id == tenant_id,
        IsmsApplicabilityOverride.set_by_control == row.ref)).rowcount
    db.flush()
    now = utcnow()
    if owner_id is not None:
        row.owner_user_id = owner_id or None
    row.assessment, row.implementation = answer, implementation or None
    row.assessed_at, row.assessed_by_user_id, row.updated_at, row.updated_by = now, user_id, now, actor
    if answer == "not_relevant":
        reason = js_trim(justification or "")[:4000]
        if not reason:
            raise _error("Explain why this does not apply. The justification appears in your Statement of "
                         "Applicability.")
        satisfies = next((c["satisfies"] for c in control_rows(db, tenant_id) if c["id"] == row.id), [])
        targets = [("control", row.ref), *(("requirement", key) for key in satisfies)]
        for target_type, key in targets:
            existing = db.execute(select(IsmsApplicabilityOverride).where(
                IsmsApplicabilityOverride.tenant_id == tenant_id, IsmsApplicabilityOverride.target_type == target_type,
                IsmsApplicabilityOverride.target_key == key)).scalar_one_or_none()
            if existing is None:
                db.add(IsmsApplicabilityOverride(tenant_id=tenant_id, target_type=target_type, target_key=key,
                                                 applicable=False, justification=reason, set_by_control=row.ref,
                                                 updated_by=actor))
            else:
                existing.applicable, existing.justification, existing.set_by_control = False, reason, row.ref
                existing.updated_at, existing.updated_by = now, actor
        db.flush()
        result = apply(db, tenant_id, actor)
        keys = {k for _, k in targets}
        rejected = [r for r in result.rejected if r.override.key in keys]
        if rejected:
            raise _error(" ".join(f"{r.override.key.split(':', 1)[-1]}: {r.problem}" for r in rejected))
    else:
        if had:
            apply(db, tenant_id, actor)
        state = _ASSESSED_STATE[answer]
        if row.state == "not_applicable" or (row.state == "implemented_evidenced" and state == "implemented"):
            pass
        else:
            row.state = state
    audit.record(db, actor, "isms.control_assessed", row.ref, tenant_id, answer=answer,
                 justification=js_trim(justification or "")[:4000] or None)


# Statement of Applicability and readiness -----------------------------------------------------------------------

def soa_rows(db: Session, tenant_id: str, framework: str) -> list[dict]:
    """Every requirement of the framework that is not mandatory (for ISO 27001 the 93 Annex A controls), with its
    applicability, justification, implementing controls, status and owners."""
    from ..models import User
    from .domain.soa import soa_status

    pack = next((p for p in pinned_packs(db, tenant_id) if p["meta"]["framework"] == framework), None)
    if pack is None:
        raise _error("That framework is not in this customer's programme.", 404)
    groups = {g["ref"]: g["title"] for g in pack["groups"]}
    implementing: dict[str, list[str]] = {}
    for m in pack["mappings"]:
        if m["strength"] == "satisfies":
            implementing.setdefault(m["requirement"], []).append(m["control"])
    decisions = {r.target_key: r for r in db.execute(select(IsmsApplicability).where(
        IsmsApplicability.tenant_id == tenant_id, IsmsApplicability.target_type == "requirement")).scalars()}
    tcs = {c.ref: c for c in controls(db, tenant_id)}
    owner_ids = {c.owner_user_id for c in tcs.values() if c.owner_user_id}
    names = {u.id: (u.name or u.email) for u in db.execute(select(User).where(User.id.in_(owner_ids))).scalars()} \
        if owner_ids else {}
    out = []
    for r in pack["requirements"]:
        if r.get("mandatory"):
            continue
        d = decisions.get(f"{framework}:{r['ref']}")
        applicable = d.applicable if d else True
        cs = [tcs[ref] for ref in sorted(set(implementing.get(r["ref"], []))) if ref in tcs]
        out.append({"ref": r["ref"], "title": r["short_title"], "group": groups.get(r["group"], r["group"]),
                    "applicable": applicable, "source": d.source if d else "default", "reason": d.reason if d else "",
                    "justification": d.justification if d else None, "locked": bool(d and d.locked),
                    "controls": [{"ref": c.ref, "title": c.title, "state": c.state, "implementation": c.implementation}
                                 for c in cs],
                    "owners": sorted({names[c.owner_user_id] for c in cs if c.owner_user_id in names}),
                    "status": soa_status(applicable, [c.state for c in cs])})
    return out


def readiness(db: Session, tenant_id: str) -> list[dict]:
    """Readiness per chosen framework from its Statement of Applicability rows (see ``domain/readiness.py`` for the
    formula), with the share of applicable controls implemented with current evidence."""
    from .domain.readiness import ReadinessRequirement, compute_readiness, control_coverage

    coverage = control_coverage([c.state for c in controls(db, tenant_id)])
    out = []
    for f in tenant_frameworks(db, tenant_id):
        rows = soa_rows(db, tenant_id, f.framework)
        result = compute_readiness([ReadinessRequirement(r["ref"], r["applicable"],
                                                         tuple(c["state"] for c in r["controls"])) for r in rows])
        out.append({"framework": f.framework, "met": result.met, "partial": result.partial, "notMet": result.not_met,
                    "applicable": result.applicable, "notApplicable": result.not_applicable,
                    "withoutControls": result.without_controls, "score": result.score, "formula": result.formula,
                    "coverage": {"evidenced": coverage.evidenced, "applicable": coverage.applicable,
                                 "score": coverage.score}})
    return out
