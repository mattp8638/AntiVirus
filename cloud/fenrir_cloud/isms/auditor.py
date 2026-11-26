"""Auditor workspace: reproducible samples over live populations and evidence requests that control owners answer.

Ported from the standalone app's ``packages/programme/src/auditor.ts``. External auditors are Fenrir accounts with
read access to the customer and an ISMS auditor role, which always expires (``memberships.py``). Every page an auditor
opens in the ISMS is recorded in the audit log (``record_view``).
"""

from __future__ import annotations

from datetime import date

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..models import User, utcnow
from .domain._js import iso_instant, js_trim
from .domain.audit import draw_sample
from .models import (IsmsAuditSample, IsmsDocument, IsmsDocumentVersion, IsmsEvidence, IsmsEvidenceRequest,
                     IsmsNonconformity, IsmsRisk, IsmsTask, IsmsTenantControl)

POPULATIONS = {
    "controls": "Applicable controls",
    "evidence": "Evidence items",
    "completed_tasks": "Completed control tasks",
    "risks": "Open risks",
    "nonconformities": "Nonconformities",
    "documents": "Published documents",
}


def _error(message: str, status: int = 400) -> HTTPException:
    return HTTPException(status, message)


def _names(db: Session, ids) -> dict[str, str]:
    ids = {i for i in ids if i}
    if not ids:
        return {}
    return {u.id: (u.name or u.email) for u in db.execute(select(User).where(User.id.in_(ids))).scalars()}


def population_items(db: Session, tenant_id: str, population: str) -> list[dict]:
    def q(model, *where):
        return db.execute(select(model).where(model.tenant_id == tenant_id, *where)).scalars()

    if population == "controls":
        return [{"id": c.id, "label": f"{c.ref} {c.title}", "detail": c.state}
                for c in q(IsmsTenantControl, IsmsTenantControl.state != "not_applicable")]
    if population == "evidence":
        return [{"id": e.id, "label": e.title,
                 "detail": e.kind + (f", valid until {e.valid_until.isoformat()}" if e.valid_until else "")}
                for e in q(IsmsEvidence)]
    if population == "completed_tasks":
        return [{"id": t.id, "label": t.title,
                 "detail": f"done {t.completed_at.date().isoformat()}" if t.completed_at else "done"}
                for t in q(IsmsTask, IsmsTask.status == "done")]
    if population == "risks":
        return [{"id": r.id, "label": f"{r.ref} {r.title}", "detail": r.status} for r in q(IsmsRisk, IsmsRisk.status != "closed")]
    if population == "nonconformities":
        return [{"id": n.id, "label": f"{n.ref} {n.title}", "detail": n.status} for n in q(IsmsNonconformity)]
    if population == "documents":
        rows = db.execute(select(IsmsDocumentVersion, IsmsDocument)
                          .join(IsmsDocument, IsmsDocument.id == IsmsDocumentVersion.document_id)
                          .where(IsmsDocument.tenant_id == tenant_id, IsmsDocumentVersion.state == "published")).all()
        return [{"id": v.id, "label": f"{d.number} {d.title}", "detail": f"version {v.version}"} for v, d in rows]
    raise _error("Choose a population.")


def create_sample(db: Session, tenant_id: str, actor: str, user_id: str, data: dict) -> IsmsAuditSample:
    population = data.get("population")
    if population not in POPULATIONS:
        raise _error("Choose a population.")
    size = data.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= 200:
        raise _error("Sample between 1 and 200 items.")
    seed = js_trim(str(data.get("seed") or "")) or iso_instant(utcnow())
    pop = population_items(db, tenant_id, population)
    if not pop:
        raise _error("That population is empty.")
    items = draw_sample(pop, size, seed, lambda x: x["id"])
    row = IsmsAuditSample(tenant_id=tenant_id, population=population, size=size, seed=seed[:200],
                          population_size=len(pop), items=items, note=js_trim(str(data.get("note") or ""))[:4000],
                          created_by_user_id=user_id, updated_by=actor)
    db.add(row)
    db.flush()
    audit.record(db, actor, "isms.audit_sample_drawn", POPULATIONS[population], tenant_id, id=row.id, size=size,
                 seed=row.seed, population_size=len(pop))
    return row


def sample_rows(db: Session, tenant_id: str) -> list[dict]:
    rows = db.execute(select(IsmsAuditSample).where(IsmsAuditSample.tenant_id == tenant_id)
                      .order_by(IsmsAuditSample.created_at.desc())).scalars().all()
    names = _names(db, [r.created_by_user_id for r in rows])
    return [{"id": r.id, "population": r.population, "populationLabel": POPULATIONS.get(r.population, r.population),
             "size": r.size, "seed": r.seed, "populationSize": r.population_size, "items": r.items, "note": r.note,
             "createdAt": iso_instant(r.created_at), "createdByName": names.get(r.created_by_user_id)} for r in rows]


# Evidence requests ------------------------------------------------------------------------------------------------

def request_rows(db: Session, tenant_id: str, status: str = "all", owner_id: str | None = None) -> list[dict]:
    rows = db.execute(select(IsmsEvidenceRequest).where(IsmsEvidenceRequest.tenant_id == tenant_id)).scalars().all()
    controls = {c.id: c for c in db.execute(select(IsmsTenantControl).where(
        IsmsTenantControl.id.in_({r.tenant_control_id for r in rows if r.tenant_control_id}))).scalars()} if rows else {}
    evidence = {e.id: e.title for e in db.execute(select(IsmsEvidence).where(
        IsmsEvidence.id.in_({r.evidence_id for r in rows if r.evidence_id}))).scalars()} if rows else {}
    names = _names(db, [r.requested_by_user_id for r in rows] + [r.answered_by_user_id for r in rows])
    out = []
    for r in rows:
        c = controls.get(r.tenant_control_id)
        if status == "open" and r.status != "open":
            continue
        if owner_id and (c is None or c.owner_user_id != owner_id):
            continue
        out.append({"id": r.id, "controlId": r.tenant_control_id, "controlRef": c.ref if c else None,
                    "controlOwnerId": c.owner_user_id if c else None, "request": r.request,
                    "dueOn": r.due_on.isoformat() if r.due_on else None, "status": r.status, "response": r.response,
                    "evidenceId": r.evidence_id, "evidenceTitle": evidence.get(r.evidence_id),
                    "requestedByName": names.get(r.requested_by_user_id),
                    "answeredByName": names.get(r.answered_by_user_id), "createdAt": iso_instant(r.created_at)})
    out.sort(key=lambda x: x["createdAt"], reverse=True)
    out.sort(key=lambda x: (x["status"] != "open", x["dueOn"] is None, x["dueOn"] or ""))
    return out


def create_request(db: Session, tenant_id: str, actor: str, user_id: str, data: dict) -> IsmsEvidenceRequest:
    request = js_trim(str(data.get("request") or ""))
    if len(request) < 3:
        raise _error("Describe the evidence you need.")
    due = None
    if data.get("dueOn"):
        try:
            due = date.fromisoformat(str(data["dueOn"]))
        except ValueError:
            raise _error("Enter a valid due date.") from None
    control = None
    if data.get("controlId"):
        control = db.get(IsmsTenantControl, str(data["controlId"]))
        if control is None or control.tenant_id != tenant_id:
            raise _error("Control not found.")
    row = IsmsEvidenceRequest(tenant_id=tenant_id, tenant_control_id=control.id if control else None,
                              request=request[:2000], due_on=due, requested_by_user_id=user_id, updated_by=actor)
    db.add(row)
    db.flush()
    audit.record(db, actor, "isms.evidence_requested", control.ref if control else "general", tenant_id, id=row.id)
    from .notify import emit
    emit(db, tenant_id, "isms.evidence_requested", id=row.id, control=control.ref if control else None,
         dueOn=due.isoformat() if due else None)
    if control and control.owner_user_id:
        from .. import mailer
        owner = db.get(User, control.owner_user_id)
        if owner:
            mailer.send(owner.email, f"Evidence requested for {control.ref}",
                        f"An auditor has asked for evidence for {control.ref} {control.title}"
                        f"{' by ' + due.strftime('%d/%m/%Y') if due else ''}: {request}\n\n"
                        "Answer it in Governance, Audit workspace.")
    return row


def answer_request(db: Session, row: IsmsEvidenceRequest, actor: str, user_id: str, response: str,
                   evidence_id: str | None) -> None:
    response = js_trim(response or "")
    if row.status == "closed":
        raise _error("That request is closed.")
    if len(response) < 2 and not evidence_id:
        raise _error("Add a note or choose evidence.")
    if evidence_id:
        e = db.get(IsmsEvidence, evidence_id)
        if e is None or e.tenant_id != row.tenant_id:
            raise _error("Evidence not found.")
    row.status, row.response, row.evidence_id = "answered", response[:8000], evidence_id
    row.answered_at, row.answered_by_user_id, row.updated_by = utcnow(), user_id, actor
    audit.record(db, actor, "isms.evidence_request_answered", row.id, row.tenant_id, evidence_id=evidence_id)


def close_request(db: Session, row: IsmsEvidenceRequest, actor: str) -> None:
    if row.status == "closed":
        return
    row.status, row.closed_at, row.updated_by = "closed", utcnow(), actor
    audit.record(db, actor, "isms.evidence_request_closed", row.id, row.tenant_id)


def control_owner(db: Session, row: IsmsEvidenceRequest) -> str | None:
    c = db.get(IsmsTenantControl, row.tenant_control_id) if row.tenant_control_id else None
    return c.owner_user_id if c else None


def record_view(db: Session, actor: str, tenant_id: str, method: str, path: str) -> None:
    """Auditors' reads are part of the audit trail, as in the standalone app."""
    audit.record(db, actor, "isms.auditor_viewed", path[:300], tenant_id, method=method)
