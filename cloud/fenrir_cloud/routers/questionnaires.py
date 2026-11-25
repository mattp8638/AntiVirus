"""Console API: security questionnaires and the answer library (GRC-15)."""
from __future__ import annotations

import csv
import io
from datetime import datetime

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from .. import questionnaires as qs
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import GrcAnswer, GrcEvidence, GrcPolicy, GrcQuestionnaire, utcnow

router = APIRouter(prefix="/api/console/grc", tags=["GRC questionnaires"])


def bad(msg: str):
    raise HTTPException(400, msg)


def _owned(db: Session, p: Principal, model, row_id: str):
    row = db.get(model, row_id)
    if row is None or row.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "Not found")
    return row


def _answer_view(db: Session, a: GrcAnswer) -> dict:
    return {"id": a.id, "question": a.question, "answer": a.answer, "tags": a.tags, "evidenceIds": a.evidence_ids,
            "policyIds": a.policy_ids, "status": a.status, "approvedBy": a.approved_by,
            "approvedAt": a.approved_at.isoformat() if a.approved_at else None, "reviewMonths": a.review_months,
            **qs.library_status(db, a)}


def _refs(db: Session, tenant: str, ids, model) -> list[str]:
    out = []
    for i in ids or []:
        row = db.get(model, str(i))
        if row is None or row.tenant_id != tenant:
            bad("evidence and policies must be this customer's")
        out.append(row.id)
    return out[:50]


@router.get("/answers")
def list_answers(tenantId: str | None = None, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    rows = db.execute(select(GrcAnswer).where(GrcAnswer.tenant_id.in_(scoped_tenant(p, tenantId)), GrcAnswer.status != "retired")
                      .order_by(GrcAnswer.question)).scalars()
    return [_answer_view(db, a) for a in rows]


@router.post("/answers")
def create_answer(body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("grc")
    tenant = str(body.get("tenantId") or "")
    p.check_tenant(tenant)
    q, ans = str(body.get("question") or "").strip(), str(body.get("answer") or "").strip()
    if len(q) < 5 or not ans:
        bad("a question and its answer")
    a = GrcAnswer(tenant_id=tenant, question=q[:4000], answer=ans[:20000], tags=[str(t)[:40] for t in body.get("tags") or []][:20],
                  evidence_ids=_refs(db, tenant, body.get("evidenceIds"), GrcEvidence),
                  policy_ids=_refs(db, tenant, body.get("policyIds"), GrcPolicy),
                  review_months=int(body.get("reviewMonths") or 12), updated_by=p.actor)
    db.add(a)
    db.flush()
    audit.record(db, p.actor, "grc.answer.created", q[:120], tenant, answer=a.id)
    db.commit()
    return _answer_view(db, a)


@router.patch("/answers/{answer_id}")
def update_answer(answer_id: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Editing an answer sends it back to draft; approving it starts its review period."""
    p.require("grc")
    a = _owned(db, p, GrcAnswer, answer_id)
    changed = False
    for k in ("question", "answer"):
        if k in body and str(body[k]).strip() != getattr(a, k):
            setattr(a, k, str(body[k]).strip()[:20000])
            changed = True
    if "evidenceIds" in body:
        a.evidence_ids = _refs(db, a.tenant_id, body["evidenceIds"], GrcEvidence)
    if "policyIds" in body:
        a.policy_ids = _refs(db, a.tenant_id, body["policyIds"], GrcPolicy)
    if changed and a.status == "approved":
        a.status, a.approved_at = "draft", None
    action = body.get("action")
    if action == "approve":
        a.status, a.approved_by, a.approved_at = "approved", p.actor, utcnow()
    elif action == "retire":
        a.status = "retired"
    a.updated_by, a.updated_at = p.actor, utcnow()
    audit.record(db, p.actor, f"grc.answer.{action or 'updated'}", a.question[:120], a.tenant_id, answer=a.id)
    db.commit()
    return _answer_view(db, a)


def _q_view(db: Session, x: GrcQuestionnaire, full: bool = True) -> dict:
    questions = x.questions or []
    counts: dict[str, int] = {}
    for q in questions:
        counts[q["state"]] = counts.get(q["state"], 0) + 1
    out = {"id": x.id, "tenantId": x.tenant_id, "title": x.title, "counterparty": x.counterparty,
           "due": x.due.date().isoformat() if x.due else None, "status": x.status, "counts": counts,
           "flagged": sum(1 for q in questions if q.get("flags")), "exports": x.exports, "createdBy": x.created_by,
           "createdAt": x.created_at.isoformat()}
    if full:
        out["questions"] = questions
    return out


@router.get("/questionnaires")
def list_questionnaires(tenantId: str | None = None, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    rows = db.execute(select(GrcQuestionnaire).where(GrcQuestionnaire.tenant_id.in_(scoped_tenant(p, tenantId)))
                      .order_by(GrcQuestionnaire.created_at.desc())).scalars()
    return [_q_view(db, x, full=False) for x in rows]


@router.post("/questionnaires")
def create_questionnaire(body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Questions pasted as CSV (a question column; section and id optional) or one per line."""
    p.require("grc")
    tenant = str(body.get("tenantId") or "")
    p.check_tenant(tenant)
    title = str(body.get("title") or "").strip()[:300]
    questions = qs.parse_questions(str(body.get("questions") or ""))
    if not title or not questions:
        bad("a title and at least one question")
    due = None
    if body.get("due"):
        try:
            due = datetime.fromisoformat(str(body["due"])[:10])
        except ValueError:
            bad("the due date is YYYY-MM-DD")
    x = GrcQuestionnaire(tenant_id=tenant, title=title, counterparty=str(body.get("counterparty") or "")[:200], due=due,
                         questions=questions, exports=[], created_by=p.actor)
    db.add(x)
    db.flush()
    audit.record(db, p.actor, "grc.questionnaire.created", title, tenant, questionnaire=x.id, questions=len(questions))
    db.commit()
    return _q_view(db, x)


@router.get("/questionnaires/{qid}")
def get_questionnaire(qid: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    x = _owned(db, p, GrcQuestionnaire, qid)
    # Flags reflect the library as it is now.
    x.questions = [{**q, "flags": qs.flags_for(db, q)} for q in x.questions or []]
    db.commit()
    return _q_view(db, x)


@router.get("/questionnaires/{qid}/questions/{question_id}/suggestions")
def suggestions(qid: str, question_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    x = _owned(db, p, GrcQuestionnaire, qid)
    q = next((q for q in x.questions or [] if q["id"] == question_id), None)
    if q is None:
        raise HTTPException(404, "no such question")
    return qs.suggest(db, x.tenant_id, q["text"])


@router.patch("/questionnaires/{qid}/questions/{question_id}")
def answer_question(qid: str, question_id: str, body: dict = Body(...), p: Principal = Depends(current_principal),
                    db: Session = Depends(get_db)):
    """Assign, answer (typed, or from a library answer that is then shown as its source) or review one question."""
    p.require("grc")
    x = _owned(db, p, GrcQuestionnaire, qid)
    if x.status == "completed":
        bad("the questionnaire is completed")
    questions = [dict(q) for q in x.questions or []]
    q = next((q for q in questions if q["id"] == question_id), None)
    if q is None:
        raise HTTPException(404, "no such question")
    if "assignee" in body:
        q["assignee"] = str(body["assignee"] or "")[:200]
    if body.get("fromAnswer"):
        a = _owned(db, p, GrcAnswer, str(body["fromAnswer"]))
        if a.tenant_id != x.tenant_id or a.status != "approved":
            bad("only an approved library answer of this customer can be used")
        q["answer"], q["evidenceIds"] = a.answer, list(a.evidence_ids or [])
        q["source"] = {"answerId": a.id, "answer": a.answer, "approvedAt": a.approved_at.isoformat() if a.approved_at else None}
        q["state"], q["reviewedBy"], q["reviewedAt"] = "drafted", None, None
    if "answer" in body:
        q["answer"] = str(body["answer"] or "")[:20000]
        q["state"] = "drafted" if q["answer"].strip() else "unanswered"
        q["reviewedBy"], q["reviewedAt"] = None, None
    if "evidenceIds" in body:
        q["evidenceIds"] = _refs(db, x.tenant_id, body["evidenceIds"], GrcEvidence)
    if body.get("review") is True:
        if not q["answer"].strip():
            bad("there is no answer to review")
        q["state"], q["reviewedBy"], q["reviewedAt"] = "reviewed", p.actor, utcnow().isoformat()
    q["flags"] = qs.flags_for(db, q)
    x.questions = questions
    if x.status == "open" and any(qq["state"] == "reviewed" for qq in questions):
        x.status = "in_review"
    audit.record(db, p.actor, "grc.questionnaire.answer", x.title, x.tenant_id, questionnaire=x.id, question=q["ref"],
                 state=q["state"], from_library=bool(body.get("fromAnswer")))
    db.commit()
    return q


@router.post("/questionnaires/{qid}/complete")
def complete(qid: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Every question answered and reviewed by a person: then it can be completed."""
    p.require("grc")
    x = _owned(db, p, GrcQuestionnaire, qid)
    left = [q["ref"] for q in x.questions or [] if q["state"] != "reviewed"]
    if left:
        bad(f"{len(left)} question(s) are not reviewed yet: {', '.join(left[:10])}")
    x.status = "completed"
    audit.record(db, p.actor, "grc.questionnaire.completed", x.title, x.tenant_id, questionnaire=x.id)
    db.commit()
    return _q_view(db, x)


@router.get("/questionnaires/{qid}/export.csv")
def export(qid: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    x = _owned(db, p, GrcQuestionnaire, qid)
    questions = [{**q, "flags": qs.flags_for(db, q)} for q in x.questions or []]
    rows = qs.export_rows(questions)
    sha = qs.digest(rows)
    x.exports = (x.exports or []) + [{"at": utcnow().isoformat(), "by": p.actor, "sha256": sha, "status": x.status}]
    audit.record(db, p.actor, "grc.questionnaire.exported", x.title, x.tenant_id, questionnaire=x.id, sha256=sha)
    db.commit()
    out = io.StringIO()
    csv.writer(out).writerows(rows)
    return Response(out.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="questionnaire-{x.id}.csv"', "X-Content-SHA256": sha})


@router.post("/questionnaires/{qid}/questions/{question_id}/to-library")
def to_library(qid: str, question_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """A reviewed answer becomes a draft library answer (approved separately)."""
    p.require("grc")
    x = _owned(db, p, GrcQuestionnaire, qid)
    q = next((q for q in x.questions or [] if q["id"] == question_id), None)
    if q is None or q["state"] != "reviewed":
        bad("only a reviewed answer can go to the library")
    a = GrcAnswer(tenant_id=x.tenant_id, question=q["text"], answer=q["answer"], evidence_ids=q.get("evidenceIds") or [],
                  updated_by=p.actor)
    db.add(a)
    db.flush()
    audit.record(db, p.actor, "grc.answer.created", q["text"][:120], x.tenant_id, answer=a.id, from_questionnaire=x.id)
    db.commit()
    return _answer_view(db, a)
