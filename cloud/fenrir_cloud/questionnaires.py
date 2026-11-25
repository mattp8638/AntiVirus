"""Security questionnaires (GRC-15): a library of approved answers, and questionnaires from customers answered from
it. A library answer is only ever suggested: a person accepts or edits it, and a reviewer signs each answer off.
Answers are flagged when the library answer is past its review date (stale) or has no current evidence behind it
(unverified); nothing is asserted as compliant automatically."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import uuid
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import GrcAnswer, GrcEvidence, GrcPolicy, utcnow

STOP = set("a an the of to and or is are be do does your you we our in on for with any all by as at it this that "
           "have has how what which who whether there their".split())
SUGGEST_AT = 0.45


def words(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in STOP and len(w) > 1}


def similarity(a: str, b: str) -> float:
    x, y = words(a), words(b)
    return len(x & y) / len(x | y) if x and y else 0.0


def parse_questions(text: str) -> list[dict]:
    """Questions from CSV (a column named question, and optionally section and id) or one per line."""
    text = text.strip()
    rows: list[dict] = []
    first = text.splitlines()[0].lower() if text else ""
    if "question" in first and ("," in first or "\t" in first):
        reader = csv.DictReader(io.StringIO(text), dialect=csv.excel_tab if "\t" in first else csv.excel)
        for r in reader:
            r = {(k or "").strip().lower(): (v or "").strip() for k, v in r.items()}
            if r.get("question"):
                rows.append({"ref": r.get("id") or r.get("ref") or "", "section": r.get("section", ""), "text": r["question"]})
    else:
        rows = [{"ref": "", "section": "", "text": line.strip()} for line in text.splitlines() if line.strip()]
    out = []
    for i, r in enumerate(rows[:2000]):
        out.append({"id": uuid.uuid4().hex[:10], "ref": (r["ref"] or str(i + 1))[:40], "section": r["section"][:200],
                    "text": r["text"][:4000], "answer": "", "source": None, "evidenceIds": [], "assignee": "",
                    "state": "unanswered", "reviewedBy": None, "reviewedAt": None, "flags": []})
    return out


def library_status(db: Session, a: GrcAnswer) -> dict:
    """Whether a library answer is stale (past its review date) or unverified (no current evidence or approved policy)."""
    now = utcnow()
    stale = a.status != "approved" or not a.approved_at or now > a.approved_at + timedelta(days=30 * a.review_months)
    ev_ok = False
    for eid in a.evidence_ids or []:
        e = db.get(GrcEvidence, eid)
        if e is not None and e.tenant_id == a.tenant_id and (e.valid_until is None or e.valid_until >= now):
            ev_ok = True
    for pid in a.policy_ids or []:
        p = db.get(GrcPolicy, pid)
        if p is not None and p.tenant_id == a.tenant_id and p.status == "approved":
            ev_ok = True
    return {"stale": stale, "unverified": not ev_ok}


def flags_for(db: Session, q: dict) -> list[str]:
    out = []
    if q.get("source"):
        a = db.get(GrcAnswer, q["source"]["answerId"])
        if a is None:
            out.append("source answer removed")
        else:
            st = library_status(db, a)
            if st["stale"]:
                out.append("stale: the library answer is past its review date")
            if st["unverified"]:
                out.append("unverified: no current evidence or approved policy behind it")
            if q.get("answer", "").strip() != q["source"].get("answer", "").strip():
                out.append("edited from the library answer")
    elif q.get("answer") and not q.get("evidenceIds"):
        out.append("unverified: no evidence referenced")
    return out


def suggest(db: Session, tenant_id: str, text: str, limit: int = 3) -> list[dict]:
    rows = db.execute(select(GrcAnswer).where(GrcAnswer.tenant_id == tenant_id, GrcAnswer.status == "approved")).scalars()
    scored = sorted(((similarity(text, a.question), a) for a in rows), key=lambda x: -x[0])
    return [{"answerId": a.id, "question": a.question, "answer": a.answer, "score": round(s, 2),
             **library_status(db, a)} for s, a in scored[:limit] if s >= SUGGEST_AT]


def export_rows(q: list[dict]) -> list[list[str]]:
    rows = [["ref", "section", "question", "answer", "evidence", "reviewed_by", "reviewed_at", "flags"]]
    for x in q:
        rows.append([x["ref"], x["section"], x["text"], x["answer"], " ".join(x.get("evidenceIds") or []),
                     x.get("reviewedBy") or "", x.get("reviewedAt") or "", "; ".join(x.get("flags") or [])])
    return rows


def digest(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()
