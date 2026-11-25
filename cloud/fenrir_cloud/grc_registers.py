"""Contextual registers (GRC-18), objectives with KPIs and management reviews (GRC-13).

Registers: business risks and opportunities (scored likelihood x impact, inherent and residual, with a treatment),
interested parties (their needs and expectations), internal and external issues, PESTEL factors, and the
improvement register. Every change keeps a version; an export is kept with its hash so it can be produced again.

A management review's input pack is built from the records as they are when it is generated: programme progress,
policies and their acknowledgement, the registers, objectives against their targets, continuity capability,
incidents since the previous review and the previous review's open actions. The pack is kept with its hash, and the
decisions and actions taken at the review are recorded against it.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import (ContinuityPlan, GrcAdoption, GrcObjective, GrcPolicy, GrcRegisterEntry, GrcRequirementState,
                     GrcReview, Incident, PolicyAttestation, utcnow)

REGISTERS = {
    "risk": ("Business risks", "R"),
    "opportunity": ("Opportunities", "O"),
    "interested_party": ("Interested parties", "IP"),
    "issue": ("Internal and external issues", "IS"),
    "pestel": ("PESTEL analysis", "PE"),
    "improvement": ("Improvement register", "IM"),
}
PESTEL = ("political", "economic", "social", "technological", "legal", "environmental")
ISSUE = ("internal", "external")
STATUS = ("open", "treating", "accepted", "closed")
TREATMENTS = {"risk": ("avoid", "reduce", "transfer", "accept"), "opportunity": ("exploit", "enhance", "share", "ignore")}
SCORED = ("risk", "opportunity")


def score(likelihood: int | None, impact: int | None) -> int | None:
    return likelihood * impact if likelihood and impact else None


def level(s: int | None) -> str:
    if s is None:
        return "unscored"
    return "high" if s >= 15 else "medium" if s >= 8 else "low"


def clean(register: str, body: dict, existing: GrcRegisterEntry | None = None) -> dict:
    """Validated fields of an entry; raises ValueError for the console."""
    if register not in REGISTERS:
        raise ValueError("unknown register")
    out: dict = {}
    if "title" in body or existing is None:
        title = str(body.get("title") or "").strip()
        if not 3 <= len(title) <= 300:
            raise ValueError("a title of 3 to 300 characters")
        out["title"] = title
    for k, n in (("description", 20000), ("owner", 200), ("treatment_plan", 20000)):
        src = {"treatment_plan": "treatmentPlan"}.get(k, k)
        if src in body:
            out[k] = str(body[src] or "")[:n]
    if "category" in body:
        c = str(body["category"] or "")
        allowed = PESTEL if register == "pestel" else ISSUE if register == "issue" else None
        if allowed and c not in allowed:
            raise ValueError(f"category is one of {', '.join(allowed)}")
        out["category"] = c[:40]
    if "status" in body:
        if body["status"] not in STATUS:
            raise ValueError("status is open, treating, accepted or closed")
        out["status"] = body["status"]
    for k in ("likelihood", "impact", "residualLikelihood", "residualImpact"):
        if k in body:
            v = body[k]
            if v is not None and (register not in SCORED or not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= 5):
                raise ValueError("likelihood and impact are 1 to 5, for risks and opportunities")
            out[{"residualLikelihood": "residual_likelihood", "residualImpact": "residual_impact"}.get(k, k)] = v
    if "treatment" in body:
        t = str(body["treatment"] or "")
        if t and t not in TREATMENTS.get(register, ()):
            raise ValueError(f"treatment is one of {', '.join(TREATMENTS.get(register, ()))}")
        out["treatment"] = t
    if "links" in body:
        out["links"] = [str(x)[:120] for x in body["links"] or []][:50]
    if "reviewDue" in body:
        out["review_due"] = _date(body["reviewDue"])
    if "actions" in body:
        acts = []
        for a in body["actions"] or []:
            if isinstance(a, dict) and str(a.get("text") or "").strip():
                acts.append({"id": str(a.get("id") or uuid.uuid4().hex[:10])[:20], "text": str(a["text"])[:1000],
                             "owner": str(a.get("owner") or "")[:200], "due": str(a.get("due") or "")[:10],
                             "done": bool(a.get("done")), "doneAt": a.get("doneAt") if a.get("done") else None})
        out["actions"] = acts[:100]
    return out


def _date(v) -> datetime | None:
    if not v:
        return None
    try:
        return datetime.fromisoformat(str(v)[:10])
    except ValueError:
        raise ValueError("dates are YYYY-MM-DD")


def next_ref(db: Session, tenant_id: str, register: str) -> str:
    n = db.execute(select(func.count()).select_from(GrcRegisterEntry).where(
        GrcRegisterEntry.tenant_id == tenant_id, GrcRegisterEntry.register == register)).scalar() or 0
    return f"{REGISTERS[register][1]}-{n + 1:03d}"


def view(e: GrcRegisterEntry) -> dict:
    s, r = score(e.likelihood, e.impact), score(e.residual_likelihood, e.residual_impact)
    now = utcnow()
    return {"id": e.id, "register": e.register, "ref": e.ref, "title": e.title, "description": e.description,
            "category": e.category, "owner": e.owner, "status": e.status, "likelihood": e.likelihood, "impact": e.impact,
            "score": s, "level": level(s), "residualLikelihood": e.residual_likelihood, "residualImpact": e.residual_impact,
            "residualScore": r, "residualLevel": level(r), "treatment": e.treatment, "treatmentPlan": e.treatment_plan,
            "links": e.links or [], "actions": e.actions or [],
            "openActions": sum(1 for a in e.actions or [] if not a.get("done")),
            "reviewDue": e.review_due.date().isoformat() if e.review_due else None,
            "reviewOverdue": bool(e.review_due and e.review_due < now and e.status != "closed"),
            "reviewedAt": e.reviewed_at.isoformat() if e.reviewed_at else None, "reviewedBy": e.reviewed_by,
            "version": e.version, "createdBy": e.created_by, "updatedAt": e.updated_at.isoformat()}


def record_version(e: GrcRegisterEntry, actor: str, note: str = "") -> None:
    snap = {k: v for k, v in view(e).items() if k not in ("openActions", "reviewOverdue")}
    e.history = (e.history or []) + [{"version": e.version, "by": actor, "at": utcnow().isoformat(), "note": note[:300],
                                      "data": snap}]


def export_rows(db: Session, tenant_id: str, register: str) -> list[dict]:
    rows = db.execute(select(GrcRegisterEntry).where(GrcRegisterEntry.tenant_id == tenant_id,
                                                     GrcRegisterEntry.register == register)
                      .order_by(GrcRegisterEntry.ref)).scalars().all()
    return [{k: v for k, v in view(e).items() if k not in ("updatedAt",)} for e in rows]


def digest(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


def objective_view(o: GrcObjective) -> dict:
    last = o.measurements[-1] if o.measurements else None
    on_track = None
    if last is not None and o.target is not None:
        on_track = last["value"] >= o.target if o.direction == "higher" else last["value"] <= o.target
    return {"id": o.id, "title": o.title, "description": o.description, "owner": o.owner, "kpi": o.kpi, "unit": o.unit,
            "target": o.target, "direction": o.direction, "due": o.due.date().isoformat() if o.due else None,
            "status": o.status, "measurements": o.measurements or [], "latest": last, "onTrack": on_track}


def build_pack(db: Session, tenant_id: str, since: datetime | None) -> dict:
    """The review's inputs, from the records as they are now."""
    from . import continuity

    now = utcnow()
    programmes = []
    for a in db.execute(select(GrcAdoption).where(GrcAdoption.tenant_id == tenant_id, GrcAdoption.status == "active")).scalars():
        states = db.execute(select(GrcRequirementState.status, func.count()).where(
            GrcRequirementState.tenant_id == tenant_id, GrcRequirementState.framework_key == a.framework_key)
            .group_by(GrcRequirementState.status)).all()
        programmes.append({"framework": a.framework_key, "requirements": {s: n for s, n in states}})
    policies = db.execute(select(GrcPolicy).where(GrcPolicy.tenant_id == tenant_id, GrcPolicy.status != "retired")).scalars().all()
    att = db.execute(select(PolicyAttestation).where(PolicyAttestation.tenant_id == tenant_id,
                                                     PolicyAttestation.removed.is_(False))).scalars().all()
    by_policy = {p.id: p for p in policies}
    acked = sum(1 for a in att if a.policy_id in by_policy and a.acknowledged_version == by_policy[a.policy_id].approved_version)
    entries = db.execute(select(GrcRegisterEntry).where(GrcRegisterEntry.tenant_id == tenant_id)).scalars().all()
    open_ = [view(e) for e in entries if e.status != "closed"]
    risks = sorted((e for e in open_ if e["register"] == "risk"), key=lambda e: -(e["residualScore"] or e["score"] or 0))
    plans = db.execute(select(ContinuityPlan).where(ContinuityPlan.tenant_id == tenant_id, ContinuityPlan.status != "retired")).scalars().all()
    bc = []
    for p in plans:
        a = continuity.assess(db, p)
        caps: dict[str, int] = {}
        for s in a["services"]:
            caps[s["capability"]] = caps.get(s["capability"], 0) + 1
        bc.append({"plan": p.name, "status": p.status, "approvedVersion": p.approved_version, "services": caps})
    inc_q = select(Incident.severity, func.count()).where(Incident.tenant_id == tenant_id)
    if since:
        inc_q = inc_q.where(Incident.created_at >= since)
    incidents = {s: n for s, n in db.execute(inc_q.group_by(Incident.severity)).all()}
    prev = db.execute(select(GrcReview).where(GrcReview.tenant_id == tenant_id, GrcReview.status == "held")
                      .order_by(GrcReview.held_on.desc()).limit(1)).scalars().first()
    return {
        "generatedAt": now.isoformat(), "since": since.isoformat() if since else None,
        "programmes": programmes,
        "policies": {"total": len(policies), "approved": sum(1 for p in policies if p.status == "approved"),
                     "reviewOverdue": [p.title for p in policies if p.review_due and p.review_due < now],
                     "acknowledgement": {"asked": len(att), "current": acked}},
        "registers": {r: {"open": sum(1 for e in open_ if e["register"] == r),
                          "reviewOverdue": sum(1 for e in open_ if e["register"] == r and e["reviewOverdue"])}
                      for r in REGISTERS},
        "topRisks": [{k: e[k] for k in ("ref", "title", "owner", "score", "residualScore", "treatment", "status")} for e in risks[:10]],
        "improvements": [{k: e[k] for k in ("ref", "title", "owner", "status", "openActions")} for e in open_ if e["register"] == "improvement"],
        "objectives": [objective_view(o) for o in db.execute(select(GrcObjective).where(
            GrcObjective.tenant_id == tenant_id, GrcObjective.status == "active")).scalars()],
        "continuity": bc,
        "incidents": incidents,
        "previousReview": {"id": prev.id, "title": prev.title, "heldOn": prev.held_on.isoformat() if prev.held_on else None,
                           "openActions": [a for a in prev.actions or [] if not a.get("done")]} if prev else None,
    }
