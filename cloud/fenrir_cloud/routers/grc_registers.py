"""Console API: contextual registers (GRC-18), objectives and management reviews (GRC-13)."""
from __future__ import annotations

import csv
import io
import uuid

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from .. import grc_registers as gr
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import GrcObjective, GrcRegisterEntry, GrcRegisterExport, GrcReview, utcnow

router = APIRouter(prefix="/api/console/grc", tags=["GRC registers and reviews"])


def bad(msg: str):
    raise HTTPException(400, msg)


def _owned(db: Session, p: Principal, model, row_id: str):
    row = db.get(model, row_id)
    if row is None or row.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "Not found")
    return row


# --- registers -----------------------------------------------------------------------------------------------------

@router.get("/registers")
def registers(p: Principal = Depends(current_principal)):
    p.require("read")
    return [{"key": k, "name": v[0], "scored": k in gr.SCORED, "categories": list(gr.PESTEL) if k == "pestel" else
             list(gr.ISSUE) if k == "issue" else [], "treatments": list(gr.TREATMENTS.get(k, ()))} for k, v in gr.REGISTERS.items()]


@router.get("/registers/{register}")
def list_entries(register: str, tenantId: str | None = None, p: Principal = Depends(current_principal),
                 db: Session = Depends(get_db)):
    p.require("read")
    if register not in gr.REGISTERS:
        raise HTTPException(404, "unknown register")
    rows = db.execute(select(GrcRegisterEntry).where(GrcRegisterEntry.register == register,
                                                     GrcRegisterEntry.tenant_id.in_(scoped_tenant(p, tenantId)))
                      .order_by(GrcRegisterEntry.ref)).scalars()
    return [gr.view(e) for e in rows]


@router.post("/registers/{register}")
def create_entry(register: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("grc")
    tenant = str(body.get("tenantId") or "")
    p.check_tenant(tenant)
    try:
        fields = gr.clean(register, body)
    except ValueError as e:
        bad(str(e))
    e = GrcRegisterEntry(tenant_id=tenant, register=register, ref=gr.next_ref(db, tenant, register), created_by=p.actor, **fields)
    db.add(e)
    db.flush()
    gr.record_version(e, p.actor, "created")
    audit.record(db, p.actor, "grc.register.created", f"{e.ref} {e.title}", tenant, register=register, entry=e.id)
    db.commit()
    return gr.view(e)


@router.get("/registers/{register}/{entry_id}")
def get_entry(register: str, entry_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    e = _owned(db, p, GrcRegisterEntry, entry_id)
    return {**gr.view(e), "history": e.history or []}


@router.patch("/registers/{register}/{entry_id}")
def update_entry(register: str, entry_id: str, body: dict = Body(...), p: Principal = Depends(current_principal),
                 db: Session = Depends(get_db)):
    p.require("grc")
    e = _owned(db, p, GrcRegisterEntry, entry_id)
    try:
        fields = gr.clean(e.register, body, e)
    except ValueError as ex:
        bad(str(ex))
    for k, v in fields.items():
        setattr(e, k, v)
    if body.get("reviewed") is True:
        e.reviewed_at, e.reviewed_by = utcnow(), p.actor
    e.version += 1
    e.updated_at = utcnow()
    gr.record_version(e, p.actor, str(body.get("note") or ("reviewed" if body.get("reviewed") else "")))
    audit.record(db, p.actor, "grc.register.updated", f"{e.ref} {e.title}", e.tenant_id, register=e.register,
                 entry=e.id, version=e.version, fields=sorted(fields))
    db.commit()
    return gr.view(e)


@router.post("/registers/{register}/exports")
def export_register(register: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """A versioned export: the register as it is now, kept with its hash."""
    p.require("read")
    tenant = str(body.get("tenantId") or "")
    p.check_tenant(tenant)
    if register not in gr.REGISTERS:
        raise HTTPException(404, "unknown register")
    rows = gr.export_rows(db, tenant, register)
    x = GrcRegisterExport(tenant_id=tenant, register=register, rows=rows, sha256=gr.digest(rows), created_by=p.actor)
    db.add(x)
    db.flush()
    audit.record(db, p.actor, "grc.register.exported", register, tenant, export=x.id, sha256=x.sha256, rows=len(rows))
    db.commit()
    return {"id": x.id, "sha256": x.sha256, "rows": len(rows), "createdAt": x.created_at.isoformat()}


@router.get("/register-exports")
def list_exports(register: str, tenantId: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    p.check_tenant(tenantId)
    rows = db.execute(select(GrcRegisterExport).where(GrcRegisterExport.tenant_id == tenantId, GrcRegisterExport.register == register)
                      .order_by(GrcRegisterExport.created_at.desc())).scalars()
    return [{"id": x.id, "sha256": x.sha256, "rows": len(x.rows), "createdAt": x.created_at.isoformat(), "createdBy": x.created_by}
            for x in rows]


@router.get("/register-exports/{export_id}.csv")
def export_csv(export_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    x = _owned(db, p, GrcRegisterExport, export_id)
    cols = ["ref", "title", "category", "owner", "status", "likelihood", "impact", "score", "residualScore", "treatment",
            "treatmentPlan", "reviewDue", "openActions", "version", "description"]
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow([f"# {gr.REGISTERS[x.register][0]} exported {x.created_at.isoformat()}Z by {x.created_by}; sha256 {x.sha256}"])
    w.writerow(cols)
    for r in x.rows:
        w.writerow([r.get(c) if r.get(c) is not None else "" for c in cols])
    return Response(out.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{x.register}-{x.created_at.date()}.csv"'})


# --- objectives ----------------------------------------------------------------------------------------------------

@router.get("/objectives")
def list_objectives(tenantId: str | None = None, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    rows = db.execute(select(GrcObjective).where(GrcObjective.tenant_id.in_(scoped_tenant(p, tenantId)))
                      .order_by(GrcObjective.title)).scalars()
    return [gr.objective_view(o) for o in rows]


def _objective_fields(body: dict, new: bool) -> dict:
    out = {}
    if "title" in body or new:
        t = str(body.get("title") or "").strip()
        if not 3 <= len(t) <= 300:
            bad("a title of 3 to 300 characters")
        out["title"] = t
    for k, n in (("description", 5000), ("owner", 200), ("kpi", 200), ("unit", 40)):
        if k in body:
            out[k] = str(body[k] or "")[:n]
    if "target" in body:
        if body["target"] is not None and not isinstance(body["target"], (int, float)):
            bad("the target is a number")
        out["target"] = body["target"]
    if "direction" in body:
        if body["direction"] not in ("higher", "lower"):
            bad("direction is higher or lower (which is better)")
        out["direction"] = body["direction"]
    if "status" in body:
        if body["status"] not in ("active", "achieved", "dropped"):
            bad("status is active, achieved or dropped")
        out["status"] = body["status"]
    if "due" in body:
        try:
            out["due"] = gr._date(body["due"])
        except ValueError as e:
            bad(str(e))
    return out


@router.post("/objectives")
def create_objective(body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("grc")
    tenant = str(body.get("tenantId") or "")
    p.check_tenant(tenant)
    o = GrcObjective(tenant_id=tenant, created_by=p.actor, measurements=[], **_objective_fields(body, True))
    db.add(o)
    db.flush()
    audit.record(db, p.actor, "grc.objective.created", o.title, tenant, objective=o.id)
    db.commit()
    return gr.objective_view(o)


@router.patch("/objectives/{objective_id}")
def update_objective(objective_id: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("grc")
    o = _owned(db, p, GrcObjective, objective_id)
    for k, v in _objective_fields(body, False).items():
        setattr(o, k, v)
    audit.record(db, p.actor, "grc.objective.updated", o.title, o.tenant_id, objective=o.id)
    db.commit()
    return gr.objective_view(o)


@router.post("/objectives/{objective_id}/measurements")
def measure(objective_id: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("grc")
    o = _owned(db, p, GrcObjective, objective_id)
    v = body.get("value")
    if not isinstance(v, (int, float)) or isinstance(v, bool):
        bad("a measurement is a number")
    o.measurements = (o.measurements or []) + [{"at": utcnow().isoformat(), "value": v, "by": p.actor,
                                                "note": str(body.get("note") or "")[:500]}]
    audit.record(db, p.actor, "grc.objective.measured", o.title, o.tenant_id, objective=o.id, value=v)
    db.commit()
    return gr.objective_view(o)


# --- management reviews --------------------------------------------------------------------------------------------

def _review_view(r: GrcReview) -> dict:
    return {"id": r.id, "tenantId": r.tenant_id, "title": r.title, "status": r.status,
            "heldOn": r.held_on.isoformat() if r.held_on else None, "attendees": r.attendees, "pack": r.pack,
            "packSha256": r.pack_sha256, "notes": r.notes, "decisions": r.decisions, "actions": r.actions,
            "createdBy": r.created_by, "createdAt": r.created_at.isoformat()}


@router.get("/reviews")
def list_reviews(tenantId: str | None = None, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    rows = db.execute(select(GrcReview).where(GrcReview.tenant_id.in_(scoped_tenant(p, tenantId)))
                      .order_by(GrcReview.created_at.desc())).scalars()
    return [_review_view(r) for r in rows]


@router.post("/reviews")
def create_review(body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("grc")
    tenant = str(body.get("tenantId") or "")
    p.check_tenant(tenant)
    title = str(body.get("title") or "").strip()[:300]
    if not title:
        bad("give the review a title")
    r = GrcReview(tenant_id=tenant, title=title, created_by=p.actor, attendees=[], decisions=[], actions=[])
    db.add(r)
    db.flush()
    audit.record(db, p.actor, "grc.review.created", title, tenant, review=r.id)
    db.commit()
    return _review_view(r)


@router.post("/reviews/{review_id}/pack")
def generate_pack(review_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Build the input pack from the current records (again, until the review is held)."""
    p.require("grc")
    r = _owned(db, p, GrcReview, review_id)
    if r.status == "held":
        bad("the review was held: its pack is kept as it was")
    prev = db.execute(select(GrcReview).where(GrcReview.tenant_id == r.tenant_id, GrcReview.status == "held",
                                              GrcReview.id != r.id).order_by(GrcReview.held_on.desc()).limit(1)).scalars().first()
    pack = gr.build_pack(db, r.tenant_id, prev.held_on if prev else None)
    r.pack, r.pack_sha256 = pack, gr.digest(pack)
    audit.record(db, p.actor, "grc.review.pack", r.title, r.tenant_id, review=r.id, sha256=r.pack_sha256)
    db.commit()
    return _review_view(r)


@router.post("/reviews/{review_id}/held")
def hold_review(review_id: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Record the meeting: who attended, notes, decisions and actions; the pack is fixed from then on."""
    p.require("grc")
    r = _owned(db, p, GrcReview, review_id)
    if r.status == "held":
        bad("already recorded")
    if not r.pack:
        bad("generate the input pack first")
    r.attendees = [str(x)[:200] for x in body.get("attendees") or []][:100]
    if not r.attendees:
        bad("list who attended")
    r.notes = str(body.get("notes") or "")[:50000]
    r.decisions = [{"id": uuid.uuid4().hex[:10], "text": str(d)[:2000]} for d in body.get("decisions") or [] if str(d).strip()][:200]
    r.actions = [{"id": uuid.uuid4().hex[:10], "text": str(a.get("text") or "")[:1000], "owner": str(a.get("owner") or "")[:200],
                  "due": str(a.get("due") or "")[:10], "done": False, "doneAt": None}
                 for a in body.get("actions") or [] if isinstance(a, dict) and str(a.get("text") or "").strip()][:200]
    try:
        r.held_on = gr._date(body.get("heldOn")) or utcnow()
    except ValueError as e:
        bad(str(e))
    r.status = "held"
    audit.record(db, p.actor, "grc.review.held", r.title, r.tenant_id, review=r.id, decisions=len(r.decisions),
                 actions=len(r.actions), pack_sha256=r.pack_sha256)
    db.commit()
    return _review_view(r)


@router.patch("/reviews/{review_id}/actions/{action_id}")
def review_action(review_id: str, action_id: str, body: dict = Body(...), p: Principal = Depends(current_principal),
                  db: Session = Depends(get_db)):
    p.require("grc")
    r = _owned(db, p, GrcReview, review_id)
    acts = [dict(a) for a in r.actions or []]
    a = next((a for a in acts if a["id"] == action_id), None)
    if a is None:
        raise HTTPException(404, "no such action")
    a["done"] = bool(body.get("done"))
    a["doneAt"] = utcnow().isoformat() if a["done"] else None
    r.actions = acts
    audit.record(db, p.actor, "grc.review.action", r.title, r.tenant_id, review=r.id, action_id=action_id, done=a["done"])
    db.commit()
    return _review_view(r)
