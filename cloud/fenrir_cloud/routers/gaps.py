"""Console API: control gaps and governance exceptions (FLOW-06), fenrir_cloud/gaps.py."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, services
from .. import gaps as gp
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import Device, GrcEvidence, GrcGap, GrcRegisterEntry, PolicyAttestation, Tenant, Ticket

router = APIRouter(prefix="/api/console/grc/gaps", tags=["GRC gaps"])


def bad(msg: str):
    raise HTTPException(400, msg)


def _gap(db: Session, p: Principal, gap_id: str) -> GrcGap:
    g = db.get(GrcGap, gap_id)
    if g is None or g.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "Not found")
    return g


def _tenant(db: Session, p: Principal, tid: str) -> Tenant:
    p.check_tenant(tid)
    t = db.get(Tenant, tid)
    if t is None:
        raise HTTPException(404, "Not found")
    return t


@router.get("")
def list_gaps(tenantId: str | None = None, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    rows = db.execute(select(GrcGap).where(GrcGap.tenant_id.in_(scoped_tenant(p, tenantId)))
                      .order_by(GrcGap.created_at.desc())).scalars()
    return [gp.view(g) for g in rows]


@router.post("/scan")
def scan(body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Open gaps for the customer's failing controls (and reopen ones that fail again)."""
    p.require("grc")
    t = _tenant(db, p, str(body.get("tenantId") or ""))
    out = gp.scan(db, t, p.actor)
    audit.record(db, p.actor, "grc.gaps.scanned", t.name, t.id, **out)
    db.commit()
    return out


@router.post("")
def create_gap(body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """A gap from a policy exception, a business risk, or raised by hand."""
    p.require("grc")
    t = _tenant(db, p, str(body.get("tenantId") or ""))
    source, ref = body.get("source") or "manual", str(body.get("sourceRef") or "")
    title, desc = str(body.get("title") or "").strip(), str(body.get("description") or "")
    if source == "exception":
        a = db.get(PolicyAttestation, ref)
        if a is None or a.tenant_id != t.id or not a.exception:
            bad("choose a policy acknowledgement with an exception")
        title = title or f"Policy exception: {a.email}"
        desc = desc or f"{a.exception.get('reason')} (until {a.exception.get('until')})"
    elif source == "risk":
        e = db.get(GrcRegisterEntry, ref)
        if e is None or e.tenant_id != t.id or e.register != "risk":
            bad("choose a business risk")
        title = title or f"Risk treatment: {e.ref} {e.title}"
        desc = desc or e.treatment_plan or e.description
    elif source != "manual":
        bad("a gap comes from an exception, a risk, or is raised by hand (control gaps come from a scan)")
    if len(title) < 3:
        bad("give the gap a title")
    g = GrcGap(tenant_id=t.id, source=source, source_ref=ref, title=title[:300], description=desc[:20000], created_by=p.actor,
               timeline=[], devices=[])
    db.add(g)
    gp.event(g, "opened", f"Raised from {source}", p.actor)
    db.flush()
    audit.record(db, p.actor, "grc.gap.opened", g.title, t.id, gap=g.id, source=source)
    db.commit()
    return gp.view(g)


@router.patch("/{gap_id}")
def update_gap(gap_id: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("grc")
    g = _gap(db, p, gap_id)
    if g.status == "closed":
        bad("the gap is closed")
    changes = []
    if "owner" in body:
        g.owner = str(body["owner"] or "")[:200]
        changes.append(f"owner {g.owner}")
    if "due" in body:
        try:
            g.due = datetime.fromisoformat(str(body["due"])[:10]) if body["due"] else None
        except ValueError:
            bad("the due date is YYYY-MM-DD")
        changes.append(f"due {body['due']}")
    if "treatment" in body:
        if body["treatment"] not in ("remediate", "compensate", "accept"):
            bad("treatment is remediate, compensate or accept")
        g.treatment = body["treatment"]
        changes.append(f"treatment {g.treatment}")
    if "justification" in body:
        g.justification = str(body["justification"] or "")[:5000]
        changes.append("justification")
    if "devices" in body:
        ids = [str(x) for x in body["devices"] or []][:500]
        for d in ids:
            dev = db.get(Device, d)
            if dev is None or dev.tenant_id != g.tenant_id:
                bad("devices must be this customer's")
        g.devices = ids
        changes.append(f"{len(ids)} devices")
    if "evidenceIds" in body:
        ids = [str(x) for x in body["evidenceIds"] or []][:100]
        for e in ids:
            ev = db.get(GrcEvidence, e)
            if ev is None or ev.tenant_id != g.tenant_id:
                bad("evidence must be this customer's")
        g.evidence_ids = ids
        changes.append(f"{len(ids)} evidence items")
    if g.status == "open" and (g.owner or g.ticket_id):
        g.status = "treating"
    gp.event(g, "updated", ", ".join(changes) or "updated", p.actor)
    audit.record(db, p.actor, "grc.gap.updated", g.title, g.tenant_id, gap=g.id, changes=changes)
    db.commit()
    return gp.view(g)


@router.post("/{gap_id}/ticket")
def open_ticket(gap_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The work as a ticket on the service desk, assigned to the gap's owner."""
    p.require("grc")
    g = _gap(db, p, gap_id)
    if g.ticket_id:
        bad("the gap already has a ticket")
    t = services.open_ticket(db, g.tenant_id, f"[GRC] {g.title}",
                             f"{g.description}\n\nTreatment: {g.treatment}. Close the gap from Compliance > Gaps once the "
                             f"work is done and evidenced.", priority="P3", source="grc",
                             device_id=(g.devices or [None])[0], requester=p.actor, assignee=g.owner or None)
    g.ticket_id = t.id
    if g.status == "open":
        g.status = "treating"
    gp.event(g, "ticket", f"Ticket #{t.number} opened", p.actor)
    audit.record(db, p.actor, "grc.gap.ticket", g.title, g.tenant_id, gap=g.id, ticket=t.id)
    db.commit()
    return {**gp.view(g), "ticketNumber": t.number}


@router.post("/{gap_id}/submit")
def submit(gap_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("grc")
    g = _gap(db, p, gap_id)
    if g.status not in ("open", "treating"):
        bad("only an open gap is submitted for review")
    if not g.owner:
        bad("give the gap an owner first")
    g.status, g.submitted_by = "in_review", p.actor
    gp.event(g, "submitted", "Submitted for review", p.actor)
    audit.record(db, p.actor, "grc.gap.submitted", g.title, g.tenant_id, gap=g.id)
    db.commit()
    return gp.view(g)


@router.post("/{gap_id}/review")
def review(gap_id: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Close the gap (evidence there, and a remediated control passing now) or send it back."""
    p.require("grc")
    g = _gap(db, p, gap_id)
    if g.status != "in_review":
        bad("the gap is not in review")
    note = str(body.get("note") or "")[:2000]
    if body.get("outcome") == "close":
        why = gp.can_close(db, db.get(Tenant, g.tenant_id), g)
        if why:
            raise HTTPException(409, why)
        g.status = "closed"
        g.review = {"by": p.actor, "outcome": "closed", "note": note, "at": gp.utcnow().isoformat(),
                    "sameAsSubmitter": p.actor == g.submitted_by}
        if g.ticket_id:
            t = db.get(Ticket, g.ticket_id)
            if t is not None and t.status not in ("Resolved", "Closed"):
                t.comments = (t.comments or []) + [{"at": gp.utcnow().isoformat(), "by": p.actor, "internal": True,
                                                    "text": "The GRC gap was reviewed and closed."}]
        gp.event(g, "closed", f"Reviewed and closed. {note}".strip(), p.actor)
    elif body.get("outcome") == "return":
        g.status = "treating"
        g.review = {"by": p.actor, "outcome": "returned", "note": note, "at": gp.utcnow().isoformat()}
        gp.event(g, "returned", f"Sent back: {note}", p.actor)
    else:
        bad("outcome is close or return")
    audit.record(db, p.actor, f"grc.gap.{g.review['outcome']}", g.title, g.tenant_id, gap=g.id, note=note[:200])
    db.commit()
    return gp.view(g)
