"""Control gaps and governance exceptions (FLOW-06).

A gap comes from a failing common control (its live signals), a policy-acknowledgement exception, a business risk,
or is raised by hand. It names the affected devices, has an owner and a due date, and its work is a ticket on the
service desk. It is treated (remediate, compensate or accept with a justification), evidence is attached, and it is
submitted for review. A reviewer closes it only when the evidence is there and, for a remediated control gap, the
control's signals pass now; otherwise it goes back. A control that fails again reopens its gap.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import grc_automation
from .models import Device, GrcEvidence, GrcGap, Tenant, utcnow

OPEN = ("open", "treating", "in_review")


def event(g: GrcGap, kind: str, text: str, by: str) -> None:
    g.timeline = (g.timeline or []) + [{"at": utcnow().isoformat(), "kind": kind, "text": text[:1000], "by": by}]
    g.updated_at = utcnow()


def control(db: Session, tenant: Tenant, control_id: str) -> dict | None:
    return next((c for c in grc_automation.status(db, tenant) if c["id"] == control_id), None)


def devices_named(db: Session, tenant_id: str, lines: list[str]) -> list[str]:
    """Devices of the customer whose host name appears in a control's evidence lines."""
    text = " ".join(lines).lower()
    return [d.id for d in db.execute(select(Device).where(Device.tenant_id == tenant_id)).scalars()
            if d.hostname and d.hostname.lower() in text][:200]


def scan(db: Session, tenant: Tenant, actor: str = "system:grc") -> dict:
    """Open a gap for each failing control without an open one; reopen a closed gap whose control fails again."""
    opened = reopened = 0
    for c in grc_automation.status(db, tenant):
        if c["automated"] != "failing":
            continue
        failing = [s for s in c["signals"] if s["passed"] is False]
        lines = [f"{s['label']}: " + "; ".join(s["evidence"][:5]) for s in failing]
        g = db.execute(select(GrcGap).where(GrcGap.tenant_id == tenant.id, GrcGap.source == "control",
                                            GrcGap.source_ref == c["id"]).order_by(GrcGap.created_at.desc())).scalars().first()
        if g is not None and g.status in OPEN:
            continue
        if g is not None and g.status == "closed":
            g.status, g.review = "open", None
            g.reopened += 1
            g.devices = sorted(set(g.devices or []) | set(devices_named(db, tenant.id, lines)))
            event(g, "reopened", "The control fails again: " + " | ".join(lines), actor)
            reopened += 1
            continue
        g = GrcGap(tenant_id=tenant.id, source="control", source_ref=c["id"], title=f"Control failing: {c['title']}",
                   description="\n".join(lines), devices=devices_named(db, tenant.id, lines), created_by=actor, timeline=[])
        db.add(g)
        event(g, "opened", "Opened because the control's signals fail", actor)
        opened += 1
    return {"opened": opened, "reopened": reopened}


def can_close(db: Session, tenant: Tenant, g: GrcGap) -> str | None:
    """Why the gap cannot be closed yet, or None."""
    if g.treatment in ("accept", "compensate") and len(g.justification.strip()) < 10:
        return "an accepted or compensated gap needs a justification"
    if not g.evidence_ids and g.treatment != "accept":
        return "attach evidence of the treatment"
    for eid in g.evidence_ids or []:
        e = db.get(GrcEvidence, eid)
        if e is None or e.tenant_id != g.tenant_id:
            return "an attached evidence item no longer exists"
    if g.source == "control" and g.treatment == "remediate":
        c = control(db, tenant, g.source_ref)
        if c is None:
            return "the control no longer exists"
        if c["automated"] == "failing":
            bad = [s["label"] for s in c["signals"] if s["passed"] is False]
            return "the control still fails now: " + ", ".join(bad)
    return None


def view(g: GrcGap) -> dict:
    return {"id": g.id, "tenantId": g.tenant_id, "source": g.source, "sourceRef": g.source_ref, "title": g.title,
            "description": g.description, "devices": g.devices or [], "owner": g.owner,
            "due": g.due.date().isoformat() if g.due else None, "treatment": g.treatment, "justification": g.justification,
            "status": g.status, "ticketId": g.ticket_id, "evidenceIds": g.evidence_ids or [], "submittedBy": g.submitted_by,
            "review": g.review, "reopened": g.reopened, "timeline": g.timeline or [], "createdBy": g.created_by,
            "createdAt": g.created_at.isoformat(), "overdue": bool(g.due and g.status in OPEN and g.due < utcnow())}
