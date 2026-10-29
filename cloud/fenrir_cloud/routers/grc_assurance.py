"""Continuous GRC: cross-framework controls, automated evidence, endpoint baselines and third-party risk."""

from __future__ import annotations

import html
from urllib.parse import parse_qs

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, grc_automation, grc_baselines, ratelimit, tprm
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import GrcEvidence, Tenant, Vendor, VendorAssessment, utcnow

router = APIRouter(prefix="/api/console/grc-assurance", tags=["GRC automation"])
public = APIRouter(tags=["Supplier questionnaire"])


def _tenant(db: Session, principal: Principal, tenant_id: str | None) -> Tenant:
    if not tenant_id:
        raise HTTPException(422, "Choose a customer")
    principal.check_tenant(tenant_id)
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "Not found")
    return tenant


# --------------------------------------------------------------------------- crosswalk and automation


@router.get("/crosswalk")
def get_crosswalk(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    return grc_automation.status(db, _tenant(db, principal, tenant_id))


@router.post("/crosswalk/propagate")
def propagate(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Carry an implemented requirement and its evidence to the same control in the customer's other frameworks."""
    principal.require("grc")
    tenant = _tenant(db, principal, body.get("tenantId"))
    try:
        updated = grc_automation.propagate(db, tenant, str(body.get("framework") or ""), str(body.get("requirementId") or ""),
                                           principal.actor)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    db.commit()
    return {"updated": updated}


@router.get("/automation")
def get_automation(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    tenant = _tenant(db, principal, tenant_id)
    settings = (tenant.settings or {}).get("grcAutomation") or {}
    evidence = db.execute(select(GrcEvidence).where(GrcEvidence.tenant_id == tenant.id, GrcEvidence.kind == "automated")
                          .order_by(GrcEvidence.created_at.desc()).limit(100)).scalars().all()
    return {"enabled": bool(settings.get("enabled")), "lastCollectedAt": settings.get("lastCollectedAt"),
            "signals": {k: {"label": grc_automation.label(k), "passed": v} for k, v in (settings.get("lastSignals") or {}).items()},
            "evidence": [{"id": e.id, "title": e.title, "controlId": e.control_id, "status": (e.data or {}).get("status"),
                          "description": e.description, "sha256": e.sha256, "createdAt": e.created_at.isoformat() + "Z",
                          "validUntil": e.valid_until.isoformat() + "Z" if e.valid_until else None} for e in evidence]}


@router.put("/automation/{tenant_id}")
def set_automation(tenant_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("grc")
    tenant = _tenant(db, principal, tenant_id)
    settings = {**((tenant.settings or {}).get("grcAutomation") or {}), "enabled": bool(body.get("enabled"))}
    tenant.settings = {**(tenant.settings or {}), "grcAutomation": settings}
    audit.record(db, principal.actor, "grc.automation.configured", tenant.name, tenant.id, enabled=settings["enabled"])
    db.commit()
    return {"enabled": settings["enabled"]}


@router.post("/automation/{tenant_id}/collect")
def collect_now(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("grc")
    result = grc_automation.collect(db, _tenant(db, principal, tenant_id), principal.actor, force=True)
    db.commit()
    return result


# --------------------------------------------------------------------------- baselines


@router.get("/baselines")
def get_baselines(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    out = {"catalogue": grc_baselines.catalogue()}
    if tenant_id:
        tenant = _tenant(db, principal, tenant_id)
        out["assigned"] = grc_baselines.assigned(tenant)
        out["report"] = grc_baselines.report(db, tenant)
    return out


@router.put("/baselines/{key}/{tenant_id}")
def assign_baseline(key: str, tenant_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                    db: Session = Depends(get_db)):
    """Assign a baseline (audit: detect only; enforce: fix drift automatically). Enforcing runs scripts on devices."""
    principal.require("grc")
    principal.require("configure")
    mode = str(body.get("mode") or "audit")
    if mode == "enforce":
        principal.require("scripts")
    tenant = _tenant(db, principal, tenant_id)
    try:
        record = grc_baselines.assign(db, tenant, key, mode, principal.actor)
    except KeyError as exc:
        raise HTTPException(404, "Unknown baseline") from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    db.commit()
    return record


@router.delete("/baselines/{key}/{tenant_id}")
def remove_baseline(key: str, tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("grc")
    principal.require("configure")
    grc_baselines.unassign(db, _tenant(db, principal, tenant_id), key, principal.actor)
    db.commit()
    return {"removed": key}


# --------------------------------------------------------------------------- suppliers


def _vendor(db: Session, principal: Principal, vendor_id: str) -> Vendor:
    row = db.get(Vendor, vendor_id)
    if row is None or row.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    return row


def _apply_vendor(row: Vendor, body: dict) -> None:
    for field, attr, limit in (("name", "name", 200), ("domain", "domain", 255), ("services", "services", 4000),
                               ("contactName", "contact_name", 200), ("contactEmail", "contact_email", 200), ("owner", "owner", 200),
                               ("notes", "notes", 8000)):
        if field in body:
            setattr(row, attr, str(body[field] or "").strip()[:limit])
    row.domain = row.domain.lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    if "criticality" in body:
        if body["criticality"] not in tprm.CRITICALITY:
            raise HTTPException(422, f"criticality must be one of {', '.join(tprm.CRITICALITY)}")
        row.criticality = body["criticality"]
    if "dataAccess" in body:
        if body["dataAccess"] not in tprm.DATA_ACCESS:
            raise HTTPException(422, f"dataAccess must be one of {', '.join(tprm.DATA_ACCESS)}")
        row.data_access = body["dataAccess"]
    if "documents" in body:
        row.documents = [{"type": str(d.get("type") or "Document")[:80], "name": str(d.get("name") or "")[:200],
                          "expiresAt": str(d.get("expiresAt") or "")[:40], "url": str(d.get("url") or "")[:1000]}
                         for d in (body["documents"] or [])[:50] if isinstance(d, dict)]
    if not row.name:
        raise HTTPException(422, "A supplier name is required")


@router.get("/vendors")
def list_vendors(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    rows = db.execute(select(Vendor).where(Vendor.tenant_id.in_(scoped_tenant(principal, tenant_id)))
                      .order_by(Vendor.status, Vendor.name)).scalars().all()
    return [tprm.view(r) for r in rows]


@router.post("/vendors")
def create_vendor(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("grc")
    tenant = _tenant(db, principal, body.get("tenantId"))
    row = Vendor(tenant_id=tenant.id, name="", created_by=principal.actor, created_at=utcnow())
    _apply_vendor(row, body)
    tprm.rescore(row)
    tprm.schedule_review(row)
    db.add(row)
    db.flush()
    audit.record(db, principal.actor, "tprm.vendor.created", row.name, tenant.id, vendor=row.id, criticality=row.criticality)
    db.commit()
    return tprm.view(row)


@router.patch("/vendors/{vendor_id}")
def update_vendor(vendor_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("grc")
    row = _vendor(db, principal, vendor_id)
    _apply_vendor(row, body)
    if body.get("status") in ("active", "offboarded"):
        row.status = body["status"]
    tprm.rescore(row)
    if {"criticality"} & set(body):
        tprm.schedule_review(row)
    audit.record(db, principal.actor, "tprm.vendor.updated", row.name, row.tenant_id, vendor=row.id, fields=sorted(body))
    db.commit()
    return tprm.view(row)


@router.post("/vendors/{vendor_id}/scan")
def scan_vendor(vendor_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("grc")
    row = _vendor(db, principal, vendor_id)
    try:
        tprm.scan(db, row)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    db.commit()
    return tprm.view(row)


@router.post("/vendors/{vendor_id}/assessments")
def send_questionnaire(vendor_id: str, body: dict = Body(default={}), principal: Principal = Depends(current_principal),
                       db: Session = Depends(get_db)):
    """Send the security questionnaire. The link is returned too, so it can be shared another way."""
    principal.require("grc")
    row = _vendor(db, principal, vendor_id)
    recipient = str(body.get("recipient") or row.contact_email or "")
    assessment, link = tprm.send_assessment(db, row, principal.actor, recipient)
    db.commit()
    return {"id": assessment.id, "link": link, "recipient": recipient, "dueAt": assessment.due_at.isoformat() + "Z"}


@router.get("/vendors/{vendor_id}/assessments")
def vendor_assessments(vendor_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    row = _vendor(db, principal, vendor_id)
    items = db.execute(select(VendorAssessment).where(VendorAssessment.vendor_id == row.id)
                       .order_by(VendorAssessment.sent_at.desc())).scalars().all()
    return [{"id": a.id, "status": a.status, "recipient": a.recipient, "score": a.score, "findings": a.findings, "answers": a.answers,
             "sentBy": a.sent_by, "sentAt": a.sent_at.isoformat() + "Z", "dueAt": a.due_at.isoformat() + "Z" if a.due_at else None,
             "completedAt": a.completed_at.isoformat() + "Z" if a.completed_at else None} for a in items]


@router.get("/questionnaire")
def questionnaire(principal: Principal = Depends(current_principal)):
    principal.require("read")
    return tprm.QUESTIONS


# --------------------------------------------------------------------------- the supplier's page (no account)

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security questionnaire</title><style>body{{font:15px/1.5 system-ui,sans-serif;max-width:760px;margin:24px auto;padding:0 16px;color:#1f2937}}
fieldset{{border:1px solid #d1d5db;border-radius:8px;margin:12px 0;padding:12px}}legend{{font-weight:600;padding:0 6px}}
label{{margin-right:14px}}textarea{{width:100%;margin-top:6px}}button{{padding:10px 18px;font-size:15px}}.muted{{color:#6b7280}}</style></head>
<body>{body}</body></html>"""


def _page(body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(PAGE.format(body=body), status_code=status,
                        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY"})


def _open_assessment(db: Session, token: str) -> tuple[VendorAssessment | None, str]:
    if len(token) > 100:
        return None, "This link is not valid."
    row = tprm.assessment_for_token(db, token)
    if row is None or row.status == "cancelled":
        return None, "This link is not valid. Ask your contact for a new one."
    if row.status == "completed":
        return None, "Thank you: this questionnaire has already been answered."
    if row.status == "expired":
        return None, "This questionnaire has expired. Ask your contact for a new link."
    return row, ""


@public.get("/vendor-assessment/{token}", response_class=HTMLResponse, include_in_schema=False)
def assessment_form(token: str, request: Request, db: Session = Depends(get_db)):
    ratelimit.check(f"vendor-assessment:{request.client.host if request.client else ''}", 60, 3600)
    row, problem = _open_assessment(db, token)
    db.commit()
    if row is None:
        return _page(f"<h1>Security questionnaire</h1><p>{html.escape(problem)}</p>", 404)
    vendor = db.get(Vendor, row.vendor_id)
    customer = db.get(Tenant, row.tenant_id)
    fields = []
    for q in tprm.QUESTIONS:
        options = "".join(f'<label><input type="radio" name="{q["id"]}" value="{v}" required> {label}</label>'
                          for v, label in (("yes", "Yes"), ("partial", "Partly"), ("no", "No"), ("na", "Not applicable")))
        fields.append(f'<fieldset><legend>{html.escape(q["domain"])}</legend><p>{html.escape(q["text"])}</p>{options}'
                      f'<textarea name="{q["id"]}-comment" rows="2" maxlength="1000" placeholder="Comment or evidence (optional)"></textarea></fieldset>')
    return _page(f"<h1>Security questionnaire</h1><p>{html.escape(customer.name if customer else 'Your customer')} asks "
                 f"{html.escape(vendor.name if vendor else 'you')} to answer these questions about the service you provide. "
                 f"It takes about ten minutes.</p><p class=muted>Due {row.due_at.strftime('%d %B %Y') if row.due_at else ''}. "
                 f"The link works once.</p><form method='post'>{''.join(fields)}<button type='submit'>Submit answers</button></form>")


@public.post("/vendor-assessment/{token}", response_class=HTMLResponse, include_in_schema=False)
async def assessment_submit(token: str, request: Request, db: Session = Depends(get_db)):
    ratelimit.check(f"vendor-assessment:{request.client.host if request.client else ''}", 60, 3600)
    raw = await request.body()
    if len(raw) > 64 * 1024:
        return _page("<h1>Security questionnaire</h1><p>The answers are too long.</p>", 413)
    form = {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace")).items()}
    row, problem = _open_assessment(db, token)
    if row is None:
        db.commit()
        return _page(f"<h1>Security questionnaire</h1><p>{html.escape(problem)}</p>", 404)
    answers = {q["id"]: {"answer": form.get(q["id"], ""), "comment": form.get(f"{q['id']}-comment", "")} for q in tprm.QUESTIONS}
    try:
        tprm.submit(db, row, answers)
    except ValueError as exc:
        return _page(f"<h1>Security questionnaire</h1><p>{html.escape(str(exc))}</p><p><a href=''>Back</a></p>", 422)
    db.commit()
    return _page("<h1>Thank you</h1><p>Your answers have been received. You can close this page.</p>")
