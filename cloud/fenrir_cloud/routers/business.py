"""CRM, PSA ticketing, billing, webhooks, and executive reports."""

from __future__ import annotations

import html
from datetime import date, timedelta

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .. import audit, compliance, policy_schema, psa, services
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import (Alert, Contact, Contract, Device, DnsQueryLog, Event, Incident, Invoice, Lead, Policy, Project, Tenant,
                      Ticket, TimeEntry, Vulnerability, Webhook, utcnow)
from ..security import new_secret
from ..serialize import apply_fields, to_dict

router = APIRouter(prefix="/api/console", tags=["Business"])


def _crm_scope(principal: Principal) -> list[str]:
    return list(principal.tenant_ids)


def _get(db: Session, principal: Principal, model, obj_id: str):
    obj = db.get(model, obj_id)
    if obj is None or obj.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    return obj


# --------------------------------------------------------------------------- generic CRM CRUD

CRM_MODELS = {
    "contacts": (Contact, {"account_tenant_id", "name", "email", "phone", "title", "is_primary", "notes"}),
    "leads": (Lead, {"company", "contact", "email", "phone", "stage", "value", "seats", "source", "owner", "notes"}),
    "projects": (Project, {"account_tenant_id", "name", "status", "progress", "budget", "due_date", "tasks", "manager", "billing_method",
                           "estimated_hours", "start_date", "phases", "description"}),
}


@router.get("/crm/{kind}")
def crm_list(kind: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    if kind not in CRM_MODELS:
        raise HTTPException(404, "Unknown CRM collection")
    principal.require("read")
    model, _ = CRM_MODELS[kind]
    rows = db.execute(select(model).where(model.tenant_id.in_(_crm_scope(principal))).order_by(model.created_at.desc())).scalars().all()
    return [to_dict(r) for r in rows]


@router.post("/crm/{kind}")
def crm_create(kind: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    if kind not in CRM_MODELS:
        raise HTTPException(404, "Unknown CRM collection")
    principal.require("crm")
    model, allowed = CRM_MODELS[kind]
    obj = model(tenant_id=principal.user.tenant_id)
    apply_fields(obj, body, allowed)
    if kind == "leads" and not obj.company:
        raise HTTPException(400, "company is required")
    if kind in {"contacts", "projects"} and not obj.name:
        raise HTTPException(400, "name is required")
    db.add(obj)
    audit.record(db, principal.actor, f"crm.{kind}.created", getattr(obj, "name", None) or getattr(obj, "company", ""), obj.tenant_id)
    db.commit()
    return to_dict(obj)


@router.patch("/crm/{kind}/{obj_id}")
def crm_update(kind: str, obj_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
               db: Session = Depends(get_db)):
    if kind not in CRM_MODELS:
        raise HTTPException(404, "Unknown CRM collection")
    principal.require("crm")
    model, allowed = CRM_MODELS[kind]
    obj = _get(db, principal, model, obj_id)
    changed = apply_fields(obj, body, allowed)
    if hasattr(obj, "updated_at"):
        obj.updated_at = utcnow()
    audit.record(db, principal.actor, f"crm.{kind}.updated", obj_id, obj.tenant_id, fields=changed)
    db.commit()
    return to_dict(obj)


@router.delete("/crm/{kind}/{obj_id}")
def crm_delete(kind: str, obj_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    if kind not in CRM_MODELS:
        raise HTTPException(404, "Unknown CRM collection")
    principal.require("crm")
    model, _ = CRM_MODELS[kind]
    obj = _get(db, principal, model, obj_id)
    db.delete(obj)
    audit.record(db, principal.actor, f"crm.{kind}.deleted", obj_id, obj.tenant_id)
    db.commit()
    return {"ok": True}


@router.post("/crm/leads/{lead_id}/convert")
def convert_lead(lead_id: str, body: dict = Body(default={}), principal: Principal = Depends(current_principal),
                 db: Session = Depends(get_db)):
    """Won deal -> customer tenant + policy + primary contact + contract + enrollment-ready."""
    principal.require("manage_tenants")
    lead = _get(db, principal, Lead, lead_id)
    if lead.converted_tenant_id:
        raise HTTPException(409, "Lead already converted")
    template = str(body.get("template") or "balanced")
    if template not in policy_schema.TEMPLATES:
        raise HTTPException(400, "Unknown template")
    import re

    slug = re.sub(r"[^a-z0-9]+", "-", lead.company.lower()).strip("-")[:60] or "customer"
    if db.execute(select(Tenant).where(Tenant.slug == slug)).scalar_one_or_none():
        slug = f"{slug}-{new_secret('x', 3)[2:].lower()}"
    tenant = Tenant(name=lead.company, slug=slug, parent_id=principal.user.tenant_id, kind="customer",
                    plan=str(body.get("plan") or "complete"))
    db.add(tenant)
    db.flush()
    policy = Policy(tenant_id=tenant.id, name=f"{lead.company} default", template=template,
                    settings=policy_schema.template_settings(template), updated_by=principal.actor)
    db.add(policy)
    db.flush()
    tenant.default_policy_id = policy.id
    if lead.contact or lead.email:
        db.add(Contact(tenant_id=principal.user.tenant_id, account_tenant_id=tenant.id, name=lead.contact or lead.company,
                       email=lead.email, phone=lead.phone, is_primary=True))
    price = float(body.get("pricePerDevice") or (lead.value / lead.seats / 12 if lead.seats else 0))
    contract = Contract(tenant_id=principal.user.tenant_id, account_tenant_id=tenant.id, name=f"{lead.company} managed security",
                        plan=tenant.plan, price_per_device=round(price, 2), sla=dict(services.DEFAULT_SLA_HOURS),
                        start_date=date.today().isoformat())
    db.add(contract)
    lead.stage, lead.converted_tenant_id, lead.updated_at = "Won", tenant.id, utcnow()
    audit.record(db, principal.actor, "crm.lead.converted", lead.company, tenant.id, template=template)
    db.commit()
    return {"tenant": to_dict(tenant), "contract": to_dict(contract), "policyId": policy.id}


@router.get("/crm-pipeline")
def pipeline(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.execute(select(Lead.stage, func.count(), func.sum(Lead.value)).where(Lead.tenant_id.in_(_crm_scope(principal)))
                      .group_by(Lead.stage)).all()
    return [{"stage": s, "count": c, "value": v or 0} for s, c, v in rows]


# --------------------------------------------------------------------------- billing


@router.get("/billing/contracts")
def list_contracts(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    rows = db.execute(select(Contract).where(or_(Contract.tenant_id.in_(principal.tenant_ids),
                                                 Contract.account_tenant_id.in_(principal.tenant_ids)))).scalars().all()
    counts = dict(db.execute(select(Device.tenant_id, func.count()).where(Device.approved.is_(True)).group_by(Device.tenant_id)).all())
    names = dict(db.execute(select(Tenant.id, Tenant.name)).all())
    return [{**to_dict(c), "account": names.get(c.account_tenant_id, ""), "devices": counts.get(c.account_tenant_id, 0),
             "monthlyValue": round(c.monthly_fee + c.price_per_device * counts.get(c.account_tenant_id, 0), 2)} for c in rows]


AGREEMENT_FIELDS = {"plan", "price_per_device", "monthly_fee", "hourly_rate", "included_hours", "currency", "sla", "active",
                    "agreement_type", "billing_cycle", "end_date", "covered_work_types", "covers_after_hours", "additions",
                    "business_hours", "notes"}


@router.post("/billing/contracts")
def create_contract(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("billing")
    account = body.get("accountTenantId")
    principal.check_tenant(account)
    contract = Contract(tenant_id=principal.user.tenant_id, account_tenant_id=account, name=str(body.get("name") or "Contract"))
    apply_fields(contract, body, AGREEMENT_FIELDS | {"start_date"})
    contract.sla = contract.sla or dict(services.DEFAULT_SLA_HOURS)
    db.add(contract)
    audit.record(db, principal.actor, "billing.contract.created", contract.name, account)
    db.commit()
    return to_dict(contract)


@router.patch("/billing/contracts/{contract_id}")
def update_contract(contract_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                    db: Session = Depends(get_db)):
    principal.require("billing")
    contract = _get(db, principal, Contract, contract_id)
    changed = apply_fields(contract, body, AGREEMENT_FIELDS | {"name"})
    audit.record(db, principal.actor, "billing.contract.updated", contract.name, contract.account_tenant_id, fields=changed)
    db.commit()
    return to_dict(contract)


@router.get("/billing/renewals")
def contract_renewals(days: int = Query(default=90, ge=1, le=730), principal: Principal = Depends(current_principal),
                      db: Session = Depends(get_db)):
    """Agreements ending within ``days`` (or already ended but still active), soonest first."""
    principal.require("crm")
    from datetime import date, timedelta as _td

    today = date.today()
    horizon = today + _td(days=days)
    out = []
    for contract in db.execute(select(Contract).where(Contract.tenant_id.in_(_crm_scope(principal)), Contract.active.is_(True))).scalars():
        try:
            end = date.fromisoformat((contract.end_date or "")[:10])
        except ValueError:
            continue
        if end <= horizon:
            tenant = db.get(Tenant, contract.account_tenant_id)
            out.append({**to_dict(contract), "account": tenant.name if tenant else "", "daysLeft": (end - today).days,
                        "monthlyValue": contract.monthly_fee})
    return sorted(out, key=lambda c: c["daysLeft"])


@router.post("/billing/invoices/generate")
def generate_invoices(body: dict = Body(default={}), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Draft one invoice per active contract: seats x price + fee + billable hours over the allowance."""
    principal.require("billing")
    period = str(body.get("period") or date.today().strftime("%Y-%m"))
    year, month = (int(part) for part in period.split("-"))
    start = utcnow().replace(year=year, month=month, day=1, hour=0, minute=0, second=0, microsecond=0)
    end = start.replace(year=year + (month == 12), month=1 if month == 12 else month + 1)
    created = []
    for contract in db.execute(select(Contract).where(Contract.tenant_id.in_(principal.tenant_ids), Contract.active.is_(True))).scalars():
        exists = db.execute(select(Invoice).where(Invoice.contract_id == contract.id, Invoice.period == period)).scalar_one_or_none()
        if exists:
            continue
        devices = db.execute(select(Device).where(Device.tenant_id == contract.account_tenant_id, Device.approved.is_(True))).scalars().all()
        entries = db.execute(select(TimeEntry).where(TimeEntry.account_tenant_id == contract.account_tenant_id,
                                                     TimeEntry.billable == "Billable", TimeEntry.invoice_id.is_(None),
                                                     TimeEntry.status.in_(("Open", "Submitted", "Approved")),
                                                     TimeEntry.started_at < end)).scalars().all()
        lines = []
        if contract.monthly_fee:
            lines.append({"description": f"{contract.plan.title()} plan - monthly fee", "quantity": 1, "unitPrice": contract.monthly_fee})
        if contract.price_per_device and devices:
            lines.append({"description": f"Protected endpoints ({contract.plan})", "quantity": len(devices), "unitPrice": contract.price_per_device})
        for addition in contract.additions or []:
            quantity = float(addition.get("quantity") or 0)
            auto = str(addition.get("autoCount") or "")
            if auto.startswith("devices"):
                platform = auto.partition(":")[2]
                quantity = len([d for d in devices if not platform or d.platform == platform or
                                (platform == "server" and "server" in d.os_version.lower())])
            if quantity and addition.get("unitPrice"):
                lines.append({"description": str(addition.get("product") or "Addition"), "quantity": quantity,
                              "unitPrice": float(addition["unitPrice"])})
        covered_hours = sum(e.hours_billed or e.hours for e in entries if psa.coverage(contract, e.work_type))
        extra_hours = max(0.0, covered_hours - (contract.included_hours or 0))
        if extra_hours and contract.hourly_rate:
            lines.append({"description": "Support time beyond allowance (hours)", "quantity": round(extra_hours, 2),
                          "unitPrice": contract.hourly_rate})
        uncovered: dict[str, float] = {}
        for entry in entries:
            if not psa.coverage(contract, entry.work_type):
                uncovered[entry.work_type] = uncovered.get(entry.work_type, 0) + (entry.hours_billed or entry.hours)
        for work_type, hours in sorted(uncovered.items()):
            rate = contract.hourly_rate * (1.5 if work_type in psa.AFTER_HOURS_TYPES else 1)
            if rate:
                lines.append({"description": f"Time & materials: {work_type} (hours)", "quantity": round(hours, 2), "unitPrice": rate})
        if not lines:
            continue
        for line in lines:
            line["amount"] = round(line["quantity"] * line["unitPrice"], 2)
        subtotal = round(sum(line["amount"] for line in lines), 2)
        tax_rate = float(body.get("taxRate", 0.2))
        count = db.execute(select(func.count()).select_from(Invoice).where(Invoice.tenant_id == contract.tenant_id)).scalar() or 0
        invoice = Invoice(number=f"INV-{period.replace('-', '')}-{count + 1:04d}", tenant_id=contract.tenant_id,
                          account_tenant_id=contract.account_tenant_id, contract_id=contract.id, period=period, lines=lines,
                          subtotal=subtotal, tax_rate=tax_rate, total=round(subtotal * (1 + tax_rate), 2), currency=contract.currency,
                          due_date=(end + timedelta(days=30)).date().isoformat())
        db.add(invoice)
        db.flush()
        for entry in entries:
            entry.invoice_id, entry.status = invoice.id, "Billed"
        created.append(to_dict(invoice))
    audit.record(db, principal.actor, "billing.invoices.generated", period, principal.user.tenant_id, count=len(created))
    db.commit()
    return {"period": period, "created": created}


@router.get("/billing/invoices")
def list_invoices(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    rows = db.execute(select(Invoice).where(or_(Invoice.tenant_id.in_(principal.tenant_ids),
                                                Invoice.account_tenant_id.in_(principal.tenant_ids)))
                      .order_by(Invoice.created_at.desc())).scalars().all()
    names = dict(db.execute(select(Tenant.id, Tenant.name)).all())
    return [{**to_dict(i), "account": names.get(i.account_tenant_id, "")} for i in rows]


@router.patch("/billing/invoices/{invoice_id}")
def update_invoice(invoice_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                   db: Session = Depends(get_db)):
    principal.require("billing")
    invoice = _get(db, principal, Invoice, invoice_id)
    if body.get("status") not in {"Draft", "Sent", "Paid", "Overdue", "Void"}:
        raise HTTPException(400, "invalid status")
    invoice.status = body["status"]
    audit.record(db, principal.actor, "billing.invoice.status", invoice.number, invoice.account_tenant_id, status=invoice.status)
    db.commit()
    return to_dict(invoice)


# --------------------------------------------------------------------------- webhooks


@router.get("/webhooks")
def list_webhooks(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return [to_dict(w) for w in db.execute(select(Webhook).where(Webhook.tenant_id.in_(principal.tenant_ids))).scalars()]


@router.post("/webhooks")
def create_webhook(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    tenant_id = body.get("tenantId") or principal.user.tenant_id
    principal.check_tenant(tenant_id)
    url = str(body.get("url") or "")
    if not url.startswith("https://"):
        raise HTTPException(400, "Webhook URLs must use https://")
    hook = Webhook(tenant_id=tenant_id, name=str(body.get("name") or "Webhook"), url=url, kind=str(body.get("kind") or "generic"),
                   events=body.get("events") or ["incident.created"], secret=new_secret("whs", 18))
    db.add(hook)
    audit.record(db, principal.actor, "webhook.created", hook.name, tenant_id)
    db.commit()
    return {**to_dict(hook), "secret": hook.secret}


@router.delete("/webhooks/{hook_id}")
def delete_webhook(hook_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    hook = _get(db, principal, Webhook, hook_id)
    db.delete(hook)
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- reports


def _report_data(db: Session, tenant: Tenant, days: int) -> dict:
    since = utcnow() - timedelta(days=days)
    devices = db.execute(select(Device).where(Device.tenant_id == tenant.id)).scalars().all()
    alerts = dict(db.execute(select(Alert.severity, func.count()).where(Alert.tenant_id == tenant.id, Alert.created_at >= since)
                             .group_by(Alert.severity)).all())
    incidents = db.execute(select(Incident).where(Incident.tenant_id == tenant.id, Incident.created_at >= since)).scalars().all()
    threats = db.execute(select(func.count()).where(Event.tenant_id == tenant.id, Event.occurred_at >= since,
                                                    Event.category == "malware")).scalar() or 0
    dns_blocked = db.execute(select(func.count()).where(DnsQueryLog.tenant_id == tenant.id, DnsQueryLog.at >= since,
                                                        DnsQueryLog.action == "block")).scalar() or 0
    vulns = dict(db.execute(select(Vulnerability.severity, func.count()).where(Vulnerability.tenant_id == tenant.id,
                                                                               Vulnerability.status == "open")
                            .group_by(Vulnerability.severity)).all())
    frameworks = compliance.evaluate(db, tenant)
    tickets = db.execute(select(Ticket).where(Ticket.account_tenant_id == tenant.id, Ticket.created_at >= since)).scalars().all()
    resolved = [t for t in tickets if t.resolved_at]
    within_sla = [t for t in resolved if t.sla_due_at and t.resolved_at <= t.sla_due_at]
    return {
        "tenant": tenant.name, "periodDays": days, "generatedAt": utcnow().isoformat() + "Z",
        "devices": {"total": len(devices), "isolatedNow": sum(d.isolated for d in devices),
                    "highRisk": sum(1 for d in devices if d.risk_score >= 40)},
        "alerts": alerts, "incidents": {"total": len(incidents), "resolved": sum(i.status in ("resolved", "closed") for i in incidents)},
        "threatEvents": threats, "dnsBlocked": dns_blocked, "openVulnerabilities": vulns,
        "compliance": [{"name": f["name"], "score": f["score"]} for f in frameworks],
        "service": {"tickets": len(tickets), "resolved": len(resolved),
                    "slaMet": round(100 * len(within_sla) / len(resolved)) if resolved else None},
    }


@router.get("/reports/executive")
def executive_report(tenant_id: str | None = None, days: int = 30, principal: Principal = Depends(current_principal),
                     db: Session = Depends(get_db)):
    tid = tenant_id or principal.user.tenant_id
    principal.check_tenant(tid)
    return _report_data(db, db.get(Tenant, tid), days)


@router.get("/reports/executive.html", response_class=HTMLResponse)
def executive_report_html(tenant_id: str | None = None, days: int = 30, principal: Principal = Depends(current_principal),
                          db: Session = Depends(get_db)):
    tid = tenant_id or principal.user.tenant_id
    principal.check_tenant(tid)
    data = _report_data(db, db.get(Tenant, tid), days)
    e = html.escape

    def rows(mapping: dict) -> str:
        return "".join(f"<tr><td>{e(str(k)).title()}</td><td>{v}</td></tr>" for k, v in mapping.items()) or "<tr><td colspan=2>None</td></tr>"

    compliance_rows = "".join(f"<tr><td>{e(c['name'])}</td><td>{c['score']}%</td></tr>" for c in data["compliance"])
    sla = "n/a" if data["service"]["slaMet"] is None else f"{data['service']['slaMet']}%"
    body = f"""<!doctype html><html><head><meta charset="utf-8"><title>Security report - {e(data['tenant'])}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:860px;margin:32px auto;color:#1b2430;padding:0 16px}}
h1{{margin-bottom:4px}}.sub{{color:#5b6675}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0}}
.card{{border:1px solid #dde3ea;border-radius:10px;padding:14px}}.card b{{display:block;font-size:28px}}
table{{width:100%;border-collapse:collapse;margin:8px 0 24px}}td{{border-bottom:1px solid #eef1f4;padding:6px 4px}}</style></head>
<body><h1>Security report: {e(data['tenant'])}</h1><div class="sub">Last {days} days &middot; generated {e(data['generatedAt'])}</div>
<div class="grid"><div class="card"><b>{data['devices']['total']}</b>protected devices</div>
<div class="card"><b>{data['threatEvents']}</b>threat events stopped</div>
<div class="card"><b>{data['dnsBlocked']}</b>malicious domains blocked</div>
<div class="card"><b>{data['incidents']['total']}</b>incidents ({data['incidents']['resolved']} resolved)</div></div>
<h2>Alerts by severity</h2><table>{rows(data['alerts'])}</table>
<h2>Open vulnerabilities</h2><table>{rows(data['openVulnerabilities'])}</table>
<h2>Compliance posture</h2><table>{compliance_rows}</table>
<h2>Service desk</h2><table><tr><td>Tickets</td><td>{data['service']['tickets']}</td></tr>
<tr><td>Resolved within SLA</td><td>{sla}</td></tr></table></body></html>"""
    return HTMLResponse(body)
