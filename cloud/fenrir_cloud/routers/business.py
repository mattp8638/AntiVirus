"""CRM, PSA ticketing, billing, webhooks, and executive reports."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .. import audit, billing_sync, policy_schema, psa, services
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth, scoped_tenant
from ..models import (AccountingConnection, Activity, Contact, Contract, Device, Invoice, Lead, Opportunity, Policy, Project, Tenant,
                      TimeEntry, Webhook, utcnow)
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
    "opportunities": (Opportunity, {"account_tenant_id", "lead_id", "name", "kind", "stage", "value", "monthly_value", "probability",
                                    "close_date", "owner", "source", "notes", "lost_reason"}),
    "activities": (Activity, {"account_tenant_id", "contact_id", "lead_id", "opportunity_id", "kind", "direction", "subject", "body",
                              "owner"}),
}

OPPORTUNITY_STAGES = {"Prospecting": 10, "Qualification": 25, "Proposal": 50, "Negotiation": 75, "Won": 100, "Lost": 0}
OPPORTUNITY_KINDS = ("New business", "Upsell", "Renewal", "Project")
ACTIVITY_KINDS = ("call", "email", "meeting", "note", "task")


def _parse_time(value) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(400, "Dates must be ISO 8601") from None
    return parsed.astimezone(timezone.utc).replace(tzinfo=None) if parsed.tzinfo else parsed


def _validate_crm(db: Session, principal: Principal, kind: str, obj, body: dict, changed: list[str]) -> None:
    """Shared checks: linked records must be the caller's; per-kind rules for deals and activities."""
    if getattr(obj, "account_tenant_id", None) and obj.account_tenant_id not in principal.tenant_ids:
        raise HTTPException(400, "accountTenantId is not one of your customers")
    for attr, model in (("contact_id", Contact), ("lead_id", Lead), ("opportunity_id", Opportunity)):
        linked = getattr(obj, attr, None)
        if linked:
            row = db.get(model, linked)
            if row is None or row.tenant_id not in principal.tenant_ids:
                raise HTTPException(400, f"{attr} not found")
    if kind == "opportunities":
        if not obj.name:
            raise HTTPException(400, "name is required")
        if obj.stage not in OPPORTUNITY_STAGES:
            raise HTTPException(400, f"stage must be one of {', '.join(OPPORTUNITY_STAGES)}")
        if obj.kind not in OPPORTUNITY_KINDS:
            raise HTTPException(400, f"kind must be one of {', '.join(OPPORTUNITY_KINDS)}")
        if "stage" in changed and "probability" not in changed or obj.stage in {"Won", "Lost"}:
            obj.probability = OPPORTUNITY_STAGES[obj.stage]
        obj.probability = max(0, min(100, int(obj.probability or 0)))
        obj.value, obj.monthly_value = float(obj.value or 0), float(obj.monthly_value or 0)
        if obj.value < 0 or obj.monthly_value < 0:
            raise HTTPException(400, "Values cannot be negative")
        if obj.stage in {"Won", "Lost"}:
            obj.closed_at = obj.closed_at or utcnow()
        else:
            obj.closed_at, obj.lost_reason = None, ""
    if kind == "activities":
        if not obj.subject:
            raise HTTPException(400, "subject is required")
        if obj.kind not in ACTIVITY_KINDS:
            raise HTTPException(400, f"kind must be one of {', '.join(ACTIVITY_KINDS)}")
        if obj.direction not in ("", "inbound", "outbound"):
            raise HTTPException(400, "direction must be inbound or outbound")
        if "dueAt" in body:
            obj.due_at = _parse_time(body.get("dueAt"))
        if "completedAt" in body:
            obj.completed_at = _parse_time(body.get("completedAt"))
        if "done" in body:
            obj.completed_at = (obj.completed_at or utcnow()) if body.get("done") else None
        if obj.kind != "task" and obj.completed_at is None:
            obj.completed_at = obj.created_at or utcnow()  # calls, emails, meetings and notes are logged as done


@router.get("/crm/{kind}")
def crm_list(kind: str, account_tenant_id: str | None = None, open_only: bool = False,
             principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    if kind not in CRM_MODELS:
        raise HTTPException(404, "Unknown CRM collection")
    principal.require("read")
    model, _ = CRM_MODELS[kind]
    query = select(model).where(model.tenant_id.in_(_crm_scope(principal)))
    if account_tenant_id and hasattr(model, "account_tenant_id"):
        query = query.where(model.account_tenant_id == account_tenant_id)
    if open_only and kind == "activities":
        query = query.where(Activity.kind == "task", Activity.completed_at.is_(None))
    elif open_only and kind == "opportunities":
        query = query.where(Opportunity.closed_at.is_(None))
    rows = db.execute(query.order_by(model.created_at.desc()).limit(2000)).scalars().all()
    return [to_dict(r) for r in rows]


@router.post("/crm/{kind}")
def crm_create(kind: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    if kind not in CRM_MODELS:
        raise HTTPException(404, "Unknown CRM collection")
    principal.require("crm")
    model, allowed = CRM_MODELS[kind]
    obj = model(tenant_id=principal.user.tenant_id)
    changed = apply_fields(obj, body, allowed)
    if kind == "opportunities":
        obj.stage, obj.kind = obj.stage or "Prospecting", obj.kind or "New business"
    if kind == "activities":
        obj.kind, obj.direction, obj.created_by = obj.kind or "note", obj.direction or "", principal.actor
        obj.owner = obj.owner or principal.actor
        obj.created_at = utcnow()
    _validate_crm(db, principal, kind, obj, body, changed)
    if kind == "leads" and not obj.company:
        raise HTTPException(400, "company is required")
    if kind in {"contacts", "projects"} and not obj.name:
        raise HTTPException(400, "name is required")
    db.add(obj)
    audit.record(db, principal.actor, f"crm.{kind}.created",
                 getattr(obj, "name", None) or getattr(obj, "company", None) or getattr(obj, "subject", ""), obj.tenant_id)
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
    _validate_crm(db, principal, kind, obj, body, changed)
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
    db.add(Opportunity(tenant_id=principal.user.tenant_id, account_tenant_id=tenant.id, lead_id=lead.id, name=f"{lead.company} onboarding",
                       kind="New business", stage="Won", probability=100, value=0, monthly_value=round(lead.value / 12, 2) if lead.value else 0,
                       owner=lead.owner, source=lead.source, closed_at=utcnow()))
    if lead.owner:
        tenant.account_owner = lead.owner
    lead.stage, lead.converted_tenant_id, lead.updated_at = "Won", tenant.id, utcnow()
    audit.record(db, principal.actor, "crm.lead.converted", lead.company, tenant.id, template=template)
    db.commit()
    return {"tenant": to_dict(tenant), "contract": to_dict(contract), "policyId": policy.id}


@router.get("/crm-pipeline")
def pipeline(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Lead count and value per stage, for reports and integrations (the console's Leads board totals the same)."""
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
    if not body.get("currency"):
        from .. import regional

        contract.currency = regional.get(db, account)["currency"]  # the MSP's default currency
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
            if auto:  # devices, devices:<platform>, m365:<SKU>, m365-users (billing_sync.py)
                counted = billing_sync.auto_quantity(db, contract, devices, auto)
                quantity = counted if counted is not None else quantity
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


# --------------------------------------------------------------------------- billing reconciliation and accounting sync


def _msp_owner(db: Session, principal: Principal) -> str:
    principal.require("billing")
    owner = services.msp_tenant_id(db, principal.user.tenant_id)
    if owner != principal.user.tenant_id:
        raise HTTPException(403, "Billing settings belong to the MSP")
    return owner


@router.get("/billing/reconciliation")
def billing_reconciliation(period: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Billed vs actually managed, per active contract: devices, counted additions and unbilled Microsoft 365 licences."""
    principal.require("billing")
    period = period or date.today().strftime("%Y-%m")
    return billing_sync.reconciliation(db, list(principal.tenant_ids), period)


@router.get("/billing/accounting")
def get_accounting(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    owner = _msp_owner(db, principal)
    row = db.execute(select(AccountingConnection).where(AccountingConnection.tenant_id == owner)).scalars().first()
    return billing_sync.view(row) if row else None


@router.put("/billing/accounting")
def set_accounting(request: Request, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    owner = _msp_owner(db, principal)
    require_reauth(request, principal)
    row = db.execute(select(AccountingConnection).where(AccountingConnection.tenant_id == owner)).scalars().first()
    if row is None:
        if not body.get("clientId") or not body.get("clientSecret"):
            raise HTTPException(422, "clientId and clientSecret are required")
        row = AccountingConnection(tenant_id=owner, client_id=str(body["clientId"])[:100])
        db.add(row)
        db.flush()
    if body.get("clientSecret"):
        billing_sync._store(row, {**billing_sync._secrets_of(row), "clientSecret": str(body["clientSecret"])})
    if body.get("accountCode"):
        row.account_code = str(body["accountCode"])[:20]
    if body.get("scopes"):
        row.scopes = str(body["scopes"])[:300]
    url = billing_sync.authorize_url(row)
    audit.record(db, principal.actor, "billing.accounting.configured", "xero", owner)
    db.commit()
    return {**billing_sync.view(row), "authorizeUrl": url}


@router.post("/billing/accounting/push")
def push_to_accounting(body: dict = Body(default={}), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Push the chosen invoices (or every Sent invoice not yet in Xero) as drafts."""
    owner = _msp_owner(db, principal)
    row = db.execute(select(AccountingConnection).where(AccountingConnection.tenant_id == owner)).scalars().first()
    if row is None:
        raise HTTPException(404, "Connect Xero first")
    if body.get("invoiceIds"):
        invoices = [i for i in (db.get(Invoice, x) for x in body["invoiceIds"]) if i is not None and i.tenant_id == owner]
    else:
        invoices = db.execute(select(Invoice).where(Invoice.tenant_id == owner, Invoice.status == "Sent",
                                                    Invoice.external_id.is_(None))).scalars().all()
    try:
        results = billing_sync.push_invoices(db, row, invoices, principal.actor)
    except (billing_sync.AccountingError, httpx.HTTPError) as exc:
        db.commit()
        raise HTTPException(502, str(exc)) from exc
    db.commit()
    return results


@router.post("/billing/accounting/pull")
def pull_from_accounting(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    owner = _msp_owner(db, principal)
    row = db.execute(select(AccountingConnection).where(AccountingConnection.tenant_id == owner)).scalars().first()
    if row is None:
        raise HTTPException(404, "Connect Xero first")
    try:
        changed = billing_sync.pull_statuses(db, row)
    except (billing_sync.AccountingError, httpx.HTTPError) as exc:
        db.commit()
        raise HTTPException(502, str(exc)) from exc
    db.commit()
    return {"updated": changed}


xero_callback = APIRouter(prefix="/api/billing/xero", tags=["Billing"])


@xero_callback.get("/callback")
def xero_oauth_callback(state: str = "", code: str = "", error: str = "", db: Session = Depends(get_db)):
    """Xero redirects here after the MSP authorises Fenrir. The single-use state ties it to the pending request."""
    from fastapi.responses import RedirectResponse

    if error or not code or not state:
        return RedirectResponse("/billing?xero=cancelled", status_code=303)
    try:
        billing_sync.complete_authorization(db, state, code)
    except (billing_sync.AccountingError, httpx.HTTPError, KeyError, ValueError):
        db.rollback()
        return RedirectResponse("/billing?xero=failed", status_code=303)
    db.commit()
    return RedirectResponse("/billing?xero=connected", status_code=303)


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


@router.patch("/webhooks/{hook_id}")
def update_webhook(hook_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    hook = _get(db, principal, Webhook, hook_id)
    if "url" in body and not str(body["url"]).startswith("https://"):
        raise HTTPException(400, "Webhook URLs must use https://")
    if "events" in body and (not isinstance(body["events"], list) or not body["events"]):
        raise HTTPException(400, "Choose at least one event")
    changed = apply_fields(hook, body, {"name", "url", "kind", "events"})
    audit.record(db, principal.actor, "webhook.updated", hook.name, hook.tenant_id, fields=changed)
    db.commit()
    return to_dict(hook)


@router.delete("/webhooks/{hook_id}")
def delete_webhook(hook_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    hook = _get(db, principal, Webhook, hook_id)
    db.delete(hook)
    audit.record(db, principal.actor, "webhook.deleted", hook.name, hook.tenant_id)
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- reports


@router.get("/reports/executive")
def executive_report(tenant_id: str | None = None, days: int = 30, principal: Principal = Depends(current_principal),
                     db: Session = Depends(get_db)):
    tid = tenant_id or principal.user.tenant_id
    principal.check_tenant(tid)
    from .. import reports

    return reports.executive_data(db, db.get(Tenant, tid), days)


