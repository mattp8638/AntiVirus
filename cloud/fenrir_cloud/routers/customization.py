"""Saved list views and custom fields: small things that make the console fit how an MSP works.

Saved views keep a page's filters under a name, private to their owner or shared with the organisation. Custom fields
are defined once by the MSP for every device or ticket (asset tag, cost centre, contract reference) and filled in per
record; values are validated against their definition and every change is audited.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .. import audit, services
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import CustomField, Device, SavedView, Ticket
from ..serialize import to_dict

router = APIRouter(prefix="/api/console", tags=["Customisation"])

PAGES = {"devices", "tickets", "alerts"}
ENTITIES = {"device": Device, "ticket": Ticket}
FIELD_TYPES = {"text", "number", "date", "select", "checkbox"}
_KEY = re.compile(r"[a-z][a-z0-9_]{0,59}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
MAX_FIELDS = 50


# --------------------------------------------------------------------------- saved views


@router.get("/saved-views")
def list_saved_views(page: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.execute(select(SavedView).where(
        SavedView.page == page, SavedView.tenant_id.in_(principal.tenant_ids),
        or_(SavedView.owner == principal.actor, SavedView.shared.is_(True))).order_by(SavedView.name)).scalars().all()
    return [{**to_dict(v), "mine": v.owner == principal.actor} for v in rows]


@router.post("/saved-views")
def create_saved_view(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    page, name = str(body.get("page") or ""), str(body.get("name") or "").strip()[:120]
    filters = body.get("filters") or {}
    if page not in PAGES:
        raise HTTPException(400, f"page must be one of {', '.join(sorted(PAGES))}")
    if not name:
        raise HTTPException(400, "Give the view a name")
    if not isinstance(filters, dict) or len(filters) > 20 or any(not isinstance(v, (str, int, float, bool)) for v in filters.values()):
        raise HTTPException(400, "Filters must be a small set of simple values")
    shared = bool(body.get("shared"))
    if shared:
        principal.require("configure")  # a shared view appears for everyone
    view = SavedView(tenant_id=principal.user.tenant_id, owner=principal.actor, page=page, name=name,
                     filters={str(k)[:40]: (v[:200] if isinstance(v, str) else v) for k, v in filters.items()}, shared=shared)
    db.add(view)
    db.commit()
    return {**to_dict(view), "mine": True}


@router.delete("/saved-views/{view_id}")
def delete_saved_view(view_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    view = db.get(SavedView, view_id)
    if view is None or view.tenant_id not in principal.tenant_ids or (view.owner != principal.actor and not view.shared):
        raise HTTPException(404, "Not found")
    if view.owner != principal.actor:
        principal.require("configure")
    db.delete(view)
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- custom fields


def _msp(db: Session, principal: Principal) -> str:
    return services.msp_tenant_id(db, principal.user.tenant_id)


def _definitions(db: Session, msp_id: str, entity: str) -> list[CustomField]:
    return db.execute(select(CustomField).where(CustomField.tenant_id == msp_id, CustomField.entity == entity)
                      .order_by(CustomField.created_at)).scalars().all()


@router.get("/custom-fields")
def list_custom_fields(entity: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    if entity not in ENTITIES:
        raise HTTPException(400, "entity must be device or ticket")
    return [to_dict(f) for f in _definitions(db, _msp(db, principal), entity)]


@router.post("/custom-fields")
def create_custom_field(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    entity, label = str(body.get("entity") or ""), str(body.get("label") or "").strip()[:120]
    field_type = str(body.get("type") or "text")
    key = str(body.get("key") or re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_"))[:60]
    if entity not in ENTITIES:
        raise HTTPException(400, "entity must be device or ticket")
    if not label or not _KEY.fullmatch(key):
        raise HTTPException(400, "Give the field a label; its key must start with a letter and use a-z, 0-9 and _")
    if field_type not in FIELD_TYPES:
        raise HTTPException(400, f"type must be one of {', '.join(sorted(FIELD_TYPES))}")
    options = [str(o).strip()[:100] for o in (body.get("options") or []) if str(o).strip()][:50]
    if field_type == "select" and not options:
        raise HTTPException(400, "A list field needs at least one option")
    msp_id = _msp(db, principal)
    principal.check_tenant(msp_id)  # only the MSP's own staff define fields for every customer
    existing = _definitions(db, msp_id, entity)
    if any(f.key == key for f in existing):
        raise HTTPException(409, f"There is already a {entity} field called {key}")
    if len(existing) >= MAX_FIELDS:
        raise HTTPException(400, f"At most {MAX_FIELDS} custom fields per record type")
    field = CustomField(tenant_id=msp_id, entity=entity, key=key, label=label, field_type=field_type,
                        options=options if field_type == "select" else [])
    db.add(field)
    audit.record(db, principal.actor, "custom_field.created", f"{entity}.{key}", msp_id, label=label, type=field_type)
    db.commit()
    return to_dict(field)


@router.delete("/custom-fields/{field_id}")
def delete_custom_field(field_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Removes the definition. Values already entered stay on the records but are no longer shown or editable."""
    principal.require("configure")
    field = db.get(CustomField, field_id)
    if field is None or field.tenant_id != _msp(db, principal):
        raise HTTPException(404, "Not found")
    principal.check_tenant(field.tenant_id)
    db.delete(field)
    audit.record(db, principal.actor, "custom_field.deleted", f"{field.entity}.{field.key}", field.tenant_id)
    db.commit()
    return {"ok": True}


def _coerce(field: CustomField, value):
    """The value to store for this field, or None to clear it. Raises 400 for a value that does not fit."""
    if value is None or value == "":
        return None
    kind = field.field_type
    if kind == "checkbox":
        if isinstance(value, bool):
            return value
        raise HTTPException(400, f"{field.label} must be true or false")
    if kind == "number":
        try:
            number = float(value)
        except (TypeError, ValueError):
            raise HTTPException(400, f"{field.label} must be a number") from None
        return int(number) if number.is_integer() else number
    text = str(value).strip()
    if kind == "date" and not _DATE.fullmatch(text):
        raise HTTPException(400, f"{field.label} must be a date (YYYY-MM-DD)")
    if kind == "select" and text not in (field.options or []):
        raise HTTPException(400, f"{field.label} must be one of: {', '.join(field.options or [])}")
    return text[:500]


@router.put("/custom-fields/values/{entity}/{record_id}")
def set_custom_values(entity: str, record_id: str, body: dict = Body(...), principal: Principal = Depends(current_principal),
                      db: Session = Depends(get_db)):
    """``{"values": {key: value}}``: sets the given fields; null or "" clears one. Other fields keep their values."""
    if entity not in ENTITIES:
        raise HTTPException(400, "entity must be device or ticket")
    if not (principal.can("configure") or principal.can("respond") or (entity == "ticket" and principal.can("crm"))):
        raise HTTPException(403, "Your role cannot change these fields")
    record = db.get(ENTITIES[entity], record_id)
    owners = {getattr(record, "tenant_id", None), getattr(record, "account_tenant_id", None)} if record is not None else set()
    if record is None or not owners & set(principal.tenant_ids):
        raise HTTPException(404, "Not found")
    values = body.get("values")
    if not isinstance(values, dict):
        raise HTTPException(400, "values must be an object of field keys")
    fields = {f.key: f for f in _definitions(db, _msp(db, principal), entity)}
    unknown = sorted(set(values) - set(fields))
    if unknown:
        raise HTTPException(400, f"Unknown field(s): {', '.join(unknown)}")
    current = dict(record.custom_fields or {})
    for key, value in values.items():
        coerced = _coerce(fields[key], value)
        if coerced is None:
            current.pop(key, None)
        else:
            current[key] = coerced
    record.custom_fields = current
    tenant = getattr(record, "account_tenant_id", None) or record.tenant_id
    audit.record(db, principal.actor, f"{entity}.custom_fields.updated", record_id, tenant, fields=sorted(values))
    db.commit()
    return {"customFields": current}
