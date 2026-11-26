"""Organization and scope (ISO 27001 4.1 to 4.3) and the asset register. Every change is audited."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..models import User, utcnow
from .domain._js import js_trim
from .domain.csv_import import CsvError, parse_csv_records
from .models import (IsmsAsset, IsmsContextIssue, IsmsEntity, IsmsInterestedParty, IsmsMembership, IsmsScope,
                     IsmsSite)

TEXT_MAX = 4000


class IsmsError(HTTPException):
    def __init__(self, message: str, status: int = 400):
        super().__init__(status, message)


# Scope ----------------------------------------------------------------------------------------------------------

SCOPE_FIELDS = ("statement", "boundaries", "interfaces", "exclusions")


def get_scope(db: Session, tenant_id: str) -> IsmsScope | None:
    return db.execute(select(IsmsScope).where(IsmsScope.tenant_id == tenant_id)).scalar_one_or_none()


def save_scope(db: Session, tenant_id: str, actor: str, values: dict[str, str]) -> IsmsScope:
    """Saves the scope statement; each material change increments the version."""
    clean = {f: js_trim(str(values.get(f) or ""))[:TEXT_MAX * 4] for f in SCOPE_FIELDS}
    if not clean["statement"]:
        raise IsmsError("The scope statement cannot be empty.")
    row = get_scope(db, tenant_id)
    if row is None:
        row = IsmsScope(tenant_id=tenant_id, version=1, updated_by=actor, **clean)
        db.add(row)
    elif any(getattr(row, f) != v for f, v in clean.items()):
        for f, v in clean.items():
            setattr(row, f, v)
        row.version += 1
        row.updated_at, row.updated_by = utcnow(), actor
    else:
        return row
    db.flush()
    audit.record(db, actor, "isms.scope_saved", f"version {row.version}", tenant_id, version=row.version)
    return row


# Simple registers ---------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Register:
    model: type
    fields: dict[str, str]  # field -> text | bool | kind
    required: tuple[str, ...]
    order: tuple[str, ...]
    label: str


REGISTERS: dict[str, Register] = {
    "entities": Register(IsmsEntity, {"name": "text", "address": "text", "in_scope": "bool"}, ("name",), ("name",),
                         "legal entity"),
    "sites": Register(IsmsSite, {"name": "text", "address": "text", "in_scope": "bool"}, ("name",), ("name",), "site"),
    "context-issues": Register(IsmsContextIssue, {"kind": "kind", "description": "text", "climate_related": "bool",
                                                  "impact": "text"}, ("kind", "description"),
                               ("kind", "created_at"), "context issue"),
    "interested-parties": Register(IsmsInterestedParty, {"name": "text", "requirements": "text",
                                                         "climate_requirements": "text", "addressed_by": "text"},
                                   ("name",), ("name",), "interested party"),
}


def register(name: str) -> Register:
    reg = REGISTERS.get(name)
    if reg is None:
        raise IsmsError("Unknown register", 404)
    return reg


def _clean(reg: Register, data: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for field, kind in reg.fields.items():
        v = data.get(field)
        if kind == "bool":
            out[field] = v is True or v in ("on", "true")
        elif kind == "kind":
            out[field] = v if v in ("internal", "external") else None
        else:
            out[field] = js_trim(v)[:TEXT_MAX] if isinstance(v, str) and js_trim(v) else None
    for f in reg.required:
        if not out[f]:
            raise IsmsError(f"Fill in {f.replace('_', ' ')}.")
    return out


def list_items(db: Session, reg: Register, tenant_id: str) -> list:
    m = reg.model
    return list(db.execute(select(m).where(m.tenant_id == tenant_id)
                           .order_by(*(getattr(m, c) for c in reg.order), m.id)).scalars())


def _text(row) -> str:
    """What the management review shows for a change: an issue's description or a party's or entity's name."""
    return str(getattr(row, "description", None) or getattr(row, "name", None) or "")[:300]


def add_item(db: Session, reg: Register, tenant_id: str, actor: str, data: dict[str, Any]):
    row = reg.model(tenant_id=tenant_id, updated_by=actor, **_clean(reg, data))
    db.add(row)
    db.flush()
    audit.record(db, actor, "isms.register_added", reg.label, tenant_id, table=reg.model.__tablename__, id=row.id,
                 text=_text(row))
    return row


def update_item(db: Session, reg: Register, row, actor: str, data: dict[str, Any]):
    for field, value in _clean(reg, data).items():
        setattr(row, field, value)
    row.updated_at, row.updated_by = utcnow(), actor
    audit.record(db, actor, "isms.register_updated", reg.label, row.tenant_id, table=reg.model.__tablename__,
                 id=row.id, text=_text(row))
    return row


def delete_item(db: Session, reg: Register, row, actor: str) -> None:
    audit.record(db, actor, "isms.register_deleted", reg.label, row.tenant_id, table=reg.model.__tablename__,
                 id=row.id, text=_text(row))
    db.delete(row)


# Assets -------------------------------------------------------------------------------------------------------

ASSET_TYPES = ("information", "system", "service", "person", "supplier", "site")
CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")
ASSET_CSV_COLUMNS = ("name", "type", "classification", "owner_email", "description")
MAX_IMPORT_ROWS = 5000


def _members(db: Session, tenant_id: str) -> dict[str, str]:
    """Lower-case email to user id for the organization's members: people with an ISMS role in this customer."""
    rows = db.execute(select(User.email, User.id).join(IsmsMembership, IsmsMembership.user_id == User.id)
                      .where(IsmsMembership.tenant_id == tenant_id)).all()
    return {email.lower(): uid for email, uid in rows}


def _validate_asset(data: dict[str, Any]) -> dict[str, Any]:
    kind = js_trim(str(data.get("type") or "")).lower()
    if kind not in ASSET_TYPES:
        raise IsmsError(f"Type must be one of: {', '.join(ASSET_TYPES)}.")
    name = js_trim(str(data.get("name") or ""))
    if not name:
        raise IsmsError("Name is required.")
    classification = js_trim(str(data.get("classification") or "")).lower() or "internal"
    if classification not in CLASSIFICATIONS:
        raise IsmsError(f"Classification must be one of: {', '.join(CLASSIFICATIONS)}.")
    description = js_trim(str(data.get("description") or "")) or None
    return {"type": kind, "name": name[:300], "description": description[:TEXT_MAX] if description else None,
            "classification": classification}


def _check_owner(db: Session, tenant_id: str, owner_id: str | None) -> str | None:
    if owner_id and owner_id not in _members(db, tenant_id).values():
        raise IsmsError("The owner must be a member of this organization.")
    return owner_id or None


def _duplicate(db: Session, tenant_id: str, kind: str, name: str, except_id: str | None = None) -> bool:
    q = select(IsmsAsset.id).where(IsmsAsset.tenant_id == tenant_id, IsmsAsset.type == kind, IsmsAsset.name == name)
    found = db.execute(q).scalars().all()
    return any(i != except_id for i in found)


def add_asset(db: Session, tenant_id: str, actor: str, data: dict[str, Any]) -> IsmsAsset:
    values = _validate_asset(data)
    owner = _check_owner(db, tenant_id, data.get("ownerId"))
    if _duplicate(db, tenant_id, values["type"], values["name"]):
        raise IsmsError(f'There is already a {values["type"]} asset called "{values["name"]}".', 409)
    row = IsmsAsset(tenant_id=tenant_id, owner_user_id=owner, updated_by=actor, **values)
    db.add(row)
    db.flush()
    audit.record(db, actor, "isms.asset_added", row.name, tenant_id, id=row.id, type=row.type)
    return row


def update_asset(db: Session, row: IsmsAsset, actor: str, data: dict[str, Any]) -> IsmsAsset:
    values = _validate_asset(data)
    owner = _check_owner(db, row.tenant_id, data.get("ownerId"))
    if _duplicate(db, row.tenant_id, values["type"], values["name"], except_id=row.id):
        raise IsmsError(f'There is already a {values["type"]} asset called "{values["name"]}".', 409)
    for field, value in values.items():
        setattr(row, field, value)
    row.owner_user_id, row.updated_at, row.updated_by = owner, utcnow(), actor
    audit.record(db, actor, "isms.asset_updated", row.name, row.tenant_id, id=row.id)
    return row


def delete_asset(db: Session, row: IsmsAsset, actor: str) -> None:
    audit.record(db, actor, "isms.asset_deleted", row.name, row.tenant_id, id=row.id)
    db.delete(row)


@dataclass
class ImportResult:
    created: int
    updated: int
    errors: list[dict]


def import_assets_csv(db: Session, tenant_id: str, actor: str, text: str) -> ImportResult:
    """All or nothing: if any row is invalid nothing is written and every problem is reported with its line. Rows
    matching an existing asset (same type and name) update it."""
    try:
        headers, records = parse_csv_records(text)
    except CsvError as e:
        return ImportResult(0, 0, [{"line": 0, "message": str(e)}])
    missing = [c for c in ("name", "type") if c not in headers]
    if missing:
        return ImportResult(0, 0, [{"line": 1, "message": f"Missing column(s): {', '.join(missing)}. "
                                                          f"Expected: {', '.join(ASSET_CSV_COLUMNS)}."}])
    if len(records) > MAX_IMPORT_ROWS:
        return ImportResult(0, 0, [{"line": 0, "message": "Import at most 5,000 rows at a time."}])
    members = _members(db, tenant_id)
    errors: list[dict] = []
    valid: list[tuple[dict, str | None]] = []
    seen: set[tuple[str, str]] = set()
    for line, rec in enumerate(records, start=2):
        try:
            values = _validate_asset(rec)
            email = (rec.get("owner_email") or "").lower()
            owner = members.get(email) if email else None
            if email and owner is None:
                raise IsmsError(f"Owner {email} is not a member of this organization.")
            key = (values["type"], values["name"].lower())
            if key in seen:
                raise IsmsError(f'Duplicate of an earlier row ({values["type"]} "{values["name"]}").')
            seen.add(key)
            valid.append((values, owner))
        except IsmsError as e:
            errors.append({"line": line, "message": e.detail})
    if errors:
        return ImportResult(0, 0, errors)
    existing = {(a.type, a.name): a for a in db.execute(select(IsmsAsset).where(IsmsAsset.tenant_id == tenant_id))
                .scalars()}
    created = updated = 0
    for values, owner in valid:
        row = existing.get((values["type"], values["name"]))
        if row is None:
            db.add(IsmsAsset(tenant_id=tenant_id, owner_user_id=owner, updated_by=actor, **values))
            created += 1
        elif (row.description, row.classification, row.owner_user_id) != (
                values["description"], values["classification"], owner):
            row.description, row.classification = values["description"], values["classification"]
            row.owner_user_id, row.updated_at, row.updated_by = owner, utcnow(), actor
            updated += 1
    audit.record(db, actor, "isms.assets_imported", f"{created} created, {updated} updated", tenant_id,
                 created=created, updated=updated)
    return ImportResult(created, updated, [])
