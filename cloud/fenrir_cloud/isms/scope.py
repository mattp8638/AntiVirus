"""Tenant scoping for ISMS data: the one way ISMS code reads and loads tenant-owned rows.

Every ISMS table has a ``tenant_id`` and is registered with ``@tenant_table``. ISMS code reads rows only through
``scoped`` (lists) and ``get_scoped`` (one row), which limit results to the tenants the principal can see. A row in
another tenant is reported as not found, never as forbidden, so ids from other tenants reveal nothing.

``tests/test_isms_scope.py`` checks, for every registered table, that tenant A cannot list or load tenant B's rows.
Row-level security on PostgreSQL is a second layer, added with the first ISMS tables (plan decision R2).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, TypeVar

from fastapi import HTTPException, status
from sqlalchemy import Select, select
from sqlalchemy.orm import Session

TENANT_TABLES: list[type] = []  # every ISMS model holding tenant data, in registration order

M = TypeVar("M")


class Scoped(Protocol):
    """What scoping needs from the caller: Fenrir's ``deps.Principal`` satisfies it."""
    tenant_ids: frozenset[str]

    def check_tenant(self, tenant_id: str | None) -> None: ...


def tenant_table(model: type[M]) -> type[M]:
    """Registers an ISMS model as tenant data, so the isolation test covers it. The model must have ``tenant_id``."""
    if not hasattr(model, "tenant_id"):
        raise TypeError(f"{model.__name__} holds tenant data but has no tenant_id column")
    if model not in TENANT_TABLES:
        TENANT_TABLES.append(model)
    return model


def visible_tenants(principal: Scoped, tenant_id: str | None = None) -> list[str]:
    """One tenant if asked for (and visible), else every tenant the principal can see."""
    if tenant_id:
        principal.check_tenant(tenant_id)
        return [tenant_id]
    return sorted(principal.tenant_ids)


def scoped(model: type[M], principal: Scoped, tenant_id: str | None = None,
           stmt: Select | None = None) -> Select:
    """``select(model)`` (or ``stmt``) limited to the principal's tenants."""
    stmt = select(model) if stmt is None else stmt
    return stmt.where(model.tenant_id.in_(visible_tenants(principal, tenant_id)))


def get_scoped(db: Session, model: type[M], row_id: str, principal: Scoped) -> M:
    """One row by id, or 404 when it does not exist or belongs to a tenant the principal cannot see."""
    row = db.get(model, row_id)
    if row is None or row.tenant_id not in principal.tenant_ids:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    return row


def require_same_tenant(rows: Iterable[object]) -> str:
    """For writes that link records (a risk to a control, evidence to a requirement): all must share one tenant."""
    tenants = {getattr(r, "tenant_id") for r in rows}
    if len(tenants) != 1:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Linked records must belong to the same organization")
    return tenants.pop()
