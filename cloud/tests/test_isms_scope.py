"""Tenant isolation for ISMS data: tenant A can never list or load tenant B's rows.

Every ISMS table registered with ``@tenant_table`` needs a row factory in ``FACTORIES`` below; the first test fails
until it has one, and the isolation tests then run against it. The scoping helper itself is checked against an
existing tenant table (``grc_policies``).
"""

from dataclasses import dataclass

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from fenrir_cloud.isms.models import IsmsMembership
from fenrir_cloud.isms.scope import TENANT_TABLES, get_scoped, require_same_tenant, scoped, tenant_table
from fenrir_cloud.models import Base, GrcPolicy

# Model -> function(tenant_id) returning an unsaved row for that tenant.
FACTORIES: dict[type, callable] = {
    IsmsMembership: lambda t: IsmsMembership(tenant_id=t, user_id=f"usr_{t}", role="staff"),
}


@dataclass
class FakePrincipal:
    tenant_ids: frozenset

    def check_tenant(self, tenant_id):
        if tenant_id not in self.tenant_ids:
            raise HTTPException(404, "Not found")


A = FakePrincipal(frozenset({"ten_a", "ten_a_site"}))  # a customer with one site below it


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    tables = [GrcPolicy.__table__, *(m.__table__ for m in FACTORIES)]
    Base.metadata.create_all(engine, tables=tables)
    with Session(engine) as session:
        yield session


def seed(db, model, make):
    rows = {t: make(t) for t in ("ten_a", "ten_a_site", "ten_b")}
    db.add_all(rows.values())
    db.commit()
    return rows


def test_every_isms_table_has_a_row_factory():
    assert set(TENANT_TABLES) == set(FACTORIES), "add a row factory for each new ISMS tenant table"


ALL = [(GrcPolicy, lambda t: GrcPolicy(tenant_id=t, title=f"Policy {t}")), *FACTORIES.items()]


@pytest.mark.parametrize("model,make", ALL, ids=lambda x: getattr(x, "__tablename__", ""))
def test_lists_show_only_visible_tenants(db, model, make):
    seed(db, model, make)
    rows = db.execute(scoped(model, A)).scalars().all()
    assert sorted(r.tenant_id for r in rows) == ["ten_a", "ten_a_site"]
    assert [r.tenant_id for r in db.execute(scoped(model, A, "ten_a_site")).scalars()] == ["ten_a_site"]
    count = db.execute(scoped(model, A, stmt=select(func.count()).select_from(model))).scalar_one()
    assert count == 2


@pytest.mark.parametrize("model,make", ALL, ids=lambda x: getattr(x, "__tablename__", ""))
def test_other_tenants_cannot_be_asked_for_or_loaded(db, model, make):
    rows = seed(db, model, make)
    with pytest.raises(HTTPException) as e:
        db.execute(scoped(model, A, "ten_b"))
    assert e.value.status_code == 404
    with pytest.raises(HTTPException) as e:
        get_scoped(db, model, rows["ten_b"].id, A)
    assert e.value.status_code == 404  # not 403: the id reveals nothing
    assert get_scoped(db, model, rows["ten_a"].id, A).tenant_id == "ten_a"
    with pytest.raises(HTTPException):
        get_scoped(db, model, "missing", A)


def test_linked_records_must_share_a_tenant():
    assert require_same_tenant([GrcPolicy(tenant_id="ten_a"), GrcPolicy(tenant_id="ten_a")]) == "ten_a"
    with pytest.raises(HTTPException) as e:
        require_same_tenant([GrcPolicy(tenant_id="ten_a"), GrcPolicy(tenant_id="ten_b")])
    assert e.value.status_code == 400


def test_registering_a_table_without_tenant_id_fails():
    class NoTenant:
        pass

    with pytest.raises(TypeError):
        tenant_table(NoTenant)
