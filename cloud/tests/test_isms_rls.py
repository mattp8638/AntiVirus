"""Row-level security on ISMS tables, on a real PostgreSQL server.

Needs FENRIR_TEST_PG_ADMIN_URL, a superuser URL such as postgresql+psycopg://postgres@127.0.0.1:5432/postgres. The test
creates a non-superuser role and a database it owns (superusers bypass row-level security), migrates it, and checks
the policies directly, below the application's own tenant scoping.
"""

import os
import secrets

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

ADMIN_URL = os.getenv("FENRIR_TEST_PG_ADMIN_URL")
pytestmark = pytest.mark.skipif(not ADMIN_URL, reason="set FENRIR_TEST_PG_ADMIN_URL to run row-level security tests")


@pytest.fixture(scope="module")
def app_engine():
    from fenrir_cloud import db as database
    from fenrir_cloud.isms.scope import TENANT_TABLES  # noqa: F401 - registers the ISMS models

    name = f"fenrir_rls_{secrets.token_hex(4)}"
    admin = create_engine(ADMIN_URL, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f"CREATE ROLE {name} LOGIN PASSWORD 'rls-test' NOSUPERUSER NOBYPASSRLS"))
        conn.execute(text(f"CREATE DATABASE {name} OWNER {name}"))
    url = make_url(ADMIN_URL).set(username=name, password="rls-test", database=name)
    engine = create_engine(url)
    database.migrate(engine)
    yield engine
    engine.dispose()
    with admin.connect() as conn:
        conn.execute(text(f"DROP DATABASE {name} WITH (FORCE)"))
        conn.execute(text(f"DROP ROLE {name}"))
    admin.dispose()


@pytest.fixture()
def rows(app_engine):
    from fenrir_cloud.isms.models import IsmsMembership
    from fenrir_cloud.models import Tenant, User

    with Session(app_engine) as db:
        db.execute(text("DELETE FROM isms_memberships"))
        for t in ("ten_a", "ten_b"):
            if db.get(Tenant, t) is None:
                db.add(Tenant(id=t, name=t, slug=t))
                db.add(User(id=f"usr_{t}", tenant_id=t, email=f"{t}@x.test", password_hash="x"))
        db.flush()
        db.add_all([IsmsMembership(tenant_id=t, user_id=f"usr_{t}", role="staff") for t in ("ten_a", "ten_b")])
        db.commit()
    return IsmsMembership


def tenants_seen(db, model):
    return sorted(db.execute(select(model.tenant_id)).scalars())


def test_every_isms_table_has_row_level_security(app_engine):
    from fenrir_cloud.isms.scope import TENANT_TABLES

    with app_engine.connect() as conn:
        forced = dict(conn.execute(text("SELECT relname, relforcerowsecurity FROM pg_class WHERE relrowsecurity")).all())
    assert {m.__tablename__ for m in TENANT_TABLES} <= {name for name, force in forced.items() if force}


def test_a_bound_session_sees_only_its_tenants_even_unscoped(app_engine, rows):
    from fenrir_cloud.isms import rls

    with Session(app_engine) as db:
        rls.bind_tenants(db, ["ten_a"])
        assert tenants_seen(db, rows) == ["ten_a"]  # no WHERE clause: the database filters
        db.commit()
        assert tenants_seen(db, rows) == ["ten_a"]  # and again in the next transaction


def test_a_bound_session_cannot_write_another_tenant(app_engine, rows):
    from sqlalchemy.exc import ProgrammingError

    from fenrir_cloud.isms import rls

    with Session(app_engine) as db:
        rls.bind_tenants(db, ["ten_a"])
        db.add(rows(tenant_id="ten_b", user_id="usr_ten_a", role="auditor"))
        with pytest.raises(ProgrammingError, match="row-level security"):
            db.commit()
    with Session(app_engine) as db:
        rls.bind_tenants(db, ["ten_a"])
        db.execute(text("UPDATE isms_memberships SET role = 'auditor'"))
        db.commit()
    with Session(app_engine) as db:
        assert dict(db.execute(select(rows.tenant_id, rows.role)).all()) == {"ten_a": "auditor", "ten_b": "staff"}


def test_an_empty_binding_sees_nothing(app_engine, rows):
    from fenrir_cloud.isms import rls

    with Session(app_engine) as db:
        rls.bind_tenants(db, [])
        assert tenants_seen(db, rows) == []


def test_unbound_maintenance_code_still_sees_everything(app_engine, rows):
    with Session(app_engine) as db:  # customer deletion and export sweep tables without a principal
        assert tenants_seen(db, rows) == ["ten_a", "ten_b"]


def test_the_binding_never_leaks_through_the_pool(app_engine, rows):
    from fenrir_cloud.isms import rls

    for _ in range(3):
        with Session(app_engine) as db:
            rls.bind_tenants(db, ["ten_a"])
            assert tenants_seen(db, rows) == ["ten_a"]
        with Session(app_engine) as db:
            assert tenants_seen(db, rows) == ["ten_a", "ten_b"]


def test_bypass_warning(app_engine):
    from fenrir_cloud.isms import rls

    with Session(app_engine) as db:
        assert rls.bypass_warning(db) is None
    superuser = create_engine(ADMIN_URL)
    with Session(superuser) as db:
        assert "superuser" in rls.bypass_warning(db)
    superuser.dispose()
