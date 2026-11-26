"""Row-level security on PostgreSQL: the second layer under ``scope.py`` (plan decision R2).

Each ISMS table gets a policy that reads the transaction setting ``fenrir.isms_tenants``:

* ISMS requests set it to the tenants the principal can see (``bind_tenants``), so a query that forgot to scope
  still cannot return another tenant's rows, and an insert for another tenant is refused.
* When it is not set (Fenrir's own maintenance code, such as customer deletion and export, which sweeps every table
  by ``tenant_id``), the policy allows the row, so that code keeps working unchanged.

The setting is transaction-local and is applied again at the start of every transaction of a bound session, so it
never leaks to another request through the connection pool. SQLite (development and the default test run) has no
row-level security; ``scope.py`` is the guard there, and ``tests/test_isms_rls.py`` runs the policies on PostgreSQL.

PostgreSQL never applies row-level security to a superuser or a role with BYPASSRLS. The official PostgreSQL image
makes ``POSTGRES_USER`` a superuser, so a default Fenrir install bypasses this layer; ``bypass_warning`` reports it on
the platform readiness page.
"""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import event, text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session

SETTING = "fenrir.isms_tenants"
_INFO_KEY = "isms_tenants"


def policy_sql(table: str) -> list[str]:
    """DDL that turns on row-level security for one ISMS table (idempotent)."""
    visible = (f"coalesce(current_setting('{SETTING}', true), '') = '' "
               f"OR tenant_id = ANY (string_to_array(current_setting('{SETTING}', true), ','))")
    return [
        f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY',
        f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY',  # the application owns the tables; owners are bound too
        f'DROP POLICY IF EXISTS isms_tenant_isolation ON "{table}"',
        f'CREATE POLICY isms_tenant_isolation ON "{table}" USING ({visible}) WITH CHECK ({visible})',
    ]


def enable(conn: Connection, tables: Iterable[str]) -> None:
    if conn.dialect.name != "postgresql":
        return
    for table in tables:
        for statement in policy_sql(table):
            conn.execute(text(statement))


def bypass_warning(db: Session) -> str | None:
    """A readiness warning when the database account ignores row-level security, else None."""
    if db.get_bind().dialect.name != "postgresql":
        return None
    bypass = db.execute(text("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user")).scalar()
    if not bypass:
        return None
    return ("The database account is a PostgreSQL superuser (or has BYPASSRLS), so row-level security on ISMS tables "
            "is not enforced. Tenant scoping in the application still applies. To add the database layer, connect "
            "Fenrir as a role without superuser rights that owns the tables.")


def bind_tenants(db: Session, tenant_ids: Iterable[str]) -> None:
    """Limits this session's ISMS rows to these tenants, now and in every later transaction of the session."""
    ids = sorted(set(tenant_ids))
    if any("," in t for t in ids):
        raise ValueError("tenant ids cannot contain commas")
    # An empty list must still restrict, so it binds a value no tenant id can take.
    db.info[_INFO_KEY] = ",".join(ids) or "-"
    if db.in_transaction():
        _apply(db, db.connection())


def _apply(db: Session, conn: Connection) -> None:
    value = db.info.get(_INFO_KEY)
    if value is not None and conn.dialect.name == "postgresql":
        conn.execute(text("SELECT set_config(:name, :value, true)"), {"name": SETTING, "value": value})


@event.listens_for(Session, "after_begin")
def _after_begin(session: Session, _transaction, connection: Connection) -> None:  # pragma: no cover - driver hook
    _apply(session, connection)
