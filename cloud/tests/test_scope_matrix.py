"""CORE-01 / AT-03: an operator (or device) of customer A must not read, infer or change customer B's records through
any API route.

The route list comes from the OpenAPI schema, so a new route is covered automatically. Customer B gets one row in
every tenant-owned table (string columns carry a marker) plus real records made through the API. Then customer A's
tenant admin, a technician and A's device key call every operation with B's identifiers in the path, the query
(tenant_id) and the JSON body. A response that contains B's marker, or any change to B's rows, is a leak.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime

import pytest
from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, LargeBinary, String, Text, inspect, select

from conftest import enroll, login
from fenrir_cloud.db import Base, session_factory
from fenrir_cloud.models import Device, Tenant, utcnow

MARK = "BRAVOLEAK"
# Routes that are deliberately not customer data (platform metadata, the caller's own account, public endpoints).
NOT_CUSTOMER_DATA = re.compile(r"^/api/(health|console/auth/|console/me\b)")


def _tenant_tables():
    out = []
    for mapper in Base.registry.mappers:
        cls = mapper.class_
        if "tenant_id" in mapper.columns or "device_id" in mapper.columns:
            out.append(cls)
    return sorted(out, key=lambda c: c.__tablename__)


def _dummy(column, ids):
    name, kind = column.name, column.type
    mark = f"{MARK}-{column.table.name}-{name}"
    if name == "tenant_id":
        return ids["tenant"]
    if name == "device_id":
        return ids["device"]
    if isinstance(kind, (String, Text)):
        length = getattr(kind, "length", None) or 200
        if name == "hash" or name.endswith("_hash"):  # digests carry no content; an export may show them redacted
            return hashlib.sha256(mark.encode()).hexdigest()[:length]
        if name.endswith("_id"):
            return (ids["any"].get(name[:-3]) or f"{MARK}{name}")[:length]
        return mark[:length]
    if isinstance(kind, Boolean):
        return False
    if isinstance(kind, Integer):
        return 1
    if isinstance(kind, Float):
        return 1.0
    if isinstance(kind, DateTime):
        return utcnow()
    if isinstance(kind, JSON):
        return {"note": mark}
    if isinstance(kind, LargeBinary):
        return MARK.encode()
    return None


def _seed_every_table(tenant_id: str, device_id: str, msp_id: str | None = None) -> dict[str, list[str]]:
    """One row per tenant-owned table for the customer, plus (with msp_id) an MSP-owned row about the customer in
    every table that has account_tenant_id - the real shape of tickets, invoices, contracts and contacts.
    Returns {table: [primary key values]}."""
    rows: dict[str, list[str]] = {}
    _seed_pass(tenant_id, None, device_id, rows)
    if msp_id:
        _seed_pass(msp_id, tenant_id, device_id, rows)
    return rows


def _seed_pass(tenant_id: str, account: str | None, device_id: str, rows: dict[str, list[str]]) -> None:
    ids = {"tenant": tenant_id, "device": device_id, "any": {}}
    for cls in _tenant_tables():
        if account and "account_tenant_id" not in cls.__table__.c:
            continue
        db = session_factory()()
        try:
            kwargs = {}
            for column in cls.__table__.columns:
                if column.primary_key and (column.default is not None or column.autoincrement is True):
                    continue
                if column.name in ("tenant_id", "device_id") or (not column.nullable and column.default is None and column.server_default is None):
                    value = _dummy(column, ids)
                    if value is not None:
                        kwargs[column.name] = value
                elif isinstance(column.type, (String, Text)) and not column.name.endswith("_id") and column.name not in ("status", "state", "kind", "role", "type"):
                    kwargs[column.name] = _dummy(column, ids)
            if account:
                kwargs["account_tenant_id"] = account
            row = cls(**{k: v for k, v in kwargs.items() if k in cls.__mapper__.attrs})
            db.add(row)
            db.commit()
            pk = inspect(row).identity
            if pk:
                rows.setdefault(cls.__tablename__, []).append(str(pk[0]))
                ids["any"].setdefault(cls.__tablename__.rstrip("s"), str(pk[0]))
        except Exception:  # noqa: BLE001 - a table that needs richer data is seeded through the API instead
            db.rollback()
        finally:
            db.close()


# Bookkeeping every request may legitimately write, whoever makes it.
BOOKKEEPING = {"audit_log", "audit_chain_head", "user_sessions", "rate_limit_buckets", "outbox_events", "event_outbox", "schema_migrations"}


def _snapshot(own_tenant: str) -> dict[str, str]:
    """Hash of every row outside the caller's own customer: other customers, the MSP and platform-wide rows."""
    db = session_factory()()
    try:
        out: dict[str, str] = {}
        for table in Base.metadata.sorted_tables:
            digest = hashlib.sha256()
            if table.name in BOOKKEEPING:
                continue
            if "tenant_id" in table.c:
                outside = (table.c.tenant_id != own_tenant) | table.c.tenant_id.is_(None)
                if "account_tenant_id" in table.c:  # MSP-owned records about this customer (tickets, configurations...)
                    outside = outside & ((table.c.account_tenant_id != own_tenant) | table.c.account_tenant_id.is_(None))
            elif "device_id" in table.c:
                outside = table.c.device_id.not_in(select(Device.id).where(Device.tenant_id == own_tenant))
            else:
                outside = None
            query = select(table) if outside is None else select(table).where(outside)
            try:
                rows = db.execute(query.order_by(*table.primary_key.columns)).all()
            except Exception:  # noqa: BLE001
                db.rollback()
                continue
            for row in rows:
                digest.update(repr(tuple(row)).encode())
            out[table.name] = digest.hexdigest()
        return out
    finally:
        db.close()


def _resolve(spec, schema):
    while isinstance(schema, dict) and "$ref" in schema:
        schema = spec["components"]["schemas"][schema["$ref"].split("/")[-1]]
    if isinstance(schema, dict) and "anyOf" in schema:
        options = [s for s in schema["anyOf"] if s.get("type") != "null"]
        schema = _resolve(spec, options[0]) if options else {}
    return schema or {}


def _value_for(spec, name: str, schema, ids) -> object:
    schema = _resolve(spec, schema)
    lname = name.lower()
    if schema.get("enum"):
        return schema["enum"][0]
    kind = schema.get("type")
    if kind == "array":
        item = _value_for(spec, name[:-1] if name.endswith("s") else name, schema.get("items", {}), ids)
        return [item]
    if kind == "object" or "properties" in schema:
        return _body(spec, schema, ids)
    if kind == "integer":
        return max(1, schema.get("minimum", 1))
    if kind == "number":
        return 1
    if kind == "boolean":
        return False
    if lname in ("tenantid", "tenant_id", "customerid"):
        return ids["tenant"]
    if lname in ("deviceid", "device_id"):
        return ids["device"]
    if lname.endswith("id"):
        return ids["guess"](lname[:-2].rstrip("_"))
    return "probe"


# Sent to routes that take a free-form JSON object, so their field handling and permission checks actually run.
GENERIC_FIELDS = ("name", "title", "subject", "status", "notes", "comment", "description", "label", "value", "enabled")


def _body(spec, schema, ids, everything=False):
    schema = _resolve(spec, schema)
    props = schema.get("properties", {})
    if not props and schema.get("type") in (None, "object") and "items" not in schema:
        return {**{f: "probe" for f in GENERIC_FIELDS}, "enabled": False, "tenantId": ids["tenant"], "deviceId": ids["device"]}
    out = {}
    for name, sub in props.items():
        if everything or name in schema.get("required", []) or name.lower().endswith(("tenantid", "deviceid", "deviceids")):
            out[name] = _value_for(spec, name, sub, ids)
    return out


def _candidates(param: str, path: str, ids, rows) -> list[str]:
    p = param.lower()
    if p in ("tenant_id", "tenant"):
        return [ids["tenant"]]
    if p == "tenant_slug":
        return [ids["slug"]]
    if p == "device_id":
        return [ids["device"]]
    if p == "framework_key":
        return ["cyber-essentials"]
    if not p.endswith("_id") and p not in ("obj_id", "vuln_pk", "short_id"):
        return ["probe"]
    stem = p[:-3] if p.endswith("_id") else re.sub(r"[^a-z]", "", path.rsplit("/{", 1)[0].rsplit("/", 1)[-1])
    stem = stem.replace("obj", "") or re.sub(r"[^a-z]", "", path.rsplit("/{", 1)[0].rsplit("/", 1)[-1])
    matched = [v for table, values in rows.items() if stem and stem[:5] in table for v in values]
    return matched or [v for values in rows.values() for v in values]


@pytest.fixture()
def world(client, admin, tenant):
    """Customer A (the fixture tenant) and customer B with data everywhere."""
    bravo = client.post("/api/console/tenants", headers=admin, json={"name": f"{MARK} Customer", "template": "balanced"}).json()
    b_device = enroll(client, admin, bravo, hostname=f"{MARK}-PC", serial=f"{MARK}-1")
    a_device = enroll(client, admin, tenant, hostname="ALPHA-PC", serial="A-1")
    # Real records through the API, so tables with richer invariants are covered too.
    client.post("/api/console/grc/programmes", headers=admin, json={"tenantId": bravo["id"], "frameworkKey": "cyber-essentials", "createPolicies": True})
    client.post("/api/console/grc/evidence", headers=admin, json={"tenantId": bravo["id"], "title": f"{MARK} evidence", "kind": "note",
                                                                   "note": MARK, "links": ["cyber-essentials:A1.1"]})
    db = session_factory()()
    try:
        msp = db.execute(select(Tenant.id).where(Tenant.kind == "msp")).scalars().first()
    finally:
        db.close()
    assert msp, "expected the bootstrap MSP tenant"
    rows = _seed_every_table(bravo["id"], b_device["deviceId"], msp)
    users = {}
    for role in ("tenant_admin", "technician"):
        email = f"{role.replace('_', '')}@alpha.example"
        created = client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": email,
                                                                        "password": "alpha-password-123", "role": role})
        assert created.status_code == 200, created.text
        users[role] = login(client, email, "alpha-password-123")
    from fenrir_cloud import apikeys

    db = session_factory()()
    try:
        slug = db.get(Tenant, bravo["id"]).slug
        _, api_token = apikeys.issue(db, tenant["id"], "matrix", list(apikeys.GRANTABLE), 1, "test")  # an integration of customer A
        db.commit()
    finally:
        db.close()
    users["api"] = {"Authorization": f"Bearer {api_token}"}
    return {"alpha": tenant["id"], "bravo": bravo, "rows": rows, "users": users, "a_device": a_device, "b_device": b_device, "slug": slug}


def _snapshot_all() -> dict[str, str]:
    db = session_factory()()
    try:
        out = {}
        for table in Base.metadata.sorted_tables:
            if table.name in BOOKKEEPING:
                continue
            digest = hashlib.sha256()
            for row in db.execute(select(table).order_by(*table.primary_key.columns)).all():
                digest.update(repr(tuple(row)).encode())
            out[table.name] = digest.hexdigest()
        return out
    finally:
        db.close()


def _guesser(rows, fallback):
    def guess(stem: str) -> str:
        for table, values in rows.items():
            if stem and stem[:5] in table:
                return values[0]
        return fallback
    return guess


def _walk(client, identities, who, ids, rows, snapshot, methods=("get", "post", "put", "patch", "delete"), read_marker=None):
    """Calls every operation once per identity in who(path); returns (findings, calls, outcomes)."""
    spec = client.app.openapi()
    before = snapshot()
    findings, calls, outcomes = [], 0, {}
    for path, item in sorted(spec["paths"].items()):
        if NOT_CUSTOMER_DATA.match(path) or "{path" in path:
            continue
        for method, op in item.items():
            if method not in methods:
                continue
            params = [p for p in op.get("parameters", []) if p["in"] == "path"]
            query_names = {p["name"] for p in op.get("parameters", []) if p["in"] == "query"}
            combos = [{}]
            for p in params:
                combos = [dict(c, **{p["name"]: v}) for c in combos for v in _candidates(p["name"], path, ids, rows)[:12]]
            body = None
            if "requestBody" in op:
                content = op["requestBody"].get("content", {})
                if "application/json" in content:
                    body = _body(spec, content["application/json"].get("schema", {}), ids, everything=method in ("patch", "put"))
            query = {"tenant_id": ids["tenant"]} if "tenant_id" in query_names else {}
            if "device_id" in query_names:
                query["device_id"] = ids["device"]
            for combo in combos[:40]:
                url = path
                for name, value in combo.items():
                    url = url.replace("{" + name + "}", str(value))
                for identity in who(path):
                    calls += 1
                    reply = client.request(method.upper(), url, headers=identities[identity], params=query, json=body)
                    outcomes.setdefault((method, reply.status_code), []).append(url)
                    if not 200 <= reply.status_code < 300:
                        continue
                    if read_marker and read_marker in reply.text:
                        findings.append(f"READ  {identity:12} {method.upper():6} {url} -> {reply.status_code}: {reply.text[:160]}")
                    if method != "get":
                        now = snapshot()
                        if now != before:
                            changed = sorted(t for t in now if now[t] != before.get(t))
                            findings.append(f"WRITE {identity:12} {method.upper():6} {url} -> {reply.status_code} changed {changed}: {reply.text[:160]}")
                            before = now
    return findings, calls, outcomes


def test_no_route_leaks_or_changes_another_customers_data(client, world):
    rows = world["rows"]
    assert len(rows) >= 70, f"only {len(rows)} tenant tables seeded"
    ids = {"tenant": world["bravo"]["id"], "device": world["b_device"]["deviceId"], "slug": world["slug"],
           "guess": _guesser(rows, world["b_device"]["deviceId"])}
    identities = dict(world["users"], deviceA=world["a_device"]["headers"])
    who = lambda path: ["deviceA"] if path.startswith("/api/v1/") else ["tenant_admin", "technician", "api"]  # noqa: E731
    leaks, calls, outcomes = _walk(client, identities, who, ids, rows, lambda: _snapshot(world["alpha"]), read_marker=MARK)
    print(f"\n{calls} calls, {len(rows)} tables seeded; outcomes " + ", ".join(f"{k[0]} {k[1]}: {len(v)}" for k, v in sorted(outcomes.items(), key=str)))
    assert calls > 1000 and len(outcomes.get(("get", 200), [])) > 50  # the walk really reached the handlers
    assert not leaks, "\n".join(leaks)


def test_read_only_viewer_cannot_change_anything(client, admin, world):
    """CORE-02 / least privilege: a viewer of customer A, using A's own identifiers, changes nothing."""
    alpha = world["alpha"]
    rows = _seed_every_table(alpha, world["a_device"]["deviceId"])
    client.post("/api/console/users", headers=admin, json={"tenantId": alpha, "email": "viewer@alpha.example",
                                                           "password": "alpha-password-123", "role": "viewer"})
    identities = {"viewer": login(client, "viewer@alpha.example", "alpha-password-123")}
    db = session_factory()()
    try:
        slug = db.get(Tenant, alpha).slug
    finally:
        db.close()
    ids = {"tenant": alpha, "device": world["a_device"]["deviceId"], "slug": slug, "guess": _guesser(rows, world["a_device"]["deviceId"])}
    who = lambda path: [] if path.startswith("/api/v1/") else ["viewer"]  # noqa: E731
    findings, calls, outcomes = _walk(client, identities, who, ids, rows, _snapshot_all, methods=("post", "put", "patch", "delete"))
    # Asking for help is allowed for every signed-in customer user (decisions.md D-09); staff fields are ignored.
    findings = [f for f in findings if not re.search(r"POST\s+/api/(console|portal)/tickets -> 200", f)]
    print(f"\n{calls} calls; outcomes " + ", ".join(f"{k[0]} {k[1]}: {len(v)}" for k, v in sorted(outcomes.items(), key=str)))
    assert calls > 200
    assert not findings, "\n".join(findings)


def test_customer_ticket_cannot_set_staff_fields_or_foreign_references(client, admin, world):
    alpha = world["alpha"]
    client.post("/api/console/users", headers=admin, json={"tenantId": alpha, "email": "viewer2@alpha.example",
                                                           "password": "alpha-password-123", "role": "viewer"})
    viewer = login(client, "viewer2@alpha.example", "alpha-password-123")
    reply = client.post("/api/console/tickets", headers=viewer, json={"subject": "Printer broken", "assignee": "someone@msp",
                                                                       "status": "Closed", "recordType": "change"})
    assert reply.status_code == 200, reply.text
    ticket = reply.json()
    assert ticket["assignee"] in ("", None) and ticket["status"] != "Closed" and ticket["recordType"] == "incident"
    # Another customer's device cannot be attached, by staff or anyone else.
    tech = world["users"]["technician"]
    assert client.post("/api/console/tickets", headers=tech, json={"subject": "x", "deviceId": world["b_device"]["deviceId"]}).status_code == 404
    other_board = next(iter(world["rows"].get("psa_boards", [])), None)
    if other_board:
        assert client.post("/api/console/tickets", headers=tech, json={"subject": "x", "boardId": other_board}).status_code == 404
    # A viewer cannot edit or comment on a ticket.
    assert client.patch(f"/api/console/tickets/{ticket['id']}", headers=viewer, json={"comment": "hi"}).status_code == 403

