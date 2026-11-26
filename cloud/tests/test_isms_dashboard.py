"""ISMS dashboard tiles from live data, per-person layouts limited by ISMS role, and email digests."""

from datetime import datetime, timedelta

import pytest
from conftest import login
from test_isms_soa import HALCYON, PW, person, programme

A = "/api/console/isms"


@pytest.fixture()
def ctx(client, admin, tenant):
    h = programme(client, admin, tenant, HALCYON)
    return h, tenant["id"]


def test_tiles_layout_and_roles(client, admin, ctx):
    h, tid = ctx
    d = client.get(f"{A}/dashboard?tenant_id={tid}", headers=h).json()
    assert d["layout"] == ["readiness", "control_health", "tasks", "evidence", "risks", "improvement"]
    tiles = {t["id"]: t for t in d["tiles"]}
    assert tiles["readiness"]["value"].endswith("%") or tiles["readiness"]["value"] == "Not started"
    assert tiles["control_health"]["value"].startswith("0 of ") and tiles["tasks"]["tab"] == "ISMS tasks"
    assert {t["id"] for t in d["available"]} >= {"incidents", "suppliers", "audit"}
    assert client.put(f"{A}/dashboard/layout", headers=h, json={"tenantId": tid, "tiles": ["secrets"]}).json()["detail"] == "Choose at least one tile."
    saved = client.put(f"{A}/dashboard/layout", headers=h, json={"tenantId": tid, "tiles": ["audit", "incidents", "audit"]}).json()
    assert saved["layout"] == ["audit", "incidents"] and saved["tiles"][0]["value"] == "None planned"
    # Staff only see the tiles their role allows: the tasks tile.
    person(client, admin, tid, "sam@acme.test", "staff")
    sam = login(client, "sam@acme.test", PW)
    d = client.get(f"{A}/dashboard?tenant_id={tid}", headers=sam).json()
    assert [t["id"] for t in d["available"]] == ["tasks"] and d["layout"] == ["tasks"]
    assert client.put(f"{A}/dashboard/layout", headers=sam, json={"tenantId": tid, "tiles": ["risks"]}).status_code == 400


def test_digests(client, admin, ctx):
    from fenrir_cloud import db as database
    from fenrir_cloud import mailer
    from fenrir_cloud.isms import dashboard
    from fenrir_cloud.isms.models import IsmsDigestSubscription, IsmsMembership
    from sqlalchemy import select
    h, tid = ctx
    assert client.put(f"{A}/dashboard/digest", headers=h, json={"tenantId": tid, "frequency": "daily"}).status_code == 400
    dg = client.put(f"{A}/dashboard/digest", headers=h, json={"tenantId": tid, "frequency": "weekly"}).json()["digest"]
    assert datetime.fromisoformat(dg["nextSendAt"].replace("Z", "+00:00")).weekday() == 0
    mailer.OUTBOX.clear()
    with database.session_factory()() as db:
        assert dashboard.send_due_digests(db) == 0  # not due yet
        later = datetime.utcnow() + timedelta(days=8)
        assert dashboard.send_due_digests(db, later) == 1
        db.commit()
        assert dashboard.send_due_digests(db, later) == 0  # moved on a week
        msg = mailer.OUTBOX[-1]
        assert msg["to"] == "isms@acme.test" and "weekly ISMS summary" in msg["subject"] and "[" in msg["body"]
        # Losing the ISMS role stops the digest.
        db.delete(db.execute(select(IsmsMembership).where(IsmsMembership.tenant_id == tid)).scalars().first())
        db.commit()
        assert dashboard.send_due_digests(db, later + timedelta(days=8)) == 0
        db.commit()
        assert db.execute(select(IsmsDigestSubscription)).scalar_one().enabled is False


def test_isolation(client, admin, ctx):
    h, tid = ctx
    other = client.post("/api/console/tenants", json={"name": "Globex", "template": "balanced"}, headers=admin).json()
    person(client, admin, other["id"], "isms@globex.test", "isms_manager")
    g = login(client, "isms@globex.test", PW)
    assert client.get(f"{A}/dashboard?tenant_id={tid}", headers=g).status_code == 404
    assert client.put(f"{A}/dashboard/digest", headers=g, json={"tenantId": tid, "frequency": "weekly"}).status_code == 404
