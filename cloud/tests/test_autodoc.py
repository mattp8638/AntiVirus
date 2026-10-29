"""Documentation generated from live data (autodoc.py): pages, kept notes, revisions only on change, daily refresh."""

from datetime import timedelta

from conftest import enroll
from test_billing_sync import add_m365
from fenrir_cloud import autodoc
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import DocumentRevision, KbArticle, Tenant, utcnow


def pages(client, admin, tenant):
    row = next(r for r in client.get("/api/console/documentation/auto", headers=admin).json() if r["tenantId"] == tenant["id"])
    return row


def test_refresh_writes_pages_keeps_notes_and_versions_only_changes(client, admin, tenant):
    enroll(client, admin, tenant, hostname="ACME-WS-01", serial="D1")
    add_m365(tenant["id"])
    first = client.post(f"/api/console/documentation/auto/{tenant['id']}/refresh", headers=admin).json()
    assert {r["page"] for r in first} == {"overview", "network", "microsoft-365", "devices"} and all(r["changed"] for r in first)
    ids = {r["page"]: r["articleId"] for r in first}

    with session_factory()() as db:
        devices = db.get(KbArticle, ids["devices"])
        assert "ACME-WS-01" in devices.body and devices.category == autodoc.CATEGORY
        assert "O365_BUSINESS_PREMIUM" in db.get(KbArticle, ids["microsoft-365"]).body
        devices.body += "Reception PC is on the UPS by the door."  # an engineer's note below the notes line
        db.commit()

    # Nothing changed in the environment: no page changes beyond restoring the generated part, notes kept.
    second = {r["page"]: r for r in client.post(f"/api/console/documentation/auto/{tenant['id']}/refresh", headers=admin).json()}
    assert not second["overview"]["changed"] and not second["network"]["changed"]
    with session_factory()() as db:
        assert db.query(DocumentRevision).filter_by(article_id=ids["overview"]).count() == 1

    enroll(client, admin, tenant, hostname="ACME-WS-02", serial="D2")
    third = {r["page"]: r for r in client.post(f"/api/console/documentation/auto/{tenant['id']}/refresh", headers=admin).json()}
    assert third["devices"]["changed"]
    with session_factory()() as db:
        body = db.get(KbArticle, ids["devices"]).body
        assert "ACME-WS-02" in body and body.rstrip().endswith("Reception PC is on the UPS by the door.")
        assert db.query(DocumentRevision).filter_by(article_id=ids["devices"]).count() >= 2
    assert len(pages(client, admin, tenant)["pages"]) == 4


def test_daily_refresh_only_for_customers_that_opted_in(client, admin, tenant):
    enroll(client, admin, tenant, hostname="ACME-WS-01", serial="D1")
    with session_factory()() as db:
        autodoc.tick(db)
        assert db.query(KbArticle).filter_by(tenant_id=tenant["id"]).count() == 0

    assert client.put(f"/api/console/documentation/auto/{tenant['id']}", json={"enabled": True}, headers=admin).json()["enabled"]
    with session_factory()() as db:
        autodoc.tick(db)
        assert db.query(KbArticle).filter_by(tenant_id=tenant["id"], category=autodoc.CATEGORY).count() == 4
        stamp = db.get(Tenant, tenant["id"]).settings["autoDocumentation"]["lastRefreshAt"]
        autodoc.tick(db)  # refreshed in the last day: not again
        assert db.get(Tenant, tenant["id"]).settings["autoDocumentation"]["lastRefreshAt"] == stamp
        row = db.get(Tenant, tenant["id"])
        row.settings = {**row.settings, "autoDocumentation": {"enabled": True, "lastRefreshAt": (utcnow() - timedelta(days=2)).isoformat()}}
        db.commit()
        autodoc.tick(db)
        assert db.get(Tenant, tenant["id"]).settings["autoDocumentation"]["lastRefreshAt"] != stamp
    assert pages(client, admin, tenant)["enabled"]
