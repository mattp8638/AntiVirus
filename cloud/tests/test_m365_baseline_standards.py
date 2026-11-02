"""Directory and Exchange baseline standards: evaluate, alert on drift, remediate, verify (fake tenant)."""
import httpx
import pytest

from m365_fake import FakeTenant
from test_msp_modules import connection
from fenrir_cloud import m365_standards
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import M365Connection, Tenant, Ticket


@pytest.fixture
def fake(monkeypatch):
    tenant = FakeTenant()
    monkeypatch.setattr(httpx, "Client", tenant.client)
    monkeypatch.setattr(m365_standards, "http_client", lambda: tenant.client())
    return tenant


def assign(db, tenant_id, standards: dict):
    row = db.get(Tenant, tenant_id)
    row.settings = {**(row.settings or {}), "m365Standards": {k: {"mode": m} for k, m in standards.items()}}
    db.commit()


def test_directory_and_exchange_standards(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    with session_factory()() as db:
        row = db.get(M365Connection, conn["id"])
        for key in m365_standards.AUTHZ:
            assert m365_standards.evaluate(row, key)["status"] == "drifted"
        assert m365_standards.evaluate(row, "exo.mailbox-auditing")["status"] == "compliant"
        assert m365_standards.evaluate(row, "exo.unified-audit-log")["status"] == "drifted"

        # Alert mode opens one ticket per drifted standard; remediate mode fixes and the next check passes.
        assign(db, tenant["id"], {"users.no-app-consent": "alert", "guests.restricted": "remediate",
                                  "exo.no-external-forwarding": "remediate"})
        results = {r["standard"]: r["status"] for r in m365_standards.run_for_tenant(db, db.get(Tenant, tenant["id"]))}
        db.commit()
        assert results == {"users.no-app-consent": "drifted", "guests.restricted": "drifted", "exo.no-external-forwarding": "drifted"}
        assert db.query(Ticket).filter(Ticket.source == "m365-standards").count() == 1
        assert fake.authz["guestUserRoleId"] == m365_standards.RESTRICTED_GUEST_ROLE
        assert fake.exo_org["Get-HostedOutboundSpamFilterPolicy"]["AutoForwardingMode"] == "Off"
        assert m365_standards.evaluate(row, "guests.restricted")["status"] == "compliant"
        assert m365_standards.evaluate(row, "exo.no-external-forwarding")["status"] == "compliant"
        # The alerted one is untouched: the consent setting still allows user consent.
        assert fake.authz["defaultUserRolePermissions"]["permissionGrantPoliciesAssigned"]


def test_standards_without_exchange_access_report_unknown(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    fake.exo_denied = True
    with session_factory()() as db:
        assign(db, tenant["id"], {"exo.smtp-auth-off": "remediate"})
        [result] = m365_standards.run_for_tenant(db, db.get(Tenant, tenant["id"]))
        assert result["status"] == "unknown"
    assert conn
