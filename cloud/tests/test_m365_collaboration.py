"""Teams, SharePoint and OneDrive against the fake tenant: teams with ownership issues, sites, sharing standards and
the OneDrive hand-over in offboarding."""
import httpx
import pytest

from m365_fake import USER, FakeTenant
from test_msp_modules import connection
from test_m365_lifecycle import plan, run
from test_m365_baseline_standards import assign
from fenrir_cloud import m365_standards
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import M365Connection, Tenant, Ticket


@pytest.fixture
def fake(monkeypatch):
    tenant = FakeTenant()
    monkeypatch.setattr(httpx, "Client", tenant.client)
    monkeypatch.setattr(m365_standards, "http_client", lambda: tenant.client())
    return tenant


def test_teams_sites_and_sharing(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    base = f"/api/console/m365/connections/{conn['id']}/collaboration"
    teams = client.get(base + "/teams", headers=admin).json()
    assert teams[0]["name"] == "Orphan team" and teams[0]["issue"].startswith("no owner")
    assert teams[1]["owners"] == ["max@acme.example"] and teams[1]["issue"] == "one owner"
    sites = client.get(base + "/sites", headers=admin).json()
    assert sites[0]["url"].endswith("/sites/sales") and sites[0]["storageGB"] == 5.0
    assert client.get(base + "/sharing", headers=admin).json()["label"].startswith("Anyone")


def test_sharing_standards_fix_and_verify(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    with session_factory()() as db:
        row = db.get(M365Connection, conn["id"])
        assert m365_standards.evaluate(row, "sharing.no-anyone-links")["status"] == "drifted"
        assign(db, tenant["id"], {"sharing.no-anyone-links": "remediate", "sharing.no-guest-resharing": "alert"})
        m365_standards.run_for_tenant(db, db.get(Tenant, tenant["id"]))
        db.commit()
        assert fake.sharepoint["sharingCapability"] == "externalUserSharingOnly"
        assert fake.sharepoint["isResharingByExternalUsersEnabled"] is True  # alert mode: untouched
        assert db.query(Ticket).filter(Ticket.source == "m365-standards").count() == 1


def test_offboarding_shares_the_leavers_onedrive(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    flow = plan(client, admin, conn, "offboard", {"onedriveDelegate": "max@acme.example", "markContact": False}, USER).json()
    assert any(s["key"] == "onedrive_handover" for s in flow["steps"])
    done = run(client, admin, flow)["workflow"]
    assert done["status"] == "completed", done["steps"]
    step = next(s for s in done["steps"] if s["key"] == "onedrive_handover")
    assert "acme-my.sharepoint.com" in step["result"]
    assert fake.onedrive_shares[0][1]["recipients"] == [{"email": "max@acme.example"}] and fake.onedrive_shares[0][1]["roles"] == ["write"]
