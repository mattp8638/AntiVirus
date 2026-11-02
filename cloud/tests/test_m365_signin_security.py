"""Sign-in protection: impossible travel, new country and password guessing that worked, with the playbook."""
from datetime import timedelta

import httpx
import pytest

from m365_fake import USER, FakeTenant
from test_msp_modules import connection
from fenrir_cloud import m365_signin_security as protection
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import Alert, M365Connection, M365LogEntry, Tenant, Ticket, utcnow

LONDON, NEW_YORK, MANCHESTER, PARIS = (51.5074, -0.1278), (40.7128, -74.0060), (53.4808, -2.2426), (48.8566, 2.3522)


@pytest.fixture
def fake(monkeypatch):
    tenant = FakeTenant()
    monkeypatch.setattr(httpx, "Client", tenant.client)
    return tenant


def signin(db, conn, at, where, country, ip, result="success", user="jo@acme.example"):
    db.add(M365LogEntry(tenant_id=conn["tenantId"], connection_id=conn["id"], kind="signin", external_id=f"s-{at.timestamp()}-{ip}-{result}",
                        at=at, actor=user, app="Office 365", ip=ip, location=f"{country} city", result=result,
                        details={"userId": USER, "country": country, "lat": where[0] if where else None, "lon": where[1] if where else None}))


def enable(client, admin, tenant, **extra):
    body = {"tenantId": tenant["id"], "enabled": True, **extra}
    response = client.put("/api/console/m365/signin-protection", headers=admin, json=body)
    assert response.status_code == 200, response.text


def run(conn, now):
    with session_factory()() as db:
        raised = protection.run_connection(db, db.get(M365Connection, conn["id"]), collect=False, now=now)
        db.commit()
        return raised


def test_london_then_new_york_two_hours_later_is_impossible_travel(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    enable(client, admin, tenant, playbook={"revokeSessions": True, "blockSignIn": True, "openTicket": True})
    now = utcnow()
    with session_factory()() as db:
        signin(db, conn, now - timedelta(hours=3), LONDON, "GB", "81.2.69.160")
        signin(db, conn, now - timedelta(hours=1), NEW_YORK, "US", "198.51.100.20")
        db.commit()
    assert run(conn, now) == 1
    with session_factory()() as db:
        alert = db.query(Alert).filter_by(rule_id="m365:impossible-travel").one()
        assert alert.severity == "high" and "km/h" in alert.details["summary"] and alert.details["speedKmh"] > 2000
        assert "signed out everywhere" in alert.details["actions"] and "sign-in blocked" in alert.details["actions"]
        assert db.query(Ticket).filter(Ticket.source == "m365-signin").count() == 1
    assert fake.users[USER]["accountEnabled"] is False
    assert any(p.endswith("/revokeSignInSessions") for m, p, _ in fake.requests if m == "POST")
    assert run(conn, now + timedelta(minutes=10)) == 0  # never raised twice


def test_plausible_journeys_and_ignored_networks_are_not_flagged(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    enable(client, admin, tenant, ignoreNetworks=["203.0.113.0/24"], newCountry=False)
    now = utcnow()
    with session_factory()() as db:
        signin(db, conn, now - timedelta(hours=4), LONDON, "GB", "81.2.69.160")
        signin(db, conn, now - timedelta(hours=1), MANCHESTER, "GB", "81.2.69.200")  # 260 km in 3 h
        signin(db, conn, now - timedelta(minutes=50), NEW_YORK, "US", "203.0.113.9")  # the company VPN's exit
        db.commit()
    assert run(conn, now) == 0


def test_new_country_needs_history_and_respects_trusted_countries(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    enable(client, admin, tenant, trustedCountries=["FR"], playbook={"revokeSessions": False, "openTicket": False})
    now = utcnow()
    with session_factory()() as db:
        for day in range(20, 40, 2):
            signin(db, conn, now - timedelta(days=day), LONDON, "GB", "81.2.69.160")
        signin(db, conn, now - timedelta(minutes=30), PARIS, "FR", "192.0.2.10")  # trusted
        signin(db, conn, now - timedelta(minutes=20), None, "BR", "192.0.2.77")  # Brazil: never seen
        signin(db, conn, now - timedelta(minutes=10), None, "BR", "192.0.2.77", user="newstarter@acme.example")
        db.commit()
    assert run(conn, now) == 1
    with session_factory()() as db:
        alert = db.query(Alert).filter_by(rule_id="m365:new-country").one()
        assert alert.details["country"] == "BR" and alert.details["usual"] == ["GB"] and alert.details["actions"] == []


def test_success_after_many_failures(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    enable(client, admin, tenant, newCountry=False, sprayFailures=10)
    now = utcnow()
    with session_factory()() as db:
        for i in range(12):
            signin(db, conn, now - timedelta(minutes=40 - i), None, "RU", f"45.0.0.{i}", result="failure")
        signin(db, conn, now - timedelta(minutes=20), None, "RU", "45.0.0.99")
        db.commit()
    assert run(conn, now) == 1
    with session_factory()() as db:
        assert db.query(Alert).filter_by(rule_id="m365:spray-success").one().details["failures"] == 12


def test_settings_are_validated_and_findings_listed(client, admin, tenant, fake):
    connection(client, admin, tenant)
    bad = client.put("/api/console/m365/signin-protection", headers=admin, json={"tenantId": tenant["id"], "trustedCountries": ["Britain"]})
    assert bad.status_code == 422
    bad = client.put("/api/console/m365/signin-protection", headers=admin, json={"tenantId": tenant["id"], "ignoreNetworks": ["the office"]})
    assert bad.status_code == 422
    enable(client, admin, tenant, trustedCountries=["gb"], ignoreNetworks=["81.2.69.0/24"])
    data = client.get("/api/console/m365/signin-protection", headers=admin, params={"tenant_id": tenant["id"]}).json()
    assert data["settings"]["trustedCountries"] == ["GB"] and data["settings"]["enabled"] and data["findings"] == []


def test_distance():
    assert 5500 < protection.distance_km(LONDON, NEW_YORK) < 5650


def test_a_synced_user_is_signed_out_but_left_to_ad_for_the_block(client, admin, tenant, fake):
    conn = connection(client, admin, tenant)
    fake.users[USER]["onPremisesSyncEnabled"] = True
    enable(client, admin, tenant, playbook={"revokeSessions": True, "blockSignIn": True, "openTicket": False})
    now = utcnow()
    with session_factory()() as db:
        signin(db, conn, now - timedelta(hours=3), LONDON, "GB", "81.2.69.160")
        signin(db, conn, now - timedelta(hours=1), NEW_YORK, "US", "198.51.100.20")
        db.commit()
    assert run(conn, now) == 1
    with session_factory()() as db:
        actions = db.query(Alert).filter_by(rule_id="m365:impossible-travel").one().details["actions"]
    assert "signed out everywhere" in actions and any("synced from Active Directory" in a for a in actions)
    assert fake.users[USER]["accountEnabled"] is True
