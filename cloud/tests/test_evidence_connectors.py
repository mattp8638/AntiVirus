"""Continuous evidence connectors (GRC-11): GitHub and an HR roster feed controls; failures and stale data give no
verdict, never a pass; backups, the risk register and policy acknowledgement give signals of their own."""

from datetime import timedelta

import httpx

from fenrir_cloud import evidence_connectors as ec
from fenrir_cloud import grc_automation
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import GrcConnector, Tenant, utcnow


def gh_transport(protected: bool, alerts: int, fail: bool = False):
    def handle(req: httpx.Request) -> httpx.Response:
        if fail:
            return httpx.Response(401, text="Bad credentials")
        assert req.headers["Authorization"] == "Bearer ghp_test"
        p = req.url.path
        if p == "/orgs/acme/repos":
            return httpx.Response(200, json=[{"name": "api", "default_branch": "main"}, {"name": "old", "archived": True}])
        if p == "/repos/acme/api/branches/main/protection":
            return httpx.Response(200, json={"required_pull_request_reviews": {"required_approving_review_count": 1}}) if protected else httpx.Response(404)
        if p == "/orgs/acme/dependabot/alerts":
            return httpx.Response(200, json=[{"repository": {"name": "api"}}] * alerts)
        return httpx.Response(404)
    return httpx.Client(transport=httpx.MockTransport(handle))


def sig(db, tid, key):
    return grc_automation.signals(db, db.get(Tenant, tid))[key]


def test_github_and_hr_connectors_with_staleness(client, admin, tenant):
    tid = tenant["id"]
    assert client.post("/api/console/grc/connectors", headers=admin, json={"tenantId": tid, "kind": "github", "org": "acme"}).status_code == 400
    gh = client.post("/api/console/grc/connectors", headers=admin, json={"tenantId": tid, "kind": "github", "org": "acme", "token": "ghp_test"}).json()
    assert gh["hasSecret"] and "token" not in str(gh["config"])
    with session_factory()() as db:
        assert sig(db, tid, "dev-branch-protection")["passed"] is None, "never collected: no verdict"
        c = db.get(GrcConnector, gh["id"])
        ec.run(db, c, gh_transport(protected=False, alerts=2))
        db.commit()
        s = sig(db, tid, "dev-branch-protection")
        assert s["passed"] is False and any("acme/api" in e for e in s["evidence"])
        assert sig(db, tid, "dev-dependency-alerts")["passed"] is False
        ec.run(db, c, gh_transport(protected=True, alerts=0))
        db.commit()
        assert sig(db, tid, "dev-branch-protection")["passed"] is True and sig(db, tid, "dev-dependency-alerts")["passed"] is True
        # A failing collection, once the last success is too old, gives no verdict with the reason.
        c.last_success_at = utcnow() - timedelta(hours=30)
        ec.run(db, c, gh_transport(True, 0, fail=True))
        db.commit()
        s = sig(db, tid, "dev-branch-protection")
        assert s["passed"] is None and "failing" in s["evidence"][0] and "Bad credentials" in s["evidence"][0]
        control = next(x for x in grc_automation.status(db, db.get(Tenant, tid)) if x["id"] == "FC-SDLC")
        assert control["automated"] == "manual", "never shown as met from stale data"

    # HR roster: a leaver who still has an active account fails the account-lifecycle signal.
    client.post("/api/console/users", headers=admin, json={"email": "gone@acme.test", "password": "a-long-password-3", "name": "Gone",
                                                           "role": "client", "tenantId": tid})
    hr = client.post("/api/console/grc/connectors", headers=admin, json={"tenantId": tid, "kind": "hr_roster"}).json()
    r = client.post(f"/api/console/grc/connectors/{hr['id']}/roster", headers=admin,
                    json={"csv": "email,status,leave_date\nann@acme.test,active,\ngone@acme.test,leaver,2026-01-31\n"}).json()
    assert r["result"]["stillActive"] == ["gone@acme.test"] and r["problem"] is None
    with session_factory()() as db:
        s = sig(db, tid, "leavers-access-removed")
        assert s["passed"] is False and "gone@acme.test" in s["evidence"][1]


def test_backup_risk_and_acknowledgement_signals(client, admin, tenant):
    tid = tenant["id"]
    with session_factory()() as db:
        assert sig(db, tid, "backup-protection")["passed"] is None
        assert sig(db, tid, "risk-register")["passed"] is None
    client.post("/api/console/grc/registers/risk", headers=admin, json={"tenantId": tid, "title": "Supplier outage", "likelihood": 2, "impact": 3,
                                                                        "reviewDue": "2099-01-01"})
    with session_factory()() as db:
        assert sig(db, tid, "risk-register")["passed"] is True
    client.post("/api/console/grc/registers/risk", headers=admin, json={"tenantId": tid, "title": "Unscored", "reviewDue": "2000-01-01"})
    with session_factory()() as db:
        s = sig(db, tid, "risk-register")
        assert s["passed"] is False and any("overdue" in e for e in s["evidence"])
