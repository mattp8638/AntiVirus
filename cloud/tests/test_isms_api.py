"""The ISMS through Fenrir's API credentials (read-only, "grc" scope) and ISMS events through webhooks."""

from conftest import login
from fenrir_cloud import db as database
from fenrir_cloud.models import PlatformEvent
from sqlalchemy import select
from test_api_credentials import bearer, create
from test_documentation_vault import stepup
from test_isms_soa import HALCYON, PW, programme

A = "/api/console/isms"


def test_api_credentials_read_the_isms_and_change_nothing(client, admin, tenant):
    h = programme(client, admin, tenant, HALCYON)
    tid = tenant["id"]
    grc = bearer(create(client, stepup(client, admin), tid, ["read", "grc"]).json()["token"])
    plain = bearer(create(client, stepup(client, admin), tid, ["read"]).json()["token"])
    assert client.get(f"{A}/soa?tenant_id={tid}&framework=iso27001", headers=grc).status_code == 200
    assert client.get(f"{A}/controls?tenant_id={tid}", headers=grc).status_code == 200
    assert client.get(f"{A}/me?tenant_id={tid}", headers=grc).json()["role"] == "api_reader"
    assert client.get(f"{A}/soa?tenant_id={tid}&framework=iso27001", headers=plain).status_code == 403
    # Read-only: no writes, whatever the endpoint.
    assert client.post(f"{A}/risks", headers=grc, json={"tenantId": tid, "title": "From the API"}).status_code == 403
    control = client.get(f"{A}/controls?tenant_id={tid}", headers=h).json()["controls"][0]
    assert client.patch(f"{A}/controls/{control['id']}", headers=grc, json={"state": "implemented"}).status_code == 403
    assert client.post(f"{A}/nonconformities", headers=grc, json={"tenantId": tid, "title": "x y z", "source": "other", "severity": "minor"}).status_code == 403
    # The role cannot be given to a person.
    me = client.get("/api/console/auth/me", headers=h).json()
    uid = (me.get("user") or me)["id"]
    assert client.put(f"{A}/memberships", headers=admin, json={"tenantId": tid, "userId": uid, "role": "api_reader"}).status_code == 400
    # Another customer is out of reach.
    other = client.post("/api/console/tenants", json={"name": "Globex", "template": "balanced"}, headers=admin).json()
    assert client.get(f"{A}/controls?tenant_id={other['id']}", headers=grc).status_code in (403, 404)


def test_isms_events_reach_webhooks(client, admin, tenant):
    h = programme(client, admin, tenant, HALCYON)
    tid = tenant["id"]
    hook = client.post("/api/console/webhooks", headers=admin, json={"url": "https://hooks.example/isms", "tenantId": tid,
                                                                     "events": ["isms.nonconformity_raised", "isms.nonconformity_closed"]})
    assert hook.status_code == 200, hook.text
    nc = client.post(f"{A}/nonconformities", headers=h, json={"tenantId": tid, "kind": "opportunity", "title": "Automate reviews",
                                                             "source": "monitoring", "description": "Secret detail"}).json()
    client.post(f"{A}/nonconformities/{nc['id']}/close", headers=h, json={"outcome": "closed", "note": "Done in Entra"})
    client.post(f"{A}/objectives", headers=h, json={"tenantId": tid, "title": "Patch fast", "measure": "Days", "direction": "at_most", "target": 14})
    with database.session_factory()() as db:
        rows = db.execute(select(PlatformEvent).where(PlatformEvent.type == "webhook.delivery")).scalars().all()
    sent = [(r.payload["event"], r.payload["body"]) for r in rows]
    assert [e for e, _ in sent] == ["isms.nonconformity_raised", "isms.nonconformity_closed"]
    raised = sent[0][1]
    assert raised["ref"] == "OFI-001" and raised["tenantId"] == tid and "Secret detail" not in str(sent)
    assert sent[1][1]["outcome"] == "closed"
