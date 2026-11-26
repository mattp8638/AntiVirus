"""Suppliers (Fenrir third-party risk) linked to ISMS assets, risks and controls, and the ISMS review of SOC
incidents with its closure rules."""

import pytest
from conftest import login
from test_isms_soa import HALCYON, PW, person, programme

A = "/api/console/isms"


def make(model, **kw):
    from fenrir_cloud import db as database
    with database.session_factory()() as db:
        row = model(**kw)
        db.add(row)
        db.commit()
        return row.id


@pytest.fixture()
def ctx(client, admin, tenant):
    from fenrir_cloud.models import Incident, Vendor
    h = programme(client, admin, tenant, HALCYON)
    tid = tenant["id"]
    controls = {c["ref"]: c for c in client.get(f"{A}/controls?tenant_id={tid}", headers=h).json()["controls"]}
    vendor = make(Vendor, tenant_id=tid, name="Payroll Bureau", criticality="high", data_access="personal")
    incident = make(Incident, tenant_id=tid, title="Phishing led to mailbox access", severity="high", status="investigating")
    return h, tid, controls, vendor, incident


def test_supplier_links(client, admin, ctx):
    h, tid, controls, vendor, incident = ctx
    asset = client.post(f"{A}/assets", headers=h, json={"tenantId": tid, "name": "Payroll data", "type": "information",
                                                        "classification": "confidential"}).json()
    link = lambda **b: client.post(f"{A}/supplier-links", headers=h, json={"tenantId": tid, "vendorId": vendor, **b})  # noqa: E731
    assert link(type="device", targetId=asset["id"]).status_code == 400
    assert link(type="asset", targetId="nope").status_code == 404
    rows = link(type="asset", targetId=asset["id"]).json()["suppliers"]
    rows = link(type="control", targetId=controls["CC-SUP-01"]["id"]).json()["suppliers"] if "CC-SUP-01" in controls else rows
    link(type="asset", targetId=asset["id"])  # twice is fine
    s = next(x for x in rows if x["id"] == vendor)
    assert s["criticality"] == "high" and {lk["label"] for lk in s["links"]} >= {"Payroll data"}
    asset_link = next(lk for lk in s["links"] if lk["type"] == "asset")
    rows = client.delete(f"{A}/supplier-links/{asset_link['id']}", headers=h).json()["suppliers"]
    assert all(lk["type"] != "asset" for lk in next(x for x in rows if x["id"] == vendor)["links"])


def test_incident_review_and_closure_rules(client, admin, ctx):
    from fenrir_cloud import db as database
    from fenrir_cloud.models import Incident
    h, tid, controls, vendor, incident = ctx
    rows = client.get(f"{A}/incidents?tenant_id={tid}", headers=h).json()["incidents"]
    assert rows[0]["status"] == "not_started" and rows[0]["severity"] == "high"
    url = f"{A}/incidents/{incident}/review"
    assert client.put(url, headers=h, json={"category": "gossip"}).status_code == 400
    assert client.put(url, headers=h, json={"controlIds": ["itc_nope"]}).status_code == 400
    r = client.put(url, headers=h, json={"category": "phishing", "personalData": True, "vendorId": vendor,
                                         "controlIds": [controls["CC-IAM-02"]["id"]]}).json()
    assert r["vendorName"] == "Payroll Bureau" and r["controls"][0]["ref"] == "CC-IAM-02" and r["breachDeadline"]
    assert set(r["blockers"]) == {"Record the root cause.", "Record the lessons learned.",
                                  "Record when the breach was reported to the regulator, or lower the severity with a reason."}
    assert client.post(f"{url}/complete", headers=h).json()["detail"] == "The SOC must resolve the incident first."
    with database.session_factory()() as db:
        db.get(Incident, incident).status = "resolved"
        db.commit()
    assert "Record the root cause." in client.post(f"{url}/complete", headers=h).json()["detail"]
    client.put(url, headers=h, json={"category": "phishing", "personalData": True, "rootCause": "No MFA on one account",
                                     "lessonsLearned": "Enforce MFA everywhere", "reportedToAuthorityAt": "2026-11-20T10:00:00Z",
                                     "controlIds": [controls["CC-IAM-02"]["id"]]})
    done = client.post(f"{url}/complete", headers=h).json()
    assert done["status"] == "complete" and done["reportedToAuthorityAt"] == "2026-11-20T10:00:00.000Z"
    assert client.put(url, headers=h, json={"category": "other"}).status_code == 400
    assert client.post(f"{url}/reopen", headers=h).json()["status"] == "open"
    kim = person(client, admin, tid, "kim@acme.test", "control_owner")  # noqa: F841
    kh = login(client, "kim@acme.test", PW)
    assert client.get(f"{A}/incidents?tenant_id={tid}", headers=kh).status_code == 200
    assert client.put(url, headers=kh, json={"category": "other"}).status_code == 403


def test_isolation(client, admin, ctx):
    h, tid, controls, vendor, incident = ctx
    other = client.post("/api/console/tenants", json={"name": "Globex", "template": "balanced"}, headers=admin).json()
    person(client, admin, other["id"], "isms@globex.test", "isms_manager")
    g = login(client, "isms@globex.test", PW)
    assert client.put(f"{A}/incidents/{incident}/review", headers=g, json={"category": "other"}).status_code == 404
    assert client.post(f"{A}/supplier-links", headers=g, json={"tenantId": other["id"], "vendorId": vendor, "type": "asset",
                                                              "targetId": "x"}).status_code == 404
