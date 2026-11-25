"""M365-15: modelled Conditional Access evaluation and gap analysis from a configuration backup."""
from test_m365_config import URL, customer, graph, tenant_a  # noqa: F401  (graph is a fixture)
from fenrir_cloud import m365_ca_simulation as sim
from fenrir_cloud.models import AuditLog
from fenrir_cloud import db as database

GA = sim.GLOBAL_ADMIN


def policies():
    return [
        {"id": "p1", "displayName": "MFA for admins", "state": "enabled",
         "conditions": {"users": {"includeRoles": [GA]}, "applications": {"includeApplications": ["All"]}, "clientAppTypes": ["all"]},
         "grantControls": {"operator": "OR", "builtInControls": ["mfa"]}},
        {"id": "p2", "displayName": "Block legacy auth", "state": "enabledForReportingButNotEnforced",
         "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]},
                        "clientAppTypes": ["exchangeActiveSync", "other"]},
         "grantControls": {"operator": "OR", "builtInControls": ["block"]}},
        {"id": "p3", "displayName": "MFA outside office", "state": "enabled",
         "conditions": {"users": {"includeUsers": ["All"], "excludeUsers": ["GuestsOrExternalUsers"]},
                        "applications": {"includeApplications": ["Office365"]}, "clientAppTypes": ["browser", "mobileAppsAndDesktopClients"],
                        "locations": {"includeLocations": ["All"], "excludeLocations": ["lA1"]}},
         "grantControls": {"operator": "OR", "builtInControls": ["mfa", "compliantDevice"]}},
        {"id": "p4", "displayName": "Device filter policy", "state": "enabled",
         "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]}, "clientAppTypes": ["all"],
                        "devices": {"deviceFilter": {"mode": "include", "rule": "device.isCompliant -eq False"}}},
         "grantControls": {"operator": "OR", "builtInControls": ["passwordChange"]}},
    ]


def test_gap_analysis_is_modelled_and_keeps_inputs(client, admin, graph):
    tenants, writes = graph
    _, ca = customer(client, admin, "Alpha")
    t = tenant_a()
    t["policies"] = policies()
    tenants[ca["id"]] = t
    snap = client.post(f"{URL}/connections/{ca['id']}/snapshots", headers=admin).json()
    calls_before = len(writes)
    run = client.post(f"{URL}/snapshots/{snap['id']}/simulate", headers=admin, json={}).json()
    assert run["kind"] == "gap-analysis" and run["summary"]["kind"] == "modelled" and run["snapshotDigest"] == snap["digest"]
    assert len(writes) == calls_before  # nothing sent to the tenant
    r = {x["scenario"]: x for x in run["results"]}
    assert all(x["modelled"] for x in run["results"])
    assert r["admin"]["verdict"] == "pass"
    # Legacy authentication is only blocked by a report-only policy.
    assert r["legacy-auth"]["verdict"] == "gap" and "report-only" in r["legacy-auth"]["reason"]
    # Members outside the office: MFA OR a compliant device, so MFA is not guaranteed.
    assert r["member-untrusted"]["verdict"] == "gap" and "OR choice" in r["member-untrusted"]["reason"]
    assert r["guest"]["verdict"] == "gap" and r["risky-signin"]["verdict"] == "gap"
    # The device-filter policy cannot be evaluated from configuration: lower confidence, named.
    assert r["admin"]["confidence"] == "medium" and any("device filter" in u["uncertain"] for u in r["admin"]["uncertain"])
    assert set(run["summary"]["gaps"]) >= {"legacy-auth", "member-untrusted", "guest", "activesync", "security-info", "risky-signin"}
    listed = client.get(f"{URL}/connections/{ca['id']}/simulations", headers=admin).json()
    assert listed[0]["id"] == run["id"] and listed[0]["scenarios"][0]["key"] == "member-untrusted"
    with database.session_factory()() as db:
        assert db.query(AuditLog).filter_by(action="m365.ca_simulated").count() == 1


def test_what_if_named_location_and_exclusion(client, admin, graph):
    tenants, _ = graph
    _, ca = customer(client, admin, "Alpha")
    t = tenant_a()
    t["policies"] = policies()[2:3]
    tenants[ca["id"]] = t
    snap = client.post(f"{URL}/connections/{ca['id']}/snapshots", headers=admin).json()
    scenarios = [{"key": "office", "user": {"kind": "member", "groups": []}, "app": "Office365", "clientApp": "browser", "ip": "198.51.100.7"},
                 {"key": "home", "user": {"kind": "member", "groups": []}, "app": "Office365", "clientApp": "browser", "ip": "192.0.2.9"},
                 {"key": "guest", "user": {"kind": "guest", "groups": []}, "app": "Office365", "clientApp": "browser", "ip": "192.0.2.9"}]
    run = client.post(f"{URL}/snapshots/{snap['id']}/simulate", headers=admin, json={"scenarios": scenarios}).json()
    r = {x["scenario"]: x for x in run["results"]}
    assert run["kind"] == "what-if"
    assert r["office"]["outcome"] == "allowed without conditions" and "excluded" in r["office"]["notApplied"][0]["why"][0]
    assert r["home"]["outcome"] == "allowed with conditions" and r["home"]["requirements"][0]["controls"] == ["mfa", "compliantDevice"]
    assert r["guest"]["outcome"] == "allowed without conditions" and r["home"]["confidence"] == "high"
