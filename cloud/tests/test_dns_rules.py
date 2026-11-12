"""DNS rules and lists, per-device results, the query explorer and the Fenrir DNS ruleset."""
import dns.message
import pytest

from conftest import enroll, login

BASE = "/api/console/dns"


def lookup(client, device, name, qtype="A"):
    from fenrir_cloud.db import session_factory
    from fenrir_cloud.models import Device

    with session_factory()() as db:
        token = db.get(Device, device["deviceId"]).dns_token
    wire = dns.message.make_query(name, qtype).to_wire()
    response = client.post(f"/dns/{token}/dns-query", content=wire, headers={"Content-Type": "application/dns-message"})
    assert response.status_code == 200, response.text
    return response.headers.get("X-Fenrir-Dns-Action"), response.headers.get("X-Fenrir-Dns-Reason", "")


@pytest.fixture(autouse=True)
def offline_upstream(monkeypatch):
    """Allowed lookups would go to the real upstream resolver: answer them locally."""
    from fenrir_cloud import dnsfilter

    def fake_forward(wire, upstream, client=None):
        query = dns.message.from_wire(wire)
        return dns.message.make_response(query).to_wire()

    monkeypatch.setattr(dnsfilter, "forward", fake_forward)


def rule(client, admin, tenant, **body):
    response = client.post(f"{BASE}/rules", json={"tenantId": tenant["id"], **body}, headers=admin)
    assert response.status_code == 200, response.text
    return response.json()


def test_rules_validate_and_decide_in_scope_order(client, admin, tenant, device):
    for bad, message in (({"patterns": ["not a domain!"]}, "not a domain"),
                         ({"match": "regex", "patterns": ["(a+)+$"]}, "not allowed"),
                         ({"match": "category", "patterns": ["cats"]}, "unknown category"),
                         ({"scopeType": "device", "scopeIds": ["dev_nope"], "patterns": ["x.example"]}, "not found"),
                         ({"schedule": {"days": [9], "start": "09:00", "end": "17:00"}, "patterns": ["x.example"]}, "Monday")):
        response = client.post(f"{BASE}/rules", json={"tenantId": tenant["id"], **bad}, headers=admin)
        assert response.status_code == 422 and message in response.text, (bad, response.text)

    blocked = rule(client, admin, tenant, kind="entry", action="block", patterns=["social.example"])
    assert lookup(client, device, "www.social.example")[0] == "block"
    # A device-specific allow wins over the customer-wide block (the closest scope decides).
    rule(client, admin, tenant, kind="entry", action="allow", patterns=["social.example"], scopeType="device", scopeIds=[device["deviceId"]])
    action, reason = lookup(client, device, "www.social.example")
    assert action == "allow"
    other = enroll(client, admin, tenant, hostname="ACME-WS-02", serial="SN-2")
    assert lookup(client, other, "www.social.example")[0] == "block"

    # Wildcards, regular expressions and query types.
    rule(client, admin, tenant, name="Ad servers", match="wildcard", patterns=["ads*.cdn.example"], action="block")
    assert lookup(client, device, "ads42.cdn.example")[0] == "block"
    assert lookup(client, device, "img.cdn.example")[0] == "allow"
    rule(client, admin, tenant, name="No TXT tunnels", match="regex", patterns=[r"^[a-z0-9]{30,}\.tunnel\.example$"], qtypes=["TXT"])
    long_name = "a" * 32 + ".tunnel.example"
    assert lookup(client, device, long_name, "TXT")[0] == "block"
    assert lookup(client, device, long_name, "A")[0] == "allow"

    # Audit mode records without blocking; the query is logged as monitored with the rule.
    audit = rule(client, admin, tenant, name="Try: block news", patterns=["news.example"], mode="audit")
    assert lookup(client, device, "news.example")[0] == "allow"
    logged = client.get(f"{BASE}/queries", params={"tenant_id": tenant["id"], "q": "news.example"}, headers=admin).json()
    assert logged and logged[0]["action"] == "monitor" and logged[0]["ruleId"] == audit["id"]
    blocked_rows = client.get(f"{BASE}/queries", params={"tenant_id": tenant["id"], "action": "block", "q": "social"}, headers=admin).json()
    assert blocked_rows[0]["source"] == "entry" and blocked_rows[0]["ruleId"] == blocked["id"] and blocked_rows[0]["hostname"] == "ACME-WS-02"

    # A schedule outside its window does nothing.
    rule(client, admin, tenant, name="Never", patterns=["schedule.example"], schedule={"days": [0], "start": "00:00", "end": "00:00"},
         priority=1)
    from fenrir_cloud.dns_rules import CACHE
    from fenrir_cloud.models import utcnow

    if not (utcnow().weekday() == 0 and utcnow().strftime("%H:%M") == "00:00"):
        assert lookup(client, device, "schedule.example")[0] == "allow"
    CACHE.invalidate()

    # Hit counts are written to the rule.
    from fenrir_cloud import dns_rules
    from fenrir_cloud.db import session_factory

    with session_factory()() as db:
        dns_rules.flush_hits(db, force=True)
        db.commit()
    listed = {r["id"]: r for r in client.get(f"{BASE}/rules", params={"tenant_id": tenant["id"]}, headers=admin).json()}
    assert listed[blocked["id"]]["hits"] >= 2


def test_explain_shows_every_step(client, admin, tenant, device):
    rule(client, admin, tenant, name="Watch", patterns=["watch.example"], mode="audit")
    rule(client, admin, tenant, kind="entry", action="block", patterns=["watch.example"], priority=200)
    result = client.get(f"{BASE}/explain", params={"domain": "https://sub.watch.example/path", "device_id": device["deviceId"]},
                        headers=admin).json()
    assert result["domain"] == "sub.watch.example" and result["action"] == "block" and result["source"] == "entry"
    assert any("audit only" in step for step in result["trail"]) and result["audits"][0]["name"] == "Watch"
    assert "ruleset" in result


def test_history_restore_import_and_quick_entries(client, admin, tenant, device):
    created = rule(client, admin, tenant, name="v1", patterns=["one.example"])
    updated = client.put(f"{BASE}/rules/{created['id']}", json={"name": "v2", "patterns": ["two.example"], "changeComment": "wider"},
                         headers=admin).json()
    assert updated["version"] == 2
    history = client.get(f"{BASE}/rules/{created['id']}/history", headers=admin).json()
    assert [h["version"] for h in history] == [2, 1] and history[0]["comment"] == "wider"
    assert {c["field"] for c in history[0]["changes"]} == {"name", "patterns"}
    restored = client.post(f"{BASE}/rules/{created['id']}/restore/1", headers=admin).json()
    assert restored["name"] == "v1" and restored["version"] == 3
    assert client.delete(f"{BASE}/rules/{created['id']}", headers=admin).status_code == 200
    back = client.post(f"{BASE}/rules/{created['id']}/restore/3", headers=admin)
    assert back.status_code == 200 and back.json()["patterns"] == ["one.example"]

    imported = client.post(f"{BASE}/rules/import", json={"tenantId": tenant["id"], "action": "block", "expiresAt": "2099-01-01",
                                                         "text": "# comment\n0.0.0.0 bad1.example\nbad2.example\nbad2.example\nnot valid!"},
                           headers=admin).json()
    assert imported["created"] == 2 and imported["skipped"] == 1 and len(imported["errors"]) == 1
    quick = client.post(f"{BASE}/quick", json={"deviceId": device["deviceId"], "domain": "bad1.example", "action": "allow", "scope": "device"},
                        headers=admin).json()
    assert quick["scopeType"] == "device" and quick["scopeNames"] == ["ACME-WS-01"]
    assert lookup(client, device, "bad1.example")[0] == "allow"
    assert lookup(client, device, "bad2.example")[0] == "block"


def test_msp_wide_rules_and_customer_isolation(client, admin, tenant, device):
    root = client.get("/api/console/auth/me", headers=admin).json()["user"]["tenantId"]
    msp_rule = client.post(f"{BASE}/rules", json={"tenantId": root, "kind": "entry", "action": "block", "patterns": ["everyone.example"]},
                           headers=admin).json()
    assert lookup(client, device, "everyone.example")[0] == "block"
    other = client.post("/api/console/tenants", json={"name": "Other Co", "template": "balanced"}, headers=admin).json()
    client.post("/api/console/users", json={"email": "ta@acme.test", "name": "T", "role": "tenant_admin", "tenantId": tenant["id"],
                                            "password": "a-long-enough-password-1"}, headers=admin)
    customer = login(client, "ta@acme.test", "a-long-enough-password-1")
    own = client.post(f"{BASE}/rules", json={"tenantId": tenant["id"], "kind": "entry", "patterns": ["mine.example"]}, headers=customer)
    assert own.status_code == 200
    rules = client.get(f"{BASE}/rules", headers=customer).json()
    by_id = {r["id"]: r for r in rules}
    assert by_id[msp_rule["id"]]["mspWide"] and not by_id[msp_rule["id"]]["editable"]
    assert client.put(f"{BASE}/rules/{msp_rule['id']}", json={"enabled": False}, headers=customer).status_code == 404
    assert client.post(f"{BASE}/rules", json={"tenantId": other["id"], "patterns": ["x.example"]}, headers=customer).status_code in (403, 404)
    other_rule = client.post(f"{BASE}/rules", json={"tenantId": other["id"], "kind": "entry", "patterns": ["theirs.example"]}, headers=admin).json()
    assert other_rule["id"] not in {r["id"] for r in client.get(f"{BASE}/rules", headers=customer).json()}
    assert client.get(f"{BASE}/rules/{other_rule['id']}/history", headers=customer).status_code == 404
    other_device = enroll(client, admin, other, hostname="OTHER-1", serial="SN-9")
    assert client.get(f"{BASE}/devices/{other_device['deviceId']}", headers=customer).status_code in (403, 404)
    assert other_device["deviceId"] not in {d["id"] for d in client.get(f"{BASE}/devices", headers=customer).json()}


def test_per_device_results_overview_and_csv(client, admin, tenant, device):
    rule(client, admin, tenant, kind="entry", action="block", patterns=["=cmd.example"[1:], "evil.example"])
    for name in ("evil.example", "www.evil.example", "fine.example"):
        lookup(client, device, name)
    from fenrir_cloud.db import session_factory
    from fenrir_cloud.models import Event, utcnow

    with session_factory()() as db:
        db.add(Event(tenant_id=tenant["id"], device_id=device["deviceId"], event_id="e1", event_type="dns.proxy.rule_applied",
                     summary="Windows now sends DNS lookups to the Fenrir DNS proxy", occurred_at=utcnow()))
        db.commit()
    devices = {d["id"]: d for d in client.get(f"{BASE}/devices", params={"tenant_id": tenant["id"]}, headers=admin).json()}
    row = devices[device["deviceId"]]
    assert row["queriesToday"] == 3 and row["blockedToday"] == 2 and row["proxy"]["state"] == "on"
    detail = client.get(f"{BASE}/devices/{device['deviceId']}", headers=admin).json()
    assert detail["daily"][-1]["blocked"] == 2 and detail["topBlocked"][0][0] in ("evil.example", "www.evil.example")
    assert detail["proxy"]["state"] == "on" and any(r["kind"] == "entry" for r in detail["rules"])
    overview = client.get(f"{BASE}/overview", params={"tenant_id": tenant["id"]}, headers=admin).json()
    assert overview["queries"] == 3 and overview["blocked"] == 2 and overview["topDevices"][0]["hostname"] == "ACME-WS-01"
    assert dict(overview["bySource"])["entry"] == 2
    csv_text = client.get(f"{BASE}/queries.csv", params={"tenant_id": tenant["id"]}, headers=admin).text
    assert "evil.example" in csv_text and csv_text.splitlines()[0].startswith("time,device,domain")


def test_fenrir_ruleset_scores_agreement_and_blocks(client, admin, tenant, device):
    from fenrir_cloud import blocklists
    from fenrir_cloud.db import session_factory

    with session_factory()() as db:
        blocklists.ensure_builtin(db)
        for key, raw in (("hagezi-tif-mini", "phish.example\nonly-mini.example\nmicrosoft.com\n"),
                         ("hagezi-pro", "phish.example\ntracker.example\n"), ("oisd-big", "tracker.example\nonly-oisd.example\n")):
            row = db.get(blocklists.DnsBlocklist, key)
            blocklists.store(db, row, raw)
            row.enabled = key == "hagezi-tif-mini"  # the ads lists feed the ruleset only when given a weight
        db.commit()
    blocklists.CACHE.invalidate()
    weights = client.put(f"{BASE}/ruleset/config", json={"weights": {"hagezi-pro": 30, "oisd-big": 30}}, headers=admin)
    assert weights.status_code == 200, weights.text
    assert client.post(f"{BASE}/ruleset/build", headers=admin).status_code == 200
    state = client.get(f"{BASE}/ruleset", headers=admin).json()
    assert not state["building"] and not state["buildError"], state
    build = state["builds"][0]
    assert build["active"] and build["version"] == 1
    # phish: mini 50 + pro 30 = 80 (blocks); tracker: pro 30 + oisd 30 = 60 (blocks where ads are blocked);
    # only-mini: 50 (monitor band); only-oisd: 30 (below monitor, not kept); microsoft.com is protected.
    assert build["stats"]["domains"] == 3 and build["stats"]["blocking"] == 2 and build["stats"]["protectedSkipped"] == 1
    explained = client.get(f"{BASE}/ruleset/explain", params={"domain": "login.phish.example"}, headers=admin).json()
    assert explained["active"]["score"] == 80 and {s["source"] for s in explained["sources"]} == {"hagezi-tif-mini", "hagezi-pro"}
    assert client.get(f"{BASE}/ruleset/explain", params={"domain": "microsoft.com"}, headers=admin).json()["protected"]

    from fenrir_cloud import dns_ruleset

    dns_ruleset.CACHE.invalidate()
    # Lists only through the ruleset: a single-list domain stops being blocked, agreed domains still are.
    policy = client.get("/api/console/policies", headers=admin).json()
    target = next(p for p in policy if p.get("tenantId") == tenant["id"]) if any(p.get("tenantId") == tenant["id"] for p in policy) else policy[0]
    response = client.put(f"/api/console/policies/{target['id']}", json={**target, "settings": {**target.get("settings", {}),
                          "dns": {**target.get("settings", {}).get("dns", {}), "externalLists": "ruleset", "fenrirRuleset": "block"}}},
                          headers=admin)
    assert response.status_code == 200, response.text
    action, reason = lookup(client, device, "phish.example")
    assert action == "block" and reason.startswith("Fenrir ruleset v1")
    assert lookup(client, device, "only-mini.example")[0] == "allow"
    rows = client.get(f"{BASE}/queries", params={"tenant_id": tenant["id"], "q": "only-mini"}, headers=admin).json()
    assert rows and rows[0]["action"] == "monitor"

    # A second build reports what changed; an earlier build can be made active again.
    with session_factory()() as db:
        blocklists.store(db, db.get(blocklists.DnsBlocklist, "hagezi-pro"), "phish.example\ntracker.example\nnew.example\nonly-mini.example\n")
        db.commit()
    blocklists.CACHE.invalidate()
    client.post(f"{BASE}/ruleset/build", headers=admin)
    second = client.get(f"{BASE}/ruleset", headers=admin).json()["builds"][0]
    assert second["version"] == 2 and second["diff"]["previousVersion"] == 1
    assert client.post(f"{BASE}/ruleset/1/activate", headers=admin).status_code == 200
    assert next(b for b in client.get(f"{BASE}/ruleset", headers=admin).json()["builds"] if b["version"] == 1)["active"]
