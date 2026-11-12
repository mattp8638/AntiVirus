"""Email policies (versioned), mail flow rules, the safe body viewer, Explorer, campaigns and bulk actions."""
from datetime import timedelta

import pytest
from test_email_security import (  # noqa: F401
    BASE,
    CLEAN_HEADERS,
    PHISH_HEADERS,
    USER,
    _by_subject,
    _prepare,
    _protect,
    ctx,
    fresh_model_cache,
    mail,
    message,
    no_dns_lookups,
)

from fenrir_cloud import db as database
from fenrir_cloud import email_content
from fenrir_cloud import email_policy as ep
from fenrir_cloud import email_security as es
from fenrir_cloud.models import EmailContent, EmailListEntry, EmailScan, Tenant, utcnow

STANDARD = ep.PRESETS["standard"]


def policy(**changes):
    doc = ep.validate({**STANDARD, **changes})
    return doc


def decide(msg, doc=None, info=None, ctx_=None):
    result = es.analyse(msg, ctx_ or ctx())
    return ep.decide(msg, result, doc or policy(), {"gateway": False, "ownDomains": {"acme.co.uk"}, **(info or {})}), result


# --------------------------------------------------------------------------- the engine

def test_validation_explains_what_is_wrong():
    with pytest.raises(ep.PolicyError, match="suspicious score must be below"):
        ep.validate({"antispam": {"suspiciousScore": 60, "phishScore": 50}})
    with pytest.raises(ep.PolicyError, match="not an IP address"):
        ep.validate({"connection": {"ipBlock": ["nonsense"]}})
    with pytest.raises(ep.PolicyError, match="at least one condition"):
        ep.validate({"rules": [{"name": "Empty", "actions": [{"type": "quarantine"}]}]})
    with pytest.raises(ep.PolicyError, match="not allowed in rules"):
        ep.validate({"rules": [{"name": "Slow", "conditions": [{"field": "subject", "operator": "matches", "value": "(a+)+"}],
                                "actions": [{"type": "quarantine"}]}]})
    strict = ep.validate(ep.PRESETS["strict"])
    assert strict["antispam"]["phishScore"] == 40 and strict["antispam"]["actions"]["spam"] == "quarantine"


def test_mail_flow_rules_conditions_exceptions_order_and_stop():
    doc = policy(rules=[
        {"name": "Invoices from free mail", "priority": 1, "conditions": [{"field": "subject", "operator": "contains", "value": "invoice"},
                                                                          {"field": "senderDomain", "operator": "in", "value": "gmail.com, outlook.com"}],
         "exceptions": [{"field": "sender", "operator": "is", "value": "accounts@gmail.com"}],
         "actions": [{"type": "quarantine"}], "stop": True},
        {"name": "Never reached", "priority": 2, "conditions": [{"field": "subject", "operator": "contains", "value": "invoice"}],
         "actions": [{"type": "deliver"}]},
    ])
    decision, _ = decide(message(sender_address="billing@gmail.com", subject="Your invoice 123"), doc)
    assert decision["action"] == "quarantine" and decision["decidedBy"] == "Mail flow rule 'Invoices from free mail'"
    assert any("Stop processing" in t["detail"] for t in decision["trail"])
    assert not any("Never reached" in t["source"] for t in decision["trail"])
    excepted, _ = decide(message(sender_address="accounts@gmail.com", subject="Your invoice 123"), doc)
    assert "Invoices from free mail" not in excepted["decidedBy"]


def test_audit_mode_records_without_acting_and_bypass_never_skips_malware():
    doc = policy(rules=[{"name": "Trial", "mode": "audit", "conditions": [{"field": "subject", "operator": "contains", "value": "order"}],
                         "actions": [{"type": "quarantine"}]},
                        {"name": "Trust supplier", "conditions": [{"field": "senderDomain", "operator": "is", "value": "supplier.example"}],
                         "actions": [{"type": "bypass"}]}])
    decision, _ = decide(message(subject="Order dispatched"), doc)
    assert decision["action"] == "deliver" and decision["audit"][0]["rule"] == "Trial"
    malware, _ = decide(message(attachments=[{"name": "invoice.pdf.exe"}]), doc)
    assert malware["action"] == "quarantine" and malware["classification"] == "malware"


def test_antimalware_looks_inside_archives_and_flags_password_protected_ones():
    inside, _ = decide(message(attachments=[{"name": "docs.zip", "members": ["readme.txt", "setup.scr"]}]))
    assert inside["classification"] == "malware" and "inside docs.zip" in inside["trail"][-1]["detail"]
    locked, _ = decide(message(attachments=[{"name": "secure.zip", "members": ["a.pdf"], "encrypted": True}]))
    assert locked["action"] == "quarantine" and "password-protected" in locked["trail"][-1]["detail"]
    allowed = policy(antimalware={**STANDARD["antimalware"], "blockedTypes": ["exe"], "encryptedArchives": "deliver"})
    ok, _ = decide(message(attachments=[{"name": "secure.zip", "members": ["setup.scr"], "encrypted": True}]), allowed)
    assert ok["action"] == "deliver"


def test_thresholds_spoofing_and_reject_in_a_mailbox():
    decision, result = decide(message(sender_address="finance@acrne.co.uk", headers=dict(PHISH_HEADERS),
                                      subject="Bank details have changed"))
    assert result["microsoft"]["dmarcAction"] == "quarantine"
    assert decision["classification"] == "spoof" and decision["decidedBy"] == "Anti-phishing policy: spoofing"
    rejecting = policy(antiphish={**STANDARD["antiphish"], "actions": {"impersonation": "reject", "spoof": "reject"}})
    mailbox, _ = decide(message(sender_address="finance@acrne.co.uk", headers=dict(PHISH_HEADERS)), rejecting)
    assert mailbox["action"] == "quarantine"  # reject is only possible at the gateway
    gateway, _ = decide(message(sender_address="finance@acrne.co.uk", headers=dict(PHISH_HEADERS)), rejecting, {"gateway": True})
    assert gateway["action"] == "reject"
    tagged, _ = decide(message(body_html="<p>Your password will expire within 24 hours. Click here to sign in.</p>"))
    assert tagged["classification"] == "suspicious" and tagged["action"] == "tag" and tagged["tag"] == "[Suspicious]"


def test_lists_connection_filter_and_rule_actions():
    blocked, _ = decide(message(), info={"lists": {("block", "subject"): {"dispatched"}}})
    assert blocked["action"] == "quarantine" and blocked["decidedBy"] == "Block list"
    doc = policy(connection={"ipAllow": [], "ipBlock": ["198.51.100.0/24"]},
                 rules=[{"name": "Mark", "conditions": [{"field": "country", "operator": "is", "value": "GB"}],
                         "actions": [{"type": "addHeader", "value": "X-Fenrir-Region: uk"}, {"type": "score", "value": 30}]}])
    ip_blocked, _ = decide(message(), doc, {"gateway": True, "ip": "198.51.100.9"})
    assert ip_blocked["action"] == "reject" and ip_blocked["decidedBy"] == "Connection filter: blocked IP"
    scored, _ = decide(message(), doc, {"details": {"origin": {"country": "GB"}}})
    assert scored["headers"] == ["X-Fenrir-Region: uk"] and scored["scoreChange"] == 30 and scored["classification"] == "suspicious"


def test_the_safe_viewer_removes_active_content_and_highlights_the_reasons():
    html = ("<style>body{background:url(https://x)}</style><p onclick='x()'>Verify your account within 24 hours</p>"
            "<script>alert(1)</script><a href='http://198.51.100.20/login'>https://www.microsoft.com</a>"
            "<img src='https://track.example/p.gif' alt='logo'><iframe src='https://evil'></iframe><form><input></form>")
    safe = email_content.safe_html(html, {"198.51.100.20"})
    for bad in ("<script", "alert(1)", "onclick", "<style", "url(", "<iframe", "<img", "<form", "href="):
        assert bad not in safe, bad
    assert "<mark" in safe and "asks you to verify your account" in safe
    assert "fenrir-flag" in safe and "[→ http://198.51.100.20/login]" in safe and "[image: logo from track.example]" in safe


# --------------------------------------------------------------------------- versions through the API

def test_policies_are_versioned_inherited_compared_and_restored(client, admin, tenant):
    with database.session_factory()() as db:
        root = db.query(Tenant).filter(Tenant.parent_id.is_(None)).first().id
    first = client.get(f"{BASE}/policy/{tenant['id']}", headers=admin).json()
    assert first["effective"]["inherited"] and first["effective"]["version"] == 0 and first["versions"] == []
    msp = client.put(f"{BASE}/policy/{root}", json={"preset": "strict", "comment": "MSP default"}, headers=admin)
    assert msp.status_code == 200 and msp.json()["version"] == 1
    inherited = client.get(f"{BASE}/policy/{tenant['id']}", headers=admin).json()
    assert inherited["effective"]["inherited"] and inherited["document"]["antispam"]["phishScore"] == 40
    doc = {**inherited["document"], "antispam": {**inherited["document"]["antispam"], "phishScore": 55}}
    own = client.put(f"{BASE}/policy/{tenant['id']}", json={"document": doc, "comment": "Looser for Acme"}, headers=admin).json()
    assert own["version"] == 1
    bad = client.put(f"{BASE}/policy/{tenant['id']}", json={"document": {**doc, "antispam": {**doc["antispam"], "phishScore": 1}}}, headers=admin)
    assert bad.status_code == 400
    doc2 = {**doc, "antispam": {**doc["antispam"], "phishScore": 60}}
    client.put(f"{BASE}/policy/{tenant['id']}", json={"document": doc2, "comment": "Even looser"}, headers=admin)
    v2 = client.get(f"{BASE}/policy/{tenant['id']}/versions/2", headers=admin).json()
    assert {"path": "antispam.phishScore", "from": 55, "to": 60} in v2["changes"]
    restored = client.post(f"{BASE}/policy/{tenant['id']}/versions/1/restore", headers=admin).json()
    assert restored["version"] == 3 and restored["comment"] == "Restored version 1" and restored["document"]["antispam"]["phishScore"] == 55
    back = client.put(f"{BASE}/policy/{tenant['id']}", json={"inherit": True, "comment": "Follow the MSP"}, headers=admin).json()
    assert back["inherit"] and client.get(f"{BASE}/policy/{tenant['id']}", headers=admin).json()["document"]["antispam"]["phishScore"] == 40
    schema = client.get(f"{BASE}/policy-schema", headers=admin).json()
    assert "subject" in schema["fields"] and "quarantine" in schema["ruleActions"] and "standard" in schema["presets"]


# --------------------------------------------------------------------------- policies on real (mocked) mail

def test_a_rule_decides_in_the_mailbox_and_the_body_is_kept_and_shown_safely(client, admin, tenant, mail):  # noqa: F811 (pytest fixture)
    row = _prepare(client, admin, tenant, mail)
    doc = {**STANDARD, "rules": [{"name": "Hold order mail", "conditions": [{"field": "subject", "operator": "contains", "value": "order"}],
                                  "actions": [{"type": "quarantine"}]}]}
    assert client.put(f"{BASE}/policy/{tenant['id']}", json={"document": doc, "comment": "test rule"}, headers=admin).status_code == 200
    _protect(client, admin, row)
    client.post(f"{BASE}/connections/{row['id']}/scan", headers=admin)
    order = client.get(f"{BASE}/messages/{_by_subject(client, admin)['Order dispatched']['id']}", headers=admin).json()
    decision = order["details"]["decision"]
    assert decision["decidedBy"] == "Mail flow rule 'Hold order mail'" and decision["policy"]["version"] == 1
    assert order["action"] == "quarantine" and ("m1", "qfolder-1") in mail.moves
    with database.session_factory()() as db:
        assert db.query(EmailContent).filter_by(scan_id=order["id"]).count() == 1  # flagged by a rule: body kept, encrypted
        assert b"Track" not in str(db.query(EmailContent).filter_by(scan_id=order["id"]).one().envelope).encode()
    shown = client.get(f"{BASE}/messages/{order['id']}/content", headers=admin).json()
    assert shown["source"] == "kept" and "Track" in shown["text"]
    junk = _by_subject(client, admin)["Verify your account"]
    viewed = client.get(f"{BASE}/messages/{junk['id']}/content", headers=admin).json()
    assert viewed["source"] == "kept" and "<mark" in viewed["html"] and "<script" not in viewed["html"]
    tested = client.post(f"{BASE}/policy/test", json={"scanId": order["id"], "document": STANDARD}, headers=admin).json()
    assert tested["decision"]["action"] == "deliver" and tested["current"]["action"] == "quarantine"  # without the rule


def test_explorer_filters_and_csv_export(client, admin, tenant, mail):  # noqa: F811 (pytest fixture)
    row = _prepare(client, admin, tenant, mail)
    client.put(f"{BASE}/connections/{row['id']}", json={"mode": "shadow"}, headers=admin)
    client.post(f"{BASE}/connections/{row['id']}/scan", headers=admin)
    found = client.get(f"{BASE}/messages", params={"attachment": "remittance", "verdict": ""}, headers=admin).json()
    assert [m["subject"] for m in found] == ["Remittance advice"]
    assert [m["subject"] for m in client.get(f"{BASE}/messages", params={"sender": "acrne", "verdict": ""}, headers=admin).json()] == ["Verify your account"]
    assert [m["subject"] for m in client.get(f"{BASE}/messages", params={"ip": "81.2.69.160", "verdict": ""}, headers=admin).json()] == ["Verify your account"]
    by_class = client.get(f"{BASE}/messages", params={"classification": "malware", "verdict": ""}, headers=admin).json()
    assert [m["subject"] for m in by_class] == ["Remittance advice"]
    with database.session_factory()() as db:
        db.query(EmailScan).filter_by(message_id="m1").update({"subject": "=HYPERLINK(\"http://x\")"})
        db.commit()
    csv = client.get(f"{BASE}/messages.csv", params={"verdict": ""}, headers=admin)
    assert csv.status_code == 200 and csv.text.splitlines()[0].startswith("received_utc,mailbox,sender")
    assert "'=HYPERLINK" in csv.text  # spreadsheet formulas are neutralised


def test_campaigns_group_related_mail_and_purge_removes_it_everywhere(client, admin, tenant, mail):  # noqa: F811 (pytest fixture)
    row = _prepare(client, admin, tenant, mail)
    client.put(f"{BASE}/connections/{row['id']}", json={"mode": "shadow"}, headers=admin)
    client.post(f"{BASE}/connections/{row['id']}/scan", headers=admin)
    groups = client.get(f"{BASE}/campaigns", headers=admin).json()
    assert {g["senderDomain"] for g in groups} >= {"acrne.co.uk", "evil.example"}
    preview = client.post(f"{BASE}/campaigns/purge", json={"senderDomain": "evil.example"}, headers=admin).json()
    assert preview["matched"] == 1 and preview["mailboxes"] == ["jo@acme.co.uk"] and mail.moves == []
    done = client.post(f"{BASE}/campaigns/purge", json={"senderDomain": "evil.example", "preview": False}, headers=admin).json()
    assert done == {"done": 1, "failed": 0} and mail.moves == [("m2", "qfolder-1")]
    gone = client.post(f"{BASE}/campaigns/purge", json={"senderDomain": "evil.example", "preview": False, "action": "delete"},
                       headers=admin).json()
    assert gone["done"] == 1 and mail.deleted == ["m2-in-qfolder-1"]


def test_bulk_actions_label_block_and_delete(client, admin, tenant, mail):  # noqa: F811 (pytest fixture)
    row = _prepare(client, admin, tenant, mail)
    client.put(f"{BASE}/connections/{row['id']}", json={"mode": "shadow"}, headers=admin)
    client.post(f"{BASE}/connections/{row['id']}/scan", headers=admin)
    ids = [m["id"] for m in client.get(f"{BASE}/messages", params={"verdict": ""}, headers=admin).json()]
    labelled = client.post(f"{BASE}/messages/bulk", json={"ids": ids, "op": "label", "value": "phish"}, headers=admin).json()
    assert labelled == {"done": 3, "failed": []}
    blocked = client.post(f"{BASE}/messages/bulk", json={"ids": ids[:1], "op": "blockDomain"}, headers=admin).json()
    assert blocked["done"] == 1
    with database.session_factory()() as db:
        assert db.query(EmailListEntry).filter_by(kind="block", match="domain").count() == 1
    deleted = client.post(f"{BASE}/messages/bulk", json={"ids": ids[:1], "op": "delete"}, headers=admin).json()
    assert deleted["done"] == 1 and len(mail.deleted) == 1
    bad = client.post(f"{BASE}/messages/bulk", json={"ids": ["nope"], "op": "label", "value": "safe"}, headers=admin).json()
    assert bad["failed"][0]["error"] == "Not found"


def test_lists_take_ips_urls_hashes_subjects_and_expire(client, admin, tenant):
    for match, value in (("ip", "198.51.100.0/24"), ("url", "https://bad.example/x"), ("hash", "a" * 64), ("subject", "Gift card")):
        r = client.post(f"{BASE}/lists", json={"tenantId": tenant["id"], "kind": "block", "match": match, "value": value}, headers=admin)
        assert r.status_code == 200, r.text
    assert client.post(f"{BASE}/lists", json={"tenantId": tenant["id"], "kind": "block", "match": "hash", "value": "abc"},
                       headers=admin).status_code == 400
    past = (utcnow() - timedelta(days=1)).isoformat()
    client.post(f"{BASE}/lists", json={"tenantId": tenant["id"], "kind": "allow", "match": "domain", "value": "old.example",
                                       "expiresAt": past}, headers=admin)
    entries = {e["value"]: e for e in client.get(f"{BASE}/lists", headers=admin).json()}
    assert entries["bad.example"]["match"] == "url" and entries["gift card"]["match"] == "subject" and entries["old.example"]["expired"]
    from fenrir_cloud import email_scan

    with database.session_factory()() as db:
        lists = email_scan.list_entries(db, tenant["id"])
        assert "old.example" not in lists[("allow", "domain")] and "198.51.100.0/24" in lists[("block", "ip")]


def test_history_lists_rule_changes_one_by_one():
    from fenrir_cloud import email_policy

    old = {"rules": [{"id": "r1", "name": "Parcel scams", "mode": "audit"}, {"id": "r2", "name": "Old rule"}]}
    new = {"rules": [{"id": "r1", "name": "Parcel scams", "mode": "enforce"}, {"id": "r3", "name": "New rule"}]}
    changes = {c["path"]: (c["from"], c["to"]) for c in email_policy.diff(old, new)}
    assert changes == {"rules: Parcel scams.mode": ("audit", "enforce"), "rules: Old rule": ("present", "removed"),
                       "rules: New rule": (None, "added")}
