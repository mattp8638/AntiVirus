"""Email security in shadow mode: Fenrir's verdict next to Microsoft's (email_security.py, email_scan.py)."""
import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, unquote, urlparse

import httpx
import pytest

from m365_fake import REAL_CLIENT, token
from test_msp_modules import connection
from fenrir_cloud import db as database, email_scan, email_security as es, m365_permissions
from fenrir_cloud.models import EmailScan, EmailScanSetting, Indicator, M365Connection, utcnow

PHISH_HEADERS = {
    "x-forefront-antispam-report": "CIP:81.2.69.160;CTRY:RU;LANG:en;SCL:5;SRV:;IPV:NLI;SFV:SPM;H:mx;CAT:PHSH;SFS:(1);DIR:INB;",
    "x-microsoft-antispam": "BCL:0;",
    "authentication-results": "spf=fail (sender IP is 203.0.113.9) smtp.mailfrom=acrne.co.uk; dkim=none (message not signed) "
                              "header.d=none;dmarc=fail action=quarantine header.from=acrne.co.uk;compauth=fail reason=000",
}
CLEAN_HEADERS = {
    "x-forefront-antispam-report": "CIP:198.51.100.1;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:mx;CAT:NONE;DIR:INB;",
    "x-microsoft-antispam": "BCL:0;",
    "authentication-results": "spf=pass smtp.mailfrom=supplier.example; dkim=pass header.d=supplier.example;"
                              "dmarc=pass action=none header.from=supplier.example;compauth=pass reason=100",
}


def ctx(**extra):
    base = dict(own_domains={"acme.co.uk"}, people={"jo leaver": "jo@acme.co.uk"}, known_senders={"supplier.example"})
    base.update(extra)
    return es.Context(**base)


def message(**extra):
    base = dict(mailbox="jo@acme.co.uk", folder="inbox", sender_address="accounts@supplier.example", sender_name="Supplier Ltd",
                reply_to=[], subject="Order 1234 dispatched", headers=dict(CLEAN_HEADERS),
                body_html="<p>Your order has shipped. <a href='https://supplier.example/track/1234'>Track it</a></p>",
                attachments=[])
    base.update(extra)
    return es.Message(**base)


# --------------------------------------------------------------------------- engine

def test_microsoft_verdict_is_read_from_its_headers():
    phish = es.microsoft_verdict(PHISH_HEADERS, "inbox")
    assert phish["verdict"] == "phish" and phish["scl"] == 5 and phish["cat"] == "PHSH"
    assert (phish["spf"], phish["dkim"], phish["dmarc"], phish["compauth"]) == ("fail", "none", "fail", "fail")
    assert es.microsoft_verdict(CLEAN_HEADERS, "inbox")["verdict"] == "clean"
    assert es.microsoft_verdict({"x-forefront-antispam-report": "SCL:6;SFV:SPM;CAT:SPM;"}, "inbox")["verdict"] == "spam"
    assert es.microsoft_verdict({"x-forefront-antispam-report": "SCL:1;CAT:BULK;"}, "inbox")["verdict"] == "bulk"
    assert es.microsoft_verdict({"x-forefront-antispam-report": "CAT:MALW;"}, "inbox")["verdict"] == "malware"
    assert es.microsoft_verdict({}, "inbox")["verdict"] == "unknown"
    assert es.microsoft_verdict({}, "junkemail")["verdict"] == "spam"


def test_an_ordinary_message_from_a_known_supplier_is_clean():
    result = es.analyse(message(), ctx())
    assert result["verdict"] == "clean" and result["score"] == 0 and result["reasons"] == []
    assert result["microsoft"]["verdict"] == "clean" and result["link_domains"] == ["supplier.example"]


def test_a_lookalike_invoice_scam_is_phish_and_says_why():
    result = es.analyse(message(
        sender_address="finance@acrne.co.uk", sender_name="Acme Finance", headers=dict(PHISH_HEADERS),
        subject="Urgent action required: bank details have changed",
        body_html="<p>Please update your payment details within 24 hours.</p>"
                  "<a href='http://198.51.100.20/login'>https://www.acme.co.uk/portal</a>"), ctx())
    codes = {r["code"] for r in result["reasons"]}
    assert result["verdict"] == "phish" and result["score"] >= es.HIGH_AT
    assert {"lookalike.own", "auth.dmarc", "link.mismatch", "link.ip", "language.scam"} <= codes
    assert result["reasons"] == sorted(result["reasons"], key=lambda r: -r["points"])
    assert any("imitates your domain acme.co.uk" in r["detail"] for r in result["reasons"])
    assert es.agreement(result["verdict"], result["microsoft"]["verdict"]) == "both"


def test_threat_intel_links_and_known_malware_attachments():
    linked = es.analyse(message(body_html="<a href='https://bad.example/x'>Open</a>"),
                        ctx(bad_domains={"bad.example": "phishing"}))
    assert linked["verdict"] == "phish" and linked["reasons"][0]["code"] == "intel.url"
    sha = "a" * 64
    attached = es.analyse(message(attachments=[{"name": "statement.pdf", "sha256": sha}]), ctx(bad_hashes={sha: "Emotet"}))
    assert attached["verdict"] == "malware" and "Emotet" in attached["reasons"][0]["detail"]
    allowed = es.analyse(message(body_html="<a href='https://bad.example/x'>Open</a>"),
                         ctx(bad_domains={"bad.example": "phishing"}, allowed_domains={"bad.example"}))
    assert allowed["verdict"] == "clean"


def test_dangerous_attachments_and_a_colleagues_name_from_gmail():
    result = es.analyse(message(sender_address="jo.leaver.work@gmail.com", sender_name="Jo Leaver",
                                attachments=[{"name": "invoice.pdf.exe"}]), ctx())
    codes = {r["code"] for r in result["reasons"]}
    assert {"impersonation.colleague", "impersonation.free-mail", "attachment.executable", "attachment.double-extension"} <= codes
    assert result["verdict"] == "malware"
    html = es.analyse(message(attachments=[{"name": "Remittance.html"}]), ctx())
    assert html["verdict"] == "suspicious" and html["reasons"][0]["code"] == "attachment.web-page"


def test_microsofts_own_domains_and_real_brands_are_not_lookalikes():
    assert es.lookalike_of("contoso.onmicrosoft.com", es.BRANDS) is None
    assert es.lookalike_of("login.microsoftonline.com", es.BRANDS) is None
    assert es.lookalike_of("email.docusign.net", es.BRANDS) is None
    assert es.lookalike_of("offices.com", es.BRANDS) is None  # a real business name, one letter from "office"
    assert es.lookalike_of("rnicrosoft.com", es.BRANDS) == "microsoft.com"
    assert es.lookalike_of("micorsoft.com", es.BRANDS) == "microsoft.com"
    assert es.lookalike_of("paypal-secure.net", es.BRANDS) == "paypal.com"
    real = es.analyse(message(sender_address="no-reply@email.docusign.net", sender_name="DocuSign",
                              body_html="<a href='https://na3.docusign.net/sign'>Review document</a>"), ctx())
    assert real["verdict"] == "clean"


def test_agreement_buckets():
    assert es.agreement("phish", "phish") == "both"
    assert es.agreement("malware", "clean") == "fenrir_only"
    assert es.agreement("suspicious", "phish") == "microsoft_only"
    assert es.agreement("clean", "spam") == "neither"


def test_the_permission_catalogue_asks_for_mail_read_on_app_connections_only():
    feature = m365_permissions.FEATURES["email.security"]
    assert feature["app"] == ["Mail.Read", "User.Read.All"] and feature["delegated"] is None
    assert "Mail.Read" in m365_permissions.APP_PERMISSIONS and "Mail.Read" not in m365_permissions.DELEGATED_PERMISSIONS


# --------------------------------------------------------------------------- scanning through Microsoft Graph (mocked)

USER = "00000000-0000-0000-0000-0000000000a1"
NOW = datetime.now(timezone.utc)


def iso(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


class FakeMail:
    """Just enough of Microsoft Graph's mail API: one mailbox with messages in Inbox and Junk Email."""

    def __init__(self):
        exe = b"MZ fake program"
        self.exe_sha = hashlib.sha256(exe).hexdigest()
        self.denied = False
        self.calls = []
        self.folders = {
            "inbox": [
                {"id": "m1", "internetMessageId": "<m1@supplier.example>", "receivedDateTime": iso(NOW - timedelta(hours=2)),
                 "subject": "Order dispatched", "from": {"emailAddress": {"address": "accounts@supplier.example", "name": "Supplier"}},
                 "replyTo": [], "hasAttachments": False, "internetMessageHeaders": [{"name": k, "value": v} for k, v in CLEAN_HEADERS.items()],
                 "body": {"content": "<a href='https://supplier.example/t'>Track</a>"}},
                {"id": "m2", "internetMessageId": "<m2@evil.example>", "receivedDateTime": iso(NOW - timedelta(hours=1)),
                 "subject": "Remittance advice", "from": {"emailAddress": {"address": "pay@evil.example", "name": "Payments"}},
                 "replyTo": [], "hasAttachments": True, "internetMessageHeaders": [{"name": k, "value": v} for k, v in CLEAN_HEADERS.items()],
                 "body": {"content": "<p>See attached.</p>"}},
            ],
            "junkemail": [
                {"id": "m3", "internetMessageId": "<m3@acrne.co.uk>", "receivedDateTime": iso(NOW - timedelta(minutes=30)),
                 "subject": "Verify your account", "from": {"emailAddress": {"address": "it@acrne.co.uk", "name": "IT Support"}},
                 "replyTo": [], "hasAttachments": False, "internetMessageHeaders": [{"name": k, "value": v} for k, v in PHISH_HEADERS.items()],
                 "body": {"content": "<p>Verify your account within 24 hours</p><a href='https://acrne.co.uk/login'>https://acme.co.uk</a>"}},
            ],
        }
        self.moves: list[tuple[str, str]] = []  # (message id, destination)
        self.patches: list[tuple[str, dict]] = []
        self.write_denied = False
        self.hidden_folders: dict[str, str] = {}
        self.attachment = {"@odata.type": "#microsoft.graph.fileAttachment", "id": "att1", "name": "Remittance.pdf.exe",
                           "contentType": "application/octet-stream", "size": len(exe), "isInline": False,
                           "contentBytes": base64.b64encode(exe).decode()}

    def client(self, **kwargs):
        return REAL_CLIENT(transport=httpx.MockTransport(self.handle))

    def handle(self, request):
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": token(["Mail.Read", "User.Read.All"])})
        path = unquote(request.url.path).removeprefix("/v1.0")
        self.calls.append(path)
        if self.denied:
            return httpx.Response(403, json={"error": {"code": "ErrorAccessDenied", "message": "Access is denied."}})
        parts = path.strip("/").split("/")
        if request.method in ("POST", "PATCH") and self.write_denied and parts[-1] != "mailFolders":
            return httpx.Response(403, json={"error": {"code": "ErrorAccessDenied", "message": "Access is denied."}})
        if parts[:2] == ["users", USER] and parts[2:] == ["mailFolders"]:
            if request.method == "POST":
                body = json.loads(request.content)
                assert body["isHidden"] is True
                self.hidden_folders[body["displayName"]] = "qfolder-1"
                return httpx.Response(201, json={"id": "qfolder-1", "displayName": body["displayName"]})
            assert request.url.params.get("includeHiddenFolders") == "true"
            return httpx.Response(200, json={"value": [{"id": v, "displayName": k} for k, v in self.hidden_folders.items()]})
        if parts[:2] == ["users", USER] and parts[2] == "messages" and len(parts) == 5 and parts[4] == "permanentDelete":
            self.deleted = getattr(self, "deleted", []) + [parts[3]]
            return httpx.Response(204)
        if parts[:2] == ["users", USER] and parts[2] == "messages" and len(parts) == 4 and request.method == "GET":
            return httpx.Response(200, json={"id": parts[3], "body": {"contentType": "html", "content":
                "<p>Please verify your account within 24 hours</p><script>alert(1)</script>"
                "<a href='http://198.51.100.20/login' onclick='x()'>https://www.microsoft.com</a><img src='https://track.example/p.gif'>"}})
        if parts[:2] == ["users", USER] and parts[2] == "messages" and len(parts) == 5 and parts[4] == "move":
            destination = json.loads(request.content)["destinationId"]
            self.moves.append((parts[3], destination))
            return httpx.Response(201, json={"id": f"{parts[3]}-in-{destination}"})
        if parts[:2] == ["users", USER] and parts[2] == "messages" and len(parts) == 4 and request.method == "PATCH":
            self.patches.append((parts[3], json.loads(request.content)))
            return httpx.Response(200, json={"id": parts[3]})
        if parts[:2] == ["users", USER] and parts[2] == "mailFolders" and parts[4] == "messages":
            query = {k: v[0] for k, v in parse_qs(urlparse(str(request.url)).query).items()}
            since = datetime.fromisoformat(query["$filter"].split(" ge ")[1].replace("Z", "+00:00"))
            rows = [m for m in self.folders[parts[3]] if datetime.fromisoformat(m["receivedDateTime"].replace("Z", "+00:00")) >= since]
            return httpx.Response(200, json={"value": rows})
        if parts[:2] == ["users", USER] and parts[2] == "messages" and parts[-1] == "$value":
            return httpx.Response(200, content=b"From: pay@evil.example\r\nSubject: Remittance advice\r\n\r\nSee attached.",
                                  headers={"Content-Type": "message/rfc822"})
        if parts[:2] == ["users", USER] and parts[2] == "messages" and parts[4] == "attachments":
            if len(parts) == 5:
                return httpx.Response(200, json={"value": [{k: v for k, v in self.attachment.items() if k != "contentBytes"}]})
            return httpx.Response(200, json=self.attachment)
        return httpx.Response(404, json={"error": {"code": "NotFound", "message": "no"}})


@pytest.fixture
def mail(monkeypatch):
    fake = FakeMail()
    monkeypatch.setattr(httpx, "Client", fake.client)
    return fake


def _prepare(client, admin, tenant, mail):
    row = connection(client, admin, tenant)
    with database.session_factory()() as db:
        conn = db.get(M365Connection, row["id"])
        conn.snapshot = {"users": [{"id": USER, "displayName": "Jo Leaver", "mail": "jo@acme.co.uk", "userPrincipalName": "jo@acme.co.uk",
                                    "accountEnabled": True, "userType": "Member", "assignedLicenses": [{"skuId": "x"}]},
                                   {"id": "nolicence", "displayName": "Old Account", "mail": "old@acme.co.uk", "accountEnabled": True,
                                    "userType": "Member", "assignedLicenses": []}],
                         "domains": [{"id": "acme.co.uk", "isVerified": True}]}
        db.add(Indicator(tenant_id=None, type="sha256", value=mail.exe_sha, verdict="malicious", category="AgentTesla", source="test"))
        db.commit()
    return row


def test_shadow_mode_scans_compares_and_never_changes_the_mailbox(client, admin, tenant, mail):
    row = _prepare(client, admin, tenant, mail)
    base = "/api/console/email-security"
    listed = client.get(base + "/connections", headers=admin).json()
    assert listed[0]["mode"] == "off" and listed[0]["mailboxes"] == 1 and listed[0]["supported"]
    assert client.post(f"{base}/connections/{row['id']}/scan", headers=admin).status_code == 409  # not on yet

    on = client.put(f"{base}/connections/{row['id']}", json={"mode": "shadow", "retentionDays": 30}, headers=admin)
    assert on.status_code == 200 and on.json()["mode"] == "shadow" and on.json()["retentionDays"] == 30
    first = client.post(f"{base}/connections/{row['id']}/scan", headers=admin).json()
    assert first["stored"] == 3 and first["error"] == ""
    assert all(not c.endswith(("/move", "/send")) for c in mail.calls)  # reads only

    msgs = {m["subject"]: m for m in client.get(base + "/messages", headers=admin).json()}
    assert msgs["Order dispatched"]["verdict"] == "clean" and msgs["Order dispatched"]["agreement"] == "neither"
    remittance = msgs["Remittance advice"]
    assert remittance["verdict"] == "malware" and remittance["microsoftVerdict"] == "clean" and remittance["agreement"] == "fenrir_only"
    junk = msgs["Verify your account"]
    assert junk["microsoftVerdict"] == "phish" and junk["verdict"] == "phish" and junk["agreement"] == "both" and junk["folder"] == "junkemail"

    detail = client.get(f"{base}/messages/{remittance['id']}", headers=admin).json()
    assert detail["attachmentDetails"][0]["sha256"] == mail.exe_sha
    assert any("AgentTesla" in r["detail"] for r in detail["reasons"])
    with database.session_factory()() as db:
        stored = db.query(EmailScan).filter_by(message_id="m2").one()
        assert "See attached" not in json.dumps({c.name: str(getattr(stored, c.name)) for c in EmailScan.__table__.columns})

    again = client.post(f"{base}/connections/{row['id']}/scan", headers=admin).json()
    assert again["stored"] == 0  # the overlap window does not store messages twice

    labelled = client.put(f"{base}/messages/{remittance['id']}/label", json={"label": "malware"}, headers=admin).json()
    assert labelled["label"] == "malware" and labelled["labelledBy"]
    overview = client.get(base + "/overview", headers=admin).json()
    assert overview["scanned"] == 3 and overview["fenrirFlagged"] == 2 and overview["microsoftFlagged"] == 1
    assert overview["both"] == 1 and overview["fenrirOnly"] == 1 and overview["agreementPercent"] == 50
    assert overview["labelled"] == 1 and overview["labelledFenrirRight"] == 1 and overview["labelledMicrosoftRight"] == 0
    only = client.get(base + "/messages", params={"agreement": "fenrir_only"}, headers=admin).json()
    assert [m["subject"] for m in only] == ["Remittance advice"]


def test_missing_mail_permission_is_explained_and_gdap_is_refused(client, admin, tenant, mail):
    row = _prepare(client, admin, tenant, mail)
    base = "/api/console/email-security"
    client.put(f"{base}/connections/{row['id']}", json={"mode": "shadow"}, headers=admin)
    mail.denied = True
    result = client.post(f"{base}/connections/{row['id']}/scan", headers=admin).json()
    assert result["stored"] == 0 and "Mail.Read" in result["error"]
    assert "Mail.Read" in client.get(base + "/connections", headers=admin).json()[0]["lastError"]

    with database.session_factory()() as db:
        db.get(M365Connection, row["id"]).auth_mode = "gdap"
        db.commit()
    refused = client.put(f"{base}/connections/{row['id']}", json={"mode": "shadow"}, headers=admin)
    assert refused.status_code == 409 and "GDAP" in refused.json()["detail"]


def test_retention_removes_old_scans(client, admin, tenant, mail):
    row = _prepare(client, admin, tenant, mail)
    client.put(f"/api/console/email-security/connections/{row['id']}", json={"mode": "shadow", "retentionDays": 7}, headers=admin)
    client.post(f"/api/console/email-security/connections/{row['id']}/scan", headers=admin)
    with database.session_factory()() as db:
        db.query(EmailScan).filter_by(message_id="m1").update({"received_at": utcnow() - timedelta(days=8)})
        db.commit()
        assert email_scan.purge(db) == 1
        assert db.query(EmailScan).count() == 2
        assert db.query(EmailScanSetting).one().retention_days == 7


def test_the_background_pass_scans_every_customer_in_shadow_mode(client, admin, tenant, mail):
    row = _prepare(client, admin, tenant, mail)
    client.put(f"/api/console/email-security/connections/{row['id']}", json={"mode": "shadow"}, headers=admin)
    from fenrir_cloud.main import _run_job

    with database.session_factory()() as db:
        assert _run_job(db, "email.shadow-scan", email_scan.tick)
        assert db.query(EmailScan).count() == 3
        setting = db.query(EmailScanSetting).one()
        assert setting.last_scanned == 3 and setting.last_error == "" and setting.last_run_at is not None



# --------------------------------------------------------------------------- phase 2: protect mode

from fenrir_cloud import email_actions  # noqa: E402
from fenrir_cloud.models import Alert, EmailListEntry  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_model_cache():
    """The active model is cached per process for a minute; each test has its own database, so start clean."""
    from fenrir_cloud import email_model

    email_model.forget_cache()
    yield
    email_model.forget_cache()


@pytest.fixture(autouse=True)
def no_dns_lookups(monkeypatch):
    """IP evidence (reverse DNS, ASN) comes from DNS; tests use fixed answers instead of the network."""
    from fenrir_cloud import email_forensics

    email_forensics._ip_cache.clear()
    monkeypatch.setattr(email_forensics, "_lookups", lambda ip: {"ptr": "mail.example.net", "asn": "64500",
                                                                  "network": "203.0.113.0/24", "owner": "EXAMPLE-NET", "country": "GB"})

BASE = "/api/console/email-security"


def _protect(client, admin, row, **body):
    """Turn protect mode on, as if three hours ago, so the fake mailbox's messages count as new."""
    response = client.put(f"{BASE}/connections/{row['id']}", json={"mode": "protect", **body}, headers=admin)
    assert response.status_code == 200, response.text
    with database.session_factory()() as db:
        db.query(EmailScanSetting).update({"protect_since": utcnow() - timedelta(hours=3)})
        db.commit()
    return response.json()


def _by_subject(client, admin):
    return {m["subject"]: m for m in client.get(BASE + "/messages", params={"verdict": ""}, headers=admin).json()}


def test_protect_mode_quarantines_threats_tags_suspicious_and_reports_once(client, admin, tenant, mail):
    row = _prepare(client, admin, tenant, mail)
    view = _protect(client, admin, row)
    assert view["mode"] == "protect" and view["actions"] == {"malware": "quarantine", "phish": "quarantine", "suspicious": "tag"}
    assert client.post(f"{BASE}/connections/{row['id']}/scan", headers=admin).json()["error"] == ""

    assert mail.hidden_folders == {"Fenrir Quarantine": "qfolder-1"}
    assert sorted(mail.moves) == [("m2", "qfolder-1"), ("m3", "qfolder-1")]  # malware (inbox) and phish (junk)
    msgs = _by_subject(client, admin)
    assert msgs["Remittance advice"]["action"] == "quarantine" and msgs["Remittance advice"]["actionStatus"] == "done"
    assert msgs["Order dispatched"]["action"] == "" and msgs["Order dispatched"]["actionStatus"] == ""
    with database.session_factory()() as db:
        alerts = db.query(Alert).filter(Alert.rule_id.like("email:%")).all()
        assert len(alerts) == 1 and alerts[0].severity == "high" and "quarantined 2 messages" in alerts[0].title
        assert "Remittance advice" in alerts[0].details["summary"]
    overview = client.get(BASE + "/overview", headers=admin).json()
    assert overview["quarantined"] == 2 and overview["releaseRequests"] == 0


def test_suspicious_mail_is_tagged_and_old_mail_is_never_touched(client, admin, tenant, mail):
    row = _prepare(client, admin, tenant, mail)
    mail.folders["inbox"][0]["subject"] = "Your password will expire"  # scam wording only: suspicious, not phish
    mail.folders["inbox"][0]["body"] = {"content": "<p>Your password will expire within 24 hours. Click here to sign in.</p>"}
    client.put(f"{BASE}/connections/{row['id']}", json={"mode": "protect"}, headers=admin)
    with database.session_factory()() as db:  # protect mode started 90 minutes ago: m1 (two hours old) is older
        db.query(EmailScanSetting).update({"protect_since": utcnow() - timedelta(minutes=90)})
        db.commit()
    client.post(f"{BASE}/connections/{row['id']}/scan", headers=admin)
    msgs = _by_subject(client, admin)
    old = msgs["Your password will expire"]
    assert old["verdict"] == "suspicious" and old["action"] == ""  # received before protect mode started
    assert [m for m, _ in mail.moves] == ["m2", "m3"]

    mail.folders["inbox"].append({**mail.folders["inbox"][0], "id": "m5", "receivedDateTime": iso(NOW - timedelta(minutes=5)),
                                  "categories": ["Blue"]})
    client.post(f"{BASE}/connections/{row['id']}/scan", headers=admin)
    assert mail.patches == [("m5", {"categories": ["Blue", "Fenrir: suspicious"]})]


def test_release_brings_mail_back_and_can_allow_the_sender(client, admin, tenant, mail):
    row = _prepare(client, admin, tenant, mail)
    _protect(client, admin, row)
    client.post(f"{BASE}/connections/{row['id']}/scan", headers=admin)
    scan = _by_subject(client, admin)["Remittance advice"]
    released = client.post(f"{BASE}/messages/{scan['id']}/release", json={"allowSender": True}, headers=admin).json()
    assert released["actionStatus"] == "released" and released["releasedBy"]
    assert mail.moves[-1] == ("m2-in-qfolder-1", "inbox")  # the moved copy's new id goes back to the Inbox
    again = client.post(f"{BASE}/messages/{scan['id']}/release", json={}, headers=admin)
    assert again.status_code == 409
    entries = client.get(BASE + "/lists", headers=admin).json()
    assert [(e["kind"], e["match"], e["value"]) for e in entries] == [("allow", "sender", "pay@evil.example")]
    with database.session_factory()() as db:  # the sender is now allowed: its next message is clean
        conn = db.get(M365Connection, row["id"])
        ctx = email_scan.build_context(db, conn, email_scan.load_intel(db))
        result = es.analyse(message(sender_address="pay@evil.example", attachments=[{"name": "invoice.pdf.exe"}]), ctx)
        assert result["verdict"] == "clean" and result["reasons"][0]["code"] == "list.allow"
        forged = es.analyse(message(sender_address="pay@evil.example", headers=dict(PHISH_HEADERS)), ctx)
        assert forged["verdict"] != "clean"  # an allow-listed sender that fails DMARC is not trusted


def test_block_list_and_list_api(client, admin, tenant, mail):
    row = _prepare(client, admin, tenant, mail)
    bad = client.post(BASE + "/lists", json={"tenantId": tenant["id"], "kind": "block", "match": "domain", "value": "not a domain"}, headers=admin)
    assert bad.status_code == 400
    entry = client.post(BASE + "/lists", json={"tenantId": tenant["id"], "kind": "block", "match": "domain",
                                               "value": "@Supplier.Example", "note": "test"}, headers=admin).json()
    assert entry["value"] == "supplier.example"
    client.put(f"{BASE}/connections/{row['id']}", json={"mode": "shadow"}, headers=admin)
    client.post(f"{BASE}/connections/{row['id']}/scan", headers=admin)
    order = _by_subject(client, admin)["Order dispatched"]
    assert order["verdict"] == "phish" and "block list" in order["topReason"]
    assert client.delete(f"{BASE}/lists/{entry['id']}", headers=admin).json() == {"ok": True}
    assert client.get(BASE + "/lists", headers=admin).json() == []


def test_the_brake_stops_mass_quarantine_and_asks_a_person(client, admin, tenant, mail, monkeypatch):
    monkeypatch.setattr(email_actions, "BRAKE", 1)
    row = _prepare(client, admin, tenant, mail)
    _protect(client, admin, row)
    client.post(f"{BASE}/connections/{row['id']}/scan", headers=admin)
    assert len(mail.moves) == 1  # the second threat was recorded but not moved
    view = client.get(BASE + "/connections", headers=admin).json()[0]
    assert "Paused automatically" in view["pausedReason"]
    with database.session_factory()() as db:
        assert db.query(Alert).filter_by(rule_id="email:brake").count() == 1
    resumed = client.put(f"{BASE}/connections/{row['id']}", json={"mode": "protect"}, headers=admin).json()
    assert resumed["pausedReason"] == ""


def test_missing_write_permission_is_recorded_on_the_message(client, admin, tenant, mail):
    row = _prepare(client, admin, tenant, mail)
    mail.write_denied = True
    _protect(client, admin, row)
    client.post(f"{BASE}/connections/{row['id']}/scan", headers=admin)
    scan = _by_subject(client, admin)["Remittance advice"]
    detail = client.get(f"{BASE}/messages/{scan['id']}", headers=admin).json()
    assert detail["actionStatus"] == "failed" and "Mail.ReadWrite" in detail["actionError"]
    assert client.get(BASE + "/overview", headers=admin).json()["actionFailures"] == 2


def test_users_ask_for_a_message_back_through_a_button_not_a_link(client, admin, tenant, mail):
    row = _prepare(client, admin, tenant, mail)
    _protect(client, admin, row)
    client.post(f"{BASE}/connections/{row['id']}/scan", headers=admin)
    scan = _by_subject(client, admin)["Remittance advice"]
    link = email_actions.release_link(scan["id"])
    path = urlparse(link).path + "?" + urlparse(link).query
    page = client.get(path)
    assert page.status_code == 200 and "Ask IT to release it" in page.text and "pay@evil.example" in page.text
    assert _by_subject(client, admin)["Remittance advice"]["actionStatus"] == "done"  # opening the link changed nothing
    assert client.get(f"/api/public/email-release/{scan['id']}?t=wrong").status_code == 404
    assert client.post(f"/api/public/email-release/{scan['id']}?t=wrong").status_code == 404
    done = client.post(path)
    assert done.status_code == 200 and "Request sent" in done.text
    assert _by_subject(client, admin)["Remittance advice"]["actionStatus"] == "release_requested"
    with database.session_factory()() as db:
        assert db.query(Alert).filter_by(rule_id="email:release-request").count() == 1
    released = client.post(f"{BASE}/messages/{scan['id']}/release", json={}, headers=admin)
    assert released.status_code == 200 and released.json()["actionStatus"] == "released"


def test_daily_digest_lists_held_mail_with_release_links(client, admin, tenant, mail, monkeypatch):
    from fenrir_cloud import mailer

    sent = []
    monkeypatch.setattr(mailer, "configured", lambda: True)
    monkeypatch.setattr(mailer, "send", lambda to, subject, body, **kw: sent.append((to, subject, body, kw.get("html"))) or "<id>")
    row = _prepare(client, admin, tenant, mail)
    _protect(client, admin, row, notify={"digest": True, "alertEmail": "soc@msp.example"})
    client.post(f"{BASE}/connections/{row['id']}/scan", headers=admin)
    digests = [s for s in sent if s[0] == "jo@acme.co.uk"]
    assert len(digests) == 1 and digests[0][1] == "Messages held back for you (2)"
    assert "/api/public/email-release/" in digests[0][2] and "Remittance advice" in digests[0][3]
    assert any(s[0] == "soc@msp.example" and "quarantined 2" in s[1] for s in sent)
    client.post(f"{BASE}/connections/{row['id']}/scan", headers=admin)
    assert len([s for s in sent if s[0] == "jo@acme.co.uk"]) == 1  # once a day


def test_new_intel_rescans_recent_mail_and_quarantines_it(client, admin, tenant, mail):
    row = _prepare(client, admin, tenant, mail)
    _protect(client, admin, row)
    client.post(f"{BASE}/connections/{row['id']}/scan", headers=admin)
    assert _by_subject(client, admin)["Order dispatched"]["verdict"] == "clean"
    with database.session_factory()() as db:
        db.add(Indicator(tenant_id=None, type="domain", value="supplier.example", verdict="malicious", category="phishing", source="test"))
        db.commit()
    client.post(f"{BASE}/connections/{row['id']}/scan", headers=admin)
    order = client.get(f"{BASE}/messages/{_by_subject(client, admin)['Order dispatched']['id']}", headers=admin).json()
    assert order["verdict"] == "phish" and order["reasons"][0]["code"] == "intel.retro" and order["action"] == "quarantine"
    assert ("m1", "qfolder-1") in mail.moves


# --------------------------------------------------------------------------- phase 3: the learned model

from fenrir_cloud import email_model  # noqa: E402
from fenrir_cloud.models import EmailModel  # noqa: E402


def _seed_history(db, tenant_id, bad=60, good=400, labelled_safe_lookalikes=0):
    """Past scans: phishing with a link mismatch and scam wording, flagged by Microsoft; ordinary mail it passed."""
    import random

    rng = random.Random(3)
    now = utcnow()
    rows = []
    for i in range(bad):
        codes = ["link.mismatch", "language.scam"] + (["reply-to.mismatch"] if i % 2 else []) + (["sender.first-contact"] if i % 3 else [])
        rows.append(EmailScan(tenant_id=tenant_id, connection_id="c1", mailbox="jo@acme.co.uk", message_id=f"b{i}",
                              received_at=now - timedelta(hours=i), microsoft_verdict="phish", microsoft={"scl": 9},
                              features={"external": 1, "url_count": 2, "link_mismatch": 1, "scam_phrases": 2,
                                        "first_contact": int(i % 3 > 0), "codes": codes}))
    for i in range(good):
        codes = ["language.scam"] if rng.random() < 0.05 else []
        rows.append(EmailScan(tenant_id=tenant_id, connection_id="c1", mailbox="jo@acme.co.uk", message_id=f"g{i}",
                              received_at=now - timedelta(minutes=i), microsoft_verdict="clean", microsoft={"scl": 1},
                              features={"external": 1, "url_count": rng.randint(0, 4), "dkim_pass": 1,
                                        "scam_phrases": len(codes), "codes": codes}))
    db.add_all(rows)
    db.commit()


def test_the_model_waits_for_enough_examples(client, admin, tenant):
    with database.session_factory()() as db:
        row = email_model.train(db)
        db.commit()
        assert not row.active and "Not enough examples" in row.reason
    view = client.get(BASE + "/model", headers=admin).json()
    assert view["active"] is None and view["latest"]["version"] == 1 and view["requirements"]["samples"] == 200


def test_the_model_learns_activates_and_only_adds_evidence(client, admin, tenant):
    with database.session_factory()() as db:
        _seed_history(db, tenant["id"])
    trained = client.post(BASE + "/model/train", headers=admin).json()
    assert trained["active"], trained["reason"]
    assert trained["metrics"]["precision"] >= email_model.MIN_PRECISION and trained["metrics"]["recall"] >= email_model.MIN_RECALL
    assert {s["input"] for s in trained["strongestSignals"]} >= {"code:link.mismatch"}
    assert not any(w["input"].startswith("ms_") for w in trained["strongestSignals"])  # Microsoft's scores are not inputs

    with database.session_factory()() as db:
        email_model.forget_cache()
        model = email_model.active(db)
        assert model is not None and model.version == trained["version"]
    # Below the rules' phish line (link mismatch 25 + scam wording 20 = 45) but just like past phishing: the model adds.
    lookalike = message(sender_address="billing@newvendor.example", subject="Invoice overdue: urgent action required",
                        body_html="<a href='https://evil.example/pay'>https://www.supplier.example/invoices</a>")
    result = es.analyse(lookalike, ctx(model=model))
    codes = {r["code"] for r in result["reasons"]}
    assert "model.learned" in codes and result["verdict"] == "phish" and result["model_score"] >= model.threshold
    # Ordinary mail: the model has a say but adds nothing, and never lowers a score.
    plain = es.analyse(message(), ctx(model=model))
    assert plain["verdict"] == "clean" and plain["model_score"] < model.threshold
    assert all(r["points"] >= 0 for r in result["reasons"])


def test_only_msp_admins_retrain_and_technicians_cannot(client, admin, tenant):
    from conftest import login

    created = client.post("/api/console/users", json={"email": "tech@acme.example", "password": "Technician-pass-123",
                                                      "role": "tenant_admin", "tenantId": tenant["id"]}, headers=admin)
    assert created.status_code == 200, created.text
    tech = login(client, "tech@acme.example", "Technician-pass-123")
    assert client.post(BASE + "/model/train", headers=tech).status_code == 403
    assert client.get(BASE + "/model", headers=tech).status_code == 200



# --------------------------------------------------------------------------- the evidence behind a verdict

from fenrir_cloud import email_forensics  # noqa: E402


def test_the_received_path_is_read_oldest_first_with_delays():
    headers = [["Received", "from mx.example.net (mx.example.net [81.2.69.142]) by relay.example.org with ESMTPS id 1; Wed, 11 Nov 2026 20:00:30 +0000"],
               ["Received", "from laptop ([192.168.1.20]) by mx.example.net with ESMTPSA id 0; Wed, 11 Nov 2026 20:00:00 +0000"]]
    hops = email_forensics.path(headers)
    assert [h["from"] for h in hops] == ["laptop", "mx.example.net"] and hops[1]["ip"] == "81.2.69.142"
    assert hops[1]["delaySeconds"] == 30 and hops[0]["with"] == "ESMTPSA"
    assert email_forensics.originating_ip(headers, hops) == "81.2.69.142"  # the first public hop, not the private laptop
    assert email_forensics.originating_ip([["X-Forefront-Antispam-Report", "CIP:198.51.100.9;CTRY:RU;"]], []) == "198.51.100.9"


def test_addresses_explain_mismatches_and_links_say_what_is_wrong():
    headers = [["From", "Accounts <accounts@supplier.example>"], ["Reply-To", "pay@gmail.com"],
               ["Return-Path", "<bounce@bulkmailer.example>"], ["X-Mailer", "PHPMailer 6.1"]]
    found = email_forensics.addresses(headers)
    assert found["envelopeFrom"] == "bounce@bulkmailer.example" and found["mailer"] == "PHPMailer 6.1"
    assert any("different domain than the From" in n for n in found["notes"]) and any("Replies go to pay@gmail.com" in n for n in found["notes"])
    links = email_forensics.links("<a href='http://198.51.100.20/login'>https://www.microsoft.com</a> <a href='https://bit.ly/x'>x</a>"
                                  "<a href='https://bad.example/p'>p</a>", ctx(bad_domains={"bad.example": "phishing"}))
    flags = {l["host"]: l["flags"] for l in links}
    assert flags["198.51.100.20"] == ["bare IP", "text shows another site"] and flags["bit.ly"] == ["shortener"]
    assert flags["bad.example"] == ["threat intel"]
    assert email_forensics.ip_info("10.0.0.5") == {"ip": "10.0.0.5", "public": False, "ptr": "", "asn": "", "network": "",
                                                   "owner": "", "country": "", "listed": False}


def test_mailbox_scans_keep_headers_origin_and_can_download_the_original(client, admin, tenant, mail):
    row = _prepare(client, admin, tenant, mail)
    client.put(f"{BASE}/connections/{row['id']}", json={"mode": "shadow"}, headers=admin)
    client.post(f"{BASE}/connections/{row['id']}/scan", headers=admin)
    junk = _by_subject(client, admin)["Verify your account"]
    detail = client.get(f"{BASE}/messages/{junk['id']}", headers=admin).json()
    evidence = detail["details"]
    assert ["x-forefront-antispam-report", PHISH_HEADERS["x-forefront-antispam-report"]] in evidence["headers"]
    assert evidence["origin"] == {"ip": "81.2.69.160", "public": True, "ptr": "mail.example.net", "asn": "64500",
                                  "network": "203.0.113.0/24", "owner": "EXAMPLE-NET", "country": "GB", "listed": False}
    assert evidence["auth"]["spf"] == "fail" and evidence["auth"]["dmarc"] == "fail" and evidence["auth"]["compauth"] == "fail"
    assert any("text shows another site" in l["flags"] for l in evidence["links"]) and detail["canDownload"]
    remittance = _by_subject(client, admin)["Remittance advice"]
    original = client.get(f"{BASE}/messages/{remittance['id']}/original", headers=admin)
    assert original.status_code == 200 and original.headers["content-type"].startswith("message/rfc822")
    assert b"Subject: Remittance advice" in original.content and "attachment" in original.headers["content-disposition"]
