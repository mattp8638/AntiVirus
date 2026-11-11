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
    "x-forefront-antispam-report": "CIP:203.0.113.9;CTRY:RU;LANG:en;SCL:5;SRV:;IPV:NLI;SFV:SPM;H:mx;CAT:PHSH;SFS:(1);DIR:INB;",
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
        if parts[:2] == ["users", USER] and parts[2] == "mailFolders" and parts[4] == "messages":
            query = {k: v[0] for k, v in parse_qs(urlparse(str(request.url)).query).items()}
            since = datetime.fromisoformat(query["$filter"].split(" ge ")[1].replace("Z", "+00:00"))
            rows = [m for m in self.folders[parts[3]] if datetime.fromisoformat(m["receivedDateTime"].replace("Z", "+00:00")) >= since]
            return httpx.Response(200, json={"value": rows})
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
