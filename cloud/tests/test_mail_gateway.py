"""Fenrir's mail gateway (mail_gateway.py): a real SMTP conversation in, a fake Microsoft 365 receiving what is delivered."""
import smtplib
import socket
import time
from email.message import EmailMessage

import pytest
from aiosmtpd.controller import Controller

from test_msp_modules import connection
from fenrir_cloud import db as database, mail_gateway
from fenrir_cloud.models import EmailGatewayDomain, EmailQuarantine, EmailScan, Indicator, M365Connection


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
PASS_AUTH = {"spf": "pass", "dkim": "pass", "dkimDomain": "supplier.example", "dmarc": "pass", "policy": "reject",
             "header": "spf=pass smtp.mailfrom=supplier.example; dkim=pass header.d=supplier.example; dmarc=pass action=none header.from=supplier.example"}


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Microsoft365:
    """Stands in for contoso.mail.protection.outlook.com: records what the gateway delivers, or defers it."""

    def __init__(self):
        self.received = []
        self.defer = False
        self.refuse = False

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if self.refuse:
            return "550 5.4.1 Recipient address rejected: Access denied. AS(201806281)"
        if self.defer:
            return "451 4.3.0 Try again later"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        self.received.append((envelope.mail_from, list(envelope.rcpt_tos), envelope.content))
        return "250 OK"


@pytest.fixture
def gateway(client, admin, tenant, tmp_path, monkeypatch):
    monkeypatch.setattr(mail_gateway, "authenticate", lambda raw, ip, helo, mail_from, from_domain: dict(PASS_AUTH))
    monkeypatch.setattr(mail_gateway, "default_destination", lambda domain: "127.0.0.1")
    row = connection(client, admin, tenant)
    with database.session_factory()() as db:
        conn = db.get(M365Connection, row["id"])
        conn.snapshot = {"users": [{"id": "u1", "displayName": "Jo Leaver", "mail": "jo@acme.co.uk", "userPrincipalName": "jo@acme.co.uk",
                                    "accountEnabled": True, "userType": "Member", "assignedLicenses": [{"skuId": "x"}]}],
                         "domains": [{"id": "acme.co.uk", "isVerified": True}]}
        db.commit()
    m365 = Microsoft365()
    downstream = Controller(m365, hostname="127.0.0.1", port=free_port())
    downstream.start()
    added = client.post(BASE + "/gateway/domains", json={"tenantId": tenant["id"], "domain": "acme.co.uk", "requireTls": False,
                                                          "destinationPort": downstream.port}, headers=admin)
    assert added.status_code == 200, added.text
    directory = mail_gateway.Directory(database.session_factory())
    spool = mail_gateway.Spool(tmp_path / "spool")
    front = Controller(mail_gateway.Handler(directory, spool), hostname="127.0.0.1", port=free_port())
    front.start()
    worker = mail_gateway.Worker(directory, spool)
    yield type("G", (), {"m365": m365, "port": front.port, "spool": spool, "worker": worker, "directory": directory,
                         "domain": added.json(), "send": staticmethod(lambda msg, rcpts=None, sender="accounts@supplier.example":
                                                                      _send(front.port, msg, sender, rcpts))})
    front.stop()
    downstream.stop()


def _send(port, msg, sender, rcpts):
    with smtplib.SMTP("127.0.0.1", port, timeout=10) as smtp:
        from email import policy as mail_policy

        return smtp.sendmail(sender, rcpts or ["jo@acme.co.uk"], msg.as_bytes(policy=mail_policy.SMTP))  # CRLF, as real servers send


def mail(subject="Order dispatched", body="<p>Your order has shipped.</p>", attachment=None, sender="accounts@supplier.example"):
    msg = EmailMessage()
    msg["From"] = f"Supplier <{sender}>"
    msg["To"] = "jo@acme.co.uk"
    msg["Subject"] = subject
    msg["Message-ID"] = f"<{time.time()}@supplier.example>"
    msg.set_content("plain")
    msg.add_alternative(body, subtype="html")
    if attachment:
        msg.add_attachment(attachment[1], maintype="application", subtype="octet-stream", filename=attachment[0])
    return msg


def run(gw):
    with database.session_factory()() as db:
        return gw.worker.run_once(db)


def test_the_gateway_is_never_an_open_relay(gateway):
    with smtplib.SMTP("127.0.0.1", gateway.port, timeout=10) as smtp:
        smtp.ehlo()
        smtp.mail("someone@anywhere.example")
        code, text = smtp.rcpt("victim@gmail.com")
        assert code == 550 and b"Relaying denied" in text
        assert smtp.rcpt("jo@acme.co.uk")[0] == 250


def test_clean_mail_is_delivered_with_fenrir_headers(gateway):
    gateway.send(mail())
    assert gateway.spool.size() == 1
    assert run(gateway) == 1 and gateway.spool.size() == 0
    sender, rcpts, content = gateway.m365.received[0]
    assert sender == "accounts@supplier.example" and rcpts == ["jo@acme.co.uk"]
    assert b"X-Fenrir-Verdict: clean; score=0" in content and b"Authentication-Results:" in content and b"dmarc=pass" in content
    with database.session_factory()() as db:
        scan = db.query(EmailScan).one()
        assert (scan.source, scan.action, scan.action_status, scan.folder) == ("gateway", "deliver", "done", "gateway")
        assert scan.recipients == ["jo@acme.co.uk"] and scan.microsoft["dmarc"] == "pass"
        assert db.get(EmailGatewayDomain, gateway.domain["id"]).last_message_at is not None


def test_malware_is_quarantined_encrypted_and_can_be_released(client, admin, gateway):
    gateway.send(mail(subject="Remittance", attachment=("remittance.pdf.exe", b"MZ fake program")))
    run(gateway)
    assert gateway.m365.received == []  # held back
    with database.session_factory()() as db:
        scan = db.query(EmailScan).one()
        assert scan.verdict == "malware" and scan.action == "quarantine" and scan.action_status == "done"
        held = db.query(EmailQuarantine).one()
        assert held.scan_id == scan.id and b"MZ fake" not in str(held.envelope).encode()  # stored encrypted
        scan_id = scan.id
    released = client.post(f"{BASE}/messages/{scan_id}/release", json={}, headers=admin)
    assert released.status_code == 200 and released.json()["actionStatus"] == "released"
    assert len(gateway.m365.received) == 1 and b"X-Fenrir-Released-By: admin@fenrir.local" in gateway.m365.received[0][2]


def test_deferred_delivery_stays_queued_and_is_retried(gateway):
    gateway.m365.defer = True
    gateway.send(mail())
    assert run(gateway) == 0 and gateway.spool.size() == 1
    meta = gateway.spool.items()[0]
    assert meta["attempts"] == 1 and meta["nextAttempt"] and "deferred" in meta["lastError"]
    assert run(gateway) == 0  # not due yet: nothing is attempted
    gateway.m365.defer = False
    meta["nextAttempt"] = None
    gateway.spool.update(meta)
    assert run(gateway) == 1 and len(gateway.m365.received) == 1
    with database.session_factory()() as db:
        assert db.query(EmailScan).count() == 1  # scanned once, delivered on the retry


def test_suspicious_mail_can_be_tagged_in_the_subject(client, admin, gateway):
    client.put(f"{BASE}/gateway/domains/{gateway.domain['id']}", json={"tagSubject": True}, headers=admin)
    gateway.directory.refresh(force=True)
    gateway.send(mail(subject="Your password will expire", body="<p>Your password will expire within 24 hours. Click here to sign in.</p>"))
    run(gateway)
    content = gateway.m365.received[0][2]
    assert b"Subject: [Suspicious] Your password will expire" in content and b"X-Fenrir-Verdict: suspicious" in content


def test_unknown_recipients_and_listed_ips_are_refused(client, admin, gateway):
    client.put(f"{BASE}/gateway/domains/{gateway.domain['id']}", json={"rejectUnknownRecipients": True}, headers=admin)
    gateway.directory.refresh(force=True)
    with smtplib.SMTP("127.0.0.1", gateway.port, timeout=10) as smtp:
        smtp.ehlo()
        smtp.mail("a@supplier.example")
        assert smtp.rcpt("nobody@acme.co.uk")[0] == 550
        assert smtp.rcpt("JO@acme.co.uk")[0] == 250
    with database.session_factory()() as db:
        db.add(Indicator(tenant_id=None, type="ip", value="127.0.0.1", verdict="malicious", category="spam", source="test"))
        db.commit()
    gateway.directory.refresh(force=True)
    with smtplib.SMTP("127.0.0.1", gateway.port, timeout=10) as smtp:
        smtp.ehlo()
        code, text = smtp.mail("a@supplier.example")
        assert code == 554 and b"threat intelligence" in text


def test_domains_must_be_verified_and_the_connector_needs_ips(client, admin, tenant, gateway):
    refused = client.post(BASE + "/gateway/domains", json={"tenantId": tenant["id"], "domain": "notmine.example"}, headers=admin)
    assert refused.status_code == 400 and "not a verified domain" in refused.json()["detail"]
    again = client.post(BASE + "/gateway/domains", json={"tenantId": tenant["id"], "domain": "acme.co.uk"}, headers=admin)
    assert again.status_code == 409
    view = client.get(BASE + "/gateway", headers=admin).json()
    assert view["domains"][0]["domain"] == "acme.co.uk" and view["domains"][0]["actions"]["malware"] == "quarantine"
    connect = client.post(f"{BASE}/gateway/domains/{gateway.domain['id']}/connect-m365", json={"lockdown": True}, headers=admin)
    assert connect.status_code == 409 and "FENRIR_GATEWAY_PUBLIC_IPS" in connect.json()["detail"]


def test_forged_microsoft_headers_are_ignored(gateway):
    msg = mail(subject="Hello")
    msg["X-Forefront-Antispam-Report"] = "SCL:-1;SFV:SKN;CAT:NONE;"
    gateway.send(msg)
    run(gateway)
    with database.session_factory()() as db:
        scan = db.query(EmailScan).one()
        assert scan.microsoft_verdict == "unknown" and "scl" not in scan.microsoft


def test_authentication_checks_dmarc_alignment(monkeypatch):
    import dkim
    import spf

    monkeypatch.setattr(spf, "check2", lambda **kw: ("pass", 250, "ok"))
    monkeypatch.setattr(dkim, "verify", lambda raw, timeout=10: False)
    monkeypatch.setattr(mail_gateway, "dmarc_policy", lambda domain: "reject")
    raw = b"DKIM-Signature: v=1; d=supplier.example; s=s1; b=abc\r\nFrom: a@supplier.example\r\n\r\nhi"
    aligned = mail_gateway.authenticate(raw, "198.51.100.1", "mx.supplier.example", "bounce@mail.supplier.example", "supplier.example")
    assert (aligned["spf"], aligned["dkim"], aligned["dmarc"]) == ("pass", "fail", "pass")  # SPF aligns on the organisational domain
    forged = mail_gateway.authenticate(raw, "198.51.100.1", "mx.evil.example", "x@evil.example", "supplier.example")
    assert forged["dmarc"] == "fail" and "action=reject" in forged["header"]
    monkeypatch.setattr(mail_gateway, "dmarc_policy", lambda domain: None)
    assert mail_gateway.authenticate(raw, "198.51.100.1", "h", "x@evil.example", "supplier.example")["dmarc"] == "none"


def test_clamav_finds_what_the_rules_miss(gateway, monkeypatch):
    import threading

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    def clamd():
        conn, _ = server.accept()
        with conn:
            data = b""
            while not data.endswith(b"\0\0\0\0"):
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
            assert data.startswith(b"zINSTREAM\0")
            conn.sendall(b"stream: Win.Test.EICAR_HDB-1 FOUND\0")

    thread = threading.Thread(target=clamd, daemon=True)
    thread.start()
    monkeypatch.setenv("FENRIR_CLAMD_HOST", "127.0.0.1")
    monkeypatch.setenv("FENRIR_CLAMD_PORT", str(server.getsockname()[1]))
    gateway.send(mail(subject="Statement", attachment=("statement.pdf", b"%PDF-1.4 harmless looking")))
    run(gateway)
    thread.join(5)
    server.close()
    assert gateway.m365.received == []
    with database.session_factory()() as db:
        scan = db.query(EmailScan).one()
        assert scan.verdict == "malware" and scan.reasons[0]["detail"] == "ClamAV found Win.Test.EICAR_HDB-1"


def test_a_crash_after_scanning_does_not_scan_twice_or_get_stuck(gateway):
    gateway.send(mail())
    meta = gateway.spool.items()[0]
    with database.session_factory()() as db:  # scanned, then the process died before noting it in the spool
        route = gateway.directory.routes["acme.co.uk"]
        gateway.worker._scan(db, meta, gateway.spool.raw(meta["id"]), route, ["jo@acme.co.uk"], dict(PASS_AUTH), None)
    assert run(gateway) == 1 and len(gateway.m365.received) == 1
    with database.session_factory()() as db:
        assert db.query(EmailScan).count() == 1


def test_a_message_that_keeps_failing_is_dropped_after_three_days(gateway, monkeypatch):
    gateway.send(mail())
    meta = gateway.spool.items()[0]
    meta["receivedAt"] = "2020-01-01T00:00:00"
    gateway.spool.update(meta)
    monkeypatch.setattr(mail_gateway, "parse", lambda raw, header: (_ for _ in ()).throw(ValueError("unreadable")))
    run(gateway)
    assert gateway.spool.size() == 0



def test_gateway_scans_keep_the_evidence_and_microsofts_reply(client, admin, gateway):
    gateway.send(mail())
    run(gateway)
    with database.session_factory()() as db:
        scan = db.query(EmailScan).one()
        details, scan_id = scan.details, scan.id
    assert details["origin"]["ip"] == "127.0.0.1" and details["origin"]["public"] is False
    assert details["addresses"]["envelopeFrom"] == "accounts@supplier.example" and details["addresses"]["recipients"] == ["jo@acme.co.uk"]
    assert details["auth"]["spf"] == "pass" and details["size"] > 100 and details["tls"] is False
    assert any(name == "Subject" and value == "Order dispatched" for name, value in details["headers"])
    assert details["delivery"]["response"].startswith("250") and details["delivery"]["attempts"] == 1
    assert details["delivery"]["host"] == "127.0.0.1"
    assert details["path"][-1]["ip"] == "127.0.0.1" and "gateway" in details["path"][-1]["raw"]
    # Delivered gateway mail is not kept, so there is no original to download.
    assert client.get(f"{BASE}/messages/{scan_id}/original", headers=admin).status_code == 404


def test_quarantined_gateway_mail_can_be_downloaded_for_analysis(client, admin, gateway):
    gateway.send(mail(subject="Remittance", attachment=("remittance.pdf.exe", b"MZ fake program")))
    run(gateway)
    with database.session_factory()() as db:
        scan_id = db.query(EmailScan).one().id
    original = client.get(f"{BASE}/messages/{scan_id}/original", headers=admin)
    assert original.status_code == 200 and b"Subject: Remittance" in original.content



def test_a_refused_message_is_kept_with_microsofts_reason_and_can_be_retried(client, admin, gateway):
    gateway.m365.refuse = True
    gateway.send(mail())
    assert run(gateway) == 1 and gateway.spool.size() == 0
    with database.session_factory()() as db:
        scan = db.query(EmailScan).one()
        assert scan.action_status == "failed" and "550 5.4.1 Recipient address rejected" in scan.action_error
        assert "Access denied" in scan.details["delivery"]["lastError"]
        assert db.query(EmailQuarantine).filter_by(scan_id=scan.id).count() == 1  # kept, encrypted
        scan_id = scan.id
    detail = client.get(f"{BASE}/messages/{scan_id}", headers=admin).json()
    assert detail["canDownload"]
    gateway.m365.refuse = False  # the cause is fixed (for example the recipient or connector)
    retried = client.post(f"{BASE}/messages/{scan_id}/release", json={}, headers=admin)
    assert retried.status_code == 200 and retried.json()["actionStatus"] == "released"
    assert len(gateway.m365.received) == 1 and retried.json()["details"]["delivery"]["response"].startswith("250")


def test_the_mailbox_scan_interval_is_configurable(monkeypatch):
    from fenrir_cloud import email_scan

    monkeypatch.delenv("FENRIR_EMAIL_SCAN_SECONDS", raising=False)
    assert email_scan.scan_interval() == 60
    monkeypatch.setenv("FENRIR_EMAIL_SCAN_SECONDS", "5")
    assert email_scan.scan_interval() == 30  # never more often than every 30 seconds
    monkeypatch.setenv("FENRIR_EMAIL_SCAN_SECONDS", "300")
    assert email_scan.scan_interval() == 300


def test_gateway_follows_the_customers_policy_rules_and_connection_filter(client, admin, tenant, gateway):
    from fenrir_cloud import email_policy

    doc = {**email_policy.PRESETS["standard"],
           "rules": [{"name": "Label supplier mail", "conditions": [{"field": "senderDomain", "operator": "is", "value": "supplier.example"}],
                      "actions": [{"type": "addHeader", "value": "X-Fenrir-Supplier: yes"}]}]}
    assert client.put(f"{BASE}/policy/{tenant['id']}", json={"document": doc}, headers=admin).status_code == 200
    gateway.send(mail())
    run(gateway)
    content = gateway.m365.received[0][2]
    assert b"X-Fenrir-Supplier: yes" in content
    with database.session_factory()() as db:
        scan = db.query(EmailScan).one()
        assert any(t["source"] == "Mail flow rule 'Label supplier mail'" for t in scan.details["decision"]["trail"])
    blocked = {**doc, "connection": {"ipAllow": [], "ipBlock": ["127.0.0.0/8"]}}
    client.put(f"{BASE}/policy/{tenant['id']}", json={"document": blocked}, headers=admin)
    gateway.directory.policy_cache.clear()
    with smtplib.SMTP("127.0.0.1", gateway.port, timeout=10) as smtp:
        smtp.ehlo()
        smtp.mail("a@supplier.example")
        code, text = smtp.rcpt("jo@acme.co.uk")
        assert code == 550 and b"blocked by the recipient's policy" in text


def test_files_inside_zip_attachments_are_checked(gateway):
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("invoice.pdf", b"%PDF")
        archive.writestr("run.js", b"WScript.Echo(1)")
    gateway.send(mail(subject="Documents", attachment=("documents.zip", buffer.getvalue())))
    run(gateway)
    assert gateway.m365.received == []
    with database.session_factory()() as db:
        scan = db.query(EmailScan).one()
        assert scan.action == "quarantine" and "run.js inside documents.zip" in scan.details["decision"]["trail"][-1]["detail"]
