"""Web protection for iPhone, iPad and Mac: a phone code becomes a DNS profile, and Fenrir watches it keep working."""

import plistlib
from datetime import timedelta

import dns.message
import pytest

from conftest import enroll, login
from fenrir_cloud import db as database
from fenrir_cloud import web_profile
from fenrir_cloud.dnsfilter import INTEL
from fenrir_cloud.models import Alert, Device, EnrollmentToken, utcnow

IPHONE_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"


def phone_code(client, admin, tenant, **extra) -> str:
    body = {"tenantId": tenant["id"], "label": "Phone: Jo", "maxUses": 1, "expiresInDays": 1, **extra}
    reply = client.post("/api/console/enrollment-tokens", headers=admin, json=body)
    assert reply.status_code == 200, reply.text
    return reply.json()["token"]


def install(client, code, kind="iphone", name="Jo's iPhone"):
    return client.post("/api/v1/enroll/apple", json={"enrollmentToken": code, "name": name, "kind": kind},
                       headers={"User-Agent": IPHONE_UA})


@pytest.fixture(autouse=True)
def offline_upstream(monkeypatch):
    """Allowed names are answered by a stand-in for the upstream resolver, so no test reaches the internet."""
    from fenrir_cloud import dnsfilter

    monkeypatch.setattr(dnsfilter, "forward", lambda wire, upstream, client=None: dns.message.make_response(dns.message.from_wire(wire)).to_wire())


@pytest.fixture()
def iphone(client, admin, tenant):
    reply = install(client, phone_code(client, admin, tenant))
    assert reply.status_code == 200, reply.text
    return reply.json()


def lookup(client, iphone, name="beacon.c2.evil.example"):
    wire = dns.message.make_query(name, "A").to_wire()
    return client.post(iphone["profileUrl"].replace("apple.mobileconfig", "dns-query"), content=wire,
                       headers={"Content-Type": "application/dns-message"})


def device_row(device_id) -> Device:
    with database.session_factory()() as db:
        row = db.get(Device, device_id)
        db.expunge(row)
        return row


def silent_alerts(device_id, status=("new", "triaged")):
    with database.session_factory()() as db:
        return [(a.title, a.status, dict(a.details)) for a in db.query(Alert).filter_by(device_id=device_id, rule_id=web_profile.SILENT_RULE)
                if a.status in status]


def age(device_id, **fields):
    with database.session_factory()() as db:
        row = db.get(Device, device_id)
        for key, value in fields.items():
            setattr(row, key, value)
        db.commit()


def test_a_phone_code_makes_a_profile_only_iphone_in_the_codes_customer(client, admin, tenant, iphone):
    assert iphone["platform"] == "ios" and iphone["hostname"] == "Jo's iPhone" and iphone["signed"] is False
    row = device_row(iphone["deviceId"])
    assert row.tenant_id == tenant["id"] and row.approved and row.os_version == "iOS 17.5.1"
    assert row.metrics["agentless"] is True and row.inventory["role"] == "phone"
    assert row.last_seen_at is None  # nothing is protected until the profile is installed and used
    with database.session_factory()() as db:
        assert db.query(EnrollmentToken).one().uses == 1
    listed = client.get("/api/console/devices", headers=admin).json()
    entry = next(d for d in (listed["items"] if isinstance(listed, dict) else listed) if d["id"] == iphone["deviceId"])
    assert entry["agentless"] is True and entry["role"] == "phone"


def test_the_code_works_once(client, admin, tenant):
    code = phone_code(client, admin, tenant)
    assert install(client, code).status_code == 200
    assert install(client, code).status_code == 403
    assert install(client, "fet_not-a-real-code").status_code == 403
    assert client.post("/api/v1/enroll/apple", json={"name": "x", "kind": "iphone"}).status_code == 403
    assert install(client, phone_code(client, admin, tenant), kind="watch").status_code == 422


def test_the_profile_points_the_device_at_its_own_encrypted_resolver(client, iphone):
    reply = client.get(iphone["profileUrl"])
    assert reply.status_code == 200
    assert reply.headers["content-type"] == "application/x-apple-aspen-config"
    assert "Fenrir-web-protection.mobileconfig" in reply.headers["content-disposition"]
    profile = plistlib.loads(reply.content)
    assert profile["PayloadType"] == "Configuration" and profile["PayloadIdentifier"] == web_profile.PROFILE_ID
    assert profile["PayloadRemovalDisallowed"] is False and "Acme Dental" in profile["PayloadDescription"]
    dns_payload = profile["PayloadContent"][0]
    assert dns_payload["PayloadType"] == "com.apple.dnsSettings.managed"
    token = iphone["profileUrl"].split("/")[2]
    assert dns_payload["DNSSettings"] == {"DNSProtocol": "HTTPS", "ServerURL": f"https://fenrir.test/dns/{token}/dns-query"}
    assert client.get(iphone["profileUrl"]).content == reply.content  # the same device always gets the same profile


def test_a_mac_and_an_ipad(client, admin, tenant):
    mac = install(client, phone_code(client, admin, tenant), kind="mac", name="").json()
    assert mac["platform"] == "macos" and mac["hostname"] == "Mac" and device_row(mac["deviceId"]).os_version == "macOS"
    ipad = install(client, phone_code(client, admin, tenant), kind="ipad", name="Reception iPad").json()
    row = device_row(ipad["deviceId"])
    assert row.platform == "ios" and row.os_version.startswith("iPadOS") and row.inventory["role"] == "tablet"


def test_profiles_are_signed_when_a_certificate_is_configured(client, iphone, tmp_path, monkeypatch):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import pkcs7
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fenrir.test")])
    now = utcnow()
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30)).sign(key, hashes.SHA256()))
    (tmp_path / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()))
    monkeypatch.setenv("FENRIR_PROFILE_SIGNING_CERT", str(tmp_path / "cert.pem"))
    monkeypatch.setenv("FENRIR_PROFILE_SIGNING_KEY", str(tmp_path / "key.pem"))
    signed = client.get(iphone["profileUrl"]).content
    assert pkcs7.load_der_pkcs7_certificates(signed)[0] == cert
    assert b"com.apple.dnsSettings.managed" in signed  # the profile travels inside the signature


def test_apple_needs_an_https_server(client, admin, tenant, monkeypatch):
    import dataclasses

    from fenrir_cloud import config

    monkeypatch.setattr(config, "_active", dataclasses.replace(config.get_settings(), public_base_url="http://fenrir.lan:8080"))
    reply = install(client, phone_code(client, admin, tenant))
    assert reply.status_code == 409 and "https" in reply.json()["detail"]


def test_only_profile_devices_have_a_profile(client, admin, tenant):
    pc = enroll(client, admin, tenant)
    token = pc["dnsOverHttpsUrl"].split("/")[-2]
    assert client.get(f"/dns/{token}/apple.mobileconfig").status_code == 404
    assert client.get("/dns/not-a-token/apple.mobileconfig").status_code == 404
    assert client.get(f"/api/console/devices/{pc['deviceId']}/web-protection", headers=admin).status_code == 404


def test_lookups_keep_it_alive_and_blocks_are_logged_against_the_iphone(client, admin, tenant, iphone):
    status = client.get(f"/api/console/devices/{iphone['deviceId']}/web-protection", headers=admin).json()
    assert status["status"] == "waiting" and status["profileUrl"].endswith("/apple.mobileconfig") and status["filtering"] is True
    client.post("/api/console/intel/indicators", headers=admin, json={"values": ["c2.evil.example"], "verdict": "malicious",
                                                                    "tenantId": tenant["id"]})
    INTEL.invalidate()
    reply = lookup(client, iphone)
    assert reply.status_code == 200 and reply.headers["X-Fenrir-Dns-Action"] == "block"
    row = device_row(iphone["deviceId"])
    assert row.last_seen_at is not None and row.metrics["firstLookupAt"]
    status = client.get(f"/api/console/devices/{iphone['deviceId']}/web-protection", headers=admin).json()
    assert status["status"] == "active" and status["blocked7d"] == 1
    assert status["recent"][0]["domain"] == "beacon.c2.evil.example"
    detail = client.get(f"/api/console/devices/{iphone['deviceId']}", headers=admin).json()
    assert detail["device"]["online"] is True and detail["policy"]["applied"] is True


def test_lookups_write_the_device_at_most_once_a_minute(client, admin, tenant, iphone):
    lookup(client, iphone)
    first = device_row(iphone["deviceId"]).last_seen_at
    lookup(client, iphone)
    assert device_row(iphone["deviceId"]).last_seen_at == first


def test_a_profile_that_is_never_installed_or_goes_quiet_alerts_and_clears_itself(client, admin, tenant, iphone):
    device_id = iphone["deviceId"]
    with database.session_factory()() as db:
        assert web_profile.tick(db) == {"raised": 0}  # just made
    age(device_id, enrolled_at=utcnow() - timedelta(hours=25))
    with database.session_factory()() as db:
        assert web_profile.tick(db) == {"raised": 1}
        assert web_profile.tick(db) == {"raised": 0}  # one alert, not one an hour
    assert silent_alerts(device_id)[0][0] == "Web protection was never installed on Jo's iPhone"
    lookup(client, iphone)
    assert silent_alerts(device_id) == []
    assert silent_alerts(device_id, ("resolved",))[0][2]["autoResolved"] == "The device is using Fenrir's DNS again."
    age(device_id, last_seen_at=utcnow() - timedelta(hours=73))
    with database.session_factory()() as db:
        assert web_profile.tick(db) == {"raised": 1}
    assert silent_alerts(device_id)[0][0] == "Web protection has stopped on Jo's iPhone"
    inbox = client.get("/api/console/triage/items", headers=admin).json()["items"]
    assert any(i["title"] == "Web protection has stopped on Jo's iPhone" for i in inbox)


def test_nothing_can_send_a_profile_device_a_command(client, admin, tenant, iphone):
    mac = install(client, phone_code(client, admin, tenant), kind="mac").json()
    for device_id in (iphone["deviceId"], mac["deviceId"]):
        refused = client.post(f"/api/console/devices/{device_id}/commands", headers=admin, json={"type": "scan.quick", "reason": "t"})
        assert refused.status_code == 400
    assert "web protection profile" in refused.json()["detail"]
    bulk = client.post("/api/console/commands/bulk", headers=admin, json={"type": "scan.quick", "deviceIds": [mac["deviceId"]]})
    assert bulk.status_code == 200 and bulk.json()["queued"] == [] and "web protection profile" in bulk.json()["skipped"][0]["reason"]


def test_a_decommissioned_iphone_keeps_working_unfiltered_until_the_profile_is_removed(client, admin, tenant, iphone):
    age(iphone["deviceId"], enrolled_at=utcnow() - timedelta(hours=25))
    with database.session_factory()() as db:
        web_profile.tick(db)
    assert client.delete(f"/api/console/devices/{iphone['deviceId']}", headers=admin).status_code == 200
    assert silent_alerts(iphone["deviceId"]) == []
    client.post("/api/console/intel/indicators", headers=admin, json={"values": ["c2.evil.example"], "verdict": "malicious",
                                                                    "tenantId": tenant["id"]})
    INTEL.invalidate()
    reply = lookup(client, iphone)
    assert reply.status_code == 200 and reply.headers["X-Fenrir-Dns-Action"] == "allow"  # its phone still reaches websites
    assert client.get(iphone["profileUrl"]).status_code == 404  # but it cannot be installed again
    pc = enroll(client, admin, tenant)
    client.delete(f"/api/console/devices/{pc['deviceId']}", headers=admin)
    assert client.post(f"/dns/{pc['dnsOverHttpsUrl'].split('/')[-2]}/dns-query", content=b"x",
                       headers={"Content-Type": "application/dns-message"}).status_code == 404


def test_another_customer_cannot_see_the_iphone(client, admin, tenant, iphone):
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Ltd", "template": "balanced"}).json()
    client.post("/api/console/users", headers=admin, json={"tenantId": other["id"], "email": "ops@other.example",
                                                           "password": "other-password-123", "role": "tenant_admin"})
    ops = login(client, "ops@other.example", "other-password-123")
    assert client.get(f"/api/console/devices/{iphone['deviceId']}/web-protection", headers=ops).status_code in (403, 404)


def test_read_only_staff_see_status_but_not_the_profile_link(client, admin, tenant, iphone):
    client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": "viewer@acme.test",
                                                           "password": "viewer-password-123", "role": "viewer"})
    viewer = login(client, "viewer@acme.test", "viewer-password-123")
    status = client.get(f"/api/console/devices/{iphone['deviceId']}/web-protection", headers=viewer)
    assert status.status_code == 200 and "profileUrl" not in status.json()


def test_the_device_counts_as_alive_even_when_the_upstream_resolver_fails(client, iphone, monkeypatch):
    import httpx

    from fenrir_cloud import dnsfilter

    def down(wire, upstream, client=None):
        raise httpx.ConnectError("upstream down")

    monkeypatch.setattr(dnsfilter, "forward", down)
    assert lookup(client, iphone, "example.com").status_code == 502
    assert device_row(iphone["deviceId"]).last_seen_at is not None
