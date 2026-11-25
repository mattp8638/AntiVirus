"""MDM-02: Apple MDM enrolment, signed check-ins, command queue, push and certificate renewal reminders."""
import base64
import json
import plistlib
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import NameOID

from test_documentation_vault import stepup
from fenrir_cloud import apple_mdm, db as database
from fenrir_cloud.models import Alert, AppleMdmCommand, AppleMdmConfig, AuditLog

URL = "/api/console/apple-mdm"
TOPIC = "com.apple.mgmt.External.0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"


def push_cert(days=365):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(apple_mdm.UID_OID, TOPIC), x509.NameAttribute(NameOID.COMMON_NAME, "APSP:test")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=days)).sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())


@pytest.fixture
def apns(monkeypatch):
    pushes = []

    def factory(cfg):
        def handler(request):
            pushes.append((str(request.url), dict(request.headers), json.loads(request.content)))
            return httpx.Response(200)
        return httpx.Client(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(apple_mdm, "_push_client", factory)
    return pushes


class Device:
    """Signs MDM requests with the identity from an enrolment profile, as iOS does."""

    def __init__(self, profile: bytes, udid="00008110-001A2B3C4D5E6F70"):
        p = plistlib.loads(profile)
        ident = next(x for x in p["PayloadContent"] if x["PayloadType"] == "com.apple.security.pkcs12")
        self.mdm = next(x for x in p["PayloadContent"] if x["PayloadType"] == "com.apple.mdm")
        self.key, self.cert, _ = pkcs12.load_key_and_certificates(ident["PayloadContent"], ident["Password"].encode())
        self.udid = udid

    def sign(self, body: bytes, key=None, cert=None) -> str:
        der = (pkcs7.PKCS7SignatureBuilder().set_data(body).add_signer(cert or self.cert, key or self.key, hashes.SHA256())
               .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary]))
        return base64.b64encode(der).decode()

    def put(self, client, path, msg, **sign):
        body = plistlib.dumps({"UDID": self.udid, **msg})
        return client.put(path, content=body, headers={"Mdm-Signature": self.sign(body, **sign)})


def configure(client, admin, tenant, days=365):
    cert, key = push_cert(days)
    r = client.put(f"{URL}/config/{tenant['id']}", headers=stepup(client, admin),
                   json={"serverUrl": "https://fenrir.example.com", "pushCertificatePem": cert, "pushKeyPem": key})
    assert r.status_code == 200, r.text
    return r.json()


def enrol(client, admin, tenant):
    out = client.post(f"{URL}/config/{tenant['id']}/enrollments", headers=admin, json={"label": "Sam's iPhone"}).json()
    return Device(base64.b64decode(out["profileBase64"]))


def test_enrolment_signed_checkins_commands_and_push(client, admin, tenant, apns):
    cfg = configure(client, admin, tenant)
    assert cfg["pushTopic"] == TOPIC and cfg["dependencies"] == {"apnsPushCertificate": True, "appleBusinessManager": False,
                                                                  "automatedDeviceEnrollment": False}
    dev = enrol(client, admin, tenant)
    assert dev.mdm["Topic"] == TOPIC and dev.mdm["ServerURL"] == "https://fenrir.example.com/mdm/server" and dev.mdm["SignMessage"] is True
    r = dev.put(client, "/mdm/checkin", {"MessageType": "Authenticate", "Topic": TOPIC, "SerialNumber": "F2LXK0ABCD", "Model": "iPhone15,2",
                                         "OSVersion": "18.1"})
    assert r.status_code == 200, r.text
    assert dev.put(client, "/mdm/checkin", {"MessageType": "TokenUpdate", "Topic": TOPIC, "Token": bytes.fromhex("ab" * 32),
                                            "PushMagic": "magic-1"}).status_code == 200
    devices = client.get(f"{URL}/devices", headers=admin, params={"tenantId": tenant["id"]}).json()
    assert devices[0]["status"] == "enrolled" and devices[0]["serialNumber"] == "F2LXK0ABCD" and devices[0]["pushToken"] == "ab" * 32

    # The first command (DeviceInformation) was queued at enrolment; the device fetches it and reports the answer.
    r = dev.put(client, "/mdm/server", {"Status": "Idle"})
    cmd = plistlib.loads(r.content)
    assert cmd["Command"]["RequestType"] == "DeviceInformation" and "OSVersion" in cmd["Command"]["Queries"]
    r = dev.put(client, "/mdm/server", {"Status": "Acknowledged", "CommandUUID": cmd["CommandUUID"],
                                        "QueryResponses": {"OSVersion": "18.1.1", "DeviceName": "Sam's iPhone", "IsSupervised": False}})
    assert r.content == b""
    devices = client.get(f"{URL}/devices", headers=admin, params={"tenantId": tenant["id"]}).json()
    assert devices[0]["osVersion"] == "18.1.1" and devices[0]["info"]["DeviceName"] == "Sam's iPhone"

    # A lock is queued, pushed to Apple, then delivered at the next check-in.
    did = devices[0]["id"]
    assert client.post(f"{URL}/devices/{did}/commands", headers=admin, json={"requestType": "DeviceLock"}).status_code == 403
    proof = stepup(client, admin)
    out = client.post(f"{URL}/devices/{did}/commands", headers=proof, json={"requestType": "DeviceLock", "payload": {"message": "Call IT"}}).json()
    assert out["push"] == {"pushed": True}
    url, headers, body = apns[0]
    assert url.endswith("ab" * 32) and headers["apns-topic"] == TOPIC and body == {"mdm": "magic-1"}
    nxt = plistlib.loads(dev.put(client, "/mdm/server", {"Status": "Idle"}).content)
    assert nxt["Command"] == {"RequestType": "DeviceLock", "Message": "Call IT"}

    # Erasing needs the serial number typed.
    r = client.post(f"{URL}/devices/{did}/commands", headers=proof, json={"requestType": "EraseDevice", "confirmSerial": "WRONG"})
    assert r.status_code == 409
    assert client.post(f"{URL}/devices/{did}/commands", headers=proof, json={"requestType": "EraseDevice", "confirmSerial": "f2lxk0abcd"}).status_code == 200
    with database.session_factory()() as db:
        assert db.query(AuditLog).filter_by(action="apple_mdm.enrolled").count() == 1
        assert db.query(AppleMdmCommand).filter_by(request_type="EraseDevice").count() == 1

    # Removal: CheckOut marks it removed and the server refuses it afterwards.
    dev.put(client, "/mdm/checkin", {"MessageType": "CheckOut", "Topic": TOPIC})
    assert dev.put(client, "/mdm/server", {"Status": "Idle"}).status_code == 401


def test_unsigned_forged_and_tampered_requests_are_refused(client, admin, tenant, apns):
    configure(client, admin, tenant)
    dev = enrol(client, admin, tenant)
    body = plistlib.dumps({"UDID": dev.udid, "MessageType": "Authenticate", "Topic": TOPIC})
    assert client.put("/mdm/checkin", content=body).status_code == 401
    # Signed by a certificate this MDM did not issue.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "intruder")])
    now = datetime.now(timezone.utc)
    rogue = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(dev.cert.serial_number)
             .not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))
    assert dev.put(client, "/mdm/checkin", {"MessageType": "Authenticate", "Topic": TOPIC}, key=key, cert=rogue).status_code == 401
    # A genuine signature over a different body.
    signature = dev.sign(body)
    tampered = plistlib.dumps({"UDID": "SOMEONE-ELSE", "MessageType": "Authenticate", "Topic": TOPIC})
    assert client.put("/mdm/checkin", content=tampered, headers={"Mdm-Signature": signature}).status_code == 401
    assert client.put("/mdm/checkin", content=body, headers={"Mdm-Signature": signature}).status_code == 200


def test_push_certificate_rules_and_renewal_alerts(client, admin, tenant, apns):
    assert client.post(f"{URL}/config/{tenant['id']}/enrollments", headers=admin, json={}).status_code == 400  # no push certificate yet
    configure(client, admin, tenant, days=20)
    # A certificate with a different topic would orphan every device: refused.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(apple_mdm.UID_OID, "com.apple.mgmt.External.other")])
    now = datetime.now(timezone.utc)
    other = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(2)
             .not_valid_before(now).not_valid_after(now + timedelta(days=365)).sign(key, hashes.SHA256()))
    r = client.put(f"{URL}/config/{tenant['id']}", headers=stepup(client, admin), json={
        "pushCertificatePem": other.public_bytes(serialization.Encoding.PEM).decode(),
        "pushKeyPem": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()})
    assert r.status_code == 400 and "Renew" in r.json()["detail"]
    with database.session_factory()() as db:
        db.query(AppleMdmConfig).update({"abm_token_expires_at": datetime.utcnow() + timedelta(days=5)})
        db.commit()
        assert apple_mdm.tick(db) == 2
        assert apple_mdm.tick(db) == 0  # not raised twice
        titles = sorted(a.title for a in db.query(Alert).filter_by(rule_id=apple_mdm.ALERT_RULE).all())
        assert titles[0].startswith("APNs push certificate expires in") and titles[1].startswith("Apple Business Manager token expires in")
