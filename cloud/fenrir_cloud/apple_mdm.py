"""Apple device management through Apple's MDM protocol (MDM-02).

**Dependencies on Apple.** These are explicit, and the console shows each one's state:

* An **APNs MDM push certificate**. The MSP requests it at Apple's Push Certificates Portal with a vendor-signed CSR,
  then uploads the certificate and key here. Without it, devices are never told to check in, and Fenrir says so.
  It expires yearly and must be *renewed* with the same Apple ID, never replaced, or every enrolled device is lost.
  Fenrir alerts 30 days and 7 days before expiry.
* **Apple Business Manager**, for automated device enrolment (ADE). Fenrir records the server token's expiry and
  reminds before it lapses. Syncing ABM devices (the DEP API) is not built yet. Devices enrol by profile.

**Enrolment.** For each device, Fenrir issues an identity certificate from its own MDM certificate authority. That
certificate is generated in Fenrir and never leaves the profile. Fenrir then builds an enrolment profile containing:

* the identity as a PKCS#12 payload;
* an MDM payload naming Fenrir's check-in and command URLs and the push topic;
* ``SignMessage``, so that every request the device sends is signed with that identity.

**Requests.** Each check-in or command request carries an ``Mdm-Signature`` header: a detached CMS signature over
the body. Fenrir checks four things before reading the body:

1. The signature is valid.
2. The signed message digest matches the body.
3. The signing certificate was issued by this customer's MDM CA.
4. Its serial belongs to an enrolment Fenrir issued, and that enrolment is not removed.

**Commands.** These are queued, pushed and returned to the device when it checks in. Results are stored, and every
command is audited:

* ``DeviceInformation``, ``ProfileList``, ``InstalledApplicationList`` and ``SecurityInfo``: inventory and posture;
* ``InstallProfile`` and ``RemoveProfile``: policy;
* ``InstallApplication`` (enterprise apps by manifest URL; App Store apps need ABM licences, which are not built);
* ``DeviceLock``;
* ``EraseDevice``: destructive, so it needs step-up and the device's serial number typed in the console.
"""
from __future__ import annotations

import base64
import json
import plistlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import NameOID
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, crypto
from .models import Alert, AppleDevice, AppleEnrollment, AppleMdmCommand, AppleMdmConfig, utcnow

APNS = "https://api.push.apple.com/3/device/"
UID_OID = x509.ObjectIdentifier("0.9.2342.19200300.100.1.1")
ENROLL_VALID = timedelta(days=7)
QUERY_COMMANDS = {"DeviceInformation", "ProfileList", "InstalledApplicationList", "SecurityInfo", "CertificateList"}
COMMANDS = QUERY_COMMANDS | {"InstallProfile", "RemoveProfile", "InstallApplication", "DeviceLock", "EraseDevice"}
DEVICE_QUERIES = ["DeviceName", "OSVersion", "BuildVersion", "ModelName", "Model", "ProductName", "SerialNumber", "UDID",
                  "IsSupervised", "IsActivationLockEnabled", "IsCloudBackupEnabled", "AvailableDeviceCapacity", "DeviceCapacity"]
ALERT_RULE = "apple_mdm.certificate_expiry"


class MdmError(Exception):
    pass


# ---- certificate authority and push certificate ---------------------------------------------------------------------

def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fenrir MDM")])


def ensure_ca(cfg: AppleMdmConfig) -> None:
    if cfg.ca_cert_pem:
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(_name(f"Fenrir MDM CA {cfg.tenant_id}")).issuer_name(_name(f"Fenrir MDM CA {cfg.tenant_id}"))
            .public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256()))
    cfg.ca_cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    cfg.ca_key_envelope = crypto.encrypt(pem, f"apple-mdm-ca:{cfg.id}")


def _ca(cfg: AppleMdmConfig):
    cert = x509.load_pem_x509_certificate(cfg.ca_cert_pem.encode())
    key = serialization.load_pem_private_key(crypto.decrypt_bytes(cfg.ca_key_envelope, f"apple-mdm-ca:{cfg.id}"), password=None)
    return cert, key


def set_push_certificate(cfg: AppleMdmConfig, cert_pem: str, key_pem: str) -> None:
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except (ValueError, TypeError):
        raise MdmError("Upload the push certificate and its private key as PEM") from None
    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        raise MdmError("The private key does not belong to this certificate")
    uid = [a.value for a in cert.subject.get_attributes_for_oid(UID_OID)]
    if not uid or not str(uid[0]).startswith("com.apple.mgmt."):
        raise MdmError("This is not an Apple MDM push certificate (its topic should start with com.apple.mgmt.)")
    if cfg.push_topic and cfg.push_topic != uid[0]:
        raise MdmError(f"This certificate's topic ({uid[0]}) differs from the current one ({cfg.push_topic}). Renew the existing "
                       "certificate in Apple's portal instead of creating a new one, or every enrolled device stops responding.")
    cfg.push_topic = str(uid[0])
    cfg.push_expires_at = cert.not_valid_after_utc.replace(tzinfo=None)
    cfg.push_envelope = crypto.encrypt(json.dumps({"cert": cert_pem, "key": key_pem}), f"apple-mdm-push:{cfg.id}")


# ---- enrolment ----------------------------------------------------------------------------------------------------------

def enrollment_profile(db: Session, cfg: AppleMdmConfig, label: str, actor: str) -> tuple[AppleEnrollment, bytes]:
    if not cfg.push_topic:
        raise MdmError("Upload the APNs MDM push certificate first: without it Fenrir cannot reach enrolled devices")
    if not cfg.server_url.startswith("https://"):
        raise MdmError("Set the public https:// address of this Fenrir server first")
    ensure_ca(cfg)
    ca_cert, ca_key = _ca(cfg)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    serial = x509.random_serial_number()
    cert = (x509.CertificateBuilder().subject_name(_name(f"Fenrir MDM device {serial:x}"[:64])).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(serial).not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=730))
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    password = secrets.token_urlsafe(18)
    p12 = pkcs12.serialize_key_and_certificates(b"fenrir-mdm", key, cert, None, serialization.BestAvailableEncryption(password.encode()))
    enrollment = AppleEnrollment(tenant_id=cfg.tenant_id, config_id=cfg.id, cert_serial=f"{serial:x}", label=label[:200], created_by=actor,
                                 expires_at=utcnow() + ENROLL_VALID)
    db.add(enrollment)
    db.flush()
    identity_uuid, mdm_uuid, profile_uuid = (str(uuid.uuid4()).upper() for _ in range(3))
    base = cfg.server_url.rstrip("/")
    profile = {
        "PayloadType": "Configuration", "PayloadVersion": 1, "PayloadScope": "System", "PayloadUUID": profile_uuid,
        "PayloadIdentifier": f"com.fenrir.mdm.{enrollment.id}", "PayloadDisplayName": "Fenrir device management",
        "PayloadDescription": "Lets your IT provider manage this device's security settings with Fenrir.",
        "PayloadContent": [
            {"PayloadType": "com.apple.security.pkcs12", "PayloadVersion": 1, "PayloadUUID": identity_uuid,
             "PayloadIdentifier": f"com.fenrir.mdm.{enrollment.id}.identity", "PayloadDisplayName": "Fenrir MDM identity",
             "PayloadContent": p12, "Password": password},
            {"PayloadType": "com.apple.mdm", "PayloadVersion": 1, "PayloadUUID": mdm_uuid, "PayloadIdentifier": f"com.fenrir.mdm.{enrollment.id}.mdm",
             "PayloadDisplayName": "Fenrir MDM", "ServerURL": f"{base}/mdm/server", "CheckInURL": f"{base}/mdm/checkin",
             "Topic": cfg.push_topic, "IdentityCertificateUUID": identity_uuid, "AccessRights": 8191, "SignMessage": True,
             "CheckOutWhenRemoved": True, "ServerCapabilities": ["com.apple.mdm.per-user-connections"]},
        ],
    }
    audit.record(db, actor, "apple_mdm.enrollment_issued", enrollment.id, cfg.tenant_id, label=label[:200], certSerial=enrollment.cert_serial)
    return enrollment, plistlib.dumps(profile)


# ---- request signatures (detached CMS, as Apple sends in Mdm-Signature) --------------------------------------------------

def _tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """(tag, value start, value end) of the DER element at pos."""
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4:
            raise MdmError("Unsupported DER length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    if pos + length > len(data):
        raise MdmError("Truncated signature")
    return tag, pos, pos + length


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int, int]]:
    """(tag, element start, value start, value end) of each child in [start, end)."""
    out, pos = [], start
    while pos < end:
        tag, vs, ve = _tlv(data, pos)
        out.append((tag, pos, vs, ve))
        pos = ve
    return out


OID_MESSAGE_DIGEST = bytes.fromhex("2a864886f70d010904")
DIGESTS = {bytes.fromhex("608648016503040201"): hashes.SHA256(), bytes.fromhex("2b0e03021a"): hashes.SHA1()}


def verify_signature(body: bytes, signature_b64: str, ca_cert: x509.Certificate) -> x509.Certificate:
    """The certificate that signed ``body``, after checking the CMS signature, the digest and the issuing CA."""
    try:
        der = base64.b64decode(signature_b64, validate=True)
    except ValueError:
        raise MdmError("Mdm-Signature is not base64") from None
    try:
        certs = pkcs7.load_der_pkcs7_certificates(der)
        _, s, e = _tlv(der, 0)                                    # ContentInfo
        ci = _children(der, s, e)
        _, s, e = _tlv(der, ci[1][2])                             # [0] EXPLICIT -> SignedData
        sd = _children(der, s, e)
        signer_set = sd[-1]
        signer = _children(der, signer_set[2], signer_set[3])[0]  # first SignerInfo
        fields = _children(der, signer[2], signer[3])
        sid = fields[1]
        sid_parts = _children(der, sid[2], sid[3])
        serial = int.from_bytes(der[sid_parts[1][2]:sid_parts[1][3]], "big")
        digest_oid = der[_children(der, fields[2][2], fields[2][3])[0][2]:_children(der, fields[2][2], fields[2][3])[0][3]]
        attrs = next((f for f in fields if f[0] == 0xA0), None)
        signature = next(der[f[2]:f[3]] for f in fields if f[0] == 0x04)
    except (IndexError, ValueError, StopIteration) as exc:
        raise MdmError(f"Mdm-Signature could not be read ({type(exc).__name__})") from None
    algorithm = DIGESTS.get(digest_oid)
    if algorithm is None or attrs is None:
        raise MdmError("Unsupported signature (digest algorithm or missing signed attributes)")
    signed_attrs = b"\x31" + der[attrs[1] + 1:attrs[3]]       # signed over as a SET OF, not [0]
    digest = None
    for attr in _children(der, attrs[2], attrs[3]):
        parts = _children(der, attr[2], attr[3])
        if der[parts[0][2]:parts[0][3]] == OID_MESSAGE_DIGEST:
            value = _children(der, parts[1][2], parts[1][3])[0]
            digest = der[value[2]:value[3]]
    h = hashes.Hash(algorithm)
    h.update(body)
    if digest is None or digest != h.finalize():
        raise MdmError("The signed digest does not match the request body")
    cert = next((c for c in certs if c.serial_number == serial), None)
    if cert is None:
        raise MdmError("The signing certificate is not in the signature")
    try:
        cert.public_key().verify(signature, signed_attrs, padding.PKCS1v15(), algorithm)
        cert.verify_directly_issued_by(ca_cert)
    except Exception:  # noqa: BLE001 - InvalidSignature, ValueError, TypeError: all mean "not ours"
        raise MdmError("The request was not signed by an identity this MDM issued") from None
    return cert


def authenticate(db: Session, body: bytes, signature: str | None) -> tuple[AppleMdmConfig, AppleEnrollment, x509.Certificate]:
    if not signature:
        raise MdmError("Unsigned MDM request")
    for cfg in db.scalars(select(AppleMdmConfig).where(AppleMdmConfig.ca_cert_pem != "")).all():
        ca = x509.load_pem_x509_certificate(cfg.ca_cert_pem.encode())
        try:
            cert = verify_signature(body, signature, ca)
        except MdmError:
            continue
        enrollment = db.scalars(select(AppleEnrollment).where(AppleEnrollment.cert_serial == f"{cert.serial_number:x}",
                                                              AppleEnrollment.config_id == cfg.id)).first()
        if enrollment is None:
            raise MdmError("Unknown device identity")
        return cfg, enrollment, cert
    raise MdmError("The request was not signed by an identity this MDM issued")


# ---- check-in and command protocol ---------------------------------------------------------------------------------------

def checkin(db: Session, body: bytes, signature: str | None) -> None:
    cfg, enrollment, _ = authenticate(db, body, signature)
    msg = plistlib.loads(body)
    kind, udid = msg.get("MessageType"), str(msg.get("UDID") or "")
    if not udid:
        raise MdmError("No UDID")
    device = db.scalars(select(AppleDevice).where(AppleDevice.udid == udid)).first()
    if device is not None and device.enrollment_id != enrollment.id:
        raise MdmError("This device is enrolled with another identity")
    if kind == "Authenticate":
        if msg.get("Topic") != cfg.push_topic:
            raise MdmError("Wrong push topic")
        if device is None and utcnow() > enrollment.expires_at:
            raise MdmError("This enrolment profile has expired")
        if device is None:
            device = AppleDevice(tenant_id=cfg.tenant_id, enrollment_id=enrollment.id, udid=udid)
            db.add(device)
        device.serial_number, device.model = str(msg.get("SerialNumber") or "")[:64], str(msg.get("Model") or msg.get("ProductName") or "")[:100]
        device.os_version, device.status = str(msg.get("OSVersion") or "")[:40], "enrolling"
        enrollment.used_at = enrollment.used_at or utcnow()
    elif kind == "TokenUpdate":
        if device is None:
            raise MdmError("TokenUpdate before Authenticate")
        token = msg.get("Token")
        device.push_token = token.hex() if isinstance(token, (bytes, bytearray)) else str(token or "")
        device.push_magic = str(msg.get("PushMagic") or "")
        if msg.get("UnlockToken"):
            device.unlock_token_envelope = crypto.encrypt(bytes(msg["UnlockToken"]), f"apple-unlock:{udid}")
        if device.status != "enrolled":
            device.status = "enrolled"
            queue(db, device, "DeviceInformation", {}, "system:apple-mdm")
            audit.record(db, "system:apple-mdm", "apple_mdm.enrolled", device.id, device.tenant_id, serial=device.serial_number, model=device.model)
    elif kind == "CheckOut":
        if device is not None:
            device.status = "removed"
            audit.record(db, "system:apple-mdm", "apple_mdm.removed", device.id, device.tenant_id, serial=device.serial_number)
    else:
        raise MdmError(f"Unsupported check-in message {kind}")
    if device is not None:
        device.last_seen_at = utcnow()


def _command_plist(cmd: AppleMdmCommand) -> bytes:
    command = {"RequestType": cmd.request_type}
    p = cmd.payload or {}
    if cmd.request_type == "DeviceInformation":
        command["Queries"] = DEVICE_QUERIES
    elif cmd.request_type == "InstallProfile":
        command["Payload"] = base64.b64decode(p["profileBase64"])
    elif cmd.request_type == "RemoveProfile":
        command["Identifier"] = p["identifier"]
    elif cmd.request_type == "InstallApplication":
        command["ManifestURL"] = p["manifestUrl"]
        command["ManagementFlags"] = 1
    elif cmd.request_type == "DeviceLock":
        command.update({k: v for k, v in (("Message", p.get("message")), ("PhoneNumber", p.get("phone")), ("PIN", p.get("pin"))) if v})
    elif cmd.request_type == "EraseDevice":
        if p.get("pin"):
            command["PIN"] = p["pin"]
    return plistlib.dumps({"CommandUUID": cmd.uuid, "Command": command})


def server(db: Session, body: bytes, signature: str | None) -> bytes:
    """A device reports the last command's result (or that it is idle) and gets the next command, or nothing."""
    cfg, enrollment, _ = authenticate(db, body, signature)
    msg = plistlib.loads(body)
    device = db.scalars(select(AppleDevice).where(AppleDevice.udid == str(msg.get("UDID") or ""), AppleDevice.enrollment_id == enrollment.id)).first()
    if device is None or device.status == "removed":
        raise MdmError("Unknown or removed device")
    device.last_seen_at = utcnow()
    status = msg.get("Status")
    if msg.get("CommandUUID"):
        cmd = db.scalars(select(AppleMdmCommand).where(AppleMdmCommand.uuid == msg["CommandUUID"], AppleMdmCommand.device_id == device.id)).first()
        if cmd is not None:
            cmd.status = {"Acknowledged": "acknowledged", "Error": "error", "NotNow": "not_now"}.get(status, cmd.status)
            result = {k: v for k, v in msg.items() if k not in ("UDID", "CommandUUID", "Status")}
            cmd.result, cmd.updated_at = json.loads(json.dumps(result, default=lambda v: v.hex() if isinstance(v, bytes) else str(v))), utcnow()
            if cmd.request_type == "DeviceInformation" and status == "Acknowledged":
                info = msg.get("QueryResponses") or {}
                device.info = {**(device.info or {}), **cmd.result.get("QueryResponses", {})}
                device.os_version = str(info.get("OSVersion") or device.os_version)
                device.serial_number = str(info.get("SerialNumber") or device.serial_number)
            if cmd.request_type == "SecurityInfo" and status == "Acknowledged":
                device.info = {**(device.info or {}), "security": cmd.result.get("SecurityInfo", {})}
            if cmd.status == "not_now":
                cmd.status = "queued"  # the device is busy (locked); it is sent again at the next check-in
    if status == "NotNow":
        return b""
    nxt = db.scalars(select(AppleMdmCommand).where(AppleMdmCommand.device_id == device.id, AppleMdmCommand.status == "queued")
                     .order_by(AppleMdmCommand.created_at)).first()
    if nxt is None:
        return b""
    nxt.status, nxt.updated_at = "sent", utcnow()
    return _command_plist(nxt)


# ---- queueing and push ----------------------------------------------------------------------------------------------------

def queue(db: Session, device: AppleDevice, request_type: str, payload: dict, actor: str) -> AppleMdmCommand:
    if request_type not in COMMANDS:
        raise MdmError("Unsupported command")
    if device.status != "enrolled":
        raise MdmError("The device is not enrolled")
    if request_type == "InstallProfile":
        try:
            plistlib.loads(base64.b64decode(payload.get("profileBase64") or ""))
        except Exception:  # noqa: BLE001
            raise MdmError("The profile is not a valid configuration profile") from None
    if request_type == "InstallApplication" and not str(payload.get("manifestUrl", "")).startswith("https://"):
        raise MdmError("Give the https:// manifest URL of the enterprise app")
    if request_type == "RemoveProfile" and not payload.get("identifier"):
        raise MdmError("Give the profile identifier to remove")
    cmd = AppleMdmCommand(tenant_id=device.tenant_id, device_id=device.id, uuid=str(uuid.uuid4()), request_type=request_type,
                          payload=payload, requested_by=actor)
    db.add(cmd)
    db.flush()
    audit.record(db, actor, "apple_mdm.command_queued", cmd.id, device.tenant_id, device=device.serial_number, requestType=request_type)
    return cmd


def _push_client(cfg: AppleMdmConfig):
    import os
    import tempfile

    pair = json.loads(crypto.decrypt(cfg.push_envelope, f"apple-mdm-push:{cfg.id}"))
    fd, path = tempfile.mkstemp(suffix=".pem")
    with os.fdopen(fd, "w") as f:
        f.write(pair["cert"] + "\n" + pair["key"])
    try:
        return httpx.Client(http2=True, cert=path, timeout=15)
    finally:
        os.unlink(path)  # the SSL context has read it; the key does not stay on disk


def push(db: Session, device: AppleDevice, client_factory=None) -> dict:
    cfg = db.scalars(select(AppleMdmConfig).where(AppleMdmConfig.tenant_id == device.tenant_id)).first()
    if cfg is None or not cfg.push_envelope:
        return {"pushed": False, "reason": "No APNs push certificate is configured"}
    if not device.push_token or not device.push_magic:
        return {"pushed": False, "reason": "The device has not sent its push token yet"}
    with (client_factory or _push_client)(cfg) as client:
        r = client.post(APNS + device.push_token, headers={"apns-topic": cfg.push_topic, "apns-priority": "10", "apns-push-type": "mdm"},
                        content=json.dumps({"mdm": device.push_magic}))
    if r.status_code == 200:
        return {"pushed": True}
    try:
        reason = r.json().get("reason", "")
    except ValueError:
        reason = ""
    if reason in ("BadDeviceToken", "Unregistered"):
        device.status = "removed"
    return {"pushed": False, "reason": f"Apple refused the push (HTTP {r.status_code} {reason})".strip()}


# ---- renewal reminders ----------------------------------------------------------------------------------------------------

def tick(db: Session) -> int:
    raised = 0
    now = utcnow()
    for cfg in db.scalars(select(AppleMdmConfig)).all():
        for what, expires in (("APNs push certificate", cfg.push_expires_at), ("Apple Business Manager token", cfg.abm_token_expires_at)):
            if expires is None:
                continue
            days = (expires - now).days
            stage = "expired" if days < 0 else "7" if days <= 7 else "30" if days <= 30 else None
            if stage is None:
                continue
            key = f"apple:{cfg.id}:{what}:{expires.date()}:{stage}"
            open_ = {(a.details or {}).get("key") for a in db.scalars(select(Alert).where(Alert.tenant_id == cfg.tenant_id, Alert.rule_id == ALERT_RULE)).all()}
            if key in open_:
                continue
            advice = ("Renew it at identity.apple.com/pushcert with the same Apple ID (Renew, not Create), then upload the new "
                      "certificate in Fenrir." if what.startswith("APNs") else "Download a new server token in Apple Business Manager and upload it.")
            db.add(Alert(tenant_id=cfg.tenant_id, rule_id=ALERT_RULE, severity="critical" if stage in ("expired", "7") else "high",
                         title=f"{what} {'has expired' if stage == 'expired' else f'expires in {days} days'} ({expires:%d %b %Y})",
                         mitre=[], event_ids=[], details={"category": "mdm", "source": "Apple MDM", "key": key, "description": advice, "link": "/apple-mdm"}))
            raised += 1
    db.commit()
    return raised
