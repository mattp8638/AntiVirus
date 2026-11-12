"""Email security, phase 4: Fenrir's mail gateway, in front of Microsoft 365.

Point a customer domain's MX record at the gateway and mail is checked **before** it reaches the mailbox:

1. **SMTP (aiosmtpd).** Accepts mail only for domains added under Email security > Gateway; anything else is refused
   with "550 relaying denied", so the gateway can never be used as an open relay. Senders whose IP is in threat intel are
   refused, each IP is rate limited, recipients can optionally be checked against the tenant's directory, and STARTTLS
   is offered (your certificate, or a self-signed one).
2. **Queue.** Each accepted message is written to a spool folder before "250 queued" is sent, so nothing is lost if the
   process restarts; delivery problems are retried with back-off for up to ``GIVE_UP_AFTER``.
3. **Checks.** Sender authentication is done here (SPF with pyspf, DKIM with dkimpy, DMARC alignment from the
   domain's policy), then the same engine as the mailbox scanner (``email_security.analyse``) with the customer's
   allow/block lists, threat intel and the learned model; ClamAV (optional, ``FENRIR_CLAMD_HOST``) scans the whole
   message too.
4. **Decision** per customer domain: quarantine (the original is kept encrypted with the vault key, not delivered),
   tag (``X-Fenrir-Verdict`` header, optional ``[Suspicious]`` subject), or deliver. Everything delivered carries
   ``X-Fenrir-Verdict``, ``X-Fenrir-Scan-Id`` and an ``Authentication-Results`` header, and goes to the tenant's
   Microsoft 365 host over TLS.
5. **Record.** One ``EmailScan`` per message and customer (``source = "gateway"``) with the verdict and reasons, shown
   with the mailbox scans in the console; quarantined mail can be released from there. Alerts and daily digests work
   as for protect mode.

Run it with ``python -m fenrir_cloud.mail_gateway`` (deploy/docker-compose.mailgateway.yml), next to the server and
sharing its database. Settings (environment):

``FENRIR_GATEWAY_HOSTNAME`` (the name in the MX record), ``FENRIR_GATEWAY_PORT`` (default 2525; publish it as 25),
``FENRIR_GATEWAY_SPOOL`` (default /data/mail-spool), ``FENRIR_GATEWAY_TLS_CERT`` / ``FENRIR_GATEWAY_TLS_KEY``,
``FENRIR_GATEWAY_MAX_MB`` (default 35), ``FENRIR_CLAMD_HOST`` / ``FENRIR_CLAMD_PORT`` (default 3310).

Not done: outbound filtering (Microsoft 365 still sends outbound mail itself), bounces (a message that can never be
delivered raises an alert instead, so the gateway never sends backscatter), attachment sandboxing.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import smtplib
import socket
import ssl
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser
from email.utils import formatdate, getaddresses, parseaddr
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import audit, crypto, email_actions, email_policy, email_security
from .models import EmailGatewayDomain, EmailQuarantine, EmailScan, Indicator, M365Connection, utcnow

log = logging.getLogger("fenrir.email.gateway")

MAX_RECIPIENTS = 100
RATE_PER_MINUTE = 120  # messages per sending IP per minute
RETRY_SCHEDULE = [60, 120, 300, 600, 1800, 3600]  # seconds; then hourly
GIVE_UP_AFTER = timedelta(days=3)
DIRECTORY_REFRESH = 60
DEFAULT_ACTIONS = {"malware": "quarantine", "phish": "quarantine", "suspicious": "tag"}
GATEWAY_ACTIONS = ("quarantine", "tag", "deliver")
DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def hostname() -> str:
    return env("FENRIR_GATEWAY_HOSTNAME") or socket.getfqdn()


def actions_for(domain: EmailGatewayDomain | dict) -> dict:
    stored = (domain.actions if isinstance(domain, EmailGatewayDomain) else domain.get("actions")) or {}
    return {**DEFAULT_ACTIONS, **{k: v for k, v in stored.items() if k in DEFAULT_ACTIONS and v in GATEWAY_ACTIONS}}


def default_destination(domain: str) -> str:
    """Where the domain's mail goes today if that is Microsoft 365 (read from its MX record before you change it),
    otherwise Microsoft's usual inbound host: contoso.co.uk -> contoso-co-uk.mail.protection.outlook.com."""
    import dns.exception
    import dns.resolver

    try:
        answers = sorted(dns.resolver.resolve(domain, "MX", lifetime=5), key=lambda r: r.preference)
        for answer in answers:
            host = str(answer.exchange).rstrip(".").lower()
            if host.endswith((".mail.protection.outlook.com", ".mx.microsoft")):
                return host
    except (dns.exception.DNSException, OSError):
        pass
    return domain.replace(".", "-") + ".mail.protection.outlook.com"


# --------------------------------------------------------------------------- what the gateway accepts

@dataclass
class Route:
    domain_id: str
    tenant_id: str
    domain: str
    destination: str
    port: int
    require_tls: bool
    tag_subject: bool
    actions: dict
    notify: dict
    known: set[str] | None  # recipients to accept, when "reject unknown recipients" is on


@dataclass
class Directory:
    """The domains the gateway accepts mail for and the IPs it refuses, re-read from the database every minute."""
    session_factory: object
    routes: dict[str, Route] = field(default_factory=dict)
    bad_ips: set[str] = field(default_factory=set)
    loaded_at: float = 0.0
    policy_cache: dict = field(default_factory=dict)

    def refresh(self, force: bool = False) -> None:
        if not force and time.monotonic() - self.loaded_at < DIRECTORY_REFRESH:
            return
        with self.session_factory() as db:
            routes = {}
            for row in db.execute(select(EmailGatewayDomain).where(EmailGatewayDomain.enabled.is_(True))).scalars():
                known = None
                if row.reject_unknown_recipients:
                    known = set()
                    for connection in db.execute(select(M365Connection).where(M365Connection.tenant_id == row.tenant_id)).scalars():
                        for user in (connection.snapshot or {}).get("users") or []:
                            for key in ("mail", "userPrincipalName"):
                                if user.get(key):
                                    known.add(str(user[key]).lower())
                            known |= {str(a).split(":", 1)[-1].lower() for a in user.get("proxyAddresses") or []}
                routes[row.domain] = Route(row.id, row.tenant_id, row.domain, row.destination, row.destination_port or 25,
                                           bool(row.require_tls), bool(row.tag_subject), actions_for(row), row.notify or {},
                                           known)
            now = utcnow()
            bad = {str(v).strip() for (v,) in db.execute(select(Indicator.value).where(
                Indicator.type == "ip", Indicator.verdict == "malicious",
                (Indicator.expires_at.is_(None)) | (Indicator.expires_at > now)))}
        self.routes, self.bad_ips, self.loaded_at = routes, bad, time.monotonic()

    def blocked_ip(self, tenant_id: str, ip: str) -> bool:
        """The customer's connection filter (email policy) blocks this IP. Policies are re-read once a minute."""
        cached = self.policy_cache.get(tenant_id)
        if not cached or time.monotonic() - cached[0] > DIRECTORY_REFRESH:
            with self.session_factory() as db:
                document, _ = email_policy.resolve(db, tenant_id)
            cached = (time.monotonic(), document)
            self.policy_cache[tenant_id] = cached
        return email_policy._in_ranges(ip, (cached[1].get("connection") or {}).get("ipBlock") or [])

    def route(self, address: str) -> Route | None:
        self.refresh()
        return self.routes.get(address.rsplit("@", 1)[-1].strip().lower().rstrip(".")) if "@" in address else None


# --------------------------------------------------------------------------- the spool

class Spool:
    """One .eml file and one .json file per accepted message. Files are written under a temporary name and renamed,
    so a crash never leaves half a message to deliver."""

    def __init__(self, folder: str | Path):
        self.folder = Path(folder)
        try:
            self.folder.mkdir(parents=True, exist_ok=True)
            probe = self.folder / ".write-test"
            probe.write_bytes(b"ok")
            probe.unlink()
        except OSError as exc:
            raise SystemExit(f"The mail queue folder {self.folder} is not writable by this user ({exc}). "
                             "Set FENRIR_GATEWAY_SPOOL to a folder on the data volume, e.g. /data/mail-spool.") from None

    def put(self, raw: bytes, meta: dict) -> str:
        spool_id = meta.get("id") or uuid.uuid4().hex
        meta = {**meta, "id": spool_id}
        for suffix, data in ((".eml", raw), (".json", json.dumps(meta).encode())):
            temporary = self.folder / f".{spool_id}{suffix}.tmp"
            temporary.write_bytes(data)
            os.replace(temporary, self.folder / f"{spool_id}{suffix}")
        return spool_id

    def update(self, meta: dict) -> None:
        temporary = self.folder / f".{meta['id']}.json.tmp"
        temporary.write_text(json.dumps(meta))
        os.replace(temporary, self.folder / f"{meta['id']}.json")

    def items(self) -> list[dict]:
        out = []
        for path in sorted(self.folder.glob("*.json"), key=lambda p: p.stat().st_mtime):
            try:
                out.append(json.loads(path.read_text()))
            except (OSError, ValueError):
                continue
        return out

    def raw(self, spool_id: str) -> bytes:
        return (self.folder / f"{spool_id}.eml").read_bytes()

    def remove(self, spool_id: str) -> None:
        for suffix in (".eml", ".json"):
            (self.folder / f"{spool_id}{suffix}").unlink(missing_ok=True)

    def size(self) -> int:
        return len(list(self.folder.glob("*.json")))


# --------------------------------------------------------------------------- SMTP

class Handler:
    """aiosmtpd handler: decides at each step whether to accept, so refused mail never reaches the spool."""

    def __init__(self, directory: Directory, spool: Spool):
        self.directory, self.spool = directory, spool
        self.recent: dict[str, list[float]] = {}

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        ip = (session.peer or ("", 0))[0]
        self.directory.refresh()
        if ip in self.directory.bad_ips:
            return "554 5.7.1 Your IP address is listed in threat intelligence"
        now = time.monotonic()
        seen = [t for t in self.recent.get(ip, []) if now - t < 60]
        if len(seen) >= RATE_PER_MINUTE:
            return "421 4.7.0 Too many messages from your address; try again later"
        self.recent[ip] = seen + [now]
        if len(self.recent) > 10000:
            self.recent = {k: v for k, v in self.recent.items() if v and now - v[-1] < 60}
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        route = self.directory.route(address)
        if route is None:
            return "550 5.7.1 Relaying denied: this server only accepts mail for its own domains"
        if route.known is not None and address.lower() not in route.known:
            return "550 5.1.1 Recipient address rejected: no such mailbox"
        ip = (session.peer or ("", 0))[0]
        if ip and self.directory.blocked_ip(route.tenant_id, ip):
            return "550 5.7.1 Message rejected: the sending IP is blocked by the recipient's policy"
        if len(envelope.rcpt_tos) >= MAX_RECIPIENTS:
            return "452 4.5.3 Too many recipients"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        raw = envelope.original_content or envelope.content
        if isinstance(raw, str):
            raw = raw.encode("utf-8", "surrogateescape")
        spool_id = self.spool.put(raw, {
            "receivedAt": utcnow().isoformat(), "peer": (session.peer or ("", 0))[0], "helo": session.host_name or "",
            "mailFrom": envelope.mail_from or "", "rcpts": list(envelope.rcpt_tos), "attempts": 0, "nextAttempt": None,
            "groups": {}, "tls": bool(getattr(session, "ssl", None))})
        return f"250 2.0.0 Queued as {spool_id}"


def tls_context() -> ssl.SSLContext:
    """Your certificate if configured, otherwise a self-signed one (fine for server-to-server STARTTLS)."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    cert, key = env("FENRIR_GATEWAY_TLS_CERT"), env("FENRIR_GATEWAY_TLS_KEY")
    if not (cert and key and Path(cert).exists() and Path(key).exists()):
        cert, key = _self_signed(Path(env("FENRIR_GATEWAY_SPOOL", "/data/mail-spool")) / ".tls")
    context.load_cert_chain(cert, key)
    return context


def _self_signed(folder: Path) -> tuple[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    folder.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = folder / "gateway.crt", folder / "gateway.key"
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname())])
    now = datetime.utcnow()
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
                   .not_valid_after(now + timedelta(days=3650))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname())]), critical=False)
                   .sign(key, hashes.SHA256()))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    os.chmod(key_path, 0o600)
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return str(cert_path), str(key_path)


# --------------------------------------------------------------------------- sender authentication

def _txt(name: str) -> list[str]:
    import dns.exception
    import dns.resolver

    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
    except (dns.exception.DNSException, OSError):
        return []
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answers]


def dmarc_record(domain: str) -> str:
    """The domain's DMARC record, falling back to its organisational domain; "" if it has none."""
    for name in dict.fromkeys([domain, email_security.registrable(domain)]):
        for record in _txt(f"_dmarc.{name}"):
            if record.lower().startswith("v=dmarc1"):
                return record[:500]
    return ""


def dmarc_policy(domain: str) -> str | None:
    """The domain's DMARC policy (none/quarantine/reject); None if it has no DMARC record."""
    record = dmarc_record(domain)
    if not record:
        return None
    match = re.search(r"\bp\s*=\s*(none|quarantine|reject)", record, re.I)
    return match.group(1).lower() if match else "none"


def authenticate(raw: bytes, ip: str, helo: str, mail_from: str, from_domain: str) -> dict:
    """SPF, DKIM and DMARC for one message: {"spf", "dkim", "dkimDomain", "dmarc", "policy", "header"}."""
    spf_result, spf_detail, dkim_result, dkim_domain = "none", "", "none", ""
    envelope_domain = email_security.domain_of(mail_from) or (helo or "").lower()
    try:
        import spf

        checked = spf.check2(i=ip, s=mail_from or f"postmaster@{helo}", h=helo or "unknown", timeout=10)
        spf_result, spf_detail = checked[0] or "none", str(checked[2] if len(checked) > 2 else "")[:300]
    except Exception as exc:  # noqa: BLE001 - DNS trouble is a temporary error, never a crash
        log.debug("SPF check failed: %s", exc)
        spf_result = "temperror"
    match = re.search(rb"^DKIM-Signature:(.*?)(?=^\S)", raw, re.M | re.S | re.I)
    if match:
        found = re.search(rb"\bd\s*=\s*([^;\s]+)", match.group(1))
        dkim_domain = found.group(1).decode("ascii", "replace").lower() if found else ""
        try:
            import dkim

            dkim_result = "pass" if dkim.verify(raw, timeout=10) else "fail"
        except Exception as exc:  # noqa: BLE001
            log.debug("DKIM check failed: %s", exc)
            dkim_result = "temperror"
    org = email_security.registrable(from_domain)
    aligned = (spf_result == "pass" and email_security.registrable(envelope_domain) == org) or \
              (dkim_result == "pass" and email_security.registrable(dkim_domain) == org)
    record = dmarc_record(from_domain) if from_domain else ""
    chosen = dmarc_policy(from_domain) if from_domain else None
    dmarc = "none" if chosen is None else ("pass" if aligned else "fail")
    header = (f"spf={spf_result} smtp.mailfrom={envelope_domain or 'unknown'}; dkim={dkim_result} header.d={dkim_domain or 'none'}; "
              f"dmarc={dmarc} action={(chosen or 'none') if dmarc == 'fail' else 'none'} header.from={from_domain or 'unknown'}")
    return {"spf": spf_result, "spfDetail": spf_detail, "dkim": dkim_result, "dkimDomain": dkim_domain, "dmarc": dmarc,
            "policy": chosen or "", "dmarcRecord": record, "aligned": aligned, "header": header}


def clamav(raw: bytes) -> str | None:
    """The ClamAV signature found in the message, or None (also None when ClamAV is not configured or not reachable)."""
    host = env("FENRIR_CLAMD_HOST")
    if not host:
        return None
    try:
        with socket.create_connection((host, int(env("FENRIR_CLAMD_PORT", "3310"))), timeout=30) as sock:
            sock.sendall(b"zINSTREAM\0")
            for start in range(0, len(raw), 65536):
                chunk = raw[start:start + 65536]
                sock.sendall(struct.pack(">I", len(chunk)) + chunk)
            sock.sendall(struct.pack(">I", 0))
            reply = sock.recv(4096).decode("utf-8", "replace").strip("\0 \n")
    except OSError as exc:
        log.warning("ClamAV not reachable: %s", exc)
        return None
    match = re.search(r":\s*(.+?)\s+FOUND$", reply)
    return match.group(1) if match else None


# --------------------------------------------------------------------------- reading a message

def parse(raw: bytes, auth_header: str) -> tuple[email_security.Message, dict]:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    headers = {k.lower(): str(v) for k, v in message.items()}
    headers["authentication-results"] = auth_header
    headers.pop("x-forefront-antispam-report", None)  # a sender could forge Microsoft's verdict headers: ignore them
    headers.pop("x-microsoft-antispam", None)
    name, address = parseaddr(str(message.get("From", "")))
    reply_to = [a for _, a in getaddresses([str(v) for v in message.get_all("Reply-To", [])]) if a]
    html, text = "", ""
    attachments = []
    import hashlib

    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        content_type = part.get_content_type()
        if filename or disposition == "attachment":
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:  # noqa: BLE001 - malformed parts are common in spam
                payload = b""
            if len(attachments) < 20:
                entry = {"name": str(filename or "attachment")[:200], "contentType": content_type,
                         "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
                members, encrypted = email_security.archive_members(entry["name"], payload)
                if members or encrypted:
                    entry["members"], entry["encrypted"] = members[:100], encrypted
                attachments.append(entry)
        elif content_type == "text/html" and not html:
            html = str(part.get_content())[:500_000]
        elif content_type == "text/plain" and not text:
            text = str(part.get_content())[:200_000]
    body = html or ("<pre>" + text + "</pre>" if text else "")
    return email_security.Message(mailbox="", folder="gateway", sender_address=address.lower(), sender_name=name,
                                  reply_to=[r.lower() for r in reply_to], subject=str(message.get("Subject", "")),
                                  headers=headers, body_html=body, attachments=attachments), {
        "messageId": str(message.get("Message-ID", ""))[:300], "fromDomain": email_security.domain_of(address)}


def context_for(db: Session, tenant_id: str, intel: dict) -> email_security.Context:
    """Like the mailbox scanner's context, for a customer reached through the gateway."""
    from . import email_model, email_scan

    own = {d for (d,) in db.execute(select(EmailGatewayDomain.domain).where(EmailGatewayDomain.tenant_id == tenant_id))}
    people = {}
    for connection in db.execute(select(M365Connection).where(M365Connection.tenant_id == tenant_id)).scalars():
        snapshot = connection.snapshot or {}
        own |= {str(d.get("id") or "").lower() for d in snapshot.get("domains") or [] if d.get("isVerified")}
        for user in snapshot.get("users") or []:
            name = email_security.normalise_name(user.get("displayName") or "")
            if name and len(name) >= 5 and (user.get("userType") or "Member") == "Member":
                people[name] = str(user.get("mail") or user.get("userPrincipalName") or "")
    merged = {"urls": set(), "domains": {}, "hashes": {}, "allow": set()}
    for key in (None, tenant_id):
        bucket = intel.get(key) or {}
        merged["urls"] |= bucket.get("urls", set())
        merged["domains"].update(bucket.get("domains", {}))
        merged["hashes"].update(bucket.get("hashes", {}))
        merged["allow"] |= bucket.get("allow", set())
    known = set(db.execute(select(EmailScan.sender_domain).where(
        EmailScan.tenant_id == tenant_id, EmailScan.received_at >= utcnow() - timedelta(days=90)).distinct().limit(50000)).scalars())
    lists = email_scan.list_entries(db, tenant_id)
    own.discard("")
    return email_security.Context(own_domains=own, people=people, bad_urls=merged["urls"], bad_domains=merged["domains"],
                                  bad_hashes=merged["hashes"], allowed_domains=merged["allow"], known_senders={k for k in known if k},
                                  allow_senders=lists[("allow", "sender")], allow_sender_domains=lists[("allow", "domain")],
                                  block_senders=lists[("block", "sender")], block_sender_domains=lists[("block", "domain")],
                                  model=email_model.active(db))


# --------------------------------------------------------------------------- delivery

class TemporaryFailure(Exception):
    pass


class PermanentFailure(Exception):
    pass


def deliver(data: bytes, mail_from: str, recipients: list[str], host: str, port: int, require_tls: bool) -> dict:
    """Hand the message to the customer's Microsoft 365 host and return what happened: {host, port, tls, response, at}.
    4xx and network trouble raise TemporaryFailure; 5xx PermanentFailure."""
    from datetime import timezone

    try:
        with smtplib.SMTP(host, port, local_hostname=hostname(), timeout=60) as smtp:
            smtp.ehlo()
            tls = False
            if smtp.has_extn("starttls"):
                context = ssl.create_default_context()
                if env("FENRIR_GATEWAY_INSECURE_TLS") == "1":  # only for lab destinations with self-signed certificates
                    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
                smtp.starttls(context=context)
                smtp.ehlo()
                tls = True
            elif require_tls:
                raise TemporaryFailure(f"{host} did not offer TLS, and this domain requires it")
            code, reply = smtp.mail(mail_from or "")
            if code >= 400:
                raise smtplib.SMTPResponseException(code, reply)
            refused = {}
            for rcpt in recipients:
                code, reply = smtp.rcpt(rcpt)
                if code >= 400:
                    refused[rcpt] = (code, reply)
            if len(refused) == len(recipients):
                codes = {c for c, _ in refused.values()}
                raise (PermanentFailure if all(500 <= c < 600 for c in codes) else TemporaryFailure)(
                    f"{host} refused {', '.join(refused)}: {next(iter(refused.values()))[0]} "
                    f"{next(iter(refused.values()))[1].decode('utf-8', 'replace')[:200]}")
            code, reply = smtp.data(data)
            if code >= 400:
                raise smtplib.SMTPResponseException(code, reply)
            text = reply.decode("utf-8", "replace") if isinstance(reply, bytes) else str(reply)
            if refused:
                text += " (refused: " + ", ".join(refused) + ")"
            return {"host": host, "port": port, "tls": tls, "response": f"{code} {text}"[:500],
                    "at": datetime.now(timezone.utc).isoformat()}
    except smtplib.SMTPResponseException as exc:
        text = exc.smtp_error.decode("utf-8", "replace") if isinstance(exc.smtp_error, bytes) else str(exc.smtp_error)
        raise (PermanentFailure if 500 <= exc.smtp_code < 600 else TemporaryFailure)(f"{host} said {exc.smtp_code} {text[:200]}") from None
    except (TemporaryFailure, PermanentFailure):
        raise
    except (OSError, smtplib.SMTPException) as exc:
        raise TemporaryFailure(f"Could not deliver to {host}: {type(exc).__name__}: {str(exc)[:150]}") from None


def _headers(meta: dict, scan: EmailScan, auth_header: str, extra: list[str] | None = None) -> bytes:
    lines = [
        f"Received: from {meta.get('helo') or 'unknown'} ([{meta.get('peer')}]) by {hostname()} (Fenrir gateway) with ESMTPS id "
        f"{meta['id']}; {formatdate(localtime=False)}",
        f"Authentication-Results: {hostname()}; {auth_header}",
        f"X-Fenrir-Verdict: {scan.verdict}; score={scan.score}",
        f"X-Fenrir-Scan-Id: {scan.id}",
        *[line for line in (extra or []) if line and "\r" not in line and "\n" not in line],
    ]
    return ("\r\n".join(lines) + "\r\n").encode()


def _tag_subject(raw: bytes, prefix: str = "[Suspicious]") -> bytes:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    subject = str(message.get("Subject", ""))
    prefix = (prefix or "[Suspicious]").strip()
    if not subject.startswith(prefix):
        del message["Subject"]
        message["Subject"] = prefix + " " + subject
    return message.as_bytes(policy=policy.SMTP)


# --------------------------------------------------------------------------- processing the spool

class Worker:
    def __init__(self, directory: Directory, spool: Spool):
        self.directory, self.spool = directory, spool
        self.intel: dict = {}
        self.intel_at = 0.0
        self.contexts: dict[str, tuple[float, email_security.Context]] = {}
        self.policies: dict[str, tuple[float, dict, dict]] = {}

    def _intel(self, db: Session) -> dict:
        from . import email_scan

        if time.monotonic() - self.intel_at > 300:
            self.intel, self.intel_at = email_scan.load_intel(db), time.monotonic()
        return self.intel

    def _policy(self, db: Session, tenant_id: str) -> tuple[dict, dict]:
        cached = self.policies.get(tenant_id)
        if cached and time.monotonic() - cached[0] < 60:
            return cached[1], cached[2]
        document, meta = email_policy.resolve(db, tenant_id)
        self.policies[tenant_id] = (time.monotonic(), document, meta)
        return document, meta

    def _context(self, db: Session, tenant_id: str) -> email_security.Context:
        cached = self.contexts.get(tenant_id)
        if cached and time.monotonic() - cached[0] < 60:
            return cached[1]
        ctx = context_for(db, tenant_id, self._intel(db))
        self.contexts[tenant_id] = (time.monotonic(), ctx)
        return ctx

    def run_once(self, db: Session) -> int:
        """Process everything in the spool that is due. Returns how many messages were finished."""
        self.directory.refresh()
        finished = 0
        now = utcnow()
        for meta in self.spool.items():
            due = meta.get("nextAttempt")
            if due and datetime.fromisoformat(due) > now:
                continue
            try:
                if self.process(db, meta):
                    finished += 1
            except Exception as exc:  # noqa: BLE001 - one bad message never blocks the queue
                db.rollback()
                log.exception("gateway could not process %s", meta.get("id"))
                received = meta.get("receivedAt")
                if received and datetime.fromisoformat(received) < utcnow() - GIVE_UP_AFTER:
                    log.error("gateway gave up on %s after %s: %s", meta.get("id"), GIVE_UP_AFTER, exc)
                    self.spool.remove(meta["id"])  # never retried forever; the error is in the log and the job record
                    continue
                self._retry(meta, f"{type(exc).__name__}: {exc}")
        return finished

    def process(self, db: Session, meta: dict) -> bool:
        raw = self.spool.raw(meta["id"])
        groups: dict[str, list[str]] = {}
        for rcpt in meta.get("rcpts") or []:
            route = self.directory.route(rcpt)
            if route is not None:
                groups.setdefault(route.domain, []).append(rcpt)
        if not groups:
            log.warning("gateway: no configured domain left for %s; dropped", meta["id"])
            self.spool.remove(meta["id"])
            return True
        message, info = parse(raw, "")
        auth = meta.get("auth") or authenticate(raw, meta.get("peer", ""), meta.get("helo", ""), meta.get("mailFrom", ""),
                                                info["fromDomain"])
        meta["auth"] = auth
        signature = meta["clamav"] if "clamav" in meta else clamav(raw)
        meta["clamav"] = signature
        pending = False
        acted: dict[str, tuple[Route, list[EmailScan]]] = {}
        for domain, rcpts in groups.items():
            state = meta["groups"].get(domain) or {}
            if state.get("done"):
                continue
            route = self.directory.routes[domain]
            scan = db.get(EmailScan, state["scanId"]) if state.get("scanId") else None
            if scan is None:
                scan = self._scan(db, meta, raw, route, rcpts, auth, signature)
                state = {"scanId": scan.id, "action": scan.action}
                meta["groups"][domain] = state
                self.spool.update(meta)
                if scan.action == "quarantine":
                    acted.setdefault(route.tenant_id, (route, []))[1].append(scan)
            if state["action"] == "quarantine":
                state["done"] = True
                continue
            decision = (scan.details or {}).get("decision") or {}
            prefix = decision.get("tag") or ""
            data = _tag_subject(raw, prefix) if (prefix and route.tag_subject) else raw
            extra = list(decision.get("headers") or [])
            if decision.get("action") in ("junk", "tag"):
                extra.append(f"X-Fenrir-Action: {decision['action']}")
            try:
                handed = deliver(_headers(meta, scan, auth["header"], extra) + data, meta.get("mailFrom", ""), rcpts, route.destination,
                                 route.port, route.require_tls)
                scan.action_status, scan.action_error, scan.acted_at = "done", "", utcnow()
                scan.details = {**(scan.details or {}), "delivery": {**handed, "attempts": int(meta.get("attempts") or 0) + 1}}
                state["done"] = True
            except TemporaryFailure as exc:
                scan.action_error = str(exc)[:300]
                scan.details = {**(scan.details or {}), "delivery": {"host": route.destination, "port": route.port,
                                                                     "attempts": int(meta.get("attempts") or 0) + 1,
                                                                     "lastError": str(exc)[:300], "at": utcnow().isoformat() + "Z"}}
                pending = True
                if datetime.fromisoformat(meta["receivedAt"]) < utcnow() - GIVE_UP_AFTER:
                    scan.action_status = "failed"
                    self._keep(db, scan, raw, meta)
                    self._undeliverable(db, route, scan, str(exc))
                    state["done"], pending = True, False
            except PermanentFailure as exc:
                scan.action_status, scan.action_error = "failed", str(exc)[:300]
                scan.details = {**(scan.details or {}), "delivery": {"host": route.destination, "port": route.port,
                                                                     "attempts": int(meta.get("attempts") or 0) + 1,
                                                                     "lastError": str(exc)[:300], "at": utcnow().isoformat() + "Z"}}
                self._keep(db, scan, raw, meta)
                self._undeliverable(db, route, scan, str(exc))
                state["done"] = True
            db.commit()
        for tenant_id, (route, scans) in acted.items():
            email_actions.report_run(db, SimpleNamespace(tenant_id=tenant_id, notify=route.notify, connection_id=route.domain_id),
                                     scans)
        if acted:
            db.commit()
        if pending:
            self._retry(meta, "delivery deferred")
            return False
        self.spool.remove(meta["id"])
        return True

    def _scan(self, db: Session, meta: dict, raw: bytes, route: Route, rcpts: list[str], auth: dict,
              signature: str | None) -> EmailScan:
        message_id = f"gw-{meta['id']}-{route.domain_id}"[:200]
        existing = db.execute(select(EmailScan).where(EmailScan.connection_id == route.domain_id,
                                                      EmailScan.message_id == message_id)).scalar_one_or_none()
        if existing is not None:  # scanned before a crash or restart: decide the same way again
            return existing
        message, info = parse(raw, auth["header"])
        message.mailbox = rcpts[0].lower()
        ctx = self._context(db, route.tenant_id)
        result = email_security.analyse(message, ctx)
        if signature:
            result["reasons"].insert(0, {"code": "clamav", "points": 100, "detail": f"ClamAV found {signature}"})
            result["score"], result["verdict"] = 100, "malware"
            result["features"]["codes"] = sorted(set(result["features"]["codes"]) | {"clamav"})
        received = datetime.fromisoformat(meta["receivedAt"])
        details = self._details(raw, meta, rcpts, auth, ctx)
        rules_policy, policy_meta = self._policy(db, route.tenant_id)
        from . import email_scan as scanner

        decision = email_policy.decide(message, result, rules_policy, {
            "gateway": True, "ip": meta.get("peer", ""), "recipients": rcpts, "size": len(raw), "ownDomains": ctx.own_domains,
            "lists": scanner.list_entries(db, route.tenant_id), "details": details, "dmarcPolicy": auth.get("policy", "")},
            policy_meta)
        details["decision"] = decision
        action = {"reject": "quarantine", "junk": "tag"}.get(decision["action"], decision["action"])
        ms = result["microsoft"]
        scan = EmailScan(
            tenant_id=route.tenant_id, connection_id=route.domain_id, mailbox=rcpts[0].lower()[:320],
            message_id=message_id, internet_message_id=info["messageId"], received_at=received,
            folder="gateway", sender_address=message.sender_address[:320], sender_name=message.sender_name[:200],
            sender_domain=result["sender_domain"][:255], subject=message.subject[:300],
            attachments=[{k: a[k] for k in ("name", "size", "sha256") if k in a} for a in message.attachments][:20],
            link_domains=result["link_domains"], microsoft_verdict="unknown",
            microsoft={k: v for k, v in ms.items() if k in ("spf", "dkim", "dmarc")} | {"dmarcPolicy": auth.get("policy", ""),
                                                                                       "peer": meta.get("peer", "")},
            verdict=result["verdict"], score=result["score"], reasons=result["reasons"],
            agreement=email_security.agreement(result["verdict"], "unknown"), features=result["features"],
            model_score=result.get("model_score"), source="gateway", recipients=[r.lower() for r in rcpts],
            action=action, action_status="", acted_at=None, details=details)
        db.add(scan)
        db.flush()
        from . import email_content

        scanner.record_hits(db, route.tenant_id, scan, decision)
        if email_content.should_keep(rules_policy, scan.verdict, action, decision):
            email_content.keep(db, scan, message.body_html, message.subject)
        if action == "quarantine":
            db.add(EmailQuarantine(scan_id=scan.id, tenant_id=route.tenant_id, mail_from=meta.get("mailFrom", "")[:320],
                                   recipients=scan.recipients, size=len(raw), envelope=crypto.encrypt(raw, f"email-quarantine:{scan.id}")))
            scan.action_status, scan.acted_at = "done", utcnow()
        domain_row = db.get(EmailGatewayDomain, route.domain_id)
        if domain_row is not None:
            domain_row.last_message_at = utcnow()
        db.commit()
        ctx.known_senders.add(result["sender_domain"])
        return scan

    def _details(self, raw: bytes, meta: dict, rcpts: list[str], auth: dict, ctx: email_security.Context) -> dict:
        from email import message_from_bytes

        from . import email_forensics

        try:
            original = message_from_bytes(raw)
            headers = email_forensics.header_list(list(original.items()))
            message, _ = parse(raw, auth.get("header", ""))
            details = email_forensics.build(headers=headers, html=message.body_html, attachments=message.attachments, ctx=ctx,
                                            bad_ips=self.directory.bad_ips, peer=meta.get("peer", ""), helo=meta.get("helo", ""),
                                            envelope_from=meta.get("mailFrom", ""), recipients=rcpts, gateway_auth=auth,
                                            size=len(raw), tls=meta.get("tls"))
            # The gateway's own hop: who handed the message to Fenrir, and when.
            path = details.get("path") or []
            last = next((h["at"] for h in reversed(path) if h.get("at")), None)
            received = datetime.fromisoformat(meta["receivedAt"]).replace(tzinfo=timezone.utc)
            delay = None
            if last:
                try:
                    delay = max(0, int((received - datetime.fromisoformat(last)).total_seconds()))
                except ValueError:
                    delay = None
            path.append({"from": meta.get("helo") or "", "by": hostname(), "with": "ESMTPS" if meta.get("tls") else "ESMTP",
                         "ip": meta.get("peer") or "", "at": received.isoformat(), "delaySeconds": delay,
                         "raw": "received by Fenrir's mail gateway"})
            details["path"] = path
            return details
        except Exception as exc:  # noqa: BLE001 - evidence is a bonus; never stop mail for it
            log.warning("gateway evidence could not be built: %s", exc)
            return {}

    def _keep(self, db: Session, scan: EmailScan, raw: bytes, meta: dict) -> None:
        """Keep an undeliverable message (encrypted) so it can be retried from the console once the cause is fixed."""
        exists = db.execute(select(EmailQuarantine).where(EmailQuarantine.scan_id == scan.id)).scalar_one_or_none()
        if exists is None:
            db.add(EmailQuarantine(scan_id=scan.id, tenant_id=scan.tenant_id, mail_from=meta.get("mailFrom", "")[:320],
                                   recipients=list(scan.recipients or []), size=len(raw),
                                   envelope=crypto.encrypt(raw, f"email-quarantine:{scan.id}")))

    def _undeliverable(self, db: Session, route: Route, scan: EmailScan, why: str) -> None:
        from .models import Alert

        db.add(Alert(tenant_id=route.tenant_id, device_id=None, rule_id="email:undeliverable",
                     title=f"Gateway could not deliver mail for {scan.mailbox}"[:300], severity="medium", status="new",
                     details={"category": "email", "scanIds": [scan.id], "key": f"email-undeliverable:{scan.id}",
                              "summary": f"\"{scan.subject[:80]}\" from {scan.sender_address} to {', '.join(scan.recipients or [])}: "
                                         f"{why}. Fenrir kept the message: fix the cause, then press Retry delivery on it in Email security > Messages."}))

    def _retry(self, meta: dict, why: str) -> None:
        attempts = int(meta.get("attempts") or 0) + 1
        delay = RETRY_SCHEDULE[min(attempts - 1, len(RETRY_SCHEDULE) - 1)]
        meta.update(attempts=attempts, lastError=why[:300], nextAttempt=(utcnow() + timedelta(seconds=delay)).isoformat())
        self.spool.update(meta)


# --------------------------------------------------------------------------- release, purge and setup

def release(db: Session, scan: EmailScan, actor: str) -> None:
    """Deliver a quarantined gateway message to its recipients now."""
    held = db.execute(select(EmailQuarantine).where(EmailQuarantine.scan_id == scan.id)).scalar_one_or_none()
    route = db.get(EmailGatewayDomain, scan.connection_id)
    if held is None or route is None:
        raise email_actions.ActionError("The original message is no longer kept (past retention, or the domain was removed).")
    raw = crypto.decrypt_bytes(held.envelope, f"email-quarantine:{scan.id}")
    header = (f"X-Fenrir-Released-By: {actor}\r\nX-Fenrir-Verdict: released; was={scan.verdict}\r\n"
              f"X-Fenrir-Scan-Id: {scan.id}\r\n").encode()
    try:
        handed = deliver(header + raw, held.mail_from, list(held.recipients or [scan.mailbox]), route.destination,
                         route.destination_port or 25, bool(route.require_tls))
    except (TemporaryFailure, PermanentFailure) as exc:
        raise email_actions.ActionError(str(exc)) from None
    previous = (scan.details or {}).get("delivery") or {}
    scan.details = {**(scan.details or {}), "delivery": {**handed, "attempts": int(previous.get("attempts") or 0) + 1,
                                                         "releasedBy": actor}}


def purge(db: Session) -> int:
    removed = 0
    for route in db.execute(select(EmailGatewayDomain)).scalars().all():
        cutoff = utcnow() - timedelta(days=max(7, min(int(route.retention_days or 90), 730)))
        old = [i for (i,) in db.execute(select(EmailScan.id).where(EmailScan.connection_id == route.id, EmailScan.received_at < cutoff))]
        if old:
            db.execute(delete(EmailQuarantine).where(EmailQuarantine.scan_id.in_(old)))
            from .models import EmailContent

            db.execute(delete(EmailContent).where(EmailContent.scan_id.in_(old)))
            removed += db.execute(delete(EmailScan).where(EmailScan.id.in_(old))).rowcount or 0
    db.commit()
    return removed


def domain_view(row: EmailGatewayDomain) -> dict:
    return {"id": row.id, "tenantId": row.tenant_id, "domain": row.domain, "destination": row.destination,
            "destinationPort": row.destination_port, "requireTls": row.require_tls,
            "rejectUnknownRecipients": row.reject_unknown_recipients, "tagSubject": row.tag_subject,
            "actions": actions_for(row), "notify": {"digest": False, "alertEmail": "", "openTicket": False, **(row.notify or {})},
            "retentionDays": row.retention_days, "enabled": row.enabled, "m365Connector": row.m365_connector or {},
            "lastMessageAt": row.last_message_at.isoformat() + "Z" if row.last_message_at else None,
            "mx": hostname() if env("FENRIR_GATEWAY_HOSTNAME") else None}


def verified_domains(db: Session, tenant_id: str) -> set[str]:
    out = set()
    for connection in db.execute(select(M365Connection).where(M365Connection.tenant_id == tenant_id)).scalars():
        out |= {str(d.get("id") or "").lower() for d in (connection.snapshot or {}).get("domains") or [] if d.get("isVerified")}
    return out


def connect_m365(db: Session, route: EmailGatewayDomain, gateway_ips: list[str], lockdown: bool, actor: str) -> dict:
    """Create (or update) the customer's inbound connector for the gateway, with Enhanced Filtering so Microsoft sees the
    real sender's IP; with ``lockdown``, Microsoft refuses internet mail that did not come through the gateway."""
    from . import m365_exchange

    connection = db.execute(select(M365Connection).where(M365Connection.tenant_id == route.tenant_id)).scalars().first()
    if connection is None:
        raise email_actions.ActionError("This customer has no Microsoft 365 connection.")
    if not gateway_ips:
        raise email_actions.ActionError("Set FENRIR_GATEWAY_PUBLIC_IPS on the server to the gateway's public IP addresses first.")
    name = "Fenrir mail gateway"
    parameters = {"SenderDomains": ["*"], "SenderIPAddresses": gateway_ips, "RequireTls": True,
                  "RestrictDomainsToIPAddresses": bool(lockdown), "EFSkipLastIP": True}
    try:
        with m365_exchange.session(connection) as (client, token):
            existing = m365_exchange.invoke(client, connection, token, "Get-InboundConnector", {})
            if any(str(c.get("Name") or c.get("Identity") or "") == name for c in existing):
                m365_exchange.invoke(client, connection, token, "Set-InboundConnector", {"Identity": name, **parameters})
            else:
                m365_exchange.invoke(client, connection, token, "New-InboundConnector",
                                     {"Name": name, "ConnectorType": "Partner", "Comment": "Mail checked by Fenrir", **parameters})
    except m365_exchange.ExchangeError as exc:
        route.m365_connector = {"status": "failed", "error": str(exc)[:300], "at": utcnow().isoformat() + "Z", "lockdown": lockdown}
        raise email_actions.ActionError(str(exc)) from None
    route.m365_connector = {"status": "done", "error": "", "at": utcnow().isoformat() + "Z", "lockdown": lockdown, "ips": gateway_ips}
    audit.record(db, actor, "email_security.m365_connector", route.domain, route.tenant_id, lockdown=lockdown, ips=gateway_ips)
    return route.m365_connector


# --------------------------------------------------------------------------- the process

def serve(stop: threading.Event | None = None) -> None:
    """Run the SMTP listener and the spool worker until stopped."""
    from aiosmtpd.controller import Controller

    from . import db as database
    from .config import get_settings

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    database.init_engine(settings.database_url)
    factory = database.session_factory()
    directory = Directory(factory)
    spool = Spool(env("FENRIR_GATEWAY_SPOOL", "/data/mail-spool"))
    handler = Handler(directory, spool)
    controller = Controller(handler, hostname="0.0.0.0", port=int(env("FENRIR_GATEWAY_PORT", "2525")),
                            server_hostname=hostname(), tls_context=tls_context(), require_starttls=False,
                            data_size_limit=int(float(env("FENRIR_GATEWAY_MAX_MB", "35")) * 1024 * 1024),
                            ident="Fenrir mail gateway")
    controller.start()
    log.info("mail gateway listening on port %s as %s", controller.port, hostname())
    worker = Worker(directory, spool)
    stop = stop or threading.Event()
    last_purge = 0.0
    try:
        while not stop.wait(2):
            with factory() as db:
                from .main import _run_job

                _run_job(db, "email.gateway", lambda session: worker.run_once(session))
                if time.monotonic() - last_purge > 3600:
                    purge(db)
                    last_purge = time.monotonic()
    finally:
        controller.stop()


def check() -> int:
    """Health check for the container: the SMTP port answers with a 220 greeting."""
    try:
        with smtplib.SMTP("127.0.0.1", int(env("FENRIR_GATEWAY_PORT", "2525")), timeout=10) as smtp:
            return 0 if smtp.noop()[0] == 250 else 1
    except (OSError, smtplib.SMTPException):
        return 1


if __name__ == "__main__":
    import sys

    if "--check" in sys.argv:
        raise SystemExit(check())
    asyncio.set_event_loop(asyncio.new_event_loop())
    serve()
