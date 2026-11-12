"""DNS over TLS (RFC 7858) for Android Private DNS.

Android's Private DNS takes one hostname and talks DNS over TLS to it on port 853, so this serves the same
filtering as the per-device DNS-over-HTTPS resolver (dnsfilter.resolve) on that port.

Which phone is asking: Private DNS carries no token, so the Fenrir app on the phone looks up
<proof>.<device id>.probe.fenrir.arpa (probe_name) through this server every few minutes and whenever its network changes. That binds
the phone's current public address to the device, and lookups from that address use its policy and are logged
against it. Until a probe arrives, the address the phone last checked in from is used. A lookup that matches no device still gets the platform's baseline protection
(malware, phishing, scam and command-and-control domains blocked) under a per-address rate limit, and is not logged
against any customer.

The certificate is the one Caddy obtains for FENRIR_DOT_HOSTNAME (a site block in the Caddyfile makes it ask), read
from Caddy's data volume and re-read when it is renewed. Android refuses a certificate it cannot verify, so a
self-signed one would not work.

Run: python -m fenrir_cloud.dot_server   (deploy/docker-compose.dot.yml)
"""
from __future__ import annotations

import asyncio
import glob
import hashlib
import hmac
import logging
import os
import socket
import ssl
import struct
import threading
import time
from collections import defaultdict
from datetime import timedelta
import dns.message
import dns.opcode
import dns.rcode
import dns.rdatatype

log = logging.getLogger("fenrir.dot")

MAX_MESSAGE = 4096
IDLE_SECONDS = 30
DEVICE_CACHE_SECONDS = 60
ANON_QUERIES_PER_MINUTE = 300
PROBE_SUFFIX = ".probe.fenrir.arpa"
BINDING_SECONDS = 6 * 3600


def probe_proof(dns_token: str) -> str:
    """Lowercase hex from the device's DNS token: DNS names are case-insensitive and resolvers may change their case."""
    return hashlib.sha256(f"fenrir-dot-probe|{dns_token}".encode()).hexdigest()[:32]


def probe_name(device) -> str:
    return f"{probe_proof(device.dns_token)}.{device.id.lower()}{PROBE_SUFFIX}"


def env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def find_certificate(hostname: str, root: str) -> tuple[str, str] | None:
    """Caddy keeps certificates at <root>/caddy/certificates/<issuer>/<host>/<host>.crt and .key."""
    explicit_cert, explicit_key = env("FENRIR_DOT_TLS_CERT"), env("FENRIR_DOT_TLS_KEY")
    if explicit_cert and explicit_key:
        return explicit_cert, explicit_key
    for cert in sorted(glob.glob(os.path.join(root, "caddy", "certificates", "*", hostname, f"{hostname}.crt"))):
        key = cert[: -len(".crt")] + ".key"
        if os.path.exists(key):
            return cert, key
    return None


class CertificateContext:
    """One SSL context for the server; a renewed certificate is loaded into it and used for new connections."""

    def __init__(self, hostname: str, root: str):
        self.hostname, self.root = hostname, root
        self._stamp: tuple[str, float, float] | None = None
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    @property
    def loaded(self) -> bool:
        return self._stamp is not None

    def refresh(self) -> bool:
        """Loads the certificate if it is new or renewed. Returns whether one is loaded."""
        found = find_certificate(self.hostname, self.root)
        if found is None:
            return self.loaded
        try:
            stamp = (found[0], os.path.getmtime(found[0]), os.path.getmtime(found[1]))
            if stamp != self._stamp:
                self.context.load_cert_chain(found[0], found[1])
                self._stamp = stamp
                log.info("DNS over TLS certificate loaded from %s", found[0])
        except (OSError, ssl.SSLError) as error:  # caught mid-renewal: keep the current one and try again later
            log.warning("could not load the certificate %s: %s", found[0], error)
        return self.loaded


class Resolver:
    """Matches a client address to a device and resolves through the normal DNS filtering."""

    def __init__(self, factory):
        self.factory = factory
        self._devices: dict[str, tuple[float, str | None]] = {}
        self._bound: dict[str, tuple[float, str]] = {}
        self._anon: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def device_for(self, db, address: str):
        from sqlalchemy import select

        from .models import Device, utcnow

        now = time.monotonic()
        with self._lock:
            bound = self._bound.get(address)
            cached = self._devices.get(address)
        if bound and now - bound[0] < BINDING_SECONDS:
            device = db.get(Device, bound[1])
            if device is not None and not getattr(device, "archived", False):
                return device
        if cached and now - cached[0] < DEVICE_CACHE_SECONDS:
            return db.get(Device, cached[1]) if cached[1] else None
        device = db.scalars(select(Device).where(
            Device.ip_address == address, Device.platform == "android",
            Device.last_seen_at >= utcnow() - timedelta(days=2)).order_by(Device.last_seen_at.desc()).limit(1)).first()
        with self._lock:
            if len(self._devices) > 50000:
                self._devices.clear()
            self._devices[address] = (now, device.id if device else None)
        return device

    def probe(self, db, address: str, query) -> bytes:
        """<token>.probe.fenrir.arpa from the phone's app: bind this address to the device and say so."""
        import dns.rrset
        from sqlalchemy import func, select

        from .models import Device

        qname = query.question[0].name.to_text().rstrip(".").lower()
        labels = qname[: -len(PROBE_SUFFIX)].split(".")
        device = None
        if len(labels) == 2 and labels[1]:
            candidate = db.get(Device, labels[1])
            if candidate is None:  # ids are stored as created; the name arrives lowercased
                candidate = db.scalars(select(Device).where(func.lower(Device.id) == labels[1]).limit(1)).first()
            if candidate is not None and candidate.dns_token and hmac.compare_digest(probe_proof(candidate.dns_token), labels[0]):
                device = candidate
        response = dns.message.make_response(query)
        if device is None:
            response.set_rcode(dns.rcode.NXDOMAIN)
            return response.to_wire()
        with self._lock:
            if len(self._bound) > 100000:
                self._bound.clear()
            self._bound[address] = (time.monotonic(), device.id)
            self._devices.pop(address, None)
        if query.question[0].rdtype == dns.rdatatype.TXT:
            response.answer.append(dns.rrset.from_text(query.question[0].name, 0, "IN", "TXT", '"fenrir-ok"'))
        return response.to_wire()

    def allow_anonymous(self, address: str) -> bool:
        now = time.monotonic()
        with self._lock:
            recent = [t for t in self._anon[address] if now - t < 60]
            if len(recent) >= ANON_QUERIES_PER_MINUTE:
                self._anon[address] = recent
                return False
            recent.append(now)
            self._anon[address] = recent
            if len(self._anon) > 50000:
                self._anon.clear()
            return True

    def resolve(self, address: str, wire: bytes) -> bytes:
        from . import dnsfilter, policy_schema, services
        from .config import get_settings

        settings = get_settings()
        with self.factory() as db:
            query = dns.message.from_wire(wire)
            if len(query.question) == 1 and query.question[0].name.to_text().rstrip(".").lower().endswith(PROBE_SUFFIX):
                return self.probe(db, address, query)
            device = self.device_for(db, address)
            if device is not None:
                resolution, _ = services.effective_policy(db, device)
                dns_settings = resolution["settings"]["dns"]
                if not dns_settings.get("enabled", True):
                    dns_settings = {**dns_settings, "blockedCategories": [], "blockDomains": [], "mode": "observe",
                                    "logQueries": "none"}
                answer, _ = dnsfilter.resolve(db, device, wire, dns_settings, settings.dns_upstream, settings.dns_sinkhole_ipv4)
                db.commit()
                return answer
            if not self.allow_anonymous(address):
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.REFUSED)
                return response.to_wire()
            return resolve_baseline(db, wire, policy_schema.defaults()["dns"], settings)


def resolve_baseline(db, wire: bytes, dns_settings: dict, settings) -> bytes:
    """No matching device: the platform's default DNS protection, nothing logged against a customer."""
    from . import blocklists, dns_ruleset, dnsfilter

    query = dns.message.from_wire(wire)
    if query.opcode() != dns.opcode.QUERY or len(query.question) != 1:
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.FORMERR)
        return response.to_wire()
    question = query.question[0]
    qname = question.name.to_text().rstrip(".")
    decision = dnsfilter.decide(qname, dns_settings, dnsfilter.INTEL.domains(db, None), blocklists.CACHE.active(db),
                                ruleset=dns_ruleset.CACHE.active(db), qtype=dns.rdatatype.to_text(question.rdtype))
    if decision.action == "block":
        return dnsfilter.blocked_response(query, dns_settings.get("blockAction", "sinkhole"), settings.dns_sinkhole_ipv4).to_wire()
    return dnsfilter.forward(wire, settings.dns_upstream)


async def serve_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, resolver: Resolver) -> None:
    peer = writer.get_extra_info("peername") or ("", 0)
    address = str(peer[0])
    if address.startswith("::ffff:"):
        address = address[7:]
    loop = asyncio.get_running_loop()
    try:
        while True:
            header = await asyncio.wait_for(reader.readexactly(2), IDLE_SECONDS)
            (length,) = struct.unpack("!H", header)
            if length == 0 or length > MAX_MESSAGE:
                break
            wire = await asyncio.wait_for(reader.readexactly(length), IDLE_SECONDS)
            try:
                answer = await loop.run_in_executor(None, resolver.resolve, address, wire)
            except Exception as error:  # a bad message or an upstream failure answers SERVFAIL, never drops the line
                log.debug("lookup from %s failed: %s", address, error)
                try:
                    response = dns.message.make_response(dns.message.from_wire(wire))
                    response.set_rcode(dns.rcode.SERVFAIL)
                    answer = response.to_wire()
                except Exception:
                    break
            writer.write(struct.pack("!H", len(answer)) + answer)
            await writer.drain()
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main_async() -> None:
    from . import db as database
    from .config import get_settings

    hostname = env("FENRIR_DOT_HOSTNAME")
    if not hostname:
        raise SystemExit("FENRIR_DOT_HOSTNAME is not set: the hostname phones use for Private DNS (for example dns.example.com)")
    database.init_engine(get_settings().database_url)
    resolver = Resolver(database.session_factory())
    certificates = CertificateContext(hostname, env("FENRIR_DOT_CADDY_DATA", "/caddy-data"))
    while not certificates.refresh():
        log.warning("waiting for Caddy to obtain a certificate for %s (add it to the Caddyfile and point its DNS here)", hostname)
        await asyncio.sleep(30)

    port = int(env("FENRIR_DOT_PORT", "8853"))
    server = await asyncio.start_server(lambda r, w: serve_connection(r, w, resolver), host="0.0.0.0", port=port,
                                        ssl=certificates.context, reuse_address=True)
    log.info("DNS over TLS for %s listening on port %s", hostname, port)
    async with server:
        while True:
            await asyncio.sleep(3600)
            certificates.refresh()  # Caddy renews well before expiry; new connections get the new certificate


def check() -> int:
    """Container health check: the port accepts a TCP connection."""
    try:
        with socket.create_connection(("127.0.0.1", int(env("FENRIR_DOT_PORT", "8853"))), timeout=5):
            return 0
    except OSError:
        return 1


if __name__ == "__main__":
    import sys

    if "--check" in sys.argv:
        raise SystemExit(check())
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    asyncio.run(main_async())
