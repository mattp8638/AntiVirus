"""Android Private DNS: phones are told the DNS-over-TLS hostname when their policy asks for it, and the DNS-over-TLS
server matches a phone by its probe and filters with that phone's policy (baseline protection for unknown addresses)."""
import asyncio
import dataclasses
import struct

import dns.message
import dns.rdatatype

from conftest import enroll
from fenrir_cloud import config, dnsfilter, dot_server, policy_schema
from fenrir_cloud import db as database
from fenrir_cloud.models import Device
from fenrir_cloud.routers import agent_api


def phone(client, admin, tenant):
    return enroll(client, admin, tenant, hostname="Pixel-8-Jo", os_version="Android 15 (Google Pixel 8)", serial="PX8-1")


def android_tenant(client, admin):
    reply = client.post("/api/console/tenants", json={"name": "Phones Ltd", "template": "android"}, headers=admin)
    assert reply.status_code == 200, reply.text
    return reply.json()


def with_hostname(monkeypatch, hostname):
    settings = dataclasses.replace(config.get_settings(), dot_hostname=hostname)
    monkeypatch.setattr(agent_api, "get_settings", lambda: settings)


def check_in(client, dev):
    reply = client.post(f"/api/v1/devices/{dev['deviceId']}/policy-check-in", headers=dev["headers"], json={})
    assert reply.status_code == 200, reply.text
    return reply.json()["policy"]


def heartbeat_revision(client, dev):
    reply = client.post(f"/api/v1/devices/{dev['deviceId']}/heartbeat", headers=dev["headers"], json={"agentVersion": "0.2.0"})
    assert reply.status_code == 200, reply.text
    return reply.json()["effectivePolicyRevision"]


def test_android_template_turns_private_dns_on():
    assert policy_schema.template_settings("android")["android"]["privateDns"] == "fenrir"
    assert policy_schema.defaults()["android"]["privateDns"] == "off"
    assert policy_schema.validate_partial({"android": {"privateDns": "fenrir"}}) is not None


def test_phone_is_told_the_hostname_only_when_policy_and_server_both_have_it(client, admin, tenant, monkeypatch):
    # Policy asks for it, but the server has no DNS over TLS: nothing is sent, so phones keep their normal DNS.
    phones = android_tenant(client, admin)
    dev = phone(client, admin, phones)
    plain = check_in(client, dev)
    assert plain["modules"]["android"]["privateDns"] == "fenrir" and "privateDnsHost" not in plain["modules"]["android"]

    with_hostname(monkeypatch, "dns.fenrir.test")
    doc = check_in(client, dev)
    android = doc["modules"]["android"]
    assert android["privateDnsHost"] == "dns.fenrir.test"
    with database.session_factory()() as db:
        assert android["privateDnsProbe"] == dot_server.probe_name(db.get(Device, dev["deviceId"]))
    assert android["privateDnsProbe"] == android["privateDnsProbe"].lower()
    # The hostname is part of the revision, and the heartbeat reports the same revision (no fetch loop on the phone).
    assert doc["revision"] != plain["revision"]
    assert heartbeat_revision(client, dev) == doc["revision"]

    # A policy that leaves it off sends nothing even with the server set up.
    other = phone(client, admin, tenant)
    assert "privateDnsHost" not in check_in(client, other)["modules"]["android"]


def _blocked(answer: bytes) -> bool:
    reply = dns.message.from_wire(answer)
    return any(rr.to_text() == "0.0.0.0" for rrset in reply.answer for rr in rrset) or reply.rcode() == dns.rcode.NXDOMAIN


def test_dot_resolver_binds_a_phone_by_its_probe_and_uses_its_policy(client, admin, tenant):
    import dns.rcode  # noqa: F401  (used by _blocked)

    phones = android_tenant(client, admin)
    dev = phone(client, admin, phones)
    reply = client.post("/api/console/intel/indicators", headers=admin,
                        json={"values": ["parcel-redelivery.example"], "verdict": "malicious", "tenantId": phones["id"]})
    assert reply.status_code == 200, reply.text
    dnsfilter.INTEL.invalidate()
    resolver = dot_server.Resolver(database.session_factory())

    # Unknown token: not bound, NXDOMAIN.
    answer = dns.message.from_wire(resolver.resolve("203.0.113.9", dns.message.make_query("nope.probe.fenrir.arpa", "TXT").to_wire()))
    assert answer.rcode() == dns.rcode.NXDOMAIN

    with database.session_factory()() as db:
        name = dot_server.probe_name(db.get(Device, dev["deviceId"]))
    # A wrong proof for a real device is refused too.
    forged = "0" * 32 + name[32:]
    assert dns.message.from_wire(resolver.resolve("203.0.113.9", dns.message.make_query(forged, "TXT").to_wire())).rcode() == dns.rcode.NXDOMAIN
    probe = dns.message.make_query(name.upper(), "TXT")  # resolvers may randomise case
    answer = dns.message.from_wire(resolver.resolve("203.0.113.9", probe.to_wire()))
    assert answer.rcode() == dns.rcode.NOERROR and '"fenrir-ok"' in answer.answer[0].to_text()

    with database.session_factory()() as db:
        assert resolver.device_for(db, "203.0.113.9").id == dev["deviceId"]
        assert resolver.device_for(db, "198.51.100.1") is None

    # The tenant's own indicator blocks for the bound phone...
    query = dns.message.make_query("track.parcel-redelivery.example", "A").to_wire()
    assert _blocked(resolver.resolve("203.0.113.9", query))


def test_dot_unknown_address_gets_baseline_protection_and_is_rate_limited(client, admin, tenant, monkeypatch):
    import dns.rcode

    client.post("/api/console/intel/indicators", headers=admin, json={"values": ["fake-bank-login.example"], "verdict": "malicious"})
    dnsfilter.INTEL.invalidate()
    resolver = dot_server.Resolver(database.session_factory())
    query = dns.message.make_query("fake-bank-login.example", "A").to_wire()
    assert _blocked(resolver.resolve("198.51.100.7", query))

    monkeypatch.setattr(dot_server, "ANON_QUERIES_PER_MINUTE", 1)
    other = dot_server.Resolver(database.session_factory())
    other.resolve("198.51.100.8", query)
    assert dns.message.from_wire(other.resolve("198.51.100.8", query)).rcode() == dns.rcode.REFUSED


def test_dot_framing_answers_each_length_prefixed_message():
    class Fixed:
        def resolve(self, address, wire):
            reply = dns.message.make_response(dns.message.from_wire(wire))
            return reply.to_wire()

    async def run():
        server = await asyncio.start_server(lambda r, w: dot_server.serve_connection(r, w, Fixed()), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        ids = []
        for name in ("a.example", "b.example"):
            query = dns.message.make_query(name, "A")
            wire = query.to_wire()
            writer.write(struct.pack("!H", len(wire)) + wire)
            await writer.drain()
            (length,) = struct.unpack("!H", await reader.readexactly(2))
            ids.append((query.id, dns.message.from_wire(await reader.readexactly(length)).id))
        writer.close()
        server.close()
        await server.wait_closed()
        return ids

    for sent, received in asyncio.run(run()):
        assert sent == received


def test_certificate_is_found_in_caddy_storage(tmp_path):
    folder = tmp_path / "caddy" / "certificates" / "acme-v02.api.letsencrypt.org-directory" / "dns.fenrir.test"
    folder.mkdir(parents=True)
    (folder / "dns.fenrir.test.crt").write_text("cert")
    (folder / "dns.fenrir.test.key").write_text("key")
    found = dot_server.find_certificate("dns.fenrir.test", str(tmp_path))
    assert found == (str(folder / "dns.fenrir.test.crt"), str(folder / "dns.fenrir.test.key"))
    assert dot_server.find_certificate("other.fenrir.test", str(tmp_path)) is None
