"""A minimal STUN server (RFC 5389 Binding only) so remote sessions can go peer-to-peer without any outside service.

WebRTC needs to learn each side's public address to connect a technician's browser straight to a device. Normally that
comes from a public STUN server run by someone else; here the Fenrir server answers itself, on UDP 3478 by default
(``FENRIR_STUN_PORT``, 0 turns it off). It only reflects the sender's address back: no relaying, no credentials, nothing
stored. When a direct connection is impossible (strict firewalls, symmetric NAT), sessions use the WebSocket relay.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import struct

log = logging.getLogger("fenrir.stun")

MAGIC = 0x2112A442
BINDING_REQUEST, BINDING_SUCCESS = 0x0001, 0x0101
XOR_MAPPED_ADDRESS, SOFTWARE = 0x0020, 0x8022


def response(request: bytes, address: tuple) -> bytes | None:
    """The Binding Success response for a Binding Request from ``address``, or None for anything else."""
    if len(request) < 20:
        return None
    kind, length, cookie = struct.unpack("!HHI", request[:8])
    transaction = request[8:20]
    if kind != BINDING_REQUEST or cookie != MAGIC or length + 20 > len(request) or length % 4:
        return None
    ip = ipaddress.ip_address(address[0])
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    port = address[1] ^ (MAGIC >> 16)
    if ip.version == 4:
        value = struct.pack("!BBH", 0, 0x01, port) + struct.pack("!I", int(ip) ^ MAGIC)
    else:
        mask = struct.pack("!I", MAGIC) + transaction
        value = struct.pack("!BBH", 0, 0x02, port) + bytes(a ^ b for a, b in zip(ip.packed, mask))
    attrs = struct.pack("!HH", XOR_MAPPED_ADDRESS, len(value)) + value
    software = b"fenrir"
    attrs += struct.pack("!HH", SOFTWARE, len(software)) + software + b"\x00" * (-len(software) % 4)
    return struct.pack("!HHI", BINDING_SUCCESS, len(attrs), MAGIC) + transaction + attrs


class _Protocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            reply = response(data, addr)
        except (ValueError, struct.error):
            return
        if reply:
            self.transport.sendto(reply, addr)


async def serve(port: int, host: str = "0.0.0.0"):
    """Start answering on UDP ``port``. Returns the transport (close it to stop), or None if the port is unavailable."""
    loop = asyncio.get_running_loop()
    try:
        transport, _ = await loop.create_datagram_endpoint(_Protocol, local_addr=(host, port))
    except OSError as exc:
        log.warning("STUN on UDP %s is unavailable (%s): remote sessions will use the relay only", port, exc)
        return None
    log.info("STUN answering on UDP %s for direct remote sessions", port)
    return transport


def port() -> int:
    try:
        return int(os.getenv("FENRIR_STUN_PORT", "3478"))
    except ValueError:
        return 0


def ice_servers(public_url: str) -> list[dict]:
    """What browsers and agents use to find their public addresses: this server's STUN port, if it is on."""
    from urllib.parse import urlparse

    stun_port = port()
    host = urlparse(public_url).hostname or ""
    if not stun_port or not host or host in {"localhost", "127.0.0.1"}:
        return []
    return [{"urls": [f"stun:{host}:{stun_port}"]}]
