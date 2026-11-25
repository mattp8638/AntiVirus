"""Outbound connections to addresses that customers supply (VULN-22): external scans, service checks run from the
server, and webhooks.

The server only connects to public internet addresses. A host name must resolve to public addresses only (any
private, loopback, link-local, cloud-metadata, carrier-grade NAT, multicast or reserved address refuses it), and the
scanner then connects to the address it checked, not to a second lookup, so DNS rebinding cannot redirect it.
Self-hosted installations run for one organisation may allow private targets with FENRIR_ALLOW_PRIVATE_TARGETS=true;
a multi-customer service must not, because the server's private network is not any customer's.
"""

from __future__ import annotations

import ipaddress
import os
import socket


class Blocked(ValueError):
    pass


METADATA = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("fd00:ec2::254"),
            ipaddress.ip_address("169.254.170.2"), ipaddress.ip_address("100.100.100.200")}


def private_allowed() -> bool:
    return os.getenv("FENRIR_ALLOW_PRIVATE_TARGETS", "").strip().lower() in {"1", "true", "yes"}


def is_public(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%")[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip in METADATA or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return False  # never, even where private targets are allowed
    return ip.is_global or (private_allowed() and ip.is_private)


def check_address(address: str) -> str:
    if not is_public(address):
        raise Blocked(f"{address} is not a public internet address (private, local, metadata and reserved addresses are refused)")
    return address


def resolve(host: str) -> list[str]:
    return sorted({i[4][0] for i in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})


def resolve_public(host: str) -> list[str]:
    """Every address of `host`, all of which must be public; raises Blocked, or OSError when it does not resolve."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return [check_address(host.strip("[]"))]
    except ValueError:
        pass
    addresses = resolve(host)
    bad = [a for a in addresses if not is_public(a)]
    if bad:
        raise Blocked(f"{host} resolves to {', '.join(bad)}, which is not a public internet address")
    return addresses


def guard_url_host(host: str) -> None:
    """For HTTP clients that resolve by themselves: refuse a host that resolves to non-public addresses (a host that
    does not resolve is left to fail on its own)."""
    try:
        resolve_public(host)
    except OSError:
        return
