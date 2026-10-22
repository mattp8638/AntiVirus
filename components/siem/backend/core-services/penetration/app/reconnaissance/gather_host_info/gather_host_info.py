# core/reconnaissance/gather_host_info/gather_host_info.py
"""Remote host fingerprinting utilities."""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, Dict, Iterable, Optional, Sequence

from logging_config import get_logger

logger = get_logger(__name__)

_DEFAULT_BANNER_PORTS: Sequence[int] = (22, 23, 80, 443, 445, 3389)


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _resolve_target(target: str) -> str:
    """Resolve *target* to an IP address preferring IPv4 entries."""

    infos = socket.getaddrinfo(target, None)
    for family, _type, _proto, _canon, sockaddr in infos:
        address = sockaddr[0]
        if family == socket.AF_INET:
            return address
    # Fall back to the first result when no IPv4 entry is found.
    return infos[0][4][0]


def _reverse_dns_lookup(ip_address: str) -> Optional[str]:
    try:
        hostname, _aliases, _addresses = socket.gethostbyaddr(ip_address)
    except (socket.herror, socket.gaierror) as exc:
        logger.debug("Reverse DNS lookup failed for %s: %s", ip_address, exc)
        return None
    return hostname


def _collect_tcp_banners(
    ip_address: str,
    ports: Iterable[int],
    timeout: float,
) -> Dict[int, Dict[str, Optional[str]]]:
    """Attempt to capture TCP banners for *ports* on *ip_address*."""

    banners: Dict[int, Dict[str, Optional[str]]] = {}
    for port in ports:
        banner = None
        status = "closed"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip_address, port))
                if result != 0:
                    continue
                status = "open"
                # Attempt a minimal protocol interaction.
                if port in {80, 8080, 8000, 443}:
                    try:
                        sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                    except OSError as exc:
                        logger.debug("HTTP banner probe failed on %s:%s: %s", ip_address, port, exc)
                try:
                    data = sock.recv(1024)
                    if data:
                        banner = data.decode(errors="replace").strip()
                except OSError as exc:
                    logger.debug("Failed to read banner from %s:%s: %s", ip_address, port, exc)
        except OSError as exc:
            logger.debug("TCP banner probe failed for %s:%s: %s", ip_address, port, exc)
        finally:
            banners[port] = {"status": status, "banner": banner}
    return banners


def gather_all_info(
    target_ip: Optional[str] = None,
    *,
    banner_ports: Sequence[int] = _DEFAULT_BANNER_PORTS,
    timeout: float = 3.0,
) -> Dict[str, Any]:
    """Fingerprint *target_ip* and return remote host metadata.

    The helper focuses on lightweight, network-friendly probes: DNS
    resolution, reverse lookups and opportunistic banner grabbing. More
    invasive techniques (for example authenticated WMI queries) require
    explicit credentials and are therefore reported as "not attempted".
    """

    if not target_ip:
        raise ValueError("target_ip must be provided for remote host fingerprinting")

    errors = []
    resolved_ip = target_ip
    if not _is_ip_address(target_ip):
        try:
            resolved_ip = _resolve_target(target_ip)
        except socket.gaierror as exc:
            logger.warning("Failed to resolve %s: %s", target_ip, exc)
            errors.append(f"DNS resolution failed: {exc}")
            resolved_ip = None

    reverse_dns = None
    tcp_banners: Dict[int, Dict[str, Optional[str]]] = {}
    if resolved_ip:
        reverse_dns = _reverse_dns_lookup(resolved_ip)
        tcp_banners = _collect_tcp_banners(resolved_ip, banner_ports, timeout)
    else:
        logger.debug("Skipping probes because the target could not be resolved")

    info: Dict[str, Any] = {
        "target_input": target_ip,
        "resolved_ip": resolved_ip,
        "reverse_dns": reverse_dns,
        "ssh_probe": tcp_banners.get(22, {}).get("banner"),
        "wmi_probe": "not attempted (credentials required)",
        "tcp_banners": tcp_banners,
    }

    if errors:
        info["errors"] = errors

    return info

if __name__ == '__main__':
    sample_target = "127.0.0.1"
    logger.info("Host Information (Sample):")
    for key, value in gather_all_info(sample_target).items():
        logger.info(f"  {key}: {value}")
