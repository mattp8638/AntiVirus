# core/reconnaissance/gather_network_info/gather_network_info.py
import ipaddress
import platform
import shutil
import socket
import subprocess
from typing import Any, Dict, List, Optional

import dns.exception
import dns.resolver

try:  # pragma: no cover - exercised via behaviour instead
    from ipwhois import IPWhois
    from ipwhois import exceptions as ipwhois_exceptions
    IPDefinedError = ipwhois_exceptions.IPDefinedError
except ImportError:  # pragma: no cover - executed when dependency missing
    IPWhois = None  # type: ignore[assignment]

    class IPDefinedError(Exception):
        """Fallback IPDefinedError when ipwhois is unavailable."""

    class _WhoisExceptions:
        IPDefinedError = IPDefinedError

    ipwhois_exceptions = _WhoisExceptions()  # type: ignore[assignment]

from logging_config import get_logger

logger = get_logger(__name__)


def _resolve_records(
    resolver: dns.resolver.Resolver,
    name: str,
    record_type: str,
    *,
    lifetime: float,
) -> List[str]:
    """Resolve DNS records using the provided resolver."""

    answers = resolver.resolve(name, record_type, lifetime=lifetime)
    return [rdata.to_text() for rdata in answers]


def _run_traceroute(
    target: str,
    *,
    max_hops: int,
    timeout: float,
) -> List[Dict[str, Any]]:
    """Execute a lightweight traceroute using the system binary if available."""

    system = platform.system().lower()
    command: Optional[str] = None
    arguments: List[str]

    if "windows" in system:
        command = shutil.which("tracert")
        if not command:
            raise FileNotFoundError("tracert binary not available")
        arguments = [command, "-h", str(max_hops), target]
    else:
        command = shutil.which("traceroute")
        if not command:
            raise FileNotFoundError("traceroute binary not available")
        arguments = [command, "-m", str(max_hops), "-w", str(timeout), target]

    completed = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        timeout=max(timeout * max_hops, timeout),
        check=False,
    )

    output = completed.stdout or completed.stderr
    hops: List[Dict[str, Any]] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or not stripped[0].isdigit():
            continue
        parts = stripped.split()
        hop_index = parts[0]
        hops.append({
            "hop": int(hop_index) if hop_index.isdigit() else hop_index,
            "raw": stripped,
        })
    return hops


def gather_network_info(
    target_domain: Optional[str] = None,
    *,
    timeout: float = 5.0,
    resolver: Optional[dns.resolver.Resolver] = None,
    run_traceroute: bool = False,
    max_hops: int = 20,
) -> Dict[str, Any]:
    """Collect network information for the local environment or a specific target."""

    resolver = resolver or dns.resolver.Resolver()
    network_info: Dict[str, Any] = {
        "local_ip": None,
        "target_input": target_domain,
        "resolved_ips": [],
        "authoritative_nameservers": [],
        "whois": {},
        "traceroute": [],
        "errors": [],
    }

    try:
        network_info["local_ip"] = socket.gethostbyname(socket.gethostname())
    except socket.error as exc:
        logger.warning("Unable to determine local IP: %s", exc)
        network_info["errors"].append(f"Unable to determine local IP: {exc}")

    if not target_domain:
        return network_info

    resolved_ips: List[str] = []
    target_is_ip = False
    try:
        try:
            resolved_ips = [str(ipaddress.ip_address(target_domain))]
            target_is_ip = True
        except ValueError:
            resolved_ips = _resolve_records(resolver, target_domain, "A", lifetime=timeout)
    except (dns.exception.DNSException, socket.gaierror) as exc:
        logger.error("Failed to resolve target %s: %s", target_domain, exc)
        network_info["errors"].append(f"Failed to resolve target: {exc}")
    else:
        network_info["resolved_ips"] = resolved_ips

    if resolved_ips:
        if IPWhois is None:
            network_info["errors"].append(
                "WHOIS lookup unavailable: ipwhois package not installed"
            )
        else:
            ip_for_whois = resolved_ips[0]
            try:
                whois_client = IPWhois(ip_for_whois)
                network_info["whois"] = whois_client.lookup_rdap(timeout=timeout)
            except IPDefinedError as exc:
                logger.info("WHOIS lookup skipped for private IP %s: %s", ip_for_whois, exc)
                network_info["errors"].append(f"WHOIS lookup skipped: {exc}")
            except Exception as exc:  # noqa: BLE001 broad for ipwhois runtime errors
                logger.error("WHOIS lookup failed for %s: %s", ip_for_whois, exc)
                network_info["errors"].append(f"WHOIS lookup failed: {exc}")

    if not target_is_ip and resolved_ips:
        try:
            network_info["authoritative_nameservers"] = _resolve_records(
                resolver, target_domain, "NS", lifetime=timeout
            )
        except dns.exception.DNSException as exc:
            logger.warning("Failed to retrieve NS records for %s: %s", target_domain, exc)
            network_info["errors"].append(f"Failed to fetch NS records: {exc}")

    if run_traceroute and resolved_ips:
        target_for_trace = resolved_ips[0]
        try:
            network_info["traceroute"] = _run_traceroute(
                target_for_trace, max_hops=max_hops, timeout=timeout
            )
        except (FileNotFoundError, subprocess.SubprocessError, OSError) as exc:
            logger.info("Traceroute unavailable: %s", exc)
            network_info["errors"].append(f"Traceroute unavailable: {exc}")

    return network_info

if __name__ == '__main__':
    local_net_info = gather_network_info()
    logger.info("Local Network Information (Placeholder):")
    for key, value in local_net_info.items():
        logger.info(f"  {key}: {value}")

    domain_net_info = gather_network_info("example.com")
    logger.info("\nDomain Network Information (Placeholder):")
    for key, value in domain_net_info.items():
        logger.info(f"  {key}: {value}")
