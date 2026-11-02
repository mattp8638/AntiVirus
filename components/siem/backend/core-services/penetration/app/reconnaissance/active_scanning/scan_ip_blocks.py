"""Active IP block scanning helpers."""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Any, Dict, Iterable, List, Optional

from logging_config import get_logger

from core.reconnaissance.active_reconnaissance.port_scanner.port_scanner import (
    COMMON_PORTS,
    ScanType,
    scan_ports,
)

logger = get_logger(__name__)

_METHOD_TO_SCAN_TYPE = {
    "ping": ScanType.TCP_CONNECT,
    "tcp_connect": ScanType.TCP_CONNECT,
    "connect": ScanType.TCP_CONNECT,
    "tcp_syn": ScanType.TCP_SYN,
    "syn": ScanType.TCP_SYN,
    "udp": ScanType.UDP,
}

DEFAULT_MAX_HOSTS = 256


def _normalise_ports(port_candidates: Optional[Iterable[int]]) -> List[int]:
    ports: List[int] = []
    if port_candidates:
        for port in port_candidates:
            try:
                number = int(port)
            except (TypeError, ValueError):
                continue
            if 1 <= number <= 65535:
                ports.append(number)
    if not ports:
        ports = sorted(COMMON_PORTS.keys())
    return sorted(set(ports))


def _resolve_scan_type(method: str) -> ScanType:
    scan_type = _METHOD_TO_SCAN_TYPE.get(method.lower()) if method else None
    if scan_type:
        return scan_type
    logger.info(
        "Unknown scan method '%s'. Falling back to TCP connect scan.",
        method,
    )
    return ScanType.TCP_CONNECT


def _expand_targets(network: str) -> List[str]:
    candidates: List[str] = []
    raw = (network or "").strip()
    if not raw:
        return candidates

    for chunk in [part for part in raw.replace(";", " ").replace(",", " ").split() if part]:
        try:
            subnet = ip_network(chunk, strict=False)
        except ValueError:
            try:
                address = ip_address(chunk)
            except ValueError:
                logger.info("Skipping invalid network specification: %s", chunk)
                continue
            candidates.append(str(address))
            continue

        if subnet.num_addresses == 1:
            candidates.append(str(subnet.network_address))
            continue

        hosts = list(subnet.hosts())
        if not hosts:
            hosts = [
                ip
                for ip in subnet
                if ip != subnet.network_address and ip != getattr(subnet, "broadcast_address", None)
            ]
        if len(hosts) > DEFAULT_MAX_HOSTS:
            logger.info(
                "Network %s contains %s hosts; limiting to first %s addresses.",
                chunk,
                len(hosts),
                DEFAULT_MAX_HOSTS,
            )
            hosts = hosts[:DEFAULT_MAX_HOSTS]
        candidates.extend(str(host) for host in hosts)

    return candidates


def _format_open_ports(raw_open_ports: Any) -> List[Dict[str, Any]]:
    formatted: List[Dict[str, Any]] = []
    if isinstance(raw_open_ports, dict):
        for key, details in raw_open_ports.items():
            port: Optional[int] = None
            try:
                port = int(key)
            except (TypeError, ValueError):
                port_value = details.get("port") if isinstance(details, dict) else None
                if isinstance(port_value, int):
                    port = port_value
                elif isinstance(port_value, str) and port_value.isdigit():
                    port = int(port_value)
            entry: Dict[str, Any] = {}
            detail_data = dict(details) if isinstance(details, dict) else {}
            if port is not None:
                entry["port"] = port
                if "port" in detail_data:
                    detail_data.pop("port")
            entry.update(detail_data)
            if entry:
                formatted.append(entry)
    elif isinstance(raw_open_ports, list):
        for item in raw_open_ports:
            if isinstance(item, dict):
                if "port" in item and isinstance(item["port"], int):
                    formatted.append(dict(item))
            elif isinstance(item, int):
                formatted.append({"port": item})
            elif isinstance(item, str) and item.isdigit():
                formatted.append({"port": int(item)})
    return formatted


def scan_ip_blocks(
    network: str,
    method: str,
    ports: Optional[List[int]] = None,
    timeout: int = 1,
    retries: int = 2,
    max_workers: int = 10,
) -> List[Dict[str, Any]]:
    """Actively scan the supplied network block for open ports.

    Args:
        network: CIDR or address string describing the targets to scan. Multiple
            blocks can be supplied when separated by spaces, commas or
            semicolons.
        method: Scan method/mode. Supported values are ``"tcp_connect"``,
            ``"tcp_syn"`` and ``"udp"``. ``"ping"`` is treated as a TCP connect
            scan with host discovery handled by the port probes.
        ports: Optional iterable of ports to scan. When omitted the common port
            set defined by :mod:`port_scanner` is used.
        timeout: Timeout in seconds for individual socket operations.
        retries: Number of retries for host discovery (currently unused but
            retained for API compatibility).
        max_workers: Maximum worker threads delegated to the underlying port
            scanner.

    Returns:
        A list of dictionaries describing every host that was scanned. Each
        entry contains the IP, structured open port information and the raw
        summary returned by :func:`scan_ports`.
    """

    logger.info(
        "Starting active scan against %s using method %s", network, method
    )

    targets = _expand_targets(network)
    if not targets:
        logger.info("No valid targets discovered for network specification '%s'", network)
        return []

    ports_to_scan = _normalise_ports(ports)
    scan_type = _resolve_scan_type(method)

    results: List[Dict[str, Any]] = []
    for target_ip in targets:
        try:
            scan_summary = scan_ports(
                target_ip,
                ports_to_scan,
                scan_type=scan_type,
                num_threads=max_workers,
                timeout=timeout,
            )
        except Exception as exc:  # pragma: no cover - defensive, depends on environment
            logger.error("Port scan against %s failed: %s", target_ip, exc)
            results.append(
                {
                    "ip": target_ip,
                    "status": "error",
                    "error": str(exc),
                    "open_ports": [],
                }
            )
            continue

        raw_open_ports = scan_summary.get("open_ports") if isinstance(scan_summary, dict) else None
        structured_ports = _format_open_ports(raw_open_ports)

        host_record: Dict[str, Any] = {
            "ip": target_ip,
            "status": "up" if structured_ports else "unknown",
            "open_ports": structured_ports,
            "scan_summary": scan_summary,
        }
        if ports_to_scan:
            host_record["ports_scanned"] = ports_to_scan
        if isinstance(scan_summary, dict) and scan_summary.get("error"):
            host_record["status"] = "error"
        results.append(host_record)

    logger.info("Completed active scan of %s targets", len(results))
    return results


def get_network_range_from_gui() -> str:
    """Retrieve a placeholder network range from a GUI element."""

    logger.warning("get_network_range_from_gui is a placeholder.")
    return "192.168.1.0/24"


def get_scan_type_from_gui() -> str:
    """Retrieve a placeholder scan type from a GUI element."""

    logger.warning("get_scan_type_from_gui is a placeholder.")
    return "ping"
