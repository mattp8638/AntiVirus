"""Service enumeration helpers used to enrich reconnaissance data."""

from __future__ import annotations

import re
import socket
from typing import Any, Callable, Dict, Iterable, List, Optional

from logging_config import get_logger

from core.reconnaissance.active_reconnaissance.port_scanner.port_scanner import (
    COMMON_PORTS,
)

logger = get_logger(__name__)

# Default timeout for lightweight banner grabbing during enumeration.
DEFAULT_BANNER_TIMEOUT = 1.5


BannerGrabber = Callable[[str, int, str, float], Optional[str]]


def _default_banner_grabber(
    target_ip: str, port: int, protocol: str, timeout: float
) -> Optional[str]:
    """Attempt to grab a banner from a TCP service."""

    if protocol.lower() != "tcp":
        return None

    try:
        with socket.create_connection((target_ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in {80, 443, 8000, 8080, 8081, 8888, 8443}:
                try:
                    request = f"HEAD / HTTP/1.0\r\nHost: {target_ip}\r\n\r\n"
                    sock.sendall(request.encode("ascii", errors="ignore"))
                except OSError:
                    # Failure to send an HTTP request should not break enumeration.
                    pass
            try:
                data = sock.recv(1024)
            except socket.timeout:
                return None
            if not data:
                return None
            return data.decode("utf-8", errors="ignore").strip() or None
    except OSError:
        return None


def _extract_version_from_banner(banner: Optional[str]) -> Optional[str]:
    if not banner:
        return None
    matches = re.findall(r"\d+(?:\.\d+)+", banner)
    if matches:
        return matches[-1]
    return None


def _infer_service_name(port: int, banner: Optional[str], fallback: Optional[str]) -> str:
    if banner:
        lowered = banner.lower()
        if "https" in lowered:
            return "https"
        if "http" in lowered:
            return "http"
        if "ftp" in lowered:
            return "ftp"
        if "ssh" in lowered:
            return "ssh"
        if "smtp" in lowered:
            return "smtp"
        if "imap" in lowered:
            return "imap"
        if "pop3" in lowered:
            return "pop3"
    if fallback:
        return fallback
    return COMMON_PORTS.get(port, "unknown")


def _normalise_port_entry(entry: Any) -> Optional[Dict[str, Any]]:
    if isinstance(entry, dict):
        data = dict(entry)
        port_value = data.pop("port", None)
        if port_value is None and "id" in data:
            port_value = data.pop("id")
        if isinstance(port_value, str) and port_value.isdigit():
            port_value = int(port_value)
        if isinstance(port_value, int):
            data.setdefault("status", "open")
            data.setdefault("protocol", "tcp")
            return {"port": port_value, **data}
        return None
    if isinstance(entry, int):
        return {"port": entry, "status": "open", "protocol": "tcp"}
    if isinstance(entry, str) and entry.isdigit():
        return {"port": int(entry), "status": "open", "protocol": "tcp"}
    return None


def enumerate_services(
    target_ip: str,
    ports: Iterable[Any],
    *,
    banner_grabber: Optional[BannerGrabber] = None,
    timeout: float = DEFAULT_BANNER_TIMEOUT,
) -> Dict[int, Dict[str, Any]]:
    """Enrich open port information with service banners and versions."""

    grabber = banner_grabber or _default_banner_grabber
    services: Dict[int, Dict[str, Any]] = {}

    for entry in ports:
        normalised = _normalise_port_entry(entry)
        if not normalised:
            continue

        port = normalised.pop("port")
        status = str(normalised.get("status", "open"))
        protocol = str(normalised.get("protocol", "tcp"))
        service_guess = normalised.get("service_name") or normalised.get("service")
        if not service_guess:
            service_guess = normalised.get("service_guess")

        banner: Optional[str] = None
        if status.lower().startswith("open"):
            try:
                banner = grabber(target_ip, port, protocol, timeout)
            except Exception as exc:  # pragma: no cover - defensive guard
                logger.debug(
                    "Banner grab failed for %s:%s (%s): %s",
                    target_ip,
                    port,
                    protocol,
                    exc,
                )
                banner = None

        service_name = _infer_service_name(port, banner, service_guess)
        version = _extract_version_from_banner(banner)

        info: Dict[str, Any] = {
            **normalised,
            "status": status,
            "protocol": protocol,
            "service_name": service_name,
            "banner": banner,
            "version": version,
            "source": normalised.get("source", "service_enumeration"),
        }

        services[port] = info

    return services


__all__ = ["enumerate_services", "DEFAULT_BANNER_TIMEOUT"]

