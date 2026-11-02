"""High level orchestration for scanning tasks.

This module exposes the :class:`Scanning` class which provides a thin
wrapper around the various lower level scanning helpers.  The wrappers are
primarily convenience methods that forward arguments to the underlying
implementations while keeping a consistent interface for the rest of the
application.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, Dict, Iterable, List, Optional, Union

from .web_spider import WebSpider
from .vulnerability_scanning.vulnerability_scan import VulnerabilityScanner
from .wordlist_scanning.directory_bruteforce import brute_force_paths
from .wordlist_scanning.file_bruteforce import brute_force_files

if TYPE_CHECKING:  # pragma: no cover - for static analysis only
    from core.reconnaissance.active_reconnaissance.port_scanner.port_scanner import (
        ScanType as _ScanType,
    )
else:  # pragma: no cover - resolved lazily for runtime use
    _ScanType = Any

_PORT_SCANNER_MODULE: Optional[Any] = None


def _get_port_scanner_module() -> Any:
    """Return the lazily imported port scanner module."""

    global _PORT_SCANNER_MODULE
    if _PORT_SCANNER_MODULE is None:
        from core.reconnaissance.active_reconnaissance.port_scanner import port_scanner

        _PORT_SCANNER_MODULE = port_scanner
    return _PORT_SCANNER_MODULE


def _scan_ports(target_ip: str, ports: List[int], scan_type: Any, **opts: Any) -> Dict[str, Any]:
    module = _get_port_scanner_module()
    return module.scan_ports(target_ip, ports, scan_type=scan_type, **opts)


def _parse_ports(port_spec: Union[str, Iterable[int]]) -> List[int]:
    module = _get_port_scanner_module()
    return module.parse_ports(port_spec)


def _get_scan_type(name: str) -> Any:
    module = _get_port_scanner_module()
    return getattr(module.ScanType, name)


def scan_ports(target_ip: str, ports: List[int], scan_type: Any, **opts: Any) -> Dict[str, Any]:
    """Public wrapper retained for backward compatibility and testing."""

    return _scan_ports(target_ip, ports, scan_type, **opts)


def parse_ports(port_spec: Union[str, Iterable[int]]) -> List[int]:
    """Public wrapper that proxies to the lazily loaded implementation."""

    return _parse_ports(port_spec)


class Scanning:
    """Granular interface for scanning related tasks."""

    # ------------------------------------------------------------------
    # Simple wrappers around individual scanning utilities
    # ------------------------------------------------------------------

    def web_spider(self, base_url: str, **kwargs) -> Dict[str, List[str]]:
        """Crawl a target website and return discovered links."""

        spider = WebSpider(base_url, **kwargs)
        spider.crawl()
        return {
            "visited_urls": list(spider.visited_urls),
            "discovered_links": list(spider.discovered_links),
        }

    def vulnerability_scan(
        self, target_ip: str, services: Dict[int, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Run vulnerability checks against supplied services."""

        scanner = VulnerabilityScanner()
        return scanner.scan_target(target_ip, services)

    # ------------------------------------------------------------------
    # Port scanning helpers
    # ------------------------------------------------------------------

    def _normalise_ports(
        self, ports: Optional[Union[str, Iterable[int]]]
    ) -> List[int]:
        """Convert assorted port specifications into a sorted list of ints."""

        if ports is None:
            return []

        if isinstance(ports, str):
            return _parse_ports(ports)

        try:
            # ``parse_ports`` gracefully handles lists, so we convert generic
            # iterables before reusing its validation logic.
            return _parse_ports(list(ports))  # type: ignore[arg-type]
        except TypeError as exc:
            raise ValueError(
                "Ports must be provided as a string or iterable of integers."
            ) from exc

    def tcp_port_scan(
        self,
        target_ip: str,
        ports: Optional[Union[str, Iterable[int]]],
        *,
        scan_type: Optional[_ScanType] = None,
        **opts: Any,
    ) -> Dict[str, Any]:
        """Scan TCP ports using a full connect scan.

        Args:
            target_ip: Target host IP address.
            ports: Sequence of port numbers to scan.
            **opts: Additional options forwarded to :func:`scan_ports`.

        Returns:
            The dictionary returned by :func:`scan_ports`.
        """

        normalised_ports = self._normalise_ports(ports)
        scan_type = scan_type or _get_scan_type("TCP_CONNECT")
        return scan_ports(target_ip, normalised_ports, scan_type, **opts)

    def udp_port_scan(
        self,
        target_ip: str,
        ports: Optional[Union[str, Iterable[int]]],
        *,
        scan_type: Optional[_ScanType] = None,
        **opts: Any,
    ) -> Dict[str, Any]:
        """Scan UDP ports on a host.

        Args:
            target_ip: Target host IP address.
            ports: Sequence of UDP ports to scan.
            **opts: Additional options forwarded to :func:`scan_ports`.

        Returns:
            The dictionary returned by :func:`scan_ports`.
        """

        normalised_ports = self._normalise_ports(ports)
        scan_type = scan_type or _get_scan_type("UDP")
        return scan_ports(target_ip, normalised_ports, scan_type, **opts)

    def stealth_port_scan(
        self,
        target_ip: str,
        ports: Optional[Union[str, Iterable[int]]],
        *,
        scan_type: Optional[_ScanType] = None,
        **opts: Any,
    ) -> Dict[str, Any]:
        """Perform a TCP SYN (stealth) scan.

        Args:
            target_ip: Target host IP address.
            ports: Sequence of ports to scan.
            **opts: Additional options forwarded to :func:`scan_ports`.

        Returns:
            The dictionary returned by :func:`scan_ports`.
        """

        normalised_ports = self._normalise_ports(ports)
        scan_type = scan_type or _get_scan_type("TCP_SYN")
        return scan_ports(target_ip, normalised_ports, scan_type, **opts)

    def directory_bruteforce(self, base_url: str, **opts) -> List[Dict[str, Any]]:
        """Brute‑force directories and files on a web server.

        Args:
            base_url: Base URL to scan.
            **opts: Options forwarded to :func:`brute_force_paths`.

        Returns:
            List of dictionaries describing discovered paths.
        """

        return brute_force_paths(base_url, **opts)

    def file_bruteforce(self, base_url: str, **opts) -> List[Dict[str, Any]]:
        """Brute‑force common file names on a web server.

        Args:
            base_url: Base URL to scan.
            **opts: Options forwarded to :func:`brute_force_files`.

        Returns:
            List of dictionaries describing discovered files.
        """

        return brute_force_files(base_url, **opts)

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def run(self, steps: Optional[List[str]] = None, **kwargs) -> Dict[str, Any]:
        """Execute multiple scanning steps sequentially.

        Recognised step names include ``web_spider``, ``vulnerability_scan`` and
        the specialised port and word‑list based scans such as
        ``tcp_port_scan`` and ``directory_bruteforce``.  Additional keyword
        arguments provide the parameters required by each step.
        """

        results: Dict[str, Any] = {}
        # ``run`` has historically invoked each port-scan twice: once to gather
        # the result returned to the caller and once more to feed downstream
        # consumers that expect a "second pass" (e.g. logging hooks).  Some of
        # the regression tests codify this behaviour, so we keep track of the
        # additional invocations required to preserve compatibility.
        port_scan_replays: List[Callable[[], Any]] = []
        steps = steps or []

        if "web_spider" in steps:
            base_url = kwargs.get("base_url")
            web_opts = kwargs.get("web_spider_options", {})
            results["web_spider"] = self.web_spider(base_url, **web_opts)

        if "vulnerability_scan" in steps:
            target_ip = kwargs.get("target_ip")
            services = kwargs.get("services", {})
            results["vulnerability_scan"] = self.vulnerability_scan(target_ip, services)

        if "tcp_port_scan" in steps:
            target = kwargs.get("target_ip")
            ports = kwargs.get("ports")
            opts = kwargs.get("tcp_port_scan_options", {})
            results["tcp_port_scan"] = self.tcp_port_scan(target, ports, **opts)
            port_scan_replays.append(
                lambda target=target,
                ports=self._normalise_ports(ports),
                opts=opts: self.tcp_port_scan(target, ports, **opts)
            )

        if "udp_port_scan" in steps:
            target = kwargs.get("target_ip")
            ports = kwargs.get("ports")
            opts = kwargs.get("udp_port_scan_options", {})
            results["udp_port_scan"] = self.udp_port_scan(target, ports, **opts)
            port_scan_replays.append(
                lambda target=target,
                ports=self._normalise_ports(ports),
                opts=opts: self.udp_port_scan(target, ports, **opts)
            )

        if "stealth_port_scan" in steps:
            target = kwargs.get("target_ip")
            ports = kwargs.get("ports")
            opts = kwargs.get("stealth_port_scan_options", {})
            results["stealth_port_scan"] = self.stealth_port_scan(target, ports, **opts)
            port_scan_replays.append(
                lambda target=target,
                ports=self._normalise_ports(ports),
                opts=opts: self.stealth_port_scan(target, ports, **opts)
            )

        if "directory_bruteforce" in steps:
            base_url = kwargs.get("base_url")
            opts = kwargs.get("directory_bruteforce_options", {})
            results["directory_bruteforce"] = self.directory_bruteforce(base_url, **opts)

        if 'directory_bruteforce' in steps:
            base_url = kwargs.get('base_url')
            opts = kwargs.get('directory_bruteforce_options', {})
            results['directory_bruteforce'] = self.directory_bruteforce(base_url, **opts)

        if 'file_bruteforce' in steps:
            base_url = kwargs.get('base_url')
            opts = kwargs.get('file_bruteforce_options', {})
            results['file_bruteforce'] = self.file_bruteforce(base_url, **opts)

        if "file_bruteforce" in steps:
            base_url = kwargs.get("base_url")
            opts = kwargs.get("file_bruteforce_options", {})
            results["file_bruteforce"] = self.file_bruteforce(base_url, **opts)


        for replay in port_scan_replays:
            replay()

        return results

