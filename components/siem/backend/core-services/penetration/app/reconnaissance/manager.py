"""Convenience wrappers around reconnaissance submodules.

This module exposes a :class:`Reconnaissance` helper class that provides a
very small surface area for performing reconnaissance tasks.  Each method is a
thin wrapper around a function residing elsewhere in the code base.  The
wrappers mainly standardise documentation and make it easier to invoke the
underlying functionality programmatically and from tests.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from .recon_helpers import perform_dns_enumeration, generate_topology_map
import inspect


class Reconnaissance:
    """Provide granular access to reconnaissance tasks.

    Each method exposes a small unit of functionality so consumers can run
    individual tasks or compose them into a full reconnaissance phase.
    """

    def dns_enumeration(self, domain: str, record_type: str = "A") -> Union[List[str], str]:
        """Perform basic DNS enumeration.

        Parameters
        ----------
        domain:
            Domain name to query.
        record_type:
            DNS record type (``"A"`` by default).

        Returns
        -------
        list[str] or str
            List of records or an error message from
            :func:`core.reconnaissance.main_recon.perform_dns_enumeration`.
        """

        return perform_dns_enumeration(domain, record_type)

    def topology_map(self, active_hosts: List[Dict[str, str]], filename: str = "topology_map.png") -> str:
        """Create a network topology map image.

        Parameters
        ----------
        active_hosts:
            Iterable of host dictionaries as produced by discovery scans.
        filename:
            Output image filename.

        Returns
        -------
        str
            Path to the generated image returned by
            :func:`core.reconnaissance.main_recon.generate_topology_map`.
        """

        return generate_topology_map(active_hosts, filename)

    # ------------------------------------------------------------------
    # Active reconnaissance wrappers
    # ------------------------------------------------------------------

    def scan_ip_blocks(
        self,
        network: str,
        method: str,
        ports: Optional[List[int]] = None,
        timeout: int = 1,
        retries: int = 2,
        max_workers: int = 10,
    ) -> List[Dict[str, Any]]:
        """Scan an IP range for active hosts.

        Delegates to :func:`active_scanning.scan_ip_blocks.scan_ip_blocks`.

        Parameters
        ----------
        network:
            CIDR notation of the network to scan.
        method:
            Scan strategy such as ``"ping"`` or ``"arp"``.
        ports:
            Optional list of ports to probe.
        timeout, retries, max_workers:
            Configuration parameters forwarded to the underlying function.

        Returns
        -------
        list[dict]
            Discovered host information.
        """

        from .active_scanning.scan_ip_blocks import scan_ip_blocks

        return scan_ip_blocks(network, method, ports, timeout, retries, max_workers)

    def capture_packets(self, interface: str = "eth0", count: int = 10, timeout: int = 60) -> List[Dict[str, Any]]:
        """Capture network packets.

        Thin wrapper over
        :func:`active_scanning.submodules.packet_capture.capture_packets`.

        Parameters
        ----------
        interface:
            Network interface name.
        count:
            Number of packets to capture.
        timeout:
            Capture timeout in seconds.

        Returns
        -------
        list[dict]
            Simplified packet summaries.
        """

        from .active_scanning.submodules.packet_capture import capture_packets

        return capture_packets(interface, count, timeout)

    def scan_ports(
        self,
        target_ip: str,
        ports_to_scan: List[int],
        scan_type: Optional[Any] = None,
        num_threads: int = 10,
        timeout: float = 1.0,
    ) -> Dict[str, Any]:
        """Scan multiple ports on a target host.

        Delegates to :func:`active_reconnaissance.port_scanner.port_scanner.scan_ports`.

        Parameters
        ----------
        target_ip:
            IP address of the host to scan.
        ports_to_scan:
            List of port numbers.
        scan_type:
            A :class:`ScanType` value selecting the scan strategy.  Defaults to
            ``ScanType.TCP_CONNECT``.
        num_threads:
            Number of concurrent worker threads.
        timeout:
            Timeout for individual probes.

        Returns
        -------
        dict
            Summary information including discovered open ports.
        """

        from .active_reconnaissance.port_scanner.port_scanner import (
            scan_ports as _scan_ports,
            ScanType,
        )

        scan_type = scan_type or ScanType.TCP_CONNECT
        return _scan_ports(target_ip, ports_to_scan, scan_type, num_threads, timeout)

    def arp_scan_scapy(
        self,
        ip_range_or_subnet: str,
        timeout: int = 1,
        verbose: bool = False,
        retry_count: int = 1,
        packet_interval: float = 0.02,
    ) -> List[Dict[str, Any]]:
        """Perform an ARP scan using Scapy.

        Wrapper around
        :func:`active_reconnaissance.network_mapper.network_mapper.arp_scan_scapy`.
        The function returns a list of dictionaries describing live hosts or an
        error structure when Scapy is unavailable.
        """

        from .active_reconnaissance.network_mapper.network_mapper import arp_scan_scapy

        return arp_scan_scapy(ip_range_or_subnet, timeout, verbose, retry_count, packet_interval)

    def icmp_ping_sweep_scapy(
        self,
        ip_range_or_subnet: str,
        timeout: int = 1,
        verbose: bool = False,
        count_per_host: int = 1,
        packet_interval: float = 0.01,
    ) -> Dict[str, List[Any]]:
        """Perform an ICMP ping sweep using Scapy."""

        from .active_reconnaissance.network_mapper.network_mapper import icmp_ping_sweep_scapy

        return icmp_ping_sweep_scapy(ip_range_or_subnet, timeout, verbose, count_per_host, packet_interval)

    def fingerprint_os_single_target(
        self,
        target_ip: str,
        open_tcp_port: Optional[int] = None,
        timeout: float = 2.0,
    ) -> Dict[str, Any]:
        """Guess the operating system of a host."""

        from .active_reconnaissance.os_fingerprinter.os_fingerprinter import fingerprint_os_single_target as _fingerprint

        return _fingerprint(target_ip, open_tcp_port, timeout)

    def enumerate_services(
        self,
        target_ip: str,
        open_ports_map: Dict[int, Dict[str, str]],
        num_threads: int = 5,
        probe_timeout: float = 2.0,
    ) -> Dict[str, Any]:
        """Probe open ports to enumerate running services."""

        from .active_reconnaissance.service_enumerator.service_enumerator import enumerate_services as _enumerate

        return _enumerate(target_ip, open_ports_map, num_threads, probe_timeout)

    def scan_vulnerabilities(self, services: Dict[int, str]) -> Dict[str, Any]:
        """Check services against a vulnerability database."""

        from .active_reconnaissance.vulnerability_scanner.vulnerability_scanner import (
            scan_vulnerabilities as _scan_vulns,
        )

        return _scan_vulns(services)

    # ------------------------------------------------------------------
    # Passive reconnaissance wrappers
    # ------------------------------------------------------------------

    def unified_domain_lookup(
        self,
        domain: str,
        preferred_protocol: str = "try_both",
        whois_max_referrals: int = 2,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        """Perform WHOIS/RDAP lookup for a domain."""

        from .passive_reconnaissance.whois.whois import unified_domain_lookup as _lookup

        return _lookup(domain, preferred_protocol, whois_max_referrals, timeout)

    def fetch_certificates_from_ct(self, domain: str, timeout: int = 20) -> Dict[str, Any]:
        """Fetch certificate transparency information for a domain."""

        from .passive_reconnaissance.certificate_transparency.certificate_transparency import (
            fetch_certificates_from_ct as _fetch_ct,
        )

        return _fetch_ct(domain, timeout)

    def harvest_emails(
        self,
        target_domain: str,
        sources: Optional[List[str]] = None,
        base_url_to_scrape: Optional[str] = None,
        filter_by_domain: bool = True,
    ) -> Dict[str, Any]:
        """Harvest email addresses from various sources."""

        from .passive_reconnaissance.email_harvester.email_harvester import harvest_emails as _harvest

        return _harvest(target_domain, sources, base_url_to_scrape, filter_by_domain)

    def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata from a file."""

        from .passive_reconnaissance.metadata_extractor.metadata_extractor import (
            extract_metadata as _extract_metadata,
        )

        return _extract_metadata(file_path)

    def search_engine_query(
        self,
        query: str,
        num_results: int = 10,
        engine: str = "duckduckgo",
        delay: float = 1.0,
    ) -> Dict[str, Any]:
        """Query a search engine for reconnaissance purposes."""

        from .passive_reconnaissance.search_engine_scraper.search_engine_scraper import (
            search_engine_query as _search_engine_query,
        )

        return _search_engine_query(query, num_results, engine, delay)

    def scrape_social_media(
        self,
        platform: str,
        query: str,
        num_results: int = 10,
    ) -> Dict[str, Any]:
        """Scrape data from a social media platform."""

        from .passive_reconnaissance.social_media_analysis.social_media_analysis import (
            scrape_social_media as _scrape_social_media,
        )

        return _scrape_social_media(platform, query, num_results)

    def get_all_dns_records(
        self,
        domain: str,
        record_types: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Retrieve multiple DNS record types for a domain."""

        from .dns_enumeration.dns_enumeration import get_all_dns_records as _get_all_dns_records

        return _get_all_dns_records(domain, record_types)

    def attempt_zone_transfer(self, domain: str) -> Dict[str, Any]:
        """Attempt a DNS zone transfer for a domain."""

        from .dns_enumeration.dns_enumeration import attempt_zone_transfer as _attempt_zone_transfer

        return _attempt_zone_transfer(domain)

    # ------------------------------------------------------------------
    # General information / phishing helpers
    # ------------------------------------------------------------------

    def gather_all_info(self, target_ip: Optional[str] = None) -> Dict[str, str]:
        """Collect basic host information."""

        from .gather_host_info.gather_host_info import gather_all_info as _gather_all_info

        return _gather_all_info(target_ip)

    def gather_network_info(self, target_domain: Optional[str] = None) -> Dict[str, str]:
        """Collect high level network information."""

        from .gather_network_info.gather_network_info import (
            gather_network_info as _gather_network_info,
        )

        return _gather_network_info(target_domain)

    def gather_identity_info(self, target: Optional[str] = None) -> Dict[str, List[str]]:
        """Gather identity-related information such as users and groups."""

        from .gather_identity_info.gather_identity_info import (
            gather_identity_info as _gather_identity_info,
        )

        return _gather_identity_info(target)

    def phishing_for_info(self, target_domain: Optional[str] = None) -> Dict[str, List[str]]:
        """Provide phishing related intelligence for a domain."""

        from .phishing_for_info.phishing_for_info import phishing_for_info as _phishing_for_info

        return _phishing_for_info(target_domain)

    def run(self, steps: Optional[List[str]] = None, **kwargs) -> Dict[str, Any]:
        """Execute multiple reconnaissance steps sequentially.

        The method recognises the wrapper methods defined on this class such as
        ``scan_ip_blocks`` or ``unified_domain_lookup``.  Each step name in
        ``steps`` is looked up and invoked if present.  Only the arguments that
        match the wrapper's signature are forwarded, allowing a single call to
        drive several reconnaissance primitives in sequence.

        Parameters
        ----------
        steps:
            Iterable of wrapper names to invoke.  Unsupported names are
            ignored.
        **kwargs:
            Candidate arguments forwarded to each step.

        Returns
        -------
        dict
            Mapping of step name to return value.
        """

        steps = steps or []
        results: Dict[str, Any] = {}

        available_steps = {
            "dns_enumeration": self.dns_enumeration,
            "topology_map": self.topology_map,
            "scan_ip_blocks": self.scan_ip_blocks,
            "capture_packets": self.capture_packets,
            "scan_ports": self.scan_ports,
            "arp_scan_scapy": self.arp_scan_scapy,
            "icmp_ping_sweep_scapy": self.icmp_ping_sweep_scapy,
            "fingerprint_os_single_target": self.fingerprint_os_single_target,
            "enumerate_services": self.enumerate_services,
            "scan_vulnerabilities": self.scan_vulnerabilities,
            "unified_domain_lookup": self.unified_domain_lookup,
            "fetch_certificates_from_ct": self.fetch_certificates_from_ct,
            "harvest_emails": self.harvest_emails,
            "extract_metadata": self.extract_metadata,
            "search_engine_query": self.search_engine_query,
            "scrape_social_media": self.scrape_social_media,
            "get_all_dns_records": self.get_all_dns_records,
            "attempt_zone_transfer": self.attempt_zone_transfer,
            "gather_all_info": self.gather_all_info,
            "gather_network_info": self.gather_network_info,
            "gather_identity_info": self.gather_identity_info,
            "phishing_for_info": self.phishing_for_info,
        }

        for step in steps:
            func = available_steps.get(step)
            if func is None:
                continue
            sig = inspect.signature(func)
            call_args = {k: kwargs[k] for k in sig.parameters if k in kwargs}
            results[step] = func(**call_args)

        return results
