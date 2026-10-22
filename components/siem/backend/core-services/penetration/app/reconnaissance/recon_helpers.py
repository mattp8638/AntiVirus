"""Defensive recon helpers kept after the offensive orchestrator was removed.

The original ``main_recon`` module also bundled exploit delivery, backdoor and
log-wiping phases. Those were dropped when this code was folded into the Fenrir
platform; only the asset-discovery helpers the manager needs remain here.
"""

from __future__ import annotations

from typing import Dict, List, Union


def perform_dns_enumeration(domain: str, record_type: str = "A") -> Union[List[str], str]:
    try:
        import dns.resolver  # type: ignore
    except ImportError:  # pragma: no cover - optional dependency
        return "dnspython is not installed"
    try:
        answers = dns.resolver.resolve(domain, record_type)
    except Exception as exc:  # noqa: BLE001 - surface resolver errors as text
        return f"DNS lookup failed: {exc}"
    return [answer.to_text() for answer in answers]


def generate_topology_map(active_hosts: List[Dict[str, str]], filename: str = "topology_map.png") -> str:
    raise NotImplementedError("Topology maps are rendered by the Fenrir console (Network > Topology).")
