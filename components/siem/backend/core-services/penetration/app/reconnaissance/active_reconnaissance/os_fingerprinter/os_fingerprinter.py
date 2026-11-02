import socket
import re
import time
import random  # Added import for random
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional
from logging_config import get_logger
logger = get_logger(__name__)

# Scapy is approved per network_mapper.py comments
try:
    from scapy.all import IP, TCP, ICMP, sr1, conf as scapy_conf
    scapy_conf.verb = 0 # Suppress Scapy's verbose output
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    logger.info("Warning: Scapy library not found. OS fingerprinting functionalities will be limited.")

# Default timeout for probes
DEFAULT_OS_PROBE_TIMEOUT = 2.0

# Common TTL starting values for different OS types (approximate)
# These can vary based on network hops, but initial values are somewhat standard.
TTL_OS_MAP = {
    range(1, 65): "Linux/Unix/MacOS (common)", # TTL usually starts at 64
    range(65, 129): "Windows (common)",      # TTL usually starts at 128
    range(129, 256): "Other/Network Device (e.g., Cisco, Solaris - TTL often 255)"
    # More specific ranges can be added, but this is a basic heuristic.
}

# Common TCP Window Sizes (can also vary greatly, less reliable than TTL alone)
# This is highly dependent on OS version, configuration, and network conditions.
# Format: {window_size: "OS guess"}
WINDOW_SIZE_OS_MAP = {
    5840: "Windows XP/2000 (Older)", # Often MSS dependent
    8192: "Windows 7/Vista/Server 2008 (Default)",
    65535: "Linux (Many versions, often large window, can be scaled)", # Also MacOS
    64240: "Linux (Common with window scaling)",
    16384: "Older Linux/Unix",
    # Add more specific known default window sizes if available
}


def get_os_from_ttl(ttl_value: int) -> str:
    """Guess an operating system based on TTL value."""
    if not isinstance(ttl_value, int):
        return "Unknown (Invalid TTL)"
    for ttl_range, os_guess in TTL_OS_MAP.items():
        if ttl_value in ttl_range:
            return f"{os_guess} (TTL: {ttl_value})"
    return f"Unknown OS (TTL: {ttl_value})"


def get_os_from_window_size(window_size: int) -> str:
    """Guess an operating system based on TCP window size."""
    if not isinstance(window_size, int):
        return "Unknown (Invalid Window Size)"
    if window_size in WINDOW_SIZE_OS_MAP:
        return f"{WINDOW_SIZE_OS_MAP[window_size]} (Window: {window_size})"
    return f"Potentially custom or less common OS (Window: {window_size})"


def fingerprint_os_single_target(
    target_ip: str,
    open_tcp_port: Optional[int] = None,
    timeout: float = DEFAULT_OS_PROBE_TIMEOUT,
) -> Dict[str, Any]:
    """Perform basic OS fingerprinting on a single target.

    Args:
        target_ip: Target IP address.
        open_tcp_port: Known open TCP port; if ``None`` only ICMP is used.
        timeout: Probe timeout in seconds.

    Returns:
        Dictionary containing TTL and window-size-based guesses and any errors.
    """
    if not HAS_SCAPY:
        return {
            "ip": target_ip,
            "ttl_os_guess": "Requires Scapy",
            "window_os_guess": "Requires Scapy for reliable check / open port",
            "errors": ["Scapy not available, OS fingerprinting limited."],
        }

    results = {"ip": target_ip, "ttl_os_guess": "N/A", "window_os_guess": "N/A", "errors": []}

    # 1. TTL-based guess using ICMP Echo Request (Ping)
    # This is often blocked by firewalls.
    icmp_ttl = None
    try:
        pkt = IP(dst=target_ip)/ICMP()
        reply = sr1(pkt, timeout=timeout, verbose=0)
        if reply and reply.haslayer(IP):
            icmp_ttl = reply.ttl
            results["ttl_os_guess"] = get_os_from_ttl(icmp_ttl)
            results["ttl_source"] = "ICMP Echo Reply"
        else:
            results["errors"].append("No ICMP Echo reply received (target might be down or blocking ping).")
    except Exception as e:
        results["errors"].append(f"Error during ICMP ping for TTL: {e}")

    # 2. TCP-based guess (TTL and Window Size from SYN-ACK)
    # This requires an open TCP port.
    port_to_probe = open_tcp_port
    if not port_to_probe:
        # Try a few common ports if no specific open port is given
        # This part could be integrated with the port scanner's output later.
        common_ports_to_try = [80, 443, 22, 21, 25, 3389]
        # Check which of these are actually open (simplified here, ideally use port scanner results)
        # For this standalone function, we'll just try them sequentially.
        # This is not efficient; it's better to pass a known open port.
        # print(f"No open_tcp_port provided for {target_ip}, will try common ports for TCP fingerprinting.")
        # For now, this function expects an open_tcp_port or will be less effective.
        # Let's assume if open_tcp_port is None, we can't reliably do TCP fingerprinting here without a scan.
        if not icmp_ttl: # If ping failed, really need an open port
             results["errors"].append("ICMP ping failed and no specific open TCP port provided for TCP-based fingerprinting.")
        # Fallback: if we got an ICMP TTL, we might not need to probe TCP for TTL.
        # However, window size still needs TCP.

    # If we have an open port (either provided or found), probe it.
    # For this example, we'll only proceed if open_tcp_port is explicitly given.
    # A real integration would use port scan results.
    if open_tcp_port:
        port_to_probe = open_tcp_port
        # print(f"Attempting TCP fingerprint on {target_ip}:{port_to_probe}")
        try:
            syn_pkt = IP(dst=target_ip)/TCP(dport=port_to_probe, flags="S", window=random.randint(1000,2000)*10) # Send a decent window
            syn_ack_reply = sr1(syn_pkt, timeout=timeout, verbose=0)

            if syn_ack_reply and syn_ack_reply.haslayer(TCP) and syn_ack_reply[TCP].flags == 0x12: # SYN-ACK
                tcp_ttl = syn_ack_reply.ttl
                tcp_window_size = syn_ack_reply[TCP].window

                if not icmp_ttl or (icmp_ttl and tcp_ttl != icmp_ttl) : # If ICMP TTL wasn't found or is different
                    results["ttl_os_guess"] = get_os_from_ttl(tcp_ttl)
                    results["ttl_source"] = f"TCP SYN-ACK from port {port_to_probe}"

                results["window_os_guess"] = get_os_from_window_size(tcp_window_size)
                results["tcp_details"] = {"port": port_to_probe, "ttl": tcp_ttl, "window": tcp_window_size}

                # Send RST to close
                rst_pkt = IP(dst=target_ip)/TCP(dport=port_to_probe, sport=syn_ack_reply[TCP].dport, seq=syn_ack_reply[TCP].ack, ack=syn_ack_reply[TCP].seq + 1, flags="R")
                sr1(rst_pkt, timeout=0.2, verbose=0) # Send and don't wait long
            else:
                results["errors"].append(f"No SYN-ACK received from {target_ip}:{port_to_probe} (port may be closed/filtered).")
        except Exception as e:
            results["errors"].append(f"Error during TCP fingerprinting on port {port_to_probe}: {e}")
    elif not icmp_ttl: # No ICMP TTL and no open port provided
        results["ttl_os_guess"] = "Failed (ICMP blocked & no open port for TCP method)"
        results["window_os_guess"] = "Failed (No open port for TCP method)"


    # Clean up results if some parts failed
    if not results["ttl_os_guess"] or results["ttl_os_guess"] == "N/A":
        if "Requires Scapy" not in results["ttl_os_guess"]:
             results["ttl_os_guess"] = "Could not determine TTL."
    if not results["window_os_guess"] or results["window_os_guess"] == "N/A":
        if "Requires Scapy" not in results["window_os_guess"]:
            results["window_os_guess"] = "Could not determine TCP Window Size."

    return results


if __name__ == "__main__":
    target_host = "scanme.nmap.org"
    # target_host = "127.0.0.1" # For local testing (ensure a service is running on 80 or 22)

    logger.info(f"--- OS Fingerprinting Test against: {target_host} ---")

    if not HAS_SCAPY:
        logger.info("Scapy is not available. OS Fingerprinting tests will be very limited or skipped.")
    else:
        logger.info("\n[Attempt 1: Auto-detect (ICMP Ping first, then potentially common ports if needed - simplified for example)]")
        # In a real scenario, we'd first scan for an open port if ping fails or if we want TCP window size.
        # For this example, we'll simulate knowing an open port if direct ping fails for scanme.nmap.org

        # Try with no specific open port first (relies on ICMP or internal common port check logic if added)
        # The current fingerprint_os_single_target is more effective if an open_tcp_port is given.
        # Let's try to find an open port on scanme.nmap.org (e.g. 22 or 80) to pass to the function

        known_open_port_on_scanme = 22 # SSH is usually open on scanme.nmap.org
        # If testing locally, ensure this port is open on 127.0.0.1 or change it.
        # if target_host == "127.0.0.1": known_open_port_on_scanme = 80 # Example if web server is on 80

        logger.info(f"  (Using known/assumed open port {known_open_port_on_scanme} for TCP-based fingerprinting if ICMP fails or for window size)")
        fingerprint_results = fingerprint_os_single_target(target_host, open_tcp_port=known_open_port_on_scanme, timeout=2.0)

        logger.info(f"\n  Results for {fingerprint_results.get('ip')}:")
        logger.info(f"    TTL OS Guess: {fingerprint_results.get('ttl_os_guess')} (Source: {fingerprint_results.get('ttl_source','N/A')})")
        logger.info(f"    Window OS Guess: {fingerprint_results.get('window_os_guess')}")
        if fingerprint_results.get('tcp_details'):
            logger.info(f"    TCP Details (Port {fingerprint_results['tcp_details']['port']}): TTL={fingerprint_results['tcp_details']['ttl']}, Window={fingerprint_results['tcp_details']['window']}")

        if fingerprint_results.get("errors"):
            logger.info("    Errors/Warnings:")
            for err in fingerprint_results["errors"]:
                logger.info(f"      - {err}")

    logger.info("\n--- OS Fingerprinting Test Finished ---")
