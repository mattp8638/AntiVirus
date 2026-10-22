import socket
import time
from typing import Any, Dict, List, Optional
from ipaddress import ip_network, ip_address
from logging_config import get_logger
logger = get_logger(__name__)

# Scapy is an approved internal module for this project
try:
    from scapy.all import Ether, ARP, srp, IP, ICMP, sr1, conf as scapy_conf
    # Suppress Scapy's verbose output during import and runtime, unless explicitly enabled
    scapy_conf.verb = 0
    HAS_SCAPY = True
except ImportError:
    logger.info("Warning: Scapy library not found. Network mapping functionalities will be severely limited or disabled.")
    HAS_SCAPY = False
    # Define dummy functions or raise exceptions if Scapy is critical and not found
    def arp_scan_scapy(*args, **kwargs): return {"error": "Scapy not found", "partial_results": []}
    def icmp_ping_sweep_scapy(*args, **kwargs): return {"error": "Scapy not found", "partial_results": []}


EMBEDDED_OUI_DB = {
    "00:00:0C": "Cisco Systems, Inc.", "00:0C:29": "VMware, Inc.", "00:1C:42": "Microsoft (Parallels/Azure)",
    "00:50:56": "VMware, Inc.", "08:00:27": "Oracle (VirtualBox)", "00:16:3E": "XenSource Inc.",
    "00:A0:C9": "Intel Corporation", "B8:27:EB": "Raspberry Pi Foundation", "DC:A6:32": "Raspberry Pi Trading Ltd",
    "00:15:5D": "Microsoft (Hyper-V)", "00:05:69": "VMware, Inc.", "00:1B:21": "Dell Inc.",
    "00:25:90": "Hewlett Packard Enterprise", "3C:D9:2B": "Hewlett Packard", "F8:75:A4": "Apple, Inc.",
    "00:01:E6": "ASUSTek COMPUTER INC.", "00:02:55": "IBM Corp", "00:1A:A0": "Google, Inc.",
    "18:65:90": "TP-LINK TECHNOLOGIES CO.,LTD.", "CC:46:D6": "NETGEAR"
}


def get_mac_vendor(mac_address: str) -> str:
    """Return the vendor name for a given MAC address.

    Args:
        mac_address: MAC address string.

    Returns:
        Vendor name if the OUI is known, otherwise ``"Unknown"``.
    """
    if not mac_address or not isinstance(mac_address, str):
        return "Unknown"
    norm_mac = mac_address.upper().replace("-", ":").replace(".", ":")
    oui_prefix = norm_mac[:8]
    return EMBEDDED_OUI_DB.get(oui_prefix, "Unknown")


def resolve_hostname_socket(ip_address: str) -> Optional[str]:
    """Resolve an IP address to a hostname using socket DNS lookup.

    Args:
        ip_address: IP address to resolve.

    Returns:
        Hostname string or ``None`` if resolution fails.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror):
        return None
    except Exception:
        return None

def arp_scan_scapy(
    ip_range_or_subnet: str,
    timeout: int = 1,
    verbose: bool = False,
    retry_count: int = 1,
    packet_interval: float = 0.02,
) -> List[Dict[str, Any]]:
    """Perform an ARP scan using Scapy.

    Args:
        ip_range_or_subnet: Target range in CIDR notation.
        timeout: Timeout per request in seconds.
        verbose: Whether to print verbose output via Scapy.
        retry_count: Number of retries for unanswered requests.
        packet_interval: Interval between packets.

    Returns:
        List of dictionaries describing live hosts or an error structure if
        Scapy is unavailable.
    """
    if not HAS_SCAPY:
        return {"error": "Scapy not installed, ARP scan unavailable.", "partial_results": []}

    live_hosts_details: List[Dict[str, Any]] = []
    try:
        arp_request = ARP(pdst=str(ip_range_or_subnet))
        broadcast_ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast_ether / arp_request
        answered, _ = srp(packet, timeout=timeout, verbose=verbose, retry=retry_count, inter=packet_interval, iface_hint=str(ip_range_or_subnet))

        for sent_pkt, received_pkt in answered:
            ip = received_pkt.psrc
            mac = received_pkt.hwsrc
            hostname = resolve_hostname_socket(ip) or ip
            vendor = get_mac_vendor(mac)
            live_hosts_details.append({
                "ip": ip, "mac": mac, "hostname": hostname, "vendor": vendor,
                "status": "up", "method": "arp"
            })
            if verbose: logger.info(f"ARP Found: IP={ip}, MAC={mac}, Hostname={hostname}, Vendor={vendor}")
    except RuntimeError as e: # Scapy might raise RuntimeError for network interface issues
        return {"error": f"Scapy runtime error during ARP scan (interface issue?): {e}", "partial_results": live_hosts_details}
    except Exception as e:
        return {"error": f"Error during ARP scan with Scapy: {e}", "partial_results": live_hosts_details}
    return live_hosts_details

def icmp_ping_sweep_scapy(
    ip_range_or_subnet: str,
    timeout: int = 1,
    verbose: bool = False,
    count_per_host: int = 1,
    packet_interval: float = 0.01,
) -> Dict[str, List[Any]]:
    """Perform an ICMP ping sweep using Scapy.

    Args:
        ip_range_or_subnet: Target range in CIDR notation.
        timeout: Timeout per request in seconds.
        verbose: Whether to output verbose information.
        count_per_host: Number of pings per host.
        packet_interval: Delay between packets.

    Returns:
        Dictionary containing lists of live hosts, unreachable hosts and any
        encountered errors.
    """
    if not HAS_SCAPY:
        return {"error": "Scapy not installed, ICMP scan unavailable.", "partial_results": []}

    live_hosts: List[Dict[str, Any]] = []
    unreachable_hosts: List[Dict[str, Any]] = []
    scapy_errors: List[Dict[str, Any]] = []
    general_errors: List[str] = []

    try:
        network = ip_network(ip_range_or_subnet, strict=False)
        target_ips = [str(ip_obj) for ip_obj in network.hosts()]
        if not target_ips and network.num_addresses == 1:
            target_ips = [str(network.network_address)]

        if not target_ips:
            general_errors.append("No valid target IPs generated from specification.")
            return {"live_hosts": [], "unreachable_hosts": [], "scapy_errors": [], "general_errors": general_errors}


        def ping_single_ip(ip_addr_str):
            if verbose: logger.info(f"  Pinging {ip_addr_str}...")
            try:
                reply = sr1(IP(dst=ip_addr_str)/ICMP(), timeout=timeout, verbose=False, retry=0)
                if reply and reply.haslayer(ICMP) and reply[ICMP].type == 0:
                    hostname = resolve_hostname_socket(ip_addr_str) or ip_addr_str
                    return {"status": "up", "ip": ip_addr_str, "hostname": hostname, "method": "icmp"}
                return {"status": "down_or_filtered", "ip": ip_addr_str}
            except RuntimeError as e_scapy:
                if verbose:
                    print(f"    Scapy runtime error pinging {ip_addr_str}: {e_scapy}")
                return {"status": "error_scapy", "ip": ip_addr_str, "error_message": str(e_scapy)}
            except Exception as e_generic:
                if verbose:
                    print(f"    Generic error pinging {ip_addr_str}: {e_generic}")
                else: # No reply or not an ICMP Echo Reply
                    return {"status": "down_or_filtered", "ip": ip_addr_str}
            except RuntimeError as e_scapy: # Scapy runtime errors (e.g., "no route found", permissions for raw socket)
                if verbose: logger.info(f"    Scapy runtime error pinging {ip_addr_str}: {e_scapy}")
                return {"status": "error_scapy", "ip": ip_addr_str, "error_message": str(e_scapy)}
            except Exception as e_generic:
                if verbose: logger.info(f"    Generic error pinging {ip_addr_str}: {e_generic}")
                return {"status": "error_generic", "ip": ip_addr_str, "error_message": str(e_generic)}

        from concurrent.futures import ThreadPoolExecutor, as_completed
        num_threads = min(len(target_ips), 32)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            future_to_ip = {executor.submit(ping_single_ip, ip_s): ip_s for ip_s in target_ips}
            for future in as_completed(future_to_ip):
                ip_s = future_to_ip[future]
                try:
                    res = future.result()
                    if res["status"] == "up":
                        live_hosts.append({"ip": res["ip"], "mac": None, "hostname": res["hostname"], "vendor": None, "status": "up", "method": "icmp"})
                        if verbose: logger.info(f"ICMP Reply from: IP={res['ip']}, Hostname={res['hostname']}")
                    elif res["status"] == "down_or_filtered":
                        unreachable_hosts.append({"ip": res["ip"], "status": "down_or_filtered"})
                    elif res["status"] == "error_scapy":
                        scapy_errors.append({"ip": res["ip"], "error": res["error_message"]})
                    elif res["status"] == "error_generic":
                        general_errors.append(f"Error on IP {res['ip']}: {res['error_message']}")
                except Exception as exc:
                    general_errors.append(f"Exception processing result for IP {ip_s}: {exc}")

                if packet_interval > 0 and num_threads > 10:
                    time.sleep(packet_interval / num_threads)

    except ValueError as e_val:
        general_errors.append(f"Invalid IP range/subnet for ICMP Ping Sweep: {e_val}")
    except ImportError:
        general_errors.append("concurrent.futures module not found, cannot run concurrent ping sweep.")
    except Exception as e_outer:
        general_errors.append(f"Outer error during ICMP Ping Sweep with Scapy: {e_outer}")

    return {
        "live_hosts": live_hosts,
        "unreachable_hosts": unreachable_hosts,
        "scapy_errors": scapy_errors,
        "general_errors": general_errors,
    }


def discover_network_hosts(
    target_spec: str,
    do_arp: bool = True,
    do_icmp: bool = True,
    arp_timeout: int = 1,
    icmp_timeout: int = 1,
    verbose: bool = False,
) -> Dict[str, Any]:
    """Discover hosts on a network using ARP and/or ICMP.

    Args:
        target_spec: IP range or single IP specification.
        do_arp: Whether to perform an ARP scan.
        do_icmp: Whether to perform an ICMP sweep.
        arp_timeout: Timeout for ARP requests.
        icmp_timeout: Timeout for ICMP requests.
        verbose: Emit verbose output during scanning.

    Returns:
        Dictionary with discovered live hosts and any errors encountered.
    """
    if not HAS_SCAPY:
        return {"live_hosts": [], "unreachable_hosts": [], "scapy_errors": [], "errors": ["Scapy library not found. Network discovery is unavailable."]}

    all_hosts_map: Dict[str, Dict[str, Any]] = {}
    combined_errors: List[str] = []

    if not target_spec:
        combined_errors.append("Target specification cannot be empty.")
        return {"live_hosts": [], "errors": combined_errors}

    if do_arp:
        if verbose: logger.info(f"\nStarting ARP scan for '{target_spec}'...")
        arp_scan_result = arp_scan_scapy(target_spec, timeout=arp_timeout, verbose=verbose) # This returns a list or a dict with error

        if isinstance(arp_scan_result, dict) and "error" in arp_scan_result:
            combined_errors.append(f"ARP Scan Error: {arp_scan_result['error']}")
            # Process partial results if any
            for host_data in arp_scan_result.get("partial_results", []):
                all_hosts_map[host_data['ip']] = host_data
        elif isinstance(arp_scan_result, list):
            for host_data in arp_scan_result:
                all_hosts_map[host_data['ip']] = host_data
        if verbose: logger.info("ARP scan finished.")

    if do_icmp:
        if verbose: logger.info(f"\nStarting ICMP Ping Sweep for '{target_spec}'...")
        # Use the enhanced icmp_ping_sweep_scapy which returns a dict
        icmp_results_dict = icmp_ping_sweep_scapy(target_spec, timeout=icmp_timeout, verbose=verbose)

        if icmp_results_dict.get("general_errors"):
            for err in icmp_results_dict["general_errors"]: combined_errors.append(f"ICMP General Error: {err}")
        if icmp_results_dict.get("scapy_errors"):
            for err_info in icmp_results_dict["scapy_errors"]: combined_errors.append(f"ICMP Scapy Error for {err_info['ip']}: {err_info['error']}")

        for host_info in icmp_results_dict.get("live_hosts", []):
            ip = host_info['ip']
            if ip in all_hosts_map: # Host found by ARP, update/merge with ICMP info
                all_hosts_map[ip]['status'] = 'up' # Confirm up
                # Append 'icmp' to method if not already there from ARP merge
                current_methods = set(m.strip() for m in all_hosts_map[ip].get('method', '').split(',') if m.strip())
                current_methods.add('icmp')
                all_hosts_map[ip]['method'] = ', '.join(sorted(list(current_methods)))

                # Prioritize hostname from ARP if available, else from ICMP
                if not all_hosts_map[ip].get('hostname') or all_hosts_map[ip]['hostname'] == ip:
                    all_hosts_map[ip]['hostname'] = host_info['hostname']
            else: # New host found purely by ICMP
                all_hosts_map[ip] = host_info # host_info already has method='icmp'
        if verbose: logger.info("ICMP Ping Sweep finished.")

    # Final clean up of method field for all entries, ensuring uniqueness and sorting
    for ip_addr in all_hosts_map:
        if 'method' in all_hosts_map[ip_addr] and isinstance(all_hosts_map[ip_addr]['method'], str):
            unique_methods = sorted(list(set(m.strip() for m in all_hosts_map[ip_addr]['method'].split(',') if m.strip())))
            all_hosts_map[ip_addr]['method'] = ', '.join(unique_methods)

    return {"live_hosts": list(all_hosts_map.values()), "errors": combined_errors}


if __name__ == "__main__":
    logger.info("--- Network Mapper (Scapy-based) Example ---")
    if not HAS_SCAPY:
        logger.info("Scapy is not installed. Examples cannot run.")
    else:
        logger.info("NOTE: Scapy functions (ARP, ICMP) often require root/administrator privileges.")
        logger.info("      Testing against localhost and a public DNS server.")

        logger.info("\nTesting ICMP against localhost (127.0.0.1)...")
        results_localhost = discover_network_hosts("127.0.0.1", do_arp=False, do_icmp=True, verbose=True)
        if results_localhost["errors"]: logger.info(f"  Errors: {results_localhost['errors']}")
        logger.info("  Live hosts for 127.0.0.1 (ICMP):")
        for h in results_localhost["live_hosts"]: logger.info(f"    - {h}")

        public_target = "8.8.8.8" # Google's DNS
        logger.info(f"\nTesting ICMP against public target ({public_target})...")
        results_public = discover_network_hosts(public_target, do_arp=False, do_icmp=True, icmp_timeout=2, verbose=True)
        if results_public["errors"]: logger.info(f"  Errors: {results_public['errors']}")
        logger.info(f"  Live hosts for {public_target} (ICMP):")
        for h in results_public["live_hosts"]: logger.info(f"    - {h}")

        # Example for local ARP scan - replace with your actual local subnet for testing
        # This part is highly environment-dependent and requires privileges.
        # local_subnet_for_test = "192.168.1.0/24" # !!! CHANGE THIS TO YOUR SUBNET !!!
        # print(f"\n(Potentially) Testing ARP & ICMP against local subnet: {local_subnet_for_test}")
        # print("(This requires appropriate privileges and network setup)")
        # results_local_lan = discover_network_hosts(local_subnet_for_test, do_arp=True, do_icmp=True, arp_timeout=2, icmp_timeout=1, verbose=False) # Verbose false for less output
        # if results_local_lan["errors"]: print(f"  Errors: {results_local_lan['errors']}")
        # print(f"  Live hosts for {local_subnet_for_test} (ARP & ICMP) - found {len(results_local_lan['live_hosts'])}:")
        # for h_idx, h_info in enumerate(results_local_lan["live_hosts"]):
        #     if h_idx < 5 : print(f"    - {h_info}") # Print first 5
        # if len(results_local_lan['live_hosts']) > 5: print(f"    ... and {len(results_local_lan['live_hosts']) - 5} more.")


    logger.info("\n--- Network Mapper Example Finished ---")
