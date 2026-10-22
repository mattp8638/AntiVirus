import socket
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum
from typing import Any, Dict, List, Optional
from logging_config import get_logger
logger = get_logger(__name__)

# Scapy is approved per network_mapper.py comments
try:
    from scapy.all import IP, TCP, UDP, ICMP, sr1, sr, conf as scapy_conf
    scapy_conf.verb = 0 # Suppress Scapy's verbose output
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    logger.info("Warning: Scapy library not found. Advanced scans (SYN, UDP with Scapy) will be disabled.")

# Default timeout for socket connections in seconds
DEFAULT_SOCKET_TIMEOUT = 1.0
# Default number of threads for concurrent scanning
DEFAULT_THREADS = 10

class ScanType(Enum):
    TCP_CONNECT = "TCP Connect"
    TCP_SYN = "TCP SYN"
    UDP = "UDP"

COMMON_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP Server", 68: "DHCP Client", 69: "TFTP",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 123: "NTP", 135: "MS RPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 162: "SNMP Trap", 389: "LDAP",
    443: "HTTPS", 445: "Microsoft-DS (SMB)", 465: "SMTPS", # SMTP over SSL
    500: "ISAKMP (IKE)", 514: "Syslog", 587: "SMTP Submission", # Often used for email client submission
    636: "LDAPS", # LDAP over SSL
    993: "IMAPS", 995: "POP3S",
    1080: "SOCKS Proxy",
    1433: "Microsoft SQL Server", 1434: "Microsoft SQL Monitor",
    1521: "Oracle DB Listener",
    1723: "PPTP",
    2049: "NFS",
    3000: "Development (e.g. Rails, Node)",
    3268: "Microsoft Global Catalog (LDAP)", 3269: "Microsoft Global Catalog SSL (LDAPS)",
    3306: "MySQL", 3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL",
    5060: "SIP", 5061: "SIPS", # SIP over TLS
    5900: "VNC", 5901: "VNC", # Often :1 display
    6379: "Redis",
    8000: "Development HTTP (Common Alt)", 8080: "HTTP Alt (Tomcat, etc.)", 8443: "HTTPS Alt",
    27017: "MongoDB", 27018: "MongoDB Shard"
}


def parse_ports(port_spec: Optional[str]) -> List[int]:
    """Convert a port specification string into a list of integers.

    Args:
        port_spec: String such as ``"22"``, ``"80,443"`` or ``"1-1024"``. The
            keyword ``"common"`` expands to a predefined list.

    Returns:
        Sorted list of unique port numbers.

    Raises:
        ValueError: If the specification contains invalid ranges or numbers.
    """
    if not port_spec:
        return []
    if isinstance(port_spec, list):
        return sorted(list(set(int(p) for p in port_spec if str(p).isdigit() and 1 <= int(p) <= 65535)))

    ports: set[int] = set()
    if port_spec.lower() == "common":
        return sorted(list(COMMON_PORTS.keys()))

    parts = port_spec.split(',')
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if part.lower() == "common":
            ports.update(COMMON_PORTS.keys())
            continue
        if '-' in part:
            try:
                start, end = map(int, part.split('-', 1))
                if 1 <= start <= end <= 65535:
                    ports.update(range(start, end + 1))
                else:
                    logger.info(f"Warning: Invalid port range '{part}'. Skipping.")
            except ValueError:
                logger.info(f"Warning: Invalid port range format '{part}'. Skipping.")
        elif part.isdigit():
            port_num = int(part)
            if 1 <= port_num <= 65535:
                ports.add(port_num)
            else:
                logger.info(f"Warning: Invalid port number '{part}'. Skipping.")
        else:
            logger.info(f"Warning: Invalid port specification '{part}'. Skipping.")

    return sorted(list(ports))


def tcp_connect_scan_port(target_ip: str, port: int, timeout: float = DEFAULT_SOCKET_TIMEOUT) -> bool:
    """Perform a TCP connect scan on a single port.

    Args:
        target_ip: Target IP address.
        port: Port number to test.
        timeout: Socket timeout in seconds.

    Returns:
        ``True`` if the port appears open, otherwise ``False``.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            return result == 0
    except socket.gaierror:
        return False
    except socket.error:
        return False
    except Exception:
        return False


def tcp_syn_scan_port(target_ip: str, port: int, timeout: float = DEFAULT_SOCKET_TIMEOUT) -> str:
    """Perform a TCP SYN scan using Scapy.

    Args:
        target_ip: Target IP address.
        port: Port number to scan.
        timeout: Timeout in seconds for the response.

    Returns:
        ``"open"``, ``"closed"`` or ``"filtered"`` depending on response. If
        Scapy is unavailable, returns ``"error_scapy_unavailable"``.
    """
    if not HAS_SCAPY:
        return "error_scapy_unavailable"

    src_port = random.randint(1024, 65535)
    ip_layer = IP(dst=target_ip)
    tcp_syn_pkt = TCP(sport=src_port, dport=port, flags="S", seq=random.randint(0, (2**32)-1))

    try:
        response = sr1(ip_layer / tcp_syn_pkt, timeout=timeout, verbose=0)

        if response is None:
            return "filtered"
        if response.haslayer(TCP):
            if response[TCP].flags == 0x12:
                rst_pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="R", ack=response[TCP].seq + 1)
                sr(rst_pkt, timeout=0.1, verbose=0, count=1)
                return "open"
            if response[TCP].flags in (0x14, 0x04):
                return "closed"
            return "filtered"
        if response.haslayer(ICMP):
            if response[ICMP].type == 3 and response[ICMP].code in [1, 2, 3, 9, 10, 13]:
                return "filtered"
            return "filtered"
        return "filtered"
    except Exception:
        return "error_scan_exception"


def udp_scan_port(target_ip: str, port: int, timeout: float = DEFAULT_SOCKET_TIMEOUT, use_scapy_if_available: bool = True) -> str:
    """Perform a UDP scan on a single port.

    Args:
        target_ip: Target IP address.
        port: UDP port number.
        timeout: Timeout for the probe.
        use_scapy_if_available: Use Scapy when available for richer results.

    Returns:
        ``"open"``, ``"closed"`` or ``"open|filtered"`` depending on response.
    """
    if HAS_SCAPY and use_scapy_if_available:
        ip_layer = IP(dst=target_ip)
        udp_pkt = UDP(sport=random.randint(1024, 65535), dport=port)

        try:
            response = sr1(ip_layer / udp_pkt, timeout=timeout, verbose=0)
            if response is None:
                return "open|filtered"
            if response.haslayer(UDP):
                return "open"
            if response.haslayer(ICMP):
                if response[ICMP].type == 3 and response[ICMP].code == 3:
                    return "closed"
                if response[ICMP].type == 3 and response[ICMP].code in [1, 2, 9, 10, 13]:
                    return "filtered"
                return "open|filtered"
            return "open|filtered"
        except Exception:
            return "error_scan_exception"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(b"", (target_ip, port))
            try:
                sock.recvfrom(1024)
                return "open"
            except socket.timeout:
                return "open|filtered"
            except ConnectionRefusedError:
                return "closed"
            except socket.error:
                return "open|filtered"
    except Exception:
        return "error_scan_exception"


def scan_ports(
    target_ip: str,
    ports_to_scan: List[int],
    scan_type: ScanType = ScanType.TCP_CONNECT,
    num_threads: int = DEFAULT_THREADS,
    timeout: float = DEFAULT_SOCKET_TIMEOUT,
) -> Dict[str, Any]:
    """Scan a list of ports on a target host.

    Args:
        target_ip: Target IP address.
        ports_to_scan: Ports to scan.
        scan_type: Type of scan to perform.
        num_threads: Number of worker threads.
        timeout: Timeout for individual scans.

    Returns:
        Summary dictionary including open ports and statistics.
    """
    if not target_ip or not ports_to_scan:
        return {"error": "Target IP and port list are required."}

    open_ports_details: Dict[int, Dict[str, str]] = {}
    closed_ports_count = 0
    filtered_ports_count = 0
    errors_encountered: List[str] = []

    try:
        socket.gethostbyname(target_ip)
    except socket.gaierror:
        return {"error": f"Cannot resolve hostname: {target_ip}"}

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_to_port = {}
        for port in ports_to_scan:
            if scan_type == ScanType.TCP_CONNECT:
                future = executor.submit(tcp_connect_scan_port, target_ip, port, timeout)
            elif scan_type == ScanType.TCP_SYN:
                if not HAS_SCAPY:
                    errors_encountered.append("Scapy not available for SYN scan.")
                    break
                future = executor.submit(tcp_syn_scan_port, target_ip, port, timeout)
            elif scan_type == ScanType.UDP:
                future = executor.submit(udp_scan_port, target_ip, port, timeout, True)
            else:
                return {"error": "Invalid scan type specified."}
            future_to_port[future] = port

        if errors_encountered and "Scapy not available" in errors_encountered[0]:
            return {"target_ip": target_ip, "scan_type": scan_type.value, "error": "Scapy is required for this scan type but not available."}

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                protocol_name = "tcp" if scan_type != ScanType.UDP else "udp"

                if scan_type == ScanType.TCP_CONNECT and result is True:
                    open_ports_details[port] = {"status": "open", "service_guess": COMMON_PORTS.get(port, "unknown"), "protocol": protocol_name}
                elif scan_type == ScanType.TCP_SYN:
                    if result == "open":
                        open_ports_details[port] = {"status": "open", "service_guess": COMMON_PORTS.get(port, "unknown"), "protocol": protocol_name}
                    elif result == "closed":
                        closed_ports_count += 1
                    elif result == "filtered":
                        filtered_ports_count += 1
                    elif isinstance(result, str) and "error" in result:
                        errors_encountered.append(f"Port {port} (SYN): {result}")
                elif scan_type == ScanType.UDP:
                    if result == "open":
                        open_ports_details[port] = {"status": "open", "service_guess": COMMON_PORTS.get(port, "unknown_udp"), "protocol": protocol_name}
                    elif result == "open|filtered":
                        open_ports_details[port] = {"status": "open|filtered", "service_guess": COMMON_PORTS.get(port, "unknown_udp"), "protocol": protocol_name}
                    elif result == "closed":
                        closed_ports_count += 1
                    elif result == "filtered":
                        filtered_ports_count += 1
                    elif isinstance(result, str) and "error" in result:
                        errors_encountered.append(f"Port {port} (UDP): {result}")
            except Exception as e:
                errors_encountered.append(f"Error processing result for port {port}: {e}")

    summary: Dict[str, Any] = {
        "target_ip": target_ip,
        "scan_type": scan_type.value,
        "open_ports": open_ports_details,
        "stats": {
            "total_ports_scanned": len(ports_to_scan),
            "open_ports_count": len(open_ports_details),
            "closed_ports_count": closed_ports_count,
            "filtered_ports_count": filtered_ports_count,
        },
    }
    if errors_encountered:
        summary["errors"] = errors_encountered

    return summary

if __name__ == "__main__":
    target = "scanme.nmap.org" # A host good for testing scanners
    # target = "127.0.0.1" # For local testing

    logger.info(f"--- Port Scanner Test against: {target} ---")

    # 1. Test Port Parsing
    logger.info("\n[Testing Port Parsing]")
    logger.info(f"  '80': {parse_ports('80')}")
    logger.info(f"  '22,80,443': {parse_ports('22,80,443')}")
    logger.info(f"  '1-5': {parse_ports('1-5')}")
    logger.info(f"  'common': First 5 of common: {parse_ports('common')[:5]}")
    logger.info(f"  '22,common,1000-1002': A few from this mixed spec: {parse_ports('22,common,1000-1002')[:5]} ...")
    logger.info(f"  Invalid 'abc,1-def,99999': {parse_ports('abc,1-def,99999')}")


    # 2. TCP Connect Scan (reliable, uses standard OS calls)
    logger.info(f"\n[TCP Connect Scan on {target}]")
    # Scan a few common ports plus a likely closed one
    ports_for_connect = parse_ports("21,22,23,25,80,110,443,3388") # 3388 likely closed on scanme
    connect_results = scan_ports(target, ports_for_connect, ScanType.TCP_CONNECT, num_threads=5, timeout=1.0)
    logger.info(f"  Open Ports (Connect): {connect_results.get('open_ports')}")
    if connect_results.get('errors'): logger.info(f"  Errors (Connect): {connect_results['errors']}")
    logger.info(f"  Stats (Connect): {connect_results.get('stats')}")


    # 3. TCP SYN Scan (requires Scapy and often root/admin)
    if HAS_SCAPY:
        logger.info(f"\n[TCP SYN Scan on {target}] (Requires Scapy & Privileges)")
        # Using a smaller set of ports for SYN to be quicker and less noisy if it fails
        ports_for_syn = parse_ports("22,80,443,53,9929") # 9929 is nmap-test-port for SYN
        syn_results = scan_ports(target, ports_for_syn, ScanType.TCP_SYN, num_threads=5, timeout=1.0)
        logger.info(f"  Open Ports (SYN): {syn_results.get('open_ports')}")
        if syn_results.get('errors'): logger.info(f"  Errors (SYN): {syn_results['errors']}")
        logger.info(f"  Stats (SYN): {syn_results.get('stats')}")

    else:
        logger.info("\n[TCP SYN Scan on {target}] - SKIPPED (Scapy not available or import failed)")

    # 4. UDP Scan (requires Scapy for best results, also often root/admin for ICMP)
    if HAS_SCAPY: # Even with Scapy, UDP is less deterministic
        logger.info(f"\n[UDP Scan on {target}] (Requires Scapy & Privileges, results can be less certain)")
        ports_for_udp = parse_ports("53,67,123,161,137") # Common UDP ports
        udp_results = scan_ports(target, ports_for_udp, ScanType.UDP, num_threads=3, timeout=1.5) # Longer timeout for UDP
        logger.info(f"  Results (UDP - open or open|filtered): {udp_results.get('open_ports')}")
        if udp_results.get('errors'): logger.info(f"  Errors (UDP): {udp_results['errors']}")
        logger.info(f"  Stats (UDP): {udp_results.get('stats')}")
    else:
        logger.info("\n[UDP Scan on {target}] - SKIPPED (Scapy not available or import failed for reliable UDP)")
        # Could add a test for the basic socket UDP scan here if desired, acknowledging its limitations.

    logger.info("\n--- Port Scanner Test Finished ---")
