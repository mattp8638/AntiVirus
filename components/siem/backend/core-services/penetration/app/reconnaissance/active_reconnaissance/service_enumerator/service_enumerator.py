import socket
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging_config import get_logger
logger = get_logger(__name__)

# Default timeout for individual probe connections
DEFAULT_PROBE_TIMEOUT = 2.0
# Max banner length
MAX_BANNER_LENGTH = 2048
# Default number of threads for concurrent service enumeration
DEFAULT_ENUM_THREADS = 10

SERVICE_PROBES = {
    'http': [
        (b"HEAD / HTTP/1.0\r\n\r\n", True),
        (b"GET / HTTP/1.0\r\n\r\n", True),
        (b"OPTIONS / HTTP/1.0\r\n\r\n", True)
    ],
    'ssh': [(None, True)],
    'ftp': [(None, True)],
    'smtp': [(None, True), (b"EHLO test.com\r\n", True)],
    'pop3': [(None, True)],
    'imap': [(None, True)],
    'dns': [(b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03', True)],
    'snmp': [(b'\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00', True)],
}

BANNER_REGEXES = [
    # SSH: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3 or SSH-2.0-dropbear_2020.78
    re.compile(r"SSH-(?P<protocol_version>[\d\.]+)-(?P<product>OpenSSH|dropbear)(?:_(?P<version>[\w\.\-]+))?(?:\s*(?P<comment>.+))?", re.IGNORECASE),
    # Fallback SSH if specific product isn't OpenSSH/dropbear but version is part of product string
    re.compile(r"SSH-(?P<protocol_version>[\d\.]+)-(?P<product>[^\s_]+)(?:_(?P<version>[\w\.\-]+))?(?:\s*(?P<comment>.+))?", re.IGNORECASE),

    # FTP
    re.compile(r"^\d{3}\s+\((?P<product>vsFTPd|ProFTPD|Pure-FTPd)\s+(?P<version>[\d\w\.\-]+)\)", re.IGNORECASE),
    re.compile(r"^\d{3}\s*(?P<product>ProFTPD|vsFTPd|Pure-FTPd)\s+(?P<version>[\d\w\.\-]+)", re.IGNORECASE),
    re.compile(r"^\d{3}\s*(?P<product>Microsoft FTP Service)", re.IGNORECASE),
    re.compile(r"^\d{3}\s*.*?(?P<product>FTP[^\s]*)\s*server ready", re.IGNORECASE),

    # SMTP
    re.compile(r"^\d{3}\s*[\w\.\-]+\s*ESMTP\s*(?P<product>Postfix|Sendmail|Exim|Microsoft ESMTP MAIL Service)(?:\s*version\s*(?P<version>[\d\w\.\-]+))?(?:\s*\((?P<comment>[^\)]+)\))?", re.IGNORECASE),
    re.compile(r"^\d{3}\s*.*?ESMTP\s*(?P<product>\S+)\s*(?:version\s*(?P<version>[\d\.\w\-]+))?", re.IGNORECASE),

    # HTTP Server
    re.compile(r"Server:\s*(?P<product>Apache|nginx|Microsoft-IIS|IIS|lighttpd|LiteSpeed)(?:/(?P<version>[\d\w\.\-]+))?(?:\s*\((?P<comment>[^\)]+)\))?", re.IGNORECASE),
    
    # POP3
    re.compile(r"^\+OK\s*(?:POP3\s*server\s*ready)?.*?(?P<product>Dovecot|Courier POP3 server)?\s*(?:ready)?", re.IGNORECASE),
    
    # IMAP
    re.compile(r"^\*\s*OK\s*(?:\[CAPABILITY[^\]]*\]\s*)?(?P<product>Dovecot|Courier-IMAP server)?\s*(?:IMAP4rev1\s*server\s*ready|ready)", re.IGNORECASE),

    # Generic (Order matters, more specific should be above these)
    re.compile(r"^(?P<product>[a-zA-Z\-_0-9]+)/(?P<version>[\d\w\.\-\+]+)", re.IGNORECASE), # Product/Version
    re.compile(r"^(?P<product>[a-zA-Z\-_0-9]+)\s+version\s+(?P<version>[\d\w\.\-\+]+)", re.IGNORECASE), # Product version X.Y.Z
    # Removed the "Product Version" (word space word) generic regex as it was too broad and error-prone.
]

def parse_banner(banner_text):
    if not banner_text:
        return {"product": "Unknown", "version": "Unknown", "comment": None}

    for regex in BANNER_REGEXES:
        match = regex.search(banner_text)
        if match:
            group_dict = match.groupdict()

            product_raw = group_dict.get("product")
            version_raw = group_dict.get("version") # This is the primary version capture
            comment_raw = group_dict.get("comment")
            protocol_version_raw = group_dict.get("protocol_version") # Specific for SSH-like banners

            product = product_raw.strip() if product_raw else "Unknown"
            version = version_raw.strip() if version_raw else "Unknown"
            comment = comment_raw.strip() if comment_raw else None
            protocol_version = protocol_version_raw.strip() if protocol_version_raw else None

            # If primary 'version' is not found, but product string itself contains a version (e.g. OpenSSH_8.2p1)
            if version == "Unknown" and product != "Unknown" and '_' in product:
                potential_prod, _, potential_ver = product.partition('_')
                # Check if the part after '_' looks like a version number
                if potential_ver and (potential_ver[0].isdigit() or (potential_ver.count('.') > 0 and potential_ver.replace('.', '').isalnum())):
                    product = potential_prod
                    version = potential_ver

            # If 'version' from regex is actually a protocol version (e.g. from a generic SSH regex)
            # and a more specific product_version was also captured (e.g. in a named group 'prod_ver'), prefer that.
            # This depends on regex design. Current SSH regex tries to capture product version directly in 'version'.

            final_comment = comment
            if protocol_version and protocol_version != version:
                final_comment = f"Protocol: {protocol_version}{f'; {comment}' if comment else ''}".strip()

            return {"product": product, "version": version, "comment": final_comment}

    return {"product": "Unknown", "version": "Unknown", "comment": None, "original_banner": banner_text}


def probe_port_tcp(target_ip, port, timeout=DEFAULT_PROBE_TIMEOUT):
    banner = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target_ip, port))
            try:
                banner_bytes = sock.recv(MAX_BANNER_LENGTH)
                banner = banner_bytes.decode('utf-8', errors='ignore').strip()
            except socket.timeout:
                banner = ""
            except socket.error:
                 return {"port": port, "protocol": "tcp", "status": "error", "error_message": "Socket error on recv"}

            if port in [80, 8000, 8080, 443, 8443] and (not banner or len(banner) < 10 or "HTTP" not in banner.upper()):
                try:
                    http_probe = SERVICE_PROBES['http'][0][0]
                    sock.sendall(http_probe)
                    time.sleep(0.1)
                    http_banner_bytes = sock.recv(MAX_BANNER_LENGTH)
                    http_banner = http_banner_bytes.decode('utf-8', errors='ignore').strip()
                    if http_banner: banner = (banner + "\n" + http_banner).strip() if banner else http_banner
                except (socket.timeout, socket.error): pass

    except socket.timeout:
        return {"port": port, "protocol": "tcp", "status": "open", "banner": "Timeout on connect (filtered or slow?)"}
    except socket.error as e:
        return {"port": port, "protocol": "tcp", "status": "closed_or_error", "error_message": str(e)}
    except Exception as e:
        return {"port": port, "protocol": "tcp", "status": "error", "error_message": f"Unexpected error: {e}"}

    if banner is None:
        return {"port": port, "protocol": "tcp", "status": "closed_or_unreachable"}

    parsed_info = parse_banner(banner)
    return {
        "port": port, "protocol": "tcp", "status": "open",
        "banner": banner if banner else "No Banner",
        "service_name": parsed_info["product"],
        "version": parsed_info["version"],
        "comment": parsed_info["comment"]
    }

def probe_port_udp(target_ip, port, timeout=DEFAULT_PROBE_TIMEOUT):
    probe_data, expect_response = None, False
    service_name_hint = "unknown_udp"

    if port == 53:
        probe_data, expect_response = SERVICE_PROBES['dns'][0]
        service_name_hint = "dns"
    elif port == 161:
        probe_data, expect_response = SERVICE_PROBES['snmp'][0]
        service_name_hint = "snmp"

    if not probe_data:
        probe_data = b""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(probe_data, (target_ip, port))
            if expect_response or not probe_data :
                try:
                    banner_bytes, _ = sock.recvfrom(MAX_BANNER_LENGTH)
                    banner = banner_bytes.decode('utf-8', errors='ignore').strip()
                    parsed_info = parse_banner(banner)
                    return {
                        "port": port, "protocol": "udp", "status": "open", "banner": banner,
                        "service_name": parsed_info.get("product", service_name_hint),
                        "version": parsed_info.get("version", "Unknown")
                    }
                except socket.timeout:
                    return {"port": port, "protocol": "udp", "status": "open|filtered", "banner": "No response (UDP Timeout)"}
                except socket.error:
                     return {"port": port, "protocol": "udp", "status": "closed?", "banner": "Socket error on recvfrom (possibly closed)"}
            else:
                return {"port": port, "protocol": "udp", "status": "probed_no_response_expected"}
    except socket.error as e:
         return {"port": port, "protocol": "udp", "status": "error_on_send", "error_message": str(e)}
    except Exception as e:
        return {"port": port, "protocol": "udp", "status": "error", "error_message": f"Unexpected error: {e}"}


def enumerate_services(target_ip, open_ports_map, num_threads=DEFAULT_ENUM_THREADS, probe_timeout=DEFAULT_PROBE_TIMEOUT):
    enumerated_services = {}
    if not open_ports_map:
        return {"target_ip": target_ip, "services": {}, "message": "No open ports provided for enumeration."}

    futures = []
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        # Input open_ports_map is expected from the new port_scanner format:
        # {port: {"status": "open", "service_guess": "...", "protocol": "tcp"}, ...}
        for port, port_details in open_ports_map.items():
            if not isinstance(port_details, dict) or "protocol" not in port_details:
                enumerated_services[port] = {"error": f"Invalid port details format for port {port}. Expected dict with 'protocol'."}
                continue

            protocol_str = str(port_details["protocol"]).lower()

            # Only probe if status indicates it's open or potentially open (for UDP)
            current_status = port_details.get("status", "unknown").lower()
            if "open" not in current_status: # Catches "open" and "open|filtered"
                # Store the status from port scanner if not 'open' or 'open|filtered'
                enumerated_services[port] = {
                    "port": port,
                    "protocol": protocol_str,
                    "status": current_status, # e.g., could be 'closed', 'filtered' if port_scanner determined that
                    "banner": "Not probed (port not open)",
                    "service_name": port_details.get("service_guess", "Unknown"),
                    "version": "Unknown"
                }
                continue

            if protocol_str == 'tcp':
                futures.append(executor.submit(probe_port_tcp, target_ip, port, probe_timeout))
            elif protocol_str == 'udp':
                futures.append(executor.submit(probe_port_udp, target_ip, port, probe_timeout))
            else:
                enumerated_services[port] = {"port": port, "protocol": protocol_str, "error": f"Unknown protocol '{protocol_str}' for port {port}"}

        for future in as_completed(futures):
            try:
                result = future.result()
                if result and "port" in result:
                    enumerated_services[result["port"]] = result
            except Exception as e:
                pass

    return {"target_ip": target_ip, "services": enumerated_services}

if __name__ == "__main__":
    target_ip_main = "127.0.0.1"
    simulated_open_ports = {}
    if target_ip_main == "127.0.0.1":
        simulated_open_ports = {22: 'tcp', 8000: 'tcp', 80: 'tcp', 53: 'udp'}
    else:
        simulated_open_ports = {22: 'tcp', 80: 'tcp', 9929: 'tcp', 31337: 'tcp'}

    logger.info(f"--- Service Enumeration Test against: {target_ip_main} ---")
    logger.info(f"Simulated open ports for enumeration: {simulated_open_ports}")
    results_main = enumerate_services(target_ip_main, simulated_open_ports, num_threads=5, probe_timeout=2.0)

    logger.info("\nEnumeration Results:")
    if results_main.get("services"):
        for port_num, service_info in sorted(results_main["services"].items()):
            logger.info(f"  Port {port_num}/{service_info.get('protocol','N/A')}:")
            logger.info(f"    Status: {service_info.get('status', 'N/A')}")
            if "error_message" in service_info:
                 logger.info(f"    Error: {service_info['error_message']}")
            else:
                logger.info(f"    Service: {service_info.get('service_name', 'Unknown')}")
                logger.info(f"    Version: {service_info.get('version', 'Unknown')}")
                if service_info.get('comment'):
                    logger.info(f"    Comment: {service_info['comment']}")
                banner_to_print = service_info.get('banner', '')
                if len(banner_to_print) > 100: banner_to_print = banner_to_print[:97] + "..."
                logger.info(f"    Banner: {banner_to_print.replace(chr(10), ' ').replace(chr(13), ' ') if banner_to_print else 'N/A'}")
    else:
        logger.info("  No services enumerated or an error occurred.")
        if "error" in results_main: logger.info(f"  Overall Error: {results_main['error']}")
        if "message" in results_main: logger.info(f"  Message: {results_main['message']}")

    logger.info("\n--- Service Enumeration Test Finished ---")
