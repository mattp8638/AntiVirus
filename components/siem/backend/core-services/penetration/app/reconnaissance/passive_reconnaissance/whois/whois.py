import socket
import re
import time
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone
from logging_config import get_logger
logger = get_logger(__name__)

# Common WHOIS port
WHOIS_PORT = 43
# Default IANA WHOIS server
IANA_WHOIS_SERVER = "whois.iana.org"
# Default timeout for socket/HTTP operations
DEFAULT_TIMEOUT = 10  # seconds

# Precompiled regex for extracting referral server from IANA response (WHOIS)
REFERRAL_REGEX_WHOIS = re.compile(r"^(?:refer|whois):\s*([a-zA-Z0-9\-\.]+)", re.IGNORECASE)

# Expanded list of common date formats found in WHOIS/RDAP
COMMON_DATE_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",       # Standard ISO 8601 (Zulu time / UTC)
    "%Y-%m-%dT%H:%M:%S.%fZ",    # ISO 8601 with milliseconds
    "%Y-%m-%dT%H:%M:%S%z",      # ISO 8601 with timezone offset (e.g., +0000 or -0700)
    "%Y-%m-%d %H:%M:%S",        # Common database/log format
    "%Y-%m-%d %H:%M:%S.%f",     # With microseconds
    "%d-%b-%Y",                 # e.g., 01-Jan-2024
    "%d-%B-%Y",                 # e.g., 01-January-2024
    "%d.%m.%Y",                 # e.g., 01.01.2024
    "%Y.%m.%d",                 # e.g., 2024.01.01
    "%Y/%m/%d",                 # e.g., 2024/01/01
    "%d/%m/%Y",                 # e.g., 01/01/2024
    "%Y%m%d",                   # e.g., 20240101
    "%B %d, %Y",                # e.g., January 01, 2024
    "%b %d %Y %H:%M:%S %Z",     # e.g., Jan 01 2024 14:00:00 GMT
    "%a %b %d %H:%M:%S %Z %Y", # e.g., Mon Jan 01 14:00:00 GMT 2024 (ctime format)
    "%Y.%m.%d %H:%M:%S",        # e.g., 2024.01.01 14:00:00
    "%Y%m%d%H%M%S%Z",            # e.g., 20240101140000Z
    "%Y-%m-%d"                  # Added simple YYYY-MM-DD as a common case
]

def parse_datetime_string(date_str):
    """
    Parses a date string from WHOIS/RDAP into a datetime object.
    Handles various common formats and timezone information.
    Returns datetime object or None if parsing fails.
    """
    if not date_str or not isinstance(date_str, str):
        return None
    
    original_date_str = date_str # Keep for timezone hint if needed
    
    # Minimal initial cleaning, mainly for common WHOIS cruft
    date_str = date_str.replace("(YYYY-MM-DD)", "").strip()
    # Remove text in parentheses at the end, often like (Expires on YYYY-MM-DD)
    date_str = re.sub(r'\s*\([^)]*\)\s*$', '', date_str).strip()
    
    if date_str.lower().startswith("before "):
        date_str = date_str[7:].strip()

    # More targeted timezone stripping:
    tz_match = re.search(r'\s+(UTC|GMT|Z|EST|EDT|CST|CDT|MST|MDT|PST|PDT)$', date_str, re.IGNORECASE)
    tz_suffix_present = False
    if tz_match:
        tz_suffix_present = True # A timezone suffix like "UTC" was found and stripped
        date_str = date_str[:tz_match.start()].strip()

    is_likely_iso_with_z = date_str.upper().endswith('Z') and 'T' in date_str

    for fmt in COMMON_DATE_FORMATS:
        try:
            dt_obj = datetime.strptime(date_str, fmt)

            # If format didn't handle timezone, but original string or suffix implies UTC
            if dt_obj.tzinfo is None:
                if is_likely_iso_with_z or (tz_suffix_present and tz_match.group(1).upper() in ["UTC", "GMT", "Z"]):
                    dt_obj = dt_obj.replace(tzinfo=timezone.utc)
            return dt_obj
        except ValueError:
            if "1992-01-01" == date_str and "%Y-%m-%d" == fmt:
                 logger.info(f"DEBUG parse_datetime_string: FAILED to parse '{date_str}' with format '{fmt}'")
            continue

    # Fallback for ISO-like format with explicit offset if not caught by %z in COMMON_DATE_FORMATS
    try:
        if 'T' in date_str and ('+' in date_str or '-' in date_str[11:]): # Check for T and +/- for timezone
            if date_str[-3] == ':': # e.g. +01:00 -> +0100 for some strptime versions
                date_str_tz_fixed = date_str[:-3] + date_str[-2:]
            else:
                date_str_tz_fixed = date_str
            # Try formats that explicitly handle offset
            for fmt_with_tz in ["%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S%z"]:
                try: return datetime.strptime(date_str_tz_fixed, fmt_with_tz)
                except ValueError: continue
    except Exception:
        pass # Ignore errors in this fallback

    return None


def query_whois_socket(query, server, port=WHOIS_PORT, timeout=DEFAULT_TIMEOUT):
    """Sends a query to a WHOIS server using raw sockets."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((server, port))
            s.send(f"{query}\r\n".encode())
            
            response_bytes = b""
            while True:
                data = s.recv(4096)
                if not data: break
                response_bytes += data

        try: return response_bytes.decode('utf-8', errors='ignore')
        except UnicodeDecodeError: return response_bytes.decode('latin-1', errors='ignore')

    except socket.timeout: return f"Error: Timeout querying {server} for {query} via WHOIS."
    except socket.gaierror: return f"Error: Could not resolve WHOIS server {server}."
    except ConnectionRefusedError: return f"Error: Connection refused by {server} for {query} via WHOIS."
    except Exception as e: return f"Error: Failed to query {server} for {query} via WHOIS: {e}"


def query_rdap_http(rdap_url, timeout=DEFAULT_TIMEOUT):
    """Sends a query to an RDAP server using HTTP GET."""
    try:
        req = urllib.request.Request(rdap_url, headers={'Accept': 'application/rdap+json', 'User-Agent': 'Python-WhoisRdapClient/0.1'})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status == 200:
                content_type = response.headers.get('Content-Type', '')
                if 'application/rdap+json' in content_type or 'application/json' in content_type:
                    return json.loads(response.read().decode('utf-8'))
                else:
                    return {"error": f"RDAP server returned non-JSON content-type: {content_type}", "response_snippet": response.read().decode('utf-8', errors='ignore')[:200]}
            elif response.status == 404:
                 return {"error": "RDAP object not found (404)."}
            else:
                return {"error": f"RDAP query failed with HTTP status {response.status}", "response_snippet": response.read().decode('utf-8', errors='ignore')[:200]}
    except urllib.error.HTTPError as e:
        return {"error": f"RDAP HTTPError: {e.code} {e.reason}", "response_snippet": e.read().decode('utf-8', errors='ignore')[:200] if hasattr(e, 'read') else ""}
    except urllib.error.URLError as e:
        return {"error": f"RDAP URLError: {e.reason}"}
    except json.JSONDecodeError:
        return {"error": "Failed to decode JSON response from RDAP server."}
    except Exception as e:
        return {"error": f"Unexpected error querying RDAP server {rdap_url}: {e}"}


def get_whois_referral_server(response_text):
    if not response_text or isinstance(response_text, dict): return None
    for line in response_text.splitlines():
        match = REFERRAL_REGEX_WHOIS.match(line)
        if match:
            server_name = match.group(1).strip().lower()
            if server_name != "none" and '.' in server_name: return server_name
    return None

def get_rdap_base_url_from_iana_bootstrap(tld, timeout=DEFAULT_TIMEOUT):
    iana_dns_bootstrap_url = "https://data.iana.org/rdap/dns.json"
    try:
        req = urllib.request.Request(iana_dns_bootstrap_url, headers={'User-Agent': 'Python-WhoisRdapClient/0.1'})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status == 200:
                bootstrap_data = json.loads(response.read().decode('utf-8'))
                services = bootstrap_data.get("services", [])
                for service_block in services:
                    if len(service_block) == 2 and len(service_block[0]) > 0 and len(service_block[1]) > 0:
                        tld_list_in_block = service_block[0]
                        url_list_in_block = service_block[1]
                        if tld.lower() in [item.lower() for item in tld_list_in_block]:
                            for url_item in url_list_in_block:
                                if url_item.startswith("https://"): return url_item
                            return url_list_in_block[0]
            return None
    except Exception:
        return None
    return None


def parse_rdap_data(rdap_json, domain_norm): # Changed 'domain' to 'domain_norm' for clarity
    if not rdap_json or "error" in rdap_json:
        # Ensure domain_queried is part of the error structure if possible
        err_result = {"error": rdap_json.get("error", "Unknown RDAP error"),
                      "raw_json": rdap_json, "protocol": "rdap",
                      "domain_name": domain_norm} # Use normalized domain here
        return err_result

    parsed = {"raw_json": rdap_json, "protocol": "rdap", "domain_name": rdap_json.get("ldhName", domain_norm).lower()}

    for event in rdap_json.get("events", []):
        action = event.get("eventAction")
        date_str = event.get("eventDate")
        dt_obj = parse_datetime_string(date_str)
        if action == "registration": parsed["creation_date"] = dt_obj
        elif action == "last changed": parsed["updated_date"] = dt_obj
        elif action == "expiration": parsed["expiration_date"] = dt_obj

    for entity in rdap_json.get("entities", []):
        if "registrar" in entity.get("roles", []):
            public_ids = entity.get("publicIds", [])
            if public_ids:
                iana_id_found = False
                for pid in public_ids:
                    if isinstance(pid, dict) and str(pid.get("type","")).upper() == "IANA REGISTRAR ID" and pid.get("identifier"):
                        parsed["registrar_iana_id"] = str(pid.get("identifier"))
                        iana_id_found = True
                        break
                if not iana_id_found and public_ids[0].get("identifier"):
                     parsed["registrar_iana_id"] = str(public_ids[0].get("identifier"))

            if entity.get("vcardArray") and len(entity["vcardArray"]) > 1:
                 vcard = entity["vcardArray"][1]
                 for item in vcard:
                     if item[0] == "fn":
                         parsed["registrar"] = item[3]
                         break
            for link in entity.get("links", []):
                if link.get("rel") == "alternate" and link.get("type") == "text/html":
                    parsed["registrar_url"] = link.get("href")
                    break
            break

    parsed["name_servers"] = [ns.get("ldhName", "").lower() for ns in rdap_json.get("nameservers", []) if ns.get("ldhName")]
    parsed["domain_status"] = rdap_json.get("status", [])

    dnssec_signed = rdap_json.get("secureDNS", {}).get("delegationSigned")
    if dnssec_signed is not None:
        parsed["dnssec"] = "signedDelegation" if dnssec_signed else "unsigned"

    contact_roles_map = {"registrant": "registrant", "administrative": "admin", "technical": "tech"}
    for entity in rdap_json.get("entities", []):
        entity_roles = entity.get("roles", [])
        main_role_for_entity = None
        if "registrant" in entity_roles: main_role_for_entity = "registrant"
        elif "administrative" in entity_roles: main_role_for_entity = "admin"
        elif "technical" in entity_roles: main_role_for_entity = "tech"

        if main_role_for_entity:
            contact_prefix = main_role_for_entity
            if entity.get("vcardArray") and len(entity["vcardArray"]) > 1:
                vcard = entity["vcardArray"][1]
                org_name, fn_name = None, None
                for item in vcard:
                    if item[0] == "fn": fn_name = item[3]
                    if item[0] == "org": org_name = item[3]

                if not parsed.get(f"{contact_prefix}_name"):
                    parsed[f"{contact_prefix}_name"] = fn_name
                if not parsed.get(f"{contact_prefix}_organization"):
                     parsed[f"{contact_prefix}_organization"] = org_name if org_name else (fn_name if not fn_name and not org_name else None)
    return parsed


def parse_whois_text_data(raw_text, domain_norm): # Changed 'domain' to 'domain_norm'
    parsed_info = {
        "raw_text": raw_text, "protocol": "whois", "domain_name": None, "registrar": None,
        "registrar_whois_server": None, "registrar_url": None, "registrar_iana_id": None,
        "creation_date": None, "updated_date": None, "expiration_date": None,
        "name_servers": [], "domain_status": [], "dnssec": None,
        "registrant_name": None, "registrant_organization": None,
        "admin_name": None, "admin_organization": None,
        "tech_name": None, "tech_organization": None,
    }
    if not raw_text or raw_text.startswith("Error:"):
        parsed_info["parser_error"] = raw_text if raw_text else "Empty WHOIS response"
        parsed_info["domain_name"] = domain_norm # Ensure domain_name is set even on parser error
        return parsed_info

    lines = raw_text.replace('\r\n', '\n').split('\n')
    current_contact_type = None
    date_field_set_flags = {"creation_date": False, "updated_date": False, "expiration_date": False}

    for line in lines:
        line = line.strip()
        if not line or line.startswith("%") or line.startswith(">>>") or line.startswith("#") or "last update of whois database" in line.lower() or "for more information on whois status codes" in line.lower():
            continue

        if ":" in line:
            key, value = line.split(":", 1)
            key_lower = key.strip().lower()
            value = value.strip()

            date_keywords = {
                "creation date": "creation_date", "created": "creation_date", "registration time": "creation_date", "registered on": "creation_date", "domain registration date": "creation_date",
                "updated date": "updated_date", "last update": "updated_date", "last modified": "updated_date", "changed": "updated_date", "domain last updated date": "updated_date",
                "expiry date": "expiration_date", "expiration time": "expiration_date", "registrar registration expiration date": "expiration_date", "paid-till": "expiration_date", "expires on": "expiration_date", "registry expiry date": "expiration_date", "domain expiration date": "expiration_date"
            }
            for kw, field_name in date_keywords.items():
                if kw in key_lower and not date_field_set_flags[field_name]:
                    dt_val = parse_datetime_string(value)
                    if dt_val:
                        parsed_info[field_name] = dt_val
                        date_field_set_flags[field_name] = True
                    break

            if "domain name" in key_lower and not parsed_info["domain_name"]: parsed_info["domain_name"] = value.lower()
            elif key_lower == "registrar" and not any(s in key_lower for s in ["abuse", "iana", "server", "url", "contact"]): parsed_info["registrar"] = value
            elif "whois server" in key_lower or "registrar whois server" in key_lower: parsed_info["registrar_whois_server"] = value.lower()
            elif "registrar url" in key_lower or (key_lower == "url" and parsed_info.get("registrar") in key): parsed_info["registrar_url"] = value
            elif "registrar iana id" in key_lower: parsed_info["registrar_iana_id"] = value
            elif "name server" in key_lower or "nserver" in key_lower or key_lower.startswith("ns_name_"):
                ns_val = value.lower().split()[0]
                if ns_val and '.' in ns_val and ns_val not in parsed_info["name_servers"]: parsed_info["name_servers"].append(ns_val)
            elif "domain status" in key_lower or (key_lower == "status" and not any(s in key_lower for s in ["payment", "billing"])):
                statuses = value.lower().split()
                for status_val in statuses:
                    if "https://" in status_val: continue
                    if status_val and status_val not in parsed_info["domain_status"]: parsed_info["domain_status"].append(status_val)
            elif "dnssec" in key_lower: parsed_info["dnssec"] = value.lower()

            contact_keywords_map = {
                "registrant name": "registrant_name", "registrant organization": "registrant_organization",
                "holder name": "registrant_name", "holder organization": "registrant_organization", # Alternative terms
                "admin name": "admin_name", "admin organization": "admin_organization", "administrative contact name": "admin_name",
                "tech name": "tech_name", "tech organization": "tech_organization", "technical contact name": "tech_name",
            }
            if key_lower in ["registrant", "administrative contact", "technical contact", "holder", "owner"]: current_contact_type = key_lower.split()[0]

            for kw, field_name in contact_keywords_map.items():
                if kw == key_lower and not parsed_info.get(field_name):
                    parsed_info[field_name] = value
                    break
                elif current_contact_type and kw.startswith(current_contact_type) and not parsed_info.get(field_name) :
                    if ("name" in kw and "name" in key_lower and "server" not in key_lower) or \
                       ("organization" in kw and "organization" in key_lower):
                         parsed_info[field_name] = value
                         break

    if not parsed_info["domain_name"] and domain_norm : parsed_info["domain_name"] = domain_norm.lower()
    if parsed_info["name_servers"]: parsed_info["name_servers"] = sorted(list(set(ns for ns in parsed_info["name_servers"] if ns != "." and ns)))
    if parsed_info["domain_status"]: parsed_info["domain_status"] = sorted(list(set(parsed_info["domain_status"])))
        
    return parsed_info


def get_authoritative_server_for_domain(domain_norm, preferred_protocol="try_both", timeout=DEFAULT_TIMEOUT): # Changed 'domain' to 'domain_norm'
    tld = domain_norm.split('.')[-1].lower()
    error_log = []

    if preferred_protocol == "rdap" or preferred_protocol == "try_both":
        rdap_base_url = get_rdap_base_url_from_iana_bootstrap(tld, timeout=timeout)
        if rdap_base_url:
            if not rdap_base_url.endswith('/'): rdap_base_url += '/'
            final_rdap_url = f"{rdap_base_url}domain/{domain_norm}"
            return final_rdap_url, "rdap", None
        else:
            error_log.append(f"Could not determine RDAP base URL for TLD '{tld}' from IANA bootstrap.")
            if preferred_protocol == "rdap":
                return None, None, " ; ".join(error_log)

    iana_response_text = query_whois_socket(domain_norm, IANA_WHOIS_SERVER, timeout=timeout)

    if iana_response_text and not iana_response_text.startswith("Error:"):
        referral_server = get_whois_referral_server(iana_response_text)
        if referral_server:
            return referral_server, "whois", " ; ".join(error_log) if error_log else None
        else:
            return IANA_WHOIS_SERVER, "whois_direct_iana", " ; ".join(error_log) if error_log else None
    else:
        error_log.append(f"Initial IANA WHOIS query for {domain_norm} failed or gave error: {iana_response_text if iana_response_text else 'No response'}")
        return None, None, " ; ".join(error_log)


def unified_domain_lookup(domain, preferred_protocol="try_both", whois_max_referrals=2, timeout=DEFAULT_TIMEOUT):
    if not domain or not isinstance(domain, str):
        return {"domain_queried": str(domain) if domain is not None else "invalid_input", "error": "Invalid domain name provided."} # Ensure domain_queried is set

    domain_norm = domain.lower().strip()
    lookup_result = {"domain_queried": domain_norm, "errors_during_lookup": [], "protocol_attempts": []}

    authoritative_server, protocol_to_use, server_det_error = get_authoritative_server_for_domain(domain_norm, preferred_protocol, timeout)

    if server_det_error:
        lookup_result["errors_during_lookup"].append(f"Server determination issue: {server_det_error}")

    if not authoritative_server or not protocol_to_use:
        lookup_result["error"] = f"Could not determine an authoritative server for {domain_norm}. Last error: {server_det_error if server_det_error else 'Unknown server determination error.'}"
        return lookup_result # domain_queried is already in lookup_result

    lookup_result["protocol_attempts"].append({"protocol": protocol_to_use, "server": authoritative_server})

    if protocol_to_use == "rdap":
        rdap_data = query_rdap_http(authoritative_server, timeout=timeout)
        if rdap_data and "error" not in rdap_data:
            parsed_data = parse_rdap_data(rdap_data, domain_norm)
            parsed_data["errors_during_lookup"] = lookup_result["errors_during_lookup"] + parsed_data.get("errors_during_lookup", [])
            parsed_data["protocol_attempts"] = lookup_result["protocol_attempts"]
            parsed_data["domain_queried"] = domain_norm # Ensure it's in final successful parse
            return parsed_data
        else:
            rdap_error_msg = rdap_data.get('error', 'Unknown RDAP error') if isinstance(rdap_data, dict) else str(rdap_data)
            lookup_result["errors_during_lookup"].append(f"RDAP query to {authoritative_server} failed: {rdap_error_msg}")

            if preferred_protocol == "try_both":
                whois_fb_server, whois_fb_protocol, whois_fb_err = get_authoritative_server_for_domain(domain_norm, "whois", timeout)
                if whois_fb_err: lookup_result["errors_during_lookup"].append(f"WHOIS fallback server determination issue: {whois_fb_err}")

                if whois_fb_server and whois_fb_protocol:
                    authoritative_server = whois_fb_server
                    protocol_to_use = whois_fb_protocol
                    lookup_result["protocol_attempts"].append({"protocol": protocol_to_use, "server": authoritative_server, "reason": "RDAP fallback"})
                else:
                    lookup_result["error"] = f"RDAP failed, and could not determine WHOIS server for fallback. Last RDAP error: {rdap_error_msg}. Last WHOIS determination error: {whois_fb_err if whois_fb_err else 'Unknown'}"
                    return lookup_result # domain_queried is in lookup_result
            else:
                 lookup_result["error"] = f"RDAP query failed: {rdap_error_msg}"
                 return lookup_result # domain_queried is in lookup_result

    if protocol_to_use == "whois" or protocol_to_use == "whois_direct_iana":
        current_whois_server = authoritative_server
        raw_whois_text = query_whois_socket(domain_norm, current_whois_server, timeout=timeout)
        referral_path = [current_whois_server]
        
        num_refs = 0
        if protocol_to_use == "whois" and raw_whois_text and not raw_whois_text.startswith("Error:"):
            potential_referral = get_whois_referral_server(raw_whois_text)
            while potential_referral and potential_referral.lower() != current_whois_server.lower() and num_refs < whois_max_referrals :
                current_whois_server = potential_referral
                referral_path.append(current_whois_server)
                new_text = query_whois_socket(domain_norm, current_whois_server, timeout=timeout)
                lookup_result["protocol_attempts"].append({"protocol": "whois_referral", "server": current_whois_server})

                if new_text and not new_text.startswith("Error:"):
                    raw_whois_text = new_text
                    potential_referral = get_whois_referral_server(raw_whois_text)
                else:
                    lookup_result["errors_during_lookup"].append(f"WHOIS query to referral server {current_whois_server} failed: {new_text if new_text else 'No response'}")
                    break
                num_refs += 1
                time.sleep(0.2)
        
        if raw_whois_text and not raw_whois_text.startswith("Error:"):
            parsed_data = parse_whois_text_data(raw_whois_text, domain_norm)
            parsed_data["queried_server"] = current_whois_server
            parsed_data["referral_path_whois"] = referral_path
            parsed_data["errors_during_lookup"] = lookup_result["errors_during_lookup"] + parsed_data.get("errors_during_lookup", [])
            parsed_data["protocol_attempts"] = lookup_result["protocol_attempts"]
            parsed_data["domain_queried"] = domain_norm # Ensure it's in final successful parse
            return parsed_data
        else:
            lookup_result["error"] = f"WHOIS query to {current_whois_server} failed: {raw_whois_text if raw_whois_text else 'No response'}"
            # lookup_result["raw_text_on_error"] = raw_whois_text
            return lookup_result # domain_queried is in lookup_result

    if "error" not in lookup_result:
        lookup_result["error"] = "Failed to get data using any determined protocol, and no specific error was captured."
    return lookup_result # domain_queried is in lookup_result


if __name__ == "__main__":
    test_domains_main = [
        "google.com", "github.io", "nic.uk", "example.de",
        "nonexistentdomain12345abc.org", "fsf.org", "gouv.fr"
    ]

    for domain_to_test in test_domains_main:
        logger.info(f"\n--- Unified Lookup for: {domain_to_test} (Prefer RDAP, fallback WHOIS) ---")
        result = unified_domain_lookup(domain_to_test, preferred_protocol="try_both")

        if "error" in result and not (result.get("raw_text") or result.get("raw_json")):
            logger.info(f"  Critical Error for {result.get('domain_queried', domain_to_test)}: {result['error']}")
        else:
            final_protocol_used = "N/A"
            if result.get("protocol_attempts"):
                final_protocol_used = result["protocol_attempts"][-1]["protocol"]
            logger.info(f"  Target Domain: {result.get('domain_queried', domain_to_test)}") # Print queried domain
            logger.info(f"  Final Protocol Used: {result.get('protocol', final_protocol_used)}")
            logger.info(f"  Queried Server/URL: {result.get('queried_server', 'N/A')}")
            if result.get('referral_path_whois'): logger.info(f"  WHOIS Referral Path: {' -> '.join(result['referral_path_whois'])}")

            if "error" in result and (result.get("raw_text") or result.get("raw_json")):
                 logger.info(f"  Lookup Warning/Error (may have partial data): {result['error']}")

            logger.info("\n  Parsed Information:")
            for key, val in result.items():
                skip_keys = ["raw_text", "raw_json", "protocol", "queried_server",
                             "referral_path_whois", "parser_error", "error",
                             "errors_during_lookup", "domain_queried", "protocol_attempts"]
                if key in skip_keys: continue

                if isinstance(val, list) and val:
                    if all(isinstance(i, str) for i in val):
                        display_val = ', '.join(val) if len(val) < 5 else f"[{len(val)} items] {', '.join(val[:2])}..."
                    else:
                        display_val = f"[{len(val)} items] {str(val[:2])}..." if len(val) > 2 else str(val)
                    logger.info(f"    {key.replace('_', ' ').title()}: {display_val}")

                elif isinstance(val, datetime):
                    tz_aware = val.tzinfo is not None and val.tzinfo.utcoffset(val) is not None
                    dt_str = val.strftime('%Y-%m-%d %H:%M:%S %Z') if tz_aware else val.strftime('%Y-%m-%d %H:%M:%S UTC (assumed)')
                    logger.info(f"    {key.replace('_', ' ').title()}: {dt_str if val else 'N/A'}")
                elif val is not None:
                    logger.info(f"    {key.replace('_', ' ').title()}: {str(val)[:200]}")

            if "parser_error" in result and result["parser_error"] and result["parser_error"] != result.get("raw_text", "") and result["parser_error"] != result.get("raw_json", {}):
                logger.info(f"  Parser Specific Error: {result['parser_error']}")
            if result.get("errors_during_lookup"):
                logger.info("  Additional errors/warnings during lookup process:")
                for e_msg in result["errors_during_lookup"]: logger.info(f"    - {e_msg}")
            if result.get("protocol_attempts"):
                logger.info("  Protocol Attempt Log:")
                for attempt in result["protocol_attempts"]: logger.info(f"    - Tried {attempt['protocol']} on {attempt.get('server','N/A')}" + (f" (Reason: {attempt.get('reason')})" if attempt.get('reason') else ""))
        logger.info("-" * 70)
        time.sleep(1.5)
