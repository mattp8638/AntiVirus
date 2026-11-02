import requests
import json
import time
from datetime import datetime
from logging_config import get_logger
logger = get_logger(__name__)

# Default timeout for HTTP requests
DEFAULT_CT_TIMEOUT = 20  # Increased timeout slightly

def parse_ct_log_entry(entry):
    """
    Parses a single certificate entry from crt.sh JSON output
    to extract common name, subject alternative names (SANs), issuer, and validity.
    """
    common_name = entry.get("common_name", "")
    name_values_str = entry.get("name_value", "")

    all_hostnames = set()
    if common_name and isinstance(common_name, str): # Ensure common_name is a string
        all_hostnames.add(common_name.strip().lower())

    if name_values_str and isinstance(name_values_str, str): # Ensure name_values_str is a string
        for name_val_line in name_values_str.split('\n'):
            name_val_line = name_val_line.strip().lower()
            if name_val_line and name_val_line not in all_hostnames :
                # Basic filter for valid-like hostnames
                if '.' in name_val_line and not '@' in name_val_line and len(name_val_line) < 256 and ' ' not in name_val_line:
                    all_hostnames.add(name_val_line)

    issuer_name = entry.get("issuer_name", "Unknown Issuer")
    not_before_str = entry.get("not_before")
    not_after_str = entry.get("not_after")

    not_before_dt = None
    not_after_dt = None
    if not_before_str and isinstance(not_before_str, str):
        try:
            not_before_dt = datetime.fromisoformat(not_before_str.replace("Z", "").split(".")[0]) # Handle potential fractional seconds and Z
        except ValueError:
            pass
    if not_after_str and isinstance(not_after_str, str):
        try:
            not_after_dt = datetime.fromisoformat(not_after_str.replace("Z", "").split(".")[0])
        except ValueError:
            pass

    return {
        "id": entry.get("id"),
        "logged_at": entry.get("entry_timestamp"),
        "common_name": common_name,
        "all_discovered_hostnames": sorted(list(all_hostnames)),
        "issuer": issuer_name,
        "valid_from": not_before_dt if not_before_dt else not_before_str,
        "valid_to": not_after_dt if not_after_dt else not_after_str,
        "min_cert_id": entry.get("min_cert_id"), # From crt.sh schema
        "min_entry_timestamp": entry.get("min_entry_timestamp") # From crt.sh schema
    }

def fetch_certificates_from_ct(domain, timeout=DEFAULT_CT_TIMEOUT):
    """
    Fetch SSL/TLS certificate information for the given domain from crt.sh.
    
    Args:
        domain (str): The target domain to query. Use "%" as a wildcard for crt.sh.
        timeout (int): Timeout for the HTTP request in seconds.
    
    Returns:
        dict: Results including "hostnames_found", "certificates_details", and "error".
    """
    query_domain = domain if "%" in domain else f"%.{domain}"
    crt_sh_url = f"https://crt.sh/?q={requests.utils.quote(query_domain)}&output=json"

    unique_hostnames = set()
    certificate_details_list = []
    
    try:
        response = requests.get(crt_sh_url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"}) # Added basic User-Agent
        response.raise_for_status()

        content_type = response.headers.get("Content-Type", "")
        if "application/json" not in content_type.lower():
            if response.text.strip() == "[]":
                 raw_certificates = []
            else: # Non-JSON, non-empty-array response
                return {
                    "hostnames_found": [], "certificates_details": [],
                    "error": f"crt.sh did not return expected JSON. Status: {response.status_code}. Response: {response.text[:200]}"
                }
        
        try:
            raw_certificates = response.json()
        except json.JSONDecodeError:
             return {
                "hostnames_found": [], "certificates_details": [],
                "error": f"Failed to decode JSON from crt.sh. Response: {response.text[:200]}"
            }

        if not isinstance(raw_certificates, list):
            return {
                "hostnames_found": [], "certificates_details": [],
                "error": f"crt.sh returned unexpected data (not a list). Data: {str(raw_certificates)[:200]}"
            }
            
        for entry in raw_certificates:
            if not isinstance(entry, dict): continue # Skip non-dict items in the list
            parsed_entry = parse_ct_log_entry(entry)
            certificate_details_list.append(parsed_entry)
            for hostname in parsed_entry["all_discovered_hostnames"]:
                # Filter out wildcards like "*.example.com" if we only want specific hosts
                # but include them for now as they are valid hostnames found in certs.
                # Also filter out empty strings that might have slipped through.
                if hostname and len(hostname) > 0:
                    unique_hostnames.add(hostname)
                
        return {
            "hostnames_found": sorted(list(unique_hostnames)),
            "certificates_details": certificate_details_list,
            "error": None
        }

    except requests.exceptions.Timeout:
        return {"hostnames_found": [], "certificates_details": [], "error": f"Timeout connecting to crt.sh for '{query_domain}'."}
    except requests.exceptions.HTTPError as e:
        return {"hostnames_found": [], "certificates_details": [], "error": f"HTTP error from crt.sh for '{query_domain}': {e}"}
    except requests.exceptions.RequestException as e:
        return {"hostnames_found": [], "certificates_details": [], "error": f"Request error for crt.sh '{query_domain}': {e}"}
    except Exception as e:
        return {"hostnames_found": [], "certificates_details": [], "error": f"Unexpected error querying CT for '{query_domain}': {e}"}

if __name__ == "__main__":
    domains_to_test_ct = ["example.com", "google.com", "sans.org", "isc.sans.edu", "zonetransfer.me", "thisshouldnotexist12345zxcvbnm.com"]

    for domain_name in domains_to_test_ct:
        logger.info(f"\n--- Certificate Transparency Log Check for: {domain_name} ---")
        # To find subdomains, it's best to query with "%.domain.com" for crt.sh
        # The function handles adding "%." if not present.
        results = fetch_certificates_from_ct(domain_name)

        if results["error"]:
            logger.info(f"  Error: {results['error']}")
        else:
            logger.info(f"  Total Unique Hostnames Found: {len(results['hostnames_found'])}")
            if results['hostnames_found']:
                logger.info("  Sample Hostnames (up to 10):")
                for hn in results['hostnames_found'][:10]:
                    logger.info(f"    - {hn}")
                if len(results['hostnames_found']) > 10:
                    logger.info(f"    ... and {len(results['hostnames_found']) - 10} more.")
            else:
                logger.info("  No hostnames found via CT logs for this query.")

            # print(f"\n  Total Certificates Parsed: {len(results['certificates_details'])}")
            # if results['certificates_details']:
            #     print("  Details of first certificate (if any):")
            #     first_cert = results['certificates_details'][0]
            #     print(f"    ID: {first_cert.get('id')}")
            #     print(f"    Common Name: {first_cert.get('common_name')}")
            #     print(f"    Discovered Hostnames in Cert: {', '.join(first_cert.get('all_discovered_hostnames',[]))}")
            #     print(f"    Issuer: {first_cert.get('issuer')}")
            #     vf = first_cert.get('valid_from')
            #     vt = first_cert.get('valid_to')
            #     print(f"    Valid From: {vf.strftime('%Y-%m-%d %H:%M:%S UTC') if isinstance(vf, datetime) else vf}")
            #     print(f"    Valid To: {vt.strftime('%Y-%m-%d %H:%M:%S UTC') if isinstance(vt, datetime) else vt}")
        logger.info("-" * 70)
        time.sleep(1.5) # Respect crt.sh usage policy by adding delays between domains

    # Example of querying for a specific subdomain pattern if needed
    # print(f"\n--- CT Log Check for: app.%.example.com (not handled by default function logic like this) ---")
    # results_specific = fetch_certificates_from_ct("app.%.example.com") # User provides the %
    # if results_specific["error"]:
    #     print(f"  Error: {results_specific['error']}")
    # else:
    #     print(f"  Hostnames for 'app.%.example.com': {results_specific['hostnames_found']}")
