# core/reconnaissance/dns_enumeration/dns_enumeration.py

import dns.resolver
import dns.zone
import dns.query
import dns.exception
import socket
from logging_config import get_logger

logger = get_logger(__name__)

DEFAULT_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'SOA', 'TXT', 'SRV']


def get_single_dns_record(domain, record_type):
    """
    Resolves a single DNS record type for a given domain.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(domain, record_type)
        return [rdata.to_text() for rdata in answers]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return f"NXDOMAIN: The domain '{domain}' does not exist."
    except dns.resolver.Timeout:
        return f"Timeout: The query for {record_type} records for '{domain}' timed out."
    except dns.exception.DNSException as e:
        return f"DNS Error for {record_type} records of '{domain}': {e}"


def get_all_dns_records(domain, record_types=None):
    """
    Gathers multiple DNS records for a given domain.
    """
    if record_types is None:
        record_types = DEFAULT_RECORD_TYPES

    results = {"domain": domain, "records": {}, "errors": []}

    try:
        # Preliminary domain existence check
        temp_resolver = dns.resolver.Resolver()
        temp_resolver.timeout = 2
        temp_resolver.lifetime = 2
        temp_resolver.resolve(domain, 'A')
    except dns.resolver.NXDOMAIN:
        results["errors"].append(f"Domain '{domain}' does not exist (NXDOMAIN).")
        return results
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.Timeout:
        results["errors"].append(f"Initial A record check for '{domain}' timed out. Proceeding with other record types.")
    except dns.exception.DNSException as e:
        results["errors"].append(f"Initial DNS check error for '{domain}': {e}. Proceeding cautiously.")

    # Perform record lookups
    for record_type in record_types:
        records_or_error = get_single_dns_record(domain, record_type)
        if isinstance(records_or_error, str):
            results["records"][record_type] = []
            if not ("NXDOMAIN" in records_or_error and any("NXDOMAIN" in e for e in results["errors"])):
                results["errors"].append(f"Error for {record_type} of {domain}: {records_or_error}")
        else:
            results["records"][record_type] = records_or_error

    return results


def attempt_zone_transfer(domain):
    """
    Attempts DNS zone transfers (AXFR) against domain's NS servers.
    """
    results = {"domain": domain, "zone_transfers": {}, "errors": []}
    ns_records_data = get_single_dns_record(domain, 'NS')

    if isinstance(ns_records_data, str):
        results["errors"].append(f"Could not retrieve NS records for {domain}: {ns_records_data}")
        return results
    if not ns_records_data:
        results["errors"].append(f"No NS records found for {domain}, cannot attempt zone transfer.")
        return results

    ns_server_names = [ns.strip('.') for ns in ns_records_data]

    for ns_name in ns_server_names:
        ns_ip = None
        try:
            ip_answers = get_single_dns_record(ns_name, 'A')
            if ip_answers and isinstance(ip_answers, list) and len(ip_answers) > 0:
                ns_ip = ip_answers[0]
            else:
                ip_answers_aaaa = get_single_dns_record(ns_name, 'AAAA')
                if ip_answers_aaaa and isinstance(ip_answers_aaaa, list) and len(ip_answers_aaaa) > 0:
                    ns_ip = ip_answers_aaaa[0]
                else:
                    error_msg = f"Could not resolve IP for NS server '{ns_name}'."
                    results["zone_transfers"][ns_name] = error_msg
                    results["errors"].append(error_msg)
                    continue
        except Exception as e_resolve:
            error_msg = f"Unexpected error resolving NS server '{ns_name}': {e_resolve}"
            results["zone_transfers"][ns_name] = error_msg
            results["errors"].append(error_msg)
            continue

        if not ns_ip:
            error_msg = f"NS server IP for '{ns_name}' resolved to None or empty. Skipping AXFR."
            results["zone_transfers"][ns_name] = error_msg
            results["errors"].append(error_msg)
            continue

        current_ns_key = f"{ns_name} ({ns_ip})"
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10.0, lifetime=15.0))
            zone_data = []
            if zone:
                for name_node, node_data in zone.nodes.items():
                    for rdataset in node_data.rdatasets:
                        zone_data.append(f"{name_node} {rdataset.to_text()}")
                results["zone_transfers"][current_ns_key] = zone_data if zone_data else "Zone transfer successful but no records returned."
            else:
                results["zone_transfers"][current_ns_key] = "Zone transfer succeeded but zone object empty."
        except dns.query.TransferError as e:
            results["zone_transfers"][current_ns_key] = f"Zone transfer failed (TransferError): {e}"
        except ConnectionRefusedError:
            results["zone_transfers"][current_ns_key] = "Zone transfer failed: Connection refused."
        except socket.timeout:
            results["zone_transfers"][current_ns_key] = "Zone transfer failed: Query timed out."
        except dns.exception.FormError as e:
            results["zone_transfers"][current_ns_key] = f"Zone transfer failed (FormError): {e}"
        except dns.resolver.NoNameservers as e:
            results["zone_transfers"][current_ns_key] = f"Zone transfer failed (NoNameservers): {e}"
        except Exception as e:
            results["zone_transfers"][current_ns_key] = f"Zone transfer failed (General Exception): {type(e).__name__} - {e}"

    return results


# 🧠 NEW — Unified orchestration function
def dns_lookup(domain, record_types=None, attempt_axfr=True):
    """
    Performs a full DNS reconnaissance workflow for the given domain.

    Args:
        domain (str): The target domain.
        record_types (list, optional): DNS record types to enumerate.
        attempt_axfr (bool): Whether to attempt zone transfer.

    Returns:
        dict: Full results including DNS records, zone transfer data, and errors.
    """
    logger.info(f"=== Starting DNS Lookup for {domain} ===")
    summary = {
        "domain": domain,
        "records": {},
        "zone_transfer": {},
        "errors": []
    }

    # 1. Get DNS Records
    all_records = get_all_dns_records(domain, record_types)
    summary["records"] = all_records.get("records", {})
    summary["errors"].extend(all_records.get("errors", []))

    # 2. If domain exists and AXFR is requested
    if attempt_axfr and not any("NXDOMAIN" in e for e in summary["errors"]):
        logger.info(f"Attempting Zone Transfer for {domain} ...")
        axfr_result = attempt_zone_transfer(domain)
        summary["zone_transfer"] = axfr_result.get("zone_transfers", {})
        summary["errors"].extend(axfr_result.get("errors", []))
    else:
        logger.info(f"Skipping AXFR for {domain} (NXDOMAIN or disabled).")

    logger.info(f"=== Completed DNS Lookup for {domain} ===")
    return summary


# --------------------------------------------------------------------------
# Example standalone run
# --------------------------------------------------------------------------
if __name__ == '__main__':
    test_domains = [
        "example.com",
        "zonetransfer.me",
        "thisshouldnotexist1234567890qwerty.com"
    ]

    for d in test_domains:
        results = dns_lookup(d)
        logger.info(f"\n>>> Summary for {d}")
        for rtype, values in results["records"].items():
            if values:
                logger.info(f"  {rtype}: {values}")
        if results["zone_transfer"]:
            logger.info(f"  Zone Transfer Results: {list(results['zone_transfer'].keys())}")
        if results["errors"]:
            logger.info(f"  Errors: {results['errors']}")
