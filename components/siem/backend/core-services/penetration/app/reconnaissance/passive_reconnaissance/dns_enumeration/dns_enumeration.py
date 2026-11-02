# core/reconnaissance/passive_reconnaissance/dns_enumeration/dns_enumeration.py

import dns.resolver
import dns.zone
import dns.query
import dns.exception
import time
from dataclasses import dataclass
from typing import Any, Optional, Dict
from logging_config import get_logger
logger = get_logger(__name__)

# (Flask related imports removed as per discussion to focus on core logic first)
# from flask import Blueprint, request, jsonify

DEFAULT_SUBDOMAIN_WORDLIST = ["www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2", "admin", "test", "dev", "webdisk", "cpanel", "autodiscover", "owa", "portal", "support", "blog", "shop"]

SUPPORTED_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'SOA', 'TXT', 'CNAME', 'SRV', 'PTR', 'DNSKEY', 'DS', 'NSEC', 'NSEC3']


@dataclass
class DNSQueryResult:
    """Standard return object for DNS operations."""
    result: Any = None
    error: Optional[str] = None

def get_authoritative_ns(domain) -> DNSQueryResult:
    """Gets authoritative Name Servers for a domain."""
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        return DNSQueryResult(result=[str(rdata.target) for rdata in answers])
    except dns.resolver.NXDOMAIN:
        return DNSQueryResult(error=f"NS query for {domain} resulted in NXDOMAIN")
    except dns.resolver.NoAnswer:
        return DNSQueryResult(error=f"No NS records found for {domain}")
    except dns.exception.Timeout:
        return DNSQueryResult(error=f"Timeout while resolving NS records for {domain}")
    except Exception as e:
        return DNSQueryResult(error=f"Unexpected error resolving NS records for {domain}: {e}")


def single_dns_lookup(domain, record_type='A', server=None, timeout=2.0) -> DNSQueryResult:
    """Performs a DNS lookup for a specific record type.
    Optionally queries a specific server."""
    resolver = dns.resolver.Resolver()
    if server:
        resolver.nameservers = [server]
    resolver.timeout = timeout
    resolver.lifetime = timeout

    results = []
    try:
        answers = resolver.resolve(domain, record_type)
        for rdata in answers:
            if record_type == 'MX':
                results.append({'preference': rdata.preference, 'exchange': str(rdata.exchange)})
            elif record_type == 'SOA':
                results.append({
                    'mname': str(rdata.mname), 'rname': str(rdata.rname),
                    'serial': rdata.serial, 'refresh': rdata.refresh,
                    'retry': rdata.retry, 'expire': rdata.expire, 'minimum': rdata.minimum
                })
            elif record_type == 'SRV':
                results.append({
                    'priority': rdata.priority, 'weight': rdata.weight,
                    'port': rdata.port, 'target': str(rdata.target)
                })
            elif record_type in ['DNSKEY', 'DS']:
                results.append(rdata.to_text())
            else:
                results.append(rdata.to_text())
        return DNSQueryResult(result=results)
    except dns.resolver.NXDOMAIN:
        return DNSQueryResult(error=f"{domain} does not exist")
    except dns.resolver.NoAnswer:
        return DNSQueryResult(error=f"No {record_type} record found for {domain}")
    except dns.exception.Timeout:
        return DNSQueryResult(error=f"Timeout querying {record_type} for {domain}" + (f" at {server}" if server else ""))
    except dns.resolver.NoNameservers:
         return DNSQueryResult(error=f"No nameservers available to query {record_type} for {domain}")
    except Exception as e:
        return DNSQueryResult(error=f"Error querying {record_type} for {domain}: {e}")

def enumerate_dns_records(domain, record_types=None, server=None, timeout=2.0) -> DNSQueryResult:
    """Enumerates multiple DNS record types for a given domain."""
    if record_types is None:
        record_types = ['A', 'AAAA', 'MX', 'NS', 'SOA', 'TXT', 'CNAME']

    results: Dict[str, DNSQueryResult] = {}
    for r_type in record_types:
        if r_type.upper() not in SUPPORTED_RECORD_TYPES:
            results[r_type] = DNSQueryResult(error=f"Unsupported record type: {r_type}")
            continue
        lookup_result = single_dns_lookup(domain, r_type.upper(), server=server, timeout=timeout)
        results[r_type] = lookup_result
        time.sleep(0.1)  # Small delay between queries
    return DNSQueryResult(result=results)

def attempt_zone_transfer(domain, ns_server=None, timeout=5.0) -> DNSQueryResult:
    """Attempts an AXFR zone transfer for the given domain from specified or authoritative NS."""
    if not ns_server:
        ns_result = get_authoritative_ns(domain)
        if ns_result.error or not ns_result.result:
            return DNSQueryResult(error=f"Could not determine authoritative NS for {domain} to attempt AXFR.")
        ns_to_try = ns_result.result[0]
    else:
        ns_to_try = ns_server

    try:
        messages = list(
            dns.query.xfr(
                ns_to_try,
                domain,
                rdtype=dns.rdatatype.AXFR,
                rdclass=dns.rdataclass.IN,
                timeout=timeout,
                lifetime=timeout * 3,
            )
        )

        if not messages:
            return DNSQueryResult(
                result={"server": ns_to_try},
                error="Zone transfer failed: No messages received from XFR query (empty or failed transfer).",
            )

        zone = dns.zone.from_xfr(messages, origin=domain, relativize=True)
        records = {}
        if zone:
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    record_type_str = dns.rdatatype.to_text(rdataset.rdtype)
                    records.setdefault(record_type_str, [])
                    for rdata in rdataset:
                        records[record_type_str].append({str(name): rdata.to_text()})
            if records:
                return DNSQueryResult(result={"server": ns_to_try, "records": records})
            return DNSQueryResult(result={"server": ns_to_try}, error="Zone transfer successful but no records found (empty zone?).")
        return DNSQueryResult(result={"server": ns_to_try}, error="Zone transfer attempt returned no zone data.")

    except dns.exception.FormError as e:
        return DNSQueryResult(result={"server": ns_to_try}, error=f"Zone transfer failed: FormError (Server refused or malformed response). Details: {e}")
    except dns.exception.Timeout as e:
        return DNSQueryResult(result={"server": ns_to_try}, error=f"Zone transfer failed: Timeout connecting to {ns_to_try}. Details: {e}")
    except dns.query.TransferError as e:
        return DNSQueryResult(result={"server": ns_to_try}, error=f"Zone transfer failed: dns.query.TransferError. Details: {e}")
    except dns.exception.DNSException as e:
        return DNSQueryResult(result={"server": ns_to_try}, error=f"Zone transfer failed: DNSException. Details: {e}")
    except ConnectionRefusedError as e:
        return DNSQueryResult(result={"server": ns_to_try}, error=f"Zone transfer failed: Connection refused by {ns_to_try}. Details: {e}")
    except ValueError as e:
        return DNSQueryResult(result={"server": ns_to_try}, error=f"Zone transfer failed for {domain} from {ns_to_try}: ValueError - Args: {e.args} Repr: {repr(e)}")
    except Exception as e:
        return DNSQueryResult(result={"server": ns_to_try}, error=f"Zone transfer failed for {domain} from {ns_to_try}: {type(e).__name__} - {e}")

def brute_force_subdomains(domain, wordlist=None, base_record_type='A', server=None, timeout=1.0, delay_between_queries=0.05) -> DNSQueryResult:
    """Brute-forces subdomains using a wordlist."""
    if wordlist is None:
        wordlist = DEFAULT_SUBDOMAIN_WORDLIST

    found_subdomains = {}
    for word in wordlist:
        subdomain = f"{word}.{domain}".lower()
        lookup = single_dns_lookup(subdomain, base_record_type, server=server, timeout=timeout)
        if not lookup.error and lookup.result:
            found_subdomains[subdomain] = lookup.result
        time.sleep(delay_between_queries)

    return DNSQueryResult(result=found_subdomains)

def comprehensive_dns_scan(domain, wordlist_path=None, perform_axfr=True, perform_bruteforce=True, custom_record_types=None) -> DNSQueryResult:
    """Performs a comprehensive set of DNS enumeration tasks."""
    scan_results = {"domain": domain, "general_records": {}, "axfr_results": [], "bruteforce_subdomains": {}}

    # 1. Standard record enumeration
    record_types_to_query = custom_record_types if custom_record_types else SUPPORTED_RECORD_TYPES
    scan_results["general_records"] = enumerate_dns_records(domain, record_types_to_query).result or {}

    # 2. Attempt Zone Transfer
    if perform_axfr:
        ns_response = get_authoritative_ns(domain)
        if ns_response.result:
            for ns in ns_response.result:
                axfr_res = attempt_zone_transfer(domain, ns_server=ns)
                scan_results["axfr_results"].append({"result": axfr_res.result, "error": axfr_res.error})
                time.sleep(0.2)
        else:
            scan_results["axfr_results"].append({"error": ns_response.error or "Could not find authoritative NS servers for AXFR attempt."})

    # 3. Brute-force Subdomains
    if perform_bruteforce:
        custom_wordlist = None
        if wordlist_path:
            try:
                with open(wordlist_path, 'r') as f:
                    custom_wordlist = [line.strip() for line in f if line.strip()]
            except Exception:
                custom_wordlist = DEFAULT_SUBDOMAIN_WORDLIST
        else:
            custom_wordlist = DEFAULT_SUBDOMAIN_WORDLIST

        brute_results = brute_force_subdomains(domain, wordlist=custom_wordlist).result
        if brute_results:
            scan_results["bruteforce_subdomains"] = brute_results

    return DNSQueryResult(result=scan_results)

# Example Usage (for testing if run directly)
if __name__ == "__main__":
    test_domain = "zonetransfer.me" # Good for testing AXFR
    # test_domain_google = "google.com"
    # test_domain_nx = "nonexistentdomain12345pleasedontregister.com"

    logger.info(f"--- Testing DNS Enumeration for: {test_domain} ---")

    # Test single lookup
    # print("\n[Single Lookup AAAA for google.com]")
    # print(single_dns_lookup(test_domain_google, 'AAAA'))
    # print("\n[Single Lookup MX for google.com]")
    # print(single_dns_lookup(test_domain_google, 'MX'))
    # print("\n[Single Lookup SOA for google.com]")
    # print(single_dns_lookup(test_domain_google, 'SOA'))
    # print("\n[Single Lookup TXT for google.com]")
    # print(single_dns_lookup(test_domain_google, 'TXT'))
    # print("\n[Single Lookup for NXDOMAIN]")
    # print(single_dns_lookup(test_domain_nx, 'A'))


    # Test general enumeration
    # print(f"\n[General Enumeration for {test_domain_google}]")
    # general_enum_results = enumerate_dns_records(test_domain_google, ['A', 'MX', 'NS', 'TXT', 'SOA'])
    # for rectype, recval in general_enum_results.items():
    #     print(f"  {rectype}: {recval}")

    # Test AXFR
    # print(f"\n[AXFR Test for {test_domain}]")
    # ns_servers = get_authoritative_ns(test_domain)
    # if ns_servers:
    #     print(f"  Authoritative NS for {test_domain}: {ns_servers}")
    #     axfr_data = attempt_zone_transfer(test_domain, ns_servers[0]) # Try first one
    #     if "error" in axfr_data:
    #         print(f"  AXFR Error: {axfr_data['error']}")
    #     elif "records" in axfr_data:
    #         print(f"  AXFR Success from {axfr_data['server']}! Found {len(axfr_data['records'])} record types.")
    #         # for r_type, r_list in axfr_data['records'].items():
    #         #     print(f"    Type: {r_type}, Count: {len(r_list)}")
    #         #     if r_list : print(f"      Sample: {list(r_list[0].items())[0]}")
    # else:
    #     print(f"  Could not get NS for {test_domain} to attempt AXFR.")

    # Test subdomain brute-force
    # print(f"\n[Subdomain Brute-force for example.com (using default list)]")
    # brute_subs = brute_force_subdomains("example.com")
    # if brute_subs:
    #     print(f"  Found subdomains for example.com:")
    #     for sub, ips in brute_subs.items():
    #         print(f"    {sub}: {ips}")
    # else:
    #     print("  No subdomains found for example.com via default brute-force.")

    # Test comprehensive scan
    logger.info(f"\n[Comprehensive Scan for {test_domain}] (AXFR and Brute-force enabled)")
    # Create a dummy wordlist for testing bruteforce part of comprehensive scan
    dummy_wordlist_content = ["office", "owa", "test", "dev", "support", "asdfnonexistent"]
    dummy_wordlist_file = "temp_wordlist.txt"
    with open(dummy_wordlist_file, "w") as f:
        for word in dummy_wordlist_content:
            f.write(word + "\n")

    comprehensive_results = comprehensive_dns_scan(test_domain, wordlist_path=dummy_wordlist_file, perform_axfr=True, perform_bruteforce=True).result

    logger.info("\n--- Comprehensive Scan Results ---")
    logger.info(f"Domain: {comprehensive_results['domain']}")

    logger.info("\n  General Records:")
    if comprehensive_results['general_records']:
        for r_type, r_data in comprehensive_results['general_records'].items():
            logger.info(f"    {r_type}: {str(r_data)[:200]}" + ("..." if len(str(r_data)) > 200 else ""))
    else:
        logger.info("    No general records found or all queries failed.")

    logger.info("\n  AXFR Results:")
    if comprehensive_results['axfr_results']:
        for axfr_attempt in comprehensive_results['axfr_results']:
            if axfr_attempt.get("error"):
                logger.info(f"    Attempt on {axfr_attempt.get('result', {}).get('server', 'Unknown Server')}: Error - {axfr_attempt['error']}")
            elif axfr_attempt.get("result", {}).get("records"):
                logger.info(f"    Attempt on {axfr_attempt['result']['server']}: Success! {len(axfr_attempt['result']['records'])} record types transferred.")
            elif axfr_attempt.get("result"):
                 logger.info(f"    Attempt on {axfr_attempt['result'].get('server', 'Unknown Server')}: {axfr_attempt['result'].get('message', '')}")
    else:
        logger.info("    No AXFR attempts made or all failed silently (should have an error).")

    logger.info("\n  Bruteforce Subdomains:")
    if comprehensive_results['bruteforce_subdomains']:
        for sub, val in comprehensive_results['bruteforce_subdomains'].items():
            logger.info(f"    {sub}: {val}")
    else:
        logger.info("    No subdomains found via brute-force with the given list.")

    import os
    os.remove(dummy_wordlist_file)
    logger.info(f"\nCleaned up {dummy_wordlist_file}")
    logger.info("--- DNS Enumeration Test Finished ---")
