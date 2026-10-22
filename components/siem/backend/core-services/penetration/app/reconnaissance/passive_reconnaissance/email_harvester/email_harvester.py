import re
import requests
import time
from urllib.parse import urlparse, urljoin
from logging_config import get_logger
logger = get_logger(__name__)

try:
    # Relative import for when this module is part of the larger package
    from ..search_engine_scraper.search_engine_scraper import search_engine_query, get_random_user_agent
except ImportError:
    # Absolute import or fallback for standalone execution / testing
    try:
        from core.reconnaissance.passive_reconnaissance.search_engine_scraper.search_engine_scraper import search_engine_query, get_random_user_agent
    except ImportError:
        logger.info("Warning: Could not import search_engine_query. Search engine harvesting will be disabled.")
        search_engine_query = None # Make it explicitly None if import fails
        def get_random_user_agent():
            return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

EMAIL_REGEX = re.compile(
    r"""(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])""",
    re.IGNORECASE
)

PGP_KEYSERVER_URL = "https://keys.openpgp.org/search?q="
DEFAULT_REQUEST_TIMEOUT = 15
DEFAULT_DELAY_BETWEEN_REQUESTS = 1.5

def extract_emails_from_text(text):
    if not text or not isinstance(text, str):
        return set()
    emails = EMAIL_REGEX.findall(text)
    return set(email.lower() for email in emails)

def scrape_emails_from_url(url, timeout=DEFAULT_REQUEST_TIMEOUT):
    found_emails = set()
    try:
        headers = {"User-Agent": get_random_user_agent()}
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        text_content = response.text
        found_emails.update(extract_emails_from_text(text_content))
        return found_emails, None
    except requests.exceptions.Timeout:
        return found_emails, f"Timeout scraping {url}."
    except requests.exceptions.HTTPError as e:
        return found_emails, f"HTTP error scraping {url}: {e.response.status_code}."
    except requests.exceptions.RequestException as e:
        return found_emails, f"Error scraping {url}: {e}."
    except Exception as e:
        return found_emails, f"Unexpected error scraping {url}: {e}."

def search_pgp_keyservers(domain_or_email_query, timeout=DEFAULT_REQUEST_TIMEOUT):
    emails = set()
    error_messages = []
    url = f"{PGP_KEYSERVER_URL}{requests.utils.quote(domain_or_email_query)}"
    try:
        headers = {"User-Agent": get_random_user_agent()}
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        emails.update(extract_emails_from_text(response.text))
    except requests.exceptions.Timeout:
        error_messages.append(f"Timeout querying PGP server {url.split('?')[0]}.")
    except requests.exceptions.HTTPError as e:
        error_messages.append(f"HTTP error querying PGP server {url.split('?')[0]}: {e.response.status_code}.")
    except requests.exceptions.RequestException as e:
        error_messages.append(f"Request error querying PGP server {url.split('?')[0]}: {e}.")
    except Exception as e:
        error_messages.append(f"Unexpected error with PGP server {url.split('?')[0]}: {e}.")
    return emails, error_messages

def harvest_emails_from_search_engines(domain, num_results_per_dork=5, delay=DEFAULT_DELAY_BETWEEN_REQUESTS):
    if not search_engine_query: # Check if the imported function is available
        return set(), ["Search engine module not available or failed to import."]

    all_emails = set()
    errors = []
    search_dorks = [
        f"\"@{domain}\"", f"email \"@{domain}\"", f"contact \"@{domain}\"",
        f"site:{domain} \"email\"", f"site:{domain} \"contact\"",
        f"site:{domain} filetype:pdf \"@{domain}\"",
        f"site:{domain} intext:\"@{domain}\""
    ]
    # Prioritize DuckDuckGo as it's generally more scraper-friendly
    # Google/Bing are very likely to block or CAPTCHA.
    engines_to_try = ["duckduckgo", "google"]

    for engine_name in engines_to_try:
        logger.info(f"    Querying search engine: {engine_name} for emails related to {domain}")
        for dork_idx, dork in enumerate(search_dorks):
            # print(f"      Using dork: {dork}") # Debug
            # Apply a slightly longer, incremental delay for search engine queries
            current_delay = delay + (dork_idx * 0.5) + (2 if engine_name != "duckduckgo" else 0)

            search_result_data = search_engine_query(query=dork, num_results=num_results_per_dork, engine=engine_name, delay=current_delay)

            if search_result_data.get("error"):
                errors.append(f"Search ({engine_name}) error for dork '{dork}': {search_result_data['error']}")
                time.sleep(current_delay * 1.5) # Longer backoff on error
                continue
            if search_result_data.get("warning"):
                 errors.append(f"Search ({engine_name}) warning for dork '{dork}': {search_result_data['warning']}")

            for result_item in search_result_data.get("results", []):
                if result_item.get("title"):
                    all_emails.update(extract_emails_from_text(result_item["title"]))
                if result_item.get("snippet"):
                    all_emails.update(extract_emails_from_text(result_item["snippet"]))

            time.sleep(current_delay) # Delay between dorks for the same engine
        time.sleep(delay * 2) # Longer delay before switching to the next engine
    return all_emails, errors

def harvest_emails(target_domain, sources=None, base_url_to_scrape=None, filter_by_domain=True):
    if sources is None:
        sources = ['url', 'search_engine'] # Default sources

    all_harvested_emails = set()
    all_errors = []

    logger.info(f"Starting email harvesting for domain: '{target_domain}' using sources: {sources}")

    if 'url' in sources:
        url_to_use = base_url_to_scrape
        if not url_to_use: # If no specific URL provided, try to form one from the target_domain
            try: # Try HTTPS first
                https_url = f"https://{target_domain}"
                requests.head(https_url, timeout=3, headers={"User-Agent": get_random_user_agent()}).raise_for_status()
                url_to_use = https_url
            except requests.RequestException:
                try: # Fallback to HTTP
                    http_url = f"http://{target_domain}"
                    requests.head(http_url, timeout=3, headers={"User-Agent": get_random_user_agent()}).raise_for_status()
                    url_to_use = http_url
                except requests.RequestException:
                    all_errors.append(f"Could not automatically determine a reachable base URL for '{target_domain}'. Skipping direct URL scrape.")

        if url_to_use:
            logger.info(f"  Scraping single URL: {url_to_use}")
            emails_from_site, err = scrape_emails_from_url(url_to_use)
            if err: all_errors.append(err)
            all_harvested_emails.update(emails_from_site)
            time.sleep(DEFAULT_DELAY_BETWEEN_REQUESTS)

    if 'search_engine' in sources and search_engine_query: # Check again if module is available
        emails_from_search, search_errs = harvest_emails_from_search_engines(target_domain, delay=DEFAULT_DELAY_BETWEEN_REQUESTS)
        all_errors.extend(search_errs)
        all_harvested_emails.update(emails_from_search)
        time.sleep(DEFAULT_DELAY_BETWEEN_REQUESTS)
    elif 'search_engine' in sources and not search_engine_query:
         all_errors.append("Search engine harvesting skipped: Email Harvester's search module dependency not met.")

    if 'pgp' in sources:
        logger.info(f"  Querying PGP key servers for: {target_domain}")
        emails_from_pgp, pgp_errs = search_pgp_keyservers(target_domain)
        all_errors.extend(pgp_errs)
        all_harvested_emails.update(emails_from_pgp)
        time.sleep(DEFAULT_DELAY_BETWEEN_REQUESTS)

    final_emails = all_harvested_emails
    if filter_by_domain:
        # Ensure target_domain is just the domain part, not part of an email address
        clean_target_domain = target_domain.split('@')[-1]
        final_emails = {email for email in all_harvested_emails if email.endswith(f"@{clean_target_domain}") or email.endswith(f".{clean_target_domain}")}

    return {"emails": sorted(list(final_emails)), "errors": all_errors}

if __name__ == "__main__":
    domain_to_test = "example.com"
    
    logger.info(f"\n--- Testing Email Harvester for domain: {domain_to_test} ---")
    # Test with multiple sources
    harvest_results = harvest_emails(domain_to_test, sources=['url', 'search_engine', 'pgp'])

    logger.info(f"\nEmails found for '{domain_to_test}' (filtered by domain):")
    if harvest_results["emails"]:
        for found_email in harvest_results["emails"]:
            logger.info(f"  - {found_email}")
    else:
        logger.info("  No emails found matching the domain criteria.")

    if harvest_results["errors"]:
        logger.info("\nErrors during harvesting process:")
        for e_msg in harvest_results["errors"]:
            logger.info(f"  - {e_msg}")

    # Example for a domain that might have PGP entries (use a well-known org)
    # print(f"\n--- Testing PGP search for: 'fsf.org' ---")
    # pgp_emails_fsf, pgp_errors_fsf = search_pgp_keyservers("fsf.org")
    # if pgp_errors_fsf: print("PGP Errors:", pgp_errors_fsf)
    # print("Sample PGP Emails for 'fsf.org':")
    # for idx, mail_item in enumerate(list(pgp_emails_fsf)[:3]): print(f"  - {mail_item}")
    # if len(pgp_emails_fsf) > 3: print(f"  ... and {len(pgp_emails_fsf)-3} more.")

    # Test with a non-existent domain to see error handling
    # print(f"\n--- Testing Email Harvester for non-existent domain: 'thisshouldreallynotexist123.com' ---")
    # non_existent_results = harvest_emails("thisshouldreallynotexist123.com", sources=['url', 'search_engine'])
    # print(f"Emails for non-existent domain: {non_existent_results['emails']}")
    # if non_existent_results['errors']:
    #     print("Errors for non-existent domain:")
    #     for err_item in non_existent_results['errors']: print(f"  - {err_item}")
