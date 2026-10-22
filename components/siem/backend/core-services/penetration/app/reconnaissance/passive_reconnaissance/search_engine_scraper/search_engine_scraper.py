import urllib.request # For HTTP requests
import urllib.parse # For URL encoding (quote) and parsing (urlparse, parse_qs)
import urllib.error # For HTTP/URL errors
import socket # For socket timeout errors specifically with urlopen

from bs4 import BeautifulSoup # For HTML parsing
import time
import random
import re
from logging_config import get_logger
logger = get_logger(__name__)

# List of common user agents to rotate
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1"
]

# Default delay between requests to the same engine (in seconds)
DEFAULT_DELAY = 3.0 # Increased default delay

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def parse_google_results(soup, num_results):
    results = []
    # Google's selectors are highly volatile. This is a best-effort attempt.
    # Common container for organic results might be divs with class 'g', 'Gx5Zad', 'Ww4FFb', 'tF2Cxc', 'hlcw0c'.
    # Titles are often in <h3>, links are <a> tags.
    # Limit search to avoid overly broad parsing.
    potential_results_containers = soup.find_all('div', class_=re.compile(r'\b(g|Gx5Zad|Ww4FFb|tF2Cxc|hlcw0c|kvH3mc)\b'), limit=num_results + 15)
    
    for container in potential_results_containers:
        title_tag = container.find('h3')
        link_tag = container.find('a', href=True)

        title = title_tag.get_text(strip=True) if title_tag else None
        raw_link = link_tag['href'] if link_tag else None

        if not (title and raw_link):
            # Sometimes the link is nested differently, e.g., inside another div within the container
            if not link_tag: # Try finding 'a' more broadly if specific structure fails
                 link_tag = container.find('a', href=True) # Find any 'a' with href in this container
                 raw_link = link_tag['href'] if link_tag else None
            if not title and link_tag : # If title is missing but link found, use link text as title
                title = link_tag.get_text(strip=True)

        if not (title and raw_link): # Still missing essential parts
            continue

        link = None
        if raw_link.startswith("/url?q="): # Google redirect
            try:
                parsed_g_url = urllib.parse.urlparse(raw_link)
                actual_link = urllib.parse.parse_qs(parsed_g_url.query).get('q', [None])[0]
                if actual_link: link = actual_link
                else: continue # Skip if 'q' param is missing
            except Exception: continue # Parsing redirect failed
        elif raw_link.startswith("http"):
            link = raw_link
        else: continue # Unrecognized link format

        # Snippet extraction
        # Common snippet classes: 'VwiC3b', 's3v9rd', 'B6fmyf', 'SALvLe', 'st3V8e', 'MUxGbd', 'vzR1rc'
        snippet_container = container.find('div', class_=re.compile(r'\b(VwiC3b|s3v9rd|B6fmyf|SALvLe|st3V8e|MUxGbd|vzR1rc|Uroaid)\b'))
        snippet = snippet_container.get_text(separator=' ', strip=True) if snippet_container else "No snippet available."

        if link: # Ensure link was successfully processed
            results.append({"title": title, "link": link, "snippet": snippet})
            if len(results) >= num_results: break
    return results

def parse_bing_results(soup, num_results):
    results = []
    # Bing's class for organic results is often 'b_algo'.
    for item in soup.find_all('li', class_='b_algo', limit=num_results + 5):
        title_tag = item.find('h2')
        link_tag = title_tag.find('a', href=True) if title_tag else item.find('a', href=True)

        title = title_tag.get_text(strip=True) if title_tag else (link_tag.get_text(strip=True) if link_tag else None)
        link = link_tag['href'] if link_tag else None

        snippet_container = item.find('div', class_='b_caption')
        snippet_p = snippet_container.find('p') if snippet_container else None
        snippet = snippet_p.get_text(strip=True) if snippet_p else "No snippet available."

        if title and link and link.startswith('http'):
            results.append({"title": title, "link": link, "snippet": snippet})
            if len(results) >= num_results: break
    return results

def parse_duckduckgo_html_results(soup, num_results):
    results = []
    # Updated selectors for DDG HTML (more resilient attempt)
    # Results are often in <article> or <div> elements with specific classes.
    # Look for a structure: an article/div containing a link (often with title text) and a snippet.

    # Common container patterns: <article class="result">, <div class="web-result">, <div class="result--body">
    # Title/Link: <a class="result__a">, <h3><a ...>
    # Snippet: <a class="result__snippet"> (yes, sometimes snippet is also a link text) or <div class="result__snippet">

    # Find all potential result blocks first
    potential_blocks = soup.find_all(['article', 'div'], class_=re.compile(r'\b(result|web-result|result--body|result__body|links_main)\b'), limit=num_results + 10)

    for block in potential_blocks:
        # Try to find the main link/title first
        # Prefer links with class 'result__a' or 'result-link'
        link_anchor = block.find('a', class_=re.compile(r'\b(result__a|result-link|result__heading)\b'), href=True)
        if not link_anchor: # Fallback: find any <a> within <h2> or <h3>
            header_tag = block.find(['h2', 'h3'])
            if header_tag: link_anchor = header_tag.find('a', href=True)
        if not link_anchor: # Last resort: any link with text in the block
             link_anchor = block.find('a', href=True, text=True)


        title = None
        raw_link = None
        if link_anchor:
            title = link_anchor.get_text(strip=True)
            raw_link = link_anchor['href']

        # Snippet: look for class 'result__snippet' or similar
        snippet_tag = block.find(['a', 'div', 'p'], class_=re.compile(r'\b(result__snippet|result-snippet)\b'))
        snippet = snippet_tag.get_text(strip=True) if snippet_tag else "No snippet available."

        link = None
        if raw_link:
            if raw_link.startswith("/l/") or "duckduckgo.com/l/" in raw_link: # DDG redirect
                try:
                    parsed_ddg_url = urllib.parse.urlparse(raw_link)
                    query_params = urllib.parse.parse_qs(parsed_ddg_url.query)
                    if 'uddg' in query_params and query_params['uddg']:
                        link = query_params['uddg'][0]
                    # Add other potential redirect params if found, e.g., 'rut'
                    elif 'rut' in query_params and query_params['rut']:
                        # Rut often has a timestamp and then the URL, need to parse it out
                        # Example: 1678886400/https://actualurl.com
                        rut_val = query_params['rut'][0]
                        if '/' in rut_val and rut_val.split('/',1)[1].startswith('http'):
                            link = rut_val.split('/',1)[1]
                    if not link: link = None # Failed to extract from redirect
                except Exception: link = None
            elif raw_link.startswith("http"):
                link = raw_link

        if title and link: # Must have both title and a successfully processed link
            results.append({"title": title, "link": link, "snippet": snippet})
            if len(results) >= num_results: break
    return results


def search_engine_query(query, num_results=10, engine="duckduckgo", delay=DEFAULT_DELAY):
    results_data = []
    encoded_query = urllib.parse.quote(query)
    
    headers = {'User-Agent': get_random_user_agent(), 'Accept-Language': 'en-US,en;q=0.5'}


    if engine == "google":
        url = f"https://www.google.com/search?q={encoded_query}&num={min(num_results, 100)}&hl=en&filter=0&cr=countryUS" # Added country restriction to try and stabilize results
    elif engine == "bing":
        url = f"https://www.bing.com/search?q={encoded_query}&count={min(num_results, 50)}&FORM=QBRE&cc=US&setlang=en-US" # Added country/lang
    elif engine == "duckduckgo":
        url = f"https://html.duckduckgo.com/html/?q={encoded_query}&kl=us-en" # kl=us-en for US-English
    else:
        return {"error": "Unsupported search engine. Choose 'google', 'bing', or 'duckduckgo'."}

    # print(f"Querying {engine} for '{query}' (URL: {url[:100]}...). Delaying for {delay}s.")
    time.sleep(delay + random.uniform(0,1)) # Add slight jitter to delay

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=25) as response: # Increased timeout further
            response_url = response.geturl()
            response_text = response.read().decode('utf-8', errors='ignore')
            status_code = response.getcode()

            if status_code == 429:
                return {"error": f"Search query failed: {engine} is rate limiting (HTTP 429). Try increasing delay or changing IP."}
            elif status_code == 503:
                 return {"error": f"Search query failed: {engine} returned HTTP 503. Possibly a CAPTCHA or temporary block."}

            if engine == "google" and ("google.com/sorry/" in response_url or "ipv4.google.com/sorry" in response_url or "CAPTCHA" in response_text or "unusual traffic" in response_text):
                 return {"error": f"Search query failed: {engine} presented a CAPTCHA or unusual traffic page."}
            if engine == "bing" and ("bing.com/newversions" in response_url or "captcha" in response_text.lower()): # Bing CAPTCHA check
                 return {"error": f"Search query failed: {engine} presented a CAPTCHA or similar block page."}


            soup = BeautifulSoup(response_text, 'html.parser')

            if engine == "google":
                results_data = parse_google_results(soup, num_results)
            elif engine == "bing":
                results_data = parse_bing_results(soup, num_results)
            elif engine == "duckduckgo":
                results_data = parse_duckduckgo_html_results(soup, num_results)

            if not results_data and status_code == 200 :
                 return {"results": [], "warning": f"No results successfully parsed for '{query}' on {engine}. HTML structure might have changed, no results exist, or page was a soft block."}

    except urllib.error.HTTPError as e:
        error_message = f"Search query failed with HTTPError: {e.code} {e.reason} for URL {url}."
        if e.code == 429: error_message = f"Search query failed: {engine} is rate limiting (HTTP 429 via HTTPError). Try increasing delay."
        elif e.code == 503: error_message = f"Search query failed: {engine} returned HTTP 503 (via HTTPError). Possibly CAPTCHA/block."
        elif e.code == 403: error_message = f"Search query failed: {engine} returned HTTP 403 Forbidden. User-agent or IP block likely."
        # Attempt to read error response body if available
        try: error_body = e.fp.read().decode(errors='ignore')[:500]
        except: error_body = "(could not read error body)"
        return {"error": error_message, "details": error_body}
    except urllib.error.URLError as e:
        return {"error": f"Search query failed due to a network/URLError: {e.reason} for URL {url}."}
    except socket.timeout:
        return {"error": f"Search query timed out for {engine} (socket timeout) for URL {url}."}
    except ConnectionResetError:
        return {"error": f"Connection reset by peer during query to {engine} for URL {url}."}
    except Exception as e:
        return {"error": f"An unexpected error occurred during search query for {engine}: {type(e).__name__} - {e} for URL {url}."}

    return {"results": results_data}


def generate_dorks(base_keyword, target_domain=None, dork_types=None):
    """
    Generates a list of search engine dorks based on a keyword and optional domain.
    """
    if dork_types is None: # Default set of dork categories
        dork_types = ["site_basic", "filetypes_common", "intitle_sensitive", "inurl_sensitive", "vulnerabilities_basic"]

    dorks = []

    # Always add the base keyword itself, and with site restriction if domain provided
    dorks.append(f'"{base_keyword}"') # Quote base keyword for exact match
    if target_domain:
        dorks.append(f'"{base_keyword}" site:{target_domain}')

    # Site-specific dorks
    if "site_basic" in dork_types and target_domain:
        dorks.append(f'site:{target_domain} intitle:"index of"')
        dorks.append(f'site:{target_domain} ext:log')
        dorks.append(f'site:{target_domain} inurl:wp-admin')
        dorks.append(f'site:{target_domain} "confidential"')
        dorks.append(f'site:{target_domain} "internal use only"')
        dorks.append(f'site:{target_domain} "password"')
        dorks.append(f'site:{target_domain} "secret"')
        dorks.append(f'site:{target_domain} ext:sql OR ext:dbf OR ext:mdb OR ext:backup OR ext:bkf OR ext:bkp')
        dorks.append(f'site:{target_domain} intext:"sql syntax error" OR intext:"mysql_fetch_array()"') # Common error messages

    # Filetype dorks
    if "filetypes_common" in dork_types:
        common_filetypes = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "log", "cfg", "ini", "env", "bak", "config", "csv"]
        for ft in common_filetypes:
            query = f'"{base_keyword}" filetype:{ft}'
            if target_domain: query = f'site:{target_domain} "{base_keyword}" filetype:{ft}'
            dorks.append(query)

    # Intitle dorks for sensitive keywords
    if "intitle_sensitive" in dork_types:
        sensitive_titles = ["login", "admin", "dashboard", "config", "internal", "restricted", "phpmyadmin", "server-status", "version"]
        for title_kw in sensitive_titles:
            query = f'"{base_keyword}" intitle:"{title_kw}"'
            if target_domain: query = f'site:{target_domain} "{base_keyword}" intitle:"{title_kw}"'
            dorks.append(query)

    # Inurl dorks for sensitive paths/parameters
    if "inurl_sensitive" in dork_types:
        sensitive_urls = ["admin", "login", "user", "pass", "config", "backup", "dump", "phpinfo.php", "cgi-bin", "owa", "remote", "includes", "secret"]
        for url_kw in sensitive_urls:
            query = f'"{base_keyword}" inurl:{url_kw}'
            if target_domain: query = f'site:{target_domain} "{base_keyword}" inurl:{url_kw}'
            dorks.append(query)

    # Related dork (if domain is provided)
    if "related_domain" in dork_types and target_domain:
        dorks.append(f"related:{target_domain}")

    # Basic vulnerability/misconfiguration dorks (examples)
    if "vulnerabilities_basic" in dork_types:
        dorks.append(f'intitle:"index of /admin"')
        dorks.append(f'inurl:php?id=1 {target_domain if target_domain else ""}') # Basic SQLi probe idea
        dorks.append(f'filetype:env "DB_PASSWORD" {target_domain if target_domain else ""}')
        dorks.append(f'intitle:"phpinfo()" "PHP Version" {target_domain if target_domain else ""}')


    return sorted(list(set(dorks))) # Remove duplicates and sort


if __name__ == "__main__":
    logger.info("--- Testing Dork Generation ---")
    example_keyword_main = "ACME Corp"
    example_domain_main = "acme.example.com"

    generated_dorks_default_main = generate_dorks(example_keyword_main, example_domain_main)
    logger.info(f"\nGenerated dorks for '{example_keyword_main}' and domain '{example_domain_main}' (default types):")
    for dork_idx_main, dork_item_main in enumerate(generated_dorks_default_main):
        if dork_idx_main < 15 : logger.info(f"  - {dork_item_main}") # Print more samples
    if len(generated_dorks_default_main) > 15: logger.info(f"  ... and {len(generated_dorks_default_main)-15} more.")

    specific_dork_types_main = ["site_basic", "filetypes_common", "related_domain"]
    generated_dorks_specific_main = generate_dorks(example_keyword_main, example_domain_main, dork_types=specific_dork_types_main)
    logger.info(f"\nGenerated dorks for '{example_keyword_main}' and domain '{example_domain_main}' (specific types: {specific_dork_types_main}):")
    for dork_idx_main, dork_item_main in enumerate(generated_dorks_specific_main):
        if dork_idx_main < 10 : logger.info(f"  - {dork_item_main}")
    if len(generated_dorks_specific_main) > 10: logger.info(f"  ... and {len(generated_dorks_specific_main)-10} more.")

    logger.info("\n\n--- Testing Search Engine Scraper (Primarily DuckDuckGo HTML) ---")

    # Use a few generated dorks for testing the scraper.
    # Pick some that are more likely to yield results on DDG for a common, real domain.
    # Using "python.org" as a more reliable test target than a fake domain.
    test_queries_for_scraper = generate_dorks("Python Software Foundation", "python.org", dork_types=["site_basic"])[:2]
    test_queries_for_scraper.append('"Django web framework" filetype:pdf site:djangoproject.com') # More specific
    test_queries_for_scraper.append('intitle:"Welcome to nginx!"') # General server fingerprint

    # Focus testing on DuckDuckGo as it's generally more scraper-friendly.
    engines_to_test_main_scraper = ["duckduckgo"]
    # engines_to_test_main_scraper = ["duckduckgo", "google", "bing"] # Test others cautiously

    for eng_name_main in engines_to_test_main_scraper:
        logger.info(f"\n\n--- TESTING ENGINE: {eng_name_main.upper()} ---")
        if eng_name_main != "duckduckgo":
            logger.info("--- (Warning: Google/Bing scraping is unstable and may be blocked quickly) ---")

        for q_idx_main_scraper, current_query_main_scraper in enumerate(test_queries_for_scraper):
            logger.info(f"\n  Querying for: '{current_query_main_scraper}' using {eng_name_main}")

            current_delay_main = DEFAULT_DELAY + random.uniform(0.5, 2.0) # Longer, more randomized delay
            if eng_name_main != "duckduckgo": current_delay_main += random.uniform(1.0, 2.5)

            results_output_main_scraper = search_engine_query(current_query_main_scraper, num_results=2, engine=eng_name_main, delay=current_delay_main)

            if "error" in results_output_main_scraper:
                logger.info(f"    Error: {results_output_main_scraper['error']}")
                if "details" in results_output_main_scraper: logger.info(f"      Details: {results_output_main_scraper['details']}")
            elif "warning" in results_output_main_scraper:
                logger.info(f"    Warning: {results_output_main_scraper['warning']}")

            if results_output_main_scraper.get("results"):
                logger.info(f"    Found {len(results_output_main_scraper['results'])} results:")
                for res_idx_main_scraper, res_item_main_scraper in enumerate(results_output_main_scraper["results"]):
                    logger.info(f"      Result {res_idx_main_scraper+1}:")
                    logger.info(f"        Title: {res_item_main_scraper['title']}")
                    logger.info(f"        Link: {res_item_main_scraper['link']}")
                    snippet_preview_main_scraper = res_item_main_scraper.get('snippet', 'N/A')
                    if snippet_preview_main_scraper and len(snippet_preview_main_scraper) > 100: snippet_preview_main_scraper = snippet_preview_main_scraper[:97] + "..."
                    logger.info(f"        Snippet: {snippet_preview_main_scraper}")
            elif "error" not in results_output_main_scraper and "warning" not in results_output_main_scraper :
                logger.info("    No results found or parsed for this query.")

            if q_idx_main_scraper < len(test_queries_for_scraper) -1 :
                time.sleep(random.uniform(1.5, 3.0))

        logger.info(f"\n--- END TESTING ENGINE: {eng_name_main.upper()} ---")
        if eng_name_main != engines_to_test_main_scraper[-1]:
            logger.info("\nSwitching engines, adding a longer delay...")
            time.sleep(random.uniform(4.0, 6.0))
