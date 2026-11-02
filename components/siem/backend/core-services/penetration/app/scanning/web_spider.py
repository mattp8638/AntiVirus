import urllib.request
import urllib.parse
import urllib.error
import ssl
import socket
import time
import random
from collections import deque
from bs4 import BeautifulSoup # Requires beautifulsoup4 to be installed

# Attempt to import or replicate get_random_user_agent
try:
    from ..reconnaissance.passive_reconnaissance.search_engine_scraper.search_engine_scraper import get_random_user_agent
except (ImportError, ValueError): # ValueError if relative import goes too high
    print("Warning (web_spider.py): Could not import get_random_user_agent. Using a basic default list.")
    USER_AGENTS_FALLBACK = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    ]
    def get_random_user_agent():
        return random.choice(USER_AGENTS_FALLBACK)

DEFAULT_MAX_DEPTH = 2
DEFAULT_TIMEOUT_SPIDER = 5.0 # seconds
DEFAULT_DELAY_SPIDER = 0.2 # seconds

UNVERIFIED_SSL_CONTEXT_SPIDER = ssl.create_default_context()
UNVERIFIED_SSL_CONTEXT_SPIDER.check_hostname = False
UNVERIFIED_SSL_CONTEXT_SPIDER.verify_mode = ssl.CERT_NONE

class WebSpider:
    def __init__(self, base_url, scope_domains=None, max_depth=DEFAULT_MAX_DEPTH,
                 user_agent=None, respect_robots_txt=True,
                 timeout=DEFAULT_TIMEOUT_SPIDER, delay=DEFAULT_DELAY_SPIDER, verbose=False):

        self.base_url = base_url
        parsed_base_url = urllib.parse.urlparse(base_url)
        self.base_netloc = parsed_base_url.netloc

        if scope_domains:
            self.scope_domains = [d.lower() for d in scope_domains]
        else:
            self.scope_domains = [self.base_netloc.lower()]

        self.max_depth = max_depth
        self.user_agent_to_use = user_agent if user_agent else get_random_user_agent()
        self.respect_robots_txt = respect_robots_txt
        self.timeout = timeout
        self.delay = delay
        self.verbose = verbose

        self.urls_to_visit = deque([(base_url, 0)]) # Store (url, depth)
        self.visited_urls = set()
        self.discovered_links = set() # All valid, in-scope links found
        self.robots_rules = {} # Store parsed robots.txt rules {user_agent: [disallowed_paths]}

        if self.respect_robots_txt:
            self._fetch_and_parse_robots_txt(parsed_base_url)

    def _is_in_scope(self, url):
        try:
            parsed_url = urllib.parse.urlparse(url)
            # Ensure it's http or https and netloc is in scope_domains
            if parsed_url.scheme not in ["http", "https"]:
                return False
            return parsed_url.netloc.lower() in self.scope_domains
        except Exception:
            return False # Invalid URL

    def _fetch_and_parse_robots_txt(self, base_parsed_url):
        robots_url = urllib.parse.urlunparse((base_parsed_url.scheme, base_parsed_url.netloc, "/robots.txt", "", "", ""))
        if self.verbose: print(f"  Fetching robots.txt from: {robots_url}")
        try:
            content, _, _ = self._fetch_url_content(robots_url) # Use internal fetcher
            if content:
                current_ua = None
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split(":", 1)
                    if len(parts) != 2:
                        continue

                    key, value = parts[0].strip().lower(), parts[1].strip()

                    if key == "user-agent":
                        current_ua = value.lower() # Store UA keys in lowercase
                        if current_ua not in self.robots_rules:
                            self.robots_rules[current_ua] = []
                    elif key == "disallow" and current_ua: # current_ua will be lowercase here
                        # Basic path handling, does not handle wildcards or complex rules fully
                        if value: # Only add if there's a path
                             self.robots_rules[current_ua].append(value)
                if self.verbose: print(f"    Parsed robots.txt. Rules for {len(self.robots_rules)} user-agents.")
            elif self.verbose:
                print(f"    robots.txt not found or empty at {robots_url}")
        except Exception as e:
            if self.verbose: print(f"    Error fetching or parsing robots.txt: {e}")

        # Ensure there's always an entry for '*' if not already parsed.
        if '*' not in self.robots_rules:
            self.robots_rules['*'] = []
        # No need to add self.user_agent_to_use here, as _can_fetch will check its lowercase version and then '*'


    def _can_fetch(self, url_path):
        """Checks if robots.txt rules allow fetching the URL path for the spider's UA."""
        if not self.respect_robots_txt or not self.robots_rules:
            return True

        ua_to_check = self.user_agent_to_use.lower()
        # Check rules for specific user agent first
        disallowed_for_specific_ua = self.robots_rules.get(ua_to_check, [])
        for disallowed_path in disallowed_for_specific_ua:
            if disallowed_path == "/" and url_path.startswith("/"): return False # Disallow all
            if disallowed_path and url_path.startswith(disallowed_path):
                return False

        # Then check rules for wildcard '*' user agent (if specific UA didn't disallow)
        disallowed_for_wildcard_ua = self.robots_rules.get('*', [])
        for disallowed_path in disallowed_for_wildcard_ua:
            if disallowed_path == "/" and url_path.startswith("/"): return False
            if disallowed_path and url_path.startswith(disallowed_path):
                return False
        return True

    def _fetch_url_content(self, url):
        """Fetches URL content, returns (content_text, final_url, error_message)."""
        req_headers = {"User-Agent": self.user_agent_to_use}
        try:
            req = urllib.request.Request(url, headers=req_headers)
            context = UNVERIFIED_SSL_CONTEXT_SPIDER if url.startswith("https://") else None
            with urllib.request.urlopen(req, context=context, timeout=self.timeout) as response:
                if response.status == 200:
                    # Check content type before decoding (simple check)
                    content_type = response.headers.get('Content-Type', '').lower()
                    if 'text/html' in content_type or 'application/xhtml+xml' in content_type:
                        charset = response.headers.get_content_charset() or 'utf-8'
                        html_content = response.read().decode(charset, errors='replace')
                        return html_content, response.geturl(), None
                    else:
                        if self.verbose: print(f"    Skipping non-HTML content at {url} (Content-Type: {content_type})")
                        return None, response.geturl(), f"Non-HTML content-type: {content_type}"
                else:
                    return None, response.geturl(), f"HTTP status {response.status}"
        except urllib.error.HTTPError as e:
            return None, url, f"HTTPError: {e.code} {e.reason}"
        except (urllib.error.URLError, socket.timeout, ConnectionRefusedError, socket.error) as e:
            return None, url, f"Network/URL Error: {e}"
        except Exception as e:
            return None, url, f"Unexpected fetch error: {e}"

    def _parse_links(self, html_content, current_page_url):
        """Parses HTML and extracts valid, in-scope links."""
        links = set()
        if not html_content:
            return links

        soup = BeautifulSoup(html_content, 'html.parser')
        for anchor_tag in soup.find_all('a', href=True):
            href = anchor_tag['href']
            if not href or href.startswith('#') or href.lower().startswith(('mailto:', 'tel:', 'javascript:')):
                continue

            # Construct absolute URL
            absolute_url = urllib.parse.urljoin(current_page_url, href)
            # Normalize: remove fragment
            absolute_url = urllib.parse.urlunparse(urllib.parse.urlparse(absolute_url)._replace(fragment=""))

            if self._is_in_scope(absolute_url):
                links.add(absolute_url)
        return links

    def crawl(self):
        """Main crawling loop."""
        if self.verbose: print(f"Starting crawl. Base URL: {self.base_url}, Scope: {self.scope_domains}, Max Depth: {self.max_depth}")

        while self.urls_to_visit:
            current_url, current_depth = self.urls_to_visit.popleft()

            if current_url in self.visited_urls or current_depth > self.max_depth:
                continue

            self.visited_urls.add(current_url)

            parsed_current_url = urllib.parse.urlparse(current_url)
            if not self._can_fetch(parsed_current_url.path or "/"): # Check path against robots.txt
                if self.verbose: print(f"  Skipping (robots.txt): {current_url}")
                continue

            if self.verbose: print(f"  Crawling (Depth {current_depth}): {current_url}")

            html_content, final_url, error = self._fetch_url_content(current_url)

            if error:
                if self.verbose: print(f"    Error fetching {current_url}: {error}")
                continue # Skip this URL on error

            # Add the final URL (after any redirects handled by _fetch_url_content)
            if final_url != current_url and self._is_in_scope(final_url):
                 self.discovered_links.add(final_url)
                 if final_url not in self.visited_urls: # Add to visited to avoid re-processing if it was a redirect loop
                     self.visited_urls.add(final_url)
            elif self._is_in_scope(current_url): # Add original if no redirect or redirect was out of scope
                self.discovered_links.add(current_url)


            if html_content and current_depth < self.max_depth:
                new_links = self._parse_links(html_content, final_url)
                for link in new_links:
                    if link not in self.visited_urls and link not in {q_item[0] for q_item in self.urls_to_visit}:
                        self.urls_to_visit.append((link, current_depth + 1))

            if self.delay > 0:
                time.sleep(self.delay)

        if self.verbose: print(f"Crawl finished. Discovered {len(self.discovered_links)} unique in-scope links.")
        return sorted(list(self.discovered_links))

if __name__ == '__main__':
    # Example Usage
    # Needs a target that has some links.
    # target_to_spider = "http://scanme.nmap.org"
    target_to_spider = "http://127.0.0.1:7000" # If running `python -m http.server 7000` in a dir with some html files

    print(f"--- Web Spider Test against {target_to_spider} ---")

    # Create dummy local server files for a more predictable test
    # mkdir -p temp_spider_site/subdir
    # echo '<html><body><a href="page2.html">Page 2</a> <a href="subdir/page3.html">Page 3</a> <a href="http://external.com">External</a> <a href="/abs_page.html">Absolute Path</a></body></html>' > temp_spider_site/index.html
    # echo '<html><body><a href="index.html">Home</a> <a href="mailto:t@e.com">Mail</a></body></html>' > temp_spider_site/page2.html
    # echo '<html><body><a href="../page2.html">Back to Page 2</a></body></html>' > temp_spider_site/subdir/page3.html
    # echo '<html><body>Absolute page</body></html>' > temp_spider_site/abs_page.html
    # echo 'User-agent: *\nDisallow: /subdir/\nDisallow: /abs_page.html' > temp_spider_site/robots.txt

    # To run this example, navigate to `temp_spider_site` and run `python -m http.server 7000`
    # Then run this web_spider.py script from its location.

    try:
        # Quick check if local server for test is up
        conn_test = socket.create_connection(("127.0.0.1", 7000), timeout=1)
        conn_test.close()
        print(f"Local test server on {target_to_spider} seems responsive.")

        spider = WebSpider(target_to_spider, max_depth=2, respect_robots_txt=True, verbose=True, delay=0.1)
        # To test scope: spider = WebSpider(target_to_spider, scope_domains=["127.0.0.1", "localhost"], max_depth=1, verbose=True)
        discovered = spider.crawl()

        print("\n--- Discovered In-Scope Links (respecting robots.txt if enabled) ---")
        for link in discovered:
            print(link)

        print(f"\nTotal unique in-scope links: {len(discovered)}")

    except (socket.error, ConnectionRefusedError):
         print(f"\nWARNING: Could not connect to local test server at {target_to_spider}.")
         print("To run this example, create the 'temp_spider_site' as described in comments,")
         print("then navigate into 'temp_spider_site' and run 'python -m http.server 7000'.")
         print("Then execute this web_spider.py script.")

    print("\n--- Web Spider Test Finished ---")
