import urllib.request
import urllib.error
import urllib.parse
import ssl
import socket
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed # Added as_completed

# Attempt to import or replicate get_random_user_agent
try:
    # Assuming search_engine_scraper is in a path accessible via PYTHONPATH or relative import
    # This relative import might need adjustment based on actual execution context / project structure
    from ...reconnaissance.passive_reconnaissance.search_engine_scraper.search_engine_scraper import get_random_user_agent
except ImportError:
    print("Warning: Could not import get_random_user_agent from search_engine_scraper. Using a basic default list.")
    USER_AGENTS_FALLBACK = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    ]
    def get_random_user_agent():
        return random.choice(USER_AGENTS_FALLBACK)

DEFAULT_WORDLIST = ["admin", "login", "test", "backup", "dev", "config", "wp-admin", "phpmyadmin", "uploads", "includes", "secret", "index"]
DEFAULT_EXTENSIONS = ["", ".php", ".html", ".htm", ".txt", ".bak", ".old", ".zip", ".tar.gz", ".rar", ".cfg", ".conf", ".ini", ".log", ".sql", ".db"] # Empty string for directories
DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 5.0 # seconds
DEFAULT_DELAY = 0.1 # seconds
DEFAULT_MAX_REDIRECTS = 3

# Create an SSL context that doesn't verify certificates (for scanning dev/internal sites)
# WARNING: This is insecure for general browsing but useful for pentesting tools.
UNVERIFIED_SSL_CONTEXT = ssl.create_default_context()
UNVERIFIED_SSL_CONTEXT.check_hostname = False
UNVERIFIED_SSL_CONTEXT.verify_mode = ssl.CERT_NONE


def check_url(url, timeout, custom_headers=None, method="HEAD"):
    """
    Checks a single URL and returns its status code and other relevant info.
    Tries HEAD first, then GET if HEAD is not informative or fails.
    """
    result = {"url": url, "status_code": None, "reason": None, "headers": None, "content_length": None, "error": None, "final_url": url}
    req_headers = {"User-Agent": get_random_user_agent()}
    if custom_headers:
        req_headers.update(custom_headers)

    try:
        req = urllib.request.Request(url, headers=req_headers, method=method)
        context_to_use = UNVERIFIED_SSL_CONTEXT if url.startswith("https://") else None

        with urllib.request.urlopen(req, context=context_to_use, timeout=timeout) as response:
            result["status_code"] = response.status
            result["reason"] = response.reason
            result["headers"] = dict(response.headers)
            result["content_length"] = response.headers.get('Content-Length')
            result["final_url"] = response.geturl() # In case of internal redirect not caught by HTTPError
            # For HEAD request, we don't read the body.
            # If method was GET and we want content snippet, we'd read here.

    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        result["reason"] = e.reason
        result["headers"] = dict(e.headers)
        result["final_url"] = e.geturl() if hasattr(e, 'geturl') else url
        # Sometimes error pages have content, but we're primarily interested in status for brute-forcing
    except (urllib.error.URLError, socket.timeout, ConnectionRefusedError, socket.error) as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"

    return result


def brute_force_paths(base_url, wordlist_path=None, custom_wordlist=None,
                      extensions=None, num_threads=DEFAULT_THREADS,
                      timeout=DEFAULT_TIMEOUT, delay=DEFAULT_DELAY,
                      follow_redirects=True, max_redirects=DEFAULT_MAX_REDIRECTS,
                      custom_headers=None, verbose=False):
    """
    Brute-forces directories and files on a web server.

    Args:
        base_url (str): The base URL to scan (e.g., "http://target.com").
        wordlist_path (str, optional): Path to a wordlist file.
        custom_wordlist (list, optional): A list of words if not using a file.
        extensions (list, optional): List of extensions to append (e.g., [".php", ".html", ""]).
        num_threads (int): Number of concurrent threads.
        timeout (float): Request timeout in seconds.
        delay (float): Delay between requests per thread.
        follow_redirects (bool): Whether to follow 3xx redirects.
        max_redirects (int): Maximum number of redirects to follow for a single path.
        custom_headers (dict, optional): Custom HTTP headers to send.
        verbose (bool): If True, prints progress and all attempts.

    Returns:
        list: A list of dictionaries, each representing a found path with details.
    """
    if not base_url.endswith('/'):
        base_url += '/'

    words = []
    if custom_wordlist:
        words = custom_wordlist
    elif wordlist_path:
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"Error: Wordlist file not found: {wordlist_path}. Using default list.")
            words = DEFAULT_WORDLIST
        except Exception as e:
            print(f"Error reading wordlist {wordlist_path}: {e}. Using default list.")
            words = DEFAULT_WORDLIST
    else:
        words = DEFAULT_WORDLIST

    if extensions is None:
        extensions = DEFAULT_EXTENSIONS

    found_paths = []
    urls_to_check = []

    for word in words:
        if not word: continue # Skip empty words
        # Normalize word: remove leading/trailing slashes as we add them systematically
        word = word.strip('/')
        for ext in extensions:
            # Construct path: word + ext. If ext is empty, it's a directory/extensionless file.
            # If word itself contains typical extension, don't add another (basic heuristic)
            path_component = word
            if ext and not any(word.lower().endswith(e) for e in ['.php', '.html', '.txt', '.js', '.asp', '.aspx'] if e): # Avoid word.php.txt
                path_component += ext

            # Ensure no double slashes if base_url ends with / and path_component starts with /
            # urllib.parse.urljoin handles this well.
            full_url = urllib.parse.urljoin(base_url, path_component)
            urls_to_check.append(full_url)

    # Deduplicate URLs before scanning
    urls_to_check = sorted(list(set(urls_to_check)))
    if verbose: print(f"Generated {len(urls_to_check)} unique URLs to check.")

    def process_url(url, current_redirect_depth=0):
        if verbose: print(f"  Checking: {url}")

        # Try HEAD first for efficiency
        head_result = check_url(url, timeout, custom_headers=custom_headers, method="HEAD")

        # Analyze HEAD result
        # If HEAD gives a clear "found" (2xx) or "forbidden" (401/403), or a definitive "not found" (404 for some servers)
        # we might not need a GET.
        # However, some servers return 404 for HEAD but 200 for GET on existing paths, or HEAD is disabled.
        # Also, for redirects, HEAD will show the redirect.

        final_result = head_result

        if head_result.get("status_code") in [None, 404, 405] or (head_result.get("error") and "method not allowed" not in head_result.get("error", "").lower()):
            # If HEAD failed, was 404 (might be misleading), 405 (Method Not Allowed), or other error, try GET.
            if verbose and (head_result.get("status_code") != 404 or head_result.get("error")): # Avoid too much noise for typical 404s on HEAD
                print(f"    HEAD request for {url} status: {head_result.get('status_code')}, error: {head_result.get('error')}. Trying GET.")
            time.sleep(delay / 2 if delay > 0 else 0) # Small pause before GET
            get_result = check_url(url, timeout, custom_headers=custom_headers, method="GET")
            final_result = get_result # Prioritize GET result if HEAD was inconclusive

        status = final_result.get("status_code")

        if status and (200 <= status < 300 or status in [401, 403, 500]):
            path_data = {
                "url": final_result.get("final_url", url),
                "status": status,
                "reason": final_result.get("reason"),
                "length": final_result.get("content_length")
            }
            if verbose or status != 404 : print(f"    FOUND: {path_data['url']} (Status: {path_data['status']})")
            return path_data

        elif follow_redirects and status and (300 <= status < 400) and current_redirect_depth < max_redirects:
            redirect_url = final_result.get("headers", {}).get("Location")
            if redirect_url:
                # Handle relative redirects
                redirect_url = urllib.parse.urljoin(final_result.get("final_url", url), redirect_url)
                if verbose: print(f"    REDIRECT: {url} -> {redirect_url} (Status: {status}). Following...")
                # Recursive call to follow, increment depth
                return process_url(redirect_url, current_redirect_depth + 1)
            elif verbose:
                print(f"    REDIRECT (Status: {status}) but no Location header found for {url}.")

        elif verbose and not (status == 404 and not final_result.get("error")): # Don't log every 404 unless there's also an error
            print(f"    Skipping: {url} (Status: {status}, Error: {final_result.get('error')})")

        return None # Not found or not interesting

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_to_url = {executor.submit(process_url, u): u for u in urls_to_check}
        for future in as_completed(future_to_url):
            # url_origin = future_to_url[future] # Original URL submitted
            try:
                path_info = future.result()
                if path_info:
                    found_paths.append(path_info)
            except Exception as exc:
                if verbose: print(f"    Error processing future for a URL: {exc}") # Should be caught by check_url
            if delay > 0:
                time.sleep(delay) # Apply delay between processing results of threads

    return sorted(found_paths, key=lambda x: x['url'])


if __name__ == '__main__':
    # Example usage:
    # You need a web server running for this to hit anything.
    # Example: python -m http.server 8000 in a directory with some files.

    test_base_url = "http://127.0.0.1:8000" # Change to a live target with EXPLICIT PERMISSION

    # Create some dummy files/dirs for local testing if using python -m http.server
    # In the directory where you run the server:
    # mkdir admin test
    # echo "secret content" > secret.txt
    # echo "<html><head><title>Login Page</title></head><body>Login form</body></html>" > login.html

    print(f"--- Directory/File Brute-Force Test against {test_base_url} ---")
    print(f"Using default wordlist and extensions. Threads: {DEFAULT_THREADS}, Timeout: {DEFAULT_TIMEOUT}s, Delay: {DEFAULT_DELAY}s")

    # For this test, use a very small custom wordlist and extensions to be quick
    custom_words_for_test = ["admin", "test", "secret", "login", "index", "nonexistent"]
    custom_exts_for_test = ["", ".html", ".txt", ".php"] # Empty for dirs

    # Check if local server is running, otherwise skip live test part
    try:
        conn_test_sock = socket.create_connection(("127.0.0.1", 8000), timeout=1)
        conn_test_sock.close()
        print(f"Local test server on {test_base_url} seems responsive.")

        found_results = brute_force_paths(
            test_base_url,
            custom_wordlist=custom_words_for_test,
            extensions=custom_exts_for_test,
            num_threads=5,
            timeout=2.0,
            delay=0.05,
            verbose=True
        )

        if found_results:
            print("\n--- Found Paths ---")
            for item in found_results:
                print(f"  URL: {item['url']}, Status: {item['status']}, Length: {item.get('length', 'N/A')}")
        else:
            print("\nNo interesting paths found with the test wordlist/extensions.")

    except (socket.error, ConnectionRefusedError):
        print(f"\nWARNING: Could not connect to local test server at {test_base_url}. Skipping live brute-force test.")
        print("To run this example, ensure a web server (e.g., 'python -m http.server 8000') is running.")

    print("\n--- Brute-Force Test Finished ---")
