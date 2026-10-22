import unittest
import time
from urllib.parse import urlparse

# from .search_engine_scraper import search_engine_query, generate_dorks, USER_AGENTS, DEFAULT_DELAY
# Simplified import for now
from search_engine_scraper import search_engine_query, generate_dorks, USER_AGENTS, DEFAULT_DELAY


NETWORK_TEST_DELAY_SEARCH = 3.5 # Increased delay for search engine queries

class TestSearchEngineScraper(unittest.TestCase):

    def test_01_generate_dorks_basic(self):
        print("\nRunning test_01_generate_dorks_basic...")
        keyword = "TestCorp"
        domain = "testcorp.example.com"
        dorks = generate_dorks(keyword, domain)
        self.assertTrue(len(dorks) > 2, "Expected several dorks to be generated.")
        self.assertIn(f'"{keyword}"', dorks)
        self.assertIn(f'"{keyword}" site:{domain}', dorks)
        self.assertIn(f'site:{domain} intitle:"index of"', dorks)
        # Check a filetype dork
        self.assertTrue(any(f'filetype:pdf' in d for d in dorks if keyword in d and f"site:{domain}" in d ), "Expected a PDF filetype dork for the domain and keyword.")
        print(f"  Generated {len(dorks)} dorks for {keyword} & {domain}. Sample: {dorks[:3]}")

    def test_02_generate_dorks_no_domain(self):
        print("\nRunning test_02_generate_dorks_no_domain...")
        keyword = "Open Source Project"
        dorks = generate_dorks(keyword, None) # No domain
        self.assertTrue(len(dorks) > 0)
        self.assertIn(f'"{keyword}"', dorks)
        self.assertFalse(any(f'site:' in d for d in dorks), "Site-specific dorks should not be present if no domain is given.")
        self.assertTrue(any(f'filetype:env "DB_PASSWORD"' in d for d in dorks)) # General vulnerability dork
        print(f"  Generated {len(dorks)} dorks for '{keyword}' (no domain). Sample: {dorks[:3]}")

    def test_03_generate_dorks_specific_types(self):
        print("\nRunning test_03_generate_dorks_specific_types...")
        keyword = "My API"
        domain = "api.example.com"
        dork_types = ["site_basic", "inurl_sensitive", "related_domain"]
        dorks = generate_dorks(keyword, domain, dork_types=dork_types)
        self.assertTrue(len(dorks) > 0)
        self.assertIn(f'"{keyword}" site:{domain}', dorks) # From base
        self.assertIn(f'site:{domain} intitle:"index of"', dorks) # From site_basic
        self.assertTrue(any(f'inurl:admin' in d for d in dorks if keyword in d), "Expected an inurl:admin dork.")
        self.assertIn(f'related:{domain}', dorks) # From related_domain
        self.assertFalse(any(f'filetype:pdf' in d for d in dorks), "Filetype dorks should not be present if not specified in types.")
        print(f"  Generated {len(dorks)} dorks for '{keyword}' & '{domain}' (specific types). Sample: {dorks[:3]}")

    # DuckDuckGo HTML scraping is generally the most stable for automated tests.
    # Google and Bing are very prone to blocking/CAPTCHAs.
    def test_04_search_engine_query_duckduckgo_html(self):
        print("\nRunning test_04_search_engine_query_duckduckgo_html...")
        # A fairly general query that should yield results on DDG HTML
        query = "\"Python programming language\" official website"
        num_results_to_fetch = 2

        print(f"  Querying DuckDuckGo HTML for: '{query}' (expecting {num_results_to_fetch} results)")
        result = search_engine_query(query, num_results=num_results_to_fetch, engine="duckduckgo", delay=NETWORK_TEST_DELAY_SEARCH)

        self.assertIsNotNone(result, "Search result should not be None.")

        if "error" in result:
            print(f"  DDG Query Error: {result['error']}")
            if "details" in result: print(f"    Details: {result['details']}")
        self.assertNotIn("error", result, f"DuckDuckGo query returned an error: {result.get('error')}")

        self.assertIn("results", result, "Result dict should contain 'results' key.")
        fetched_results = result.get("results", [])

        if "warning" in result:
            print(f"  DDG Query Warning: {result['warning']}")

        # It's hard to guarantee a specific number of results from a live web query.
        # The main thing is that the query runs without error and returns the expected structure.
        # We'll check that `fetched_results` is a list. It might be empty if DDG changes layout or blocks.
        self.assertIsInstance(fetched_results, list, f"Expected 'results' to be a list, got {type(fetched_results)}")

        if not fetched_results:
            print(f"  Note: DuckDuckGo query for '{query}' returned 0 results. This can happen due to network issues, DDG changes, or actual lack of results.")

        # If results were returned, validate their structure
        if fetched_results: # Only proceed if list is not empty
            self.assertTrue(len(fetched_results) <= num_results_to_fetch, f"Expected at most {num_results_to_fetch} results, got {len(fetched_results)}")
            for item in fetched_results:
                self.assertIn("title", item)
                self.assertIn("link", item)
                self.assertIn("snippet", item)
                self.assertTrue(item["title"], "Result title should not be empty.")
                self.assertTrue(item["link"].startswith("http"), f"Result link should be a valid URL: {item['link']}")
                # Check if link is not a DDG redirect (should have been resolved)
                self.assertFalse("duckduckgo.com/l/" in item["link"], f"Link appears to be an unresolved DDG redirect: {item['link']}")

                # Basic check that the link domain is somewhat relevant (not foolproof)
                parsed_uri = urlparse(item["link"])
                self.assertTrue(parsed_uri.netloc, f"Link should have a valid domain: {item['link']}")
        time.sleep(NETWORK_TEST_DELAY_SEARCH)


    # The following tests for Google and Bing are expected to be flaky and often fail
    # due to anti-scraping measures. They are included for completeness but might
    # need to be skipped or run in environments where scraping is less restricted.
    @unittest.skip("Google scraping is highly unreliable and often blocked by CAPTCHAs.")
    def test_05_search_engine_query_google(self):
        print("\nRunning test_05_search_engine_query_google (SKIPPED - often fails due to CAPTCHA)...")
        query = "site:nasa.gov \"mars rover\""
        num_results_to_fetch = 1
        result = search_engine_query(query, num_results=num_results_to_fetch, engine="google", delay=NETWORK_TEST_DELAY_SEARCH + 2)
        self.assertIsNotNone(result)
        if "error" in result and "CAPTCHA" in result["error"]:
            print(f"  Google CAPTCHA or block encountered as expected: {result['error']}")
            return # This is an "expected" failure mode for Google

        self.assertNotIn("error", result, f"Google query returned an error: {result.get('error')}")
        self.assertIn("results", result)
        # ... (similar assertions as for DDG if successful)
        time.sleep(NETWORK_TEST_DELAY_SEARCH)

    @unittest.skip("Bing scraping is also unreliable and may be blocked.")
    def test_06_search_engine_query_bing(self):
        print("\nRunning test_06_search_engine_query_bing (SKIPPED - often fails due to blocks)...")
        query = "microsoft learn \"azure functions\""
        num_results_to_fetch = 1
        result = search_engine_query(query, num_results=num_results_to_fetch, engine="bing", delay=NETWORK_TEST_DELAY_SEARCH + 2)
        self.assertIsNotNone(result)
        if "error" in result and ("block" in result["error"].lower() or "captcha" in result["error"].lower()):
            print(f"  Bing block or CAPTCHA encountered as expected: {result['error']}")
            return

        self.assertNotIn("error", result, f"Bing query returned an error: {result.get('error')}")
        self.assertIn("results", result)
        # ... (similar assertions as for DDG if successful)
        time.sleep(NETWORK_TEST_DELAY_SEARCH)


if __name__ == '__main__':
    # To run from the parent directory of 'core':
    # python -m core.reconnaissance.passive_reconnaissance.search_engine_scraper.test_search_engine_scraper
    # Or if in the same directory:
    # python test_search_engine_scraper.py

    suite = unittest.TestSuite()
    tests_to_run = [
        TestSearchEngineScraper('test_01_generate_dorks_basic'),
        TestSearchEngineScraper('test_02_generate_dorks_no_domain'),
        TestSearchEngineScraper('test_03_generate_dorks_specific_types'),
        TestSearchEngineScraper('test_04_search_engine_query_duckduckgo_html'),
        # TestSearchEngineScraper('test_05_search_engine_query_google'), # Skipped by default
        # TestSearchEngineScraper('test_06_search_engine_query_bing'),   # Skipped by default
    ]
    for test in tests_to_run:
        suite.addTest(test)

    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)
    # unittest.main(verbosity=2)
