import unittest
from unittest.mock import patch, MagicMock
import urllib.parse

# Assuming web_spider.py is in the same directory or adjusted relative path
# from .web_spider import WebSpider, UNVERIFIED_SSL_CONTEXT_SPIDER
# For now, direct import if in same dir for testing ease:
from web_spider import WebSpider

class TestWebSpider(unittest.TestCase):

    def test_01_is_in_scope(self):
        print("\nRunning test_01_is_in_scope...")
        spider = WebSpider("http://example.com/path", scope_domains=["example.com", "sub.example.com"])
        self.assertTrue(spider._is_in_scope("http://example.com/another"))
        self.assertTrue(spider._is_in_scope("https://example.com/secure"))
        self.assertTrue(spider._is_in_scope("http://sub.example.com/"))
        self.assertFalse(spider._is_in_scope("http://otherdomain.com"))
        self.assertFalse(spider._is_in_scope("ftp://example.com/file"))
        self.assertFalse(spider._is_in_scope("mailto:test@example.com"))
        self.assertFalse(spider._is_in_scope("javascript:alert(1)"))
        self.assertFalse(spider._is_in_scope("http://example.com:8080/path")) # Port check is part of netloc

        spider_no_sub = WebSpider("http://main.com")
        self.assertTrue(spider_no_sub._is_in_scope("http://main.com/page"))
        self.assertFalse(spider_no_sub._is_in_scope("http://sub.main.com"))


    def test_02_parse_links(self):
        print("\nRunning test_02_parse_links...")
        spider = WebSpider("http://example.com", scope_domains=["example.com"])
        html_content = """
        <html><body>
            <a href="page1.html">Page 1</a>
            <a href="/page2.html">Page 2</a>
            <a href="http://example.com/page3.html#section">Page 3 with fragment</a>
            <a href="https://sub.example.com/page4">Out of scope subdomain by default</a>
            <a href="http://other.com/page5">External Page</a>
            <a href="mailto:test@example.com">Mail me</a>
            <a href="javascript:void(0)">JS Link</a>
            <a href="./page6.html">Relative Page 6</a>
            <a href="../page7.html">Relative Page 7 Up</a>
        </body></html>
        """
        # For _parse_links, current_page_url is important for resolving relative links
        current_page_url = "http://example.com/path/current.html"
        links = spider._parse_links(html_content, current_page_url)

        expected_links = {
            "http://example.com/path/page1.html",
            "http://example.com/page2.html", # Resolved from /page2.html
            "http://example.com/page3.html", # Fragment removed
            "http://example.com/path/page6.html", # ./page6.html relative to current_page_url
            "http://example.com/page7.html" # ../page7.html relative to current_page_url's directory
        }
        self.assertEqual(links, expected_links)

        # Test with a different scope that includes sub.example.com
        spider_with_sub = WebSpider("http://example.com", scope_domains=["example.com", "sub.example.com"])
        links_with_sub = spider_with_sub._parse_links(html_content, current_page_url)
        self.assertIn("https://sub.example.com/page4", links_with_sub)


    def test_03_fetch_and_parse_robots_txt(self):
        print("\nRunning test_03_fetch_and_parse_robots_txt...")
        spider = WebSpider("http://example.com", respect_robots_txt=True, verbose=False)

        robots_content_simple = "User-agent: *\nDisallow: /admin\nDisallow: /private/"
        robots_content_specific_ua = "User-agent: TestSpider\nDisallow: /secret\nUser-agent: *\nDisallow: /common"

        # Mock _fetch_url_content
        with patch.object(spider, '_fetch_url_content', return_value=(robots_content_simple, "http://example.com/robots.txt", None)) as mock_fetch:
            spider._fetch_and_parse_robots_txt(urllib.parse.urlparse("http://example.com"))
            self.assertIn("*", spider.robots_rules)
            self.assertIn("/admin", spider.robots_rules["*"])
            self.assertIn("/private/", spider.robots_rules["*"])
            mock_fetch.assert_called_once_with("http://example.com/robots.txt")

        spider.robots_rules = {} # Reset for next test
        spider.user_agent_to_use = "TestSpider/1.0" # This UA will be used by _can_fetch (lowercased)
        # The parsing logic now stores UA keys from robots.txt in lowercase.
        with patch.object(spider, '_fetch_url_content', return_value=(robots_content_specific_ua, "http://example.com/robots.txt", None)):
            spider._fetch_and_parse_robots_txt(urllib.parse.urlparse("http://example.com"))
            self.assertIn("testspider", spider.robots_rules) # Check for lowercase key
            self.assertIn("/secret", spider.robots_rules["testspider"]) # Access with lowercase key
            self.assertIn("*", spider.robots_rules)
            self.assertIn("/common", spider.robots_rules["*"])


    def test_04_can_fetch_with_robots(self):
        print("\nRunning test_04_can_fetch_with_robots...")
        spider = WebSpider("http://example.com", respect_robots_txt=True, verbose=False)
        spider.user_agent_to_use = "MyCrawler" # This will be lowercased by _can_fetch for lookup
        # Set up mock rules with lowercase specific user-agent
        spider.robots_rules = {
            "mycrawler": ["/disallowed_for_mycrawler/", "/specific_file.html"], # Key is now lowercase
            "*": ["/disallowed_for_all/", "/common_secret/"]
        }

        self.assertTrue(spider._can_fetch("/allowed/page.html"))
        self.assertFalse(spider._can_fetch("/disallowed_for_mycrawler/subdir/page.html"))
        self.assertFalse(spider._can_fetch("/specific_file.html"))
        self.assertFalse(spider._can_fetch("/disallowed_for_all/other.html"))
        self.assertTrue(spider._can_fetch("/common_secret_but_allowed/")) # Not starting with /common_secret/
        self.assertFalse(spider._can_fetch("/common_secret/file.txt"))

        # Test root disallow
        spider.robots_rules["*"].append("/")
        self.assertFalse(spider._can_fetch("/any_path_for_wildcard_root_disallow"))
        spider.robots_rules["*"].remove("/") # clean up

        spider.respect_robots_txt = False # Test when ignoring robots.txt
        self.assertTrue(spider._can_fetch("/disallowed_for_mycrawler/page.html"))


    @patch('web_spider.WebSpider._fetch_url_content') # Patching at the module level where WebSpider is defined
    def test_05_crawl_basic_and_depth(self, mock_fetch_url_content):
        print("\nRunning test_05_crawl_basic_and_depth...")
        # Setup mock responses
        # url: (html_content, final_url_after_redirects_if_any)
        mock_page_data = {
            "http://example.com/": ('<html><a href="page1.html">1</a> <a href="/page2.html">2</a></html>', "http://example.com/"),
            "http://example.com/page1.html": ('<html><a href="sub/page1_1.html">1.1</a></html>', "http://example.com/page1.html"),
            "http://example.com/page2.html": ('<html><a href="http://example.com/">Home</a></html>', "http://example.com/page2.html"),
            "http://example.com/sub/page1_1.html": ('<html>Deepest page</html>', "http://example.com/sub/page1_1.html")
        }

        def fetch_side_effect(url):
            if url in mock_page_data:
                content, final_url = mock_page_data[url]
                return content, final_url, None
            return None, url, "404 Not Found" # Simulate 404 for other URLs

        mock_fetch_url_content.side_effect = fetch_side_effect

        # Test crawl with depth 1
        spider_depth1 = WebSpider("http://example.com/", max_depth=1, respect_robots_txt=False, verbose=False, delay=0)
        # spider_depth1.user_agent_to_use = "TestSpider" # Set for consistent robots.txt if it were enabled

        discovered1 = spider_depth1.crawl()
        expected_depth1 = {
            "http://example.com/",
            "http://example.com/page1.html",
            "http://example.com/page2.html"
        }
        self.assertEqual(set(discovered1), expected_depth1, f"Crawl depth 1 failed. Got: {discovered1}")
        self.assertNotIn("http://example.com/sub/page1_1.html", discovered1) # Should not be crawled

        # Test crawl with depth 2
        mock_fetch_url_content.reset_mock() # Reset call count for next spider
        spider_depth2 = WebSpider("http://example.com/", max_depth=2, respect_robots_txt=False, verbose=False, delay=0)
        # spider_depth2.user_agent_to_use = "TestSpider"

        discovered2 = spider_depth2.crawl()
        expected_depth2 = {
            "http://example.com/",
            "http://example.com/page1.html",
            "http://example.com/page2.html",
            "http://example.com/sub/page1_1.html"
        }
        self.assertEqual(set(discovered2), expected_depth2, f"Crawl depth 2 failed. Got: {discovered2}")


    @patch('web_spider.WebSpider._fetch_url_content')
    def test_06_crawl_with_robots_respect(self, mock_fetch_url_content):
        print("\nRunning test_06_crawl_with_robots_respect...")
        base = "http://site.com/"
        robots_txt_content = "User-agent: *\nDisallow: /secret/\nDisallow: /another.html"

        mock_page_data = {
            base: ('<html><a href="page1.html">1</a> <a href="secret/page2.html">2</a> <a href="another.html">3</a></html>', base),
            base + "page1.html": ('<html>Allowed page</html>', base + "page1.html"),
            base + "secret/page2.html": ('<html>Secret page data!</html>', base + "secret/page2.html"), # Should not be fetched
            base + "another.html": ('<html>Another secret page!</html>', base + "another.html") # Should not be fetched
        }

        def fetch_side_effect(url):
            if url == base + "robots.txt":
                return robots_txt_content, url, None
            if url in mock_page_data:
                content, final_url = mock_page_data[url]
                return content, final_url, None
            return None, url, "404 Not Found"

        mock_fetch_url_content.side_effect = fetch_side_effect

        spider = WebSpider(base, max_depth=1, respect_robots_txt=True, verbose=False, delay=0)
        discovered = spider.crawl()

        expected_discovered = {base, base + "page1.html"}
        self.assertEqual(set(discovered), expected_discovered, f"Crawl with robots.txt failed. Got: {discovered}")

        # Check that disallowed URLs were not fetched for content (robots.txt itself is fetched)
        fetched_urls_for_content = set()
        for call_arg in mock_fetch_url_content.call_args_list:
            url_called = call_arg[0][0] # First positional argument of the call
            if url_called != base + "robots.txt":
                fetched_urls_for_content.add(url_called)

        self.assertNotIn(base + "secret/page2.html", fetched_urls_for_content)
        self.assertNotIn(base + "another.html", fetched_urls_for_content)


if __name__ == '__main__':
    suite = unittest.TestSuite()
    tests_to_run = [
        TestWebSpider('test_01_is_in_scope'),
        TestWebSpider('test_02_parse_links'),
        TestWebSpider('test_03_fetch_and_parse_robots_txt'),
        TestWebSpider('test_04_can_fetch_with_robots'),
        TestWebSpider('test_05_crawl_basic_and_depth'),
        TestWebSpider('test_06_crawl_with_robots_respect'),
    ]
    for test in tests_to_run:
        suite.addTest(test)
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)
    # unittest.main(verbosity=2)
