import unittest
from unittest.mock import patch, MagicMock, mock_open
import urllib.request
import urllib.error
import ssl
import socket
import os # For creating temporary wordlist file

# Import from the sibling module using a relative import so the tests run whether
# the package is executed directly or as part of the larger project.
from .directory_bruteforce import (
    check_url,
    brute_force_paths,
    DEFAULT_WORDLIST,
    DEFAULT_EXTENSIONS,
    UNVERIFIED_SSL_CONTEXT,
)

class TestDirectoryBruteforcer(unittest.TestCase):

    def test_01_check_url_found_200(self):
        print("\nRunning test_01_check_url_found_200...")
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.reason = "OK"
        mock_response.headers = {'Content-Length': '1234', 'Content-Type': 'text/html'}
        mock_response.geturl.return_value = "http://example.com/test"

        mock_urlopen_context = MagicMock()
        mock_urlopen_context.__enter__.return_value = mock_response

        with patch('urllib.request.urlopen', return_value=mock_urlopen_context) as mock_urlopen:
            result = check_url("http://example.com/test", timeout=1.0, method="GET")
            self.assertEqual(result["status_code"], 200)
            self.assertEqual(result["content_length"], '1234')
            self.assertIsNone(result["error"])
            mock_urlopen.assert_called_once()
            self.assertEqual(mock_urlopen.call_args[0][0].method, "GET")


    def test_02_check_url_not_found_404(self):
        print("\nRunning test_02_check_url_not_found_404...")
        mock_http_error = urllib.error.HTTPError("http://example.com/notfound", 404, "Not Found",
                                                 hdrs={'Server': 'TestServer'}, fp=None)
        with patch('urllib.request.urlopen', side_effect=mock_http_error) as mock_urlopen:
            result = check_url("http://example.com/notfound", timeout=1.0, method="GET")
            self.assertEqual(result["status_code"], 404)
            self.assertIsNone(result["error"]) # HTTPError itself is not an "error" for the function, it's a valid response
            self.assertIn('Server', result["headers"])
            mock_urlopen.assert_called_once()

    def test_03_check_url_redirect_301(self):
        print("\nRunning test_03_check_url_redirect_301...")
        mock_response = MagicMock()
        mock_response.status = 301
        mock_response.reason = "Moved Permanently"
        mock_response.headers = {'Location': 'http://example.com/new-location'}
        mock_response.geturl.return_value = "http://example.com/old" # URL after internal handling by urlopen if any

        mock_urlopen_context = MagicMock()
        mock_urlopen_context.__enter__.return_value = mock_response

        with patch('urllib.request.urlopen', return_value=mock_urlopen_context):
            result = check_url("http://example.com/old", timeout=1.0, method="GET")
            self.assertEqual(result["status_code"], 301)
            self.assertEqual(result["headers"]['Location'], 'http://example.com/new-location')

    def test_04_check_url_timeout(self):
        print("\nRunning test_04_check_url_timeout...")
        with patch('urllib.request.urlopen', side_effect=socket.timeout("Timed out")) as mock_urlopen:
            result = check_url("http://example.com/timeout", timeout=0.1, method="GET")
            self.assertIsNone(result["status_code"])
            self.assertIn("Timed out", result["error"])
            mock_urlopen.assert_called_once()

    def test_05_check_url_ssl_context_https(self):
        print("\nRunning test_05_check_url_ssl_context_https...")
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.geturl.return_value = "https://example.com/secure"
        mock_response.headers = {}


        mock_urlopen_context = MagicMock()
        mock_urlopen_context.__enter__.return_value = mock_response

        with patch('urllib.request.urlopen', return_value=mock_urlopen_context) as mock_urlopen:
            check_url("https://example.com/secure", timeout=1.0, method="GET")
            mock_urlopen.assert_called_once()
            call_args, call_kwargs = mock_urlopen.call_args
            # Ensure the UNVERIFIED_SSL_CONTEXT was passed to urlopen for HTTPS
            self.assertEqual(call_kwargs.get('context'), UNVERIFIED_SSL_CONTEXT)

    def test_06_check_url_head_then_get(self):
        print("\nRunning test_06_check_url_head_then_get...")
        # Mock HEAD response (e.g., 405 Method Not Allowed)
        mock_head_error = urllib.error.HTTPError("http://example.com/resource", 405, "Method Not Allowed", {}, fp=None)

        # Mock GET response (e.g., 200 OK)
        mock_get_response = MagicMock()
        mock_get_response.status = 200
        mock_get_response.reason = "OK"
        mock_get_response.headers = {'Content-Length': '500'}
        mock_get_response.geturl.return_value = "http://example.com/resource"

        mock_get_urlopen_context = MagicMock()
        mock_get_urlopen_context.__enter__.return_value = mock_get_response

        # Side effect for urlopen: first call (HEAD) raises error, second call (GET) returns mock_get_response
        with patch('urllib.request.urlopen', side_effect=[mock_head_error, mock_get_urlopen_context]) as mock_urlopen:
            # The brute_force_paths function implements the HEAD then GET logic
            # We are testing check_url here, which is called by brute_force_paths.
            # The test for brute_force_paths will cover the combined logic better.
            # For check_url, we test one method at a time.

            # Test HEAD path (will be called by brute_force_paths first)
            head_call_result = check_url("http://example.com/resource", timeout=1.0, method="HEAD")
            self.assertEqual(head_call_result["status_code"], 405) # From mock_head_error

            # Test GET path (would be called if HEAD was inconclusive)
            get_call_result = check_url("http://example.com/resource", timeout=1.0, method="GET")
            self.assertEqual(get_call_result["status_code"], 200) # From mock_get_response
            self.assertEqual(get_call_result["content_length"], '500')

            self.assertEqual(mock_urlopen.call_count, 2)


    def test_07_brute_force_paths_basic(self):
        print("\nRunning test_07_brute_force_paths_basic...")
        base_url = "http://testserver.com"
        test_words = ["admin", "test", "backup"]
        test_extensions = ["", ".php"] # Test directory and .php file

        # Expected URLs:
        # http://testserver.com/admin
        # http://testserver.com/admin.php
        # http://testserver.com/test
        # http://testserver.com/test.php
        # http://testserver.com/backup
        # http://testserver.com/backup.php

        # Mock responses for check_url
        def mock_check_url_side_effect(url, timeout, custom_headers=None, method="HEAD"):
            # Simulate some found, some not found, one redirect
            if url == "http://testserver.com/admin":
                return {"url": url, "status_code": 200, "reason": "OK", "content_length": "100", "final_url": url}
            elif url == "http://testserver.com/test.php":
                return {"url": url, "status_code": 200, "reason": "OK", "content_length": "200", "final_url": url}
            elif url == "http://testserver.com/backup": # This will be a redirect
                return {"url": url, "status_code": 301, "reason": "Moved",
                        "headers": {"Location": "http://testserver.com/backup_new_location/"},
                        "final_url": "http://testserver.com/backup_new_location/"}
            elif url == "http://testserver.com/backup_new_location/": # The target of the redirect
                 return {"url": url, "status_code": 200, "reason": "OK", "content_length": "300", "final_url": url}
            # Other URLs will implicitly return None from the mock if not specified,
            # or we can explicitly make check_url return None for 404s etc.
            # The actual check_url returns a dict with status 404.
            # For this test, let's assume default return of MagicMock (None) for unhandled.
            # Or, more accurately, mock the 404 response.
            return {"url": url, "status_code": 404, "reason": "Not Found", "final_url": url}


        # Patch the check_url function *within* the directory_bruteforce module
        with patch(
            'core.scanning.wordlist_scanning.directory_bruteforce.check_url',
            side_effect=mock_check_url_side_effect,
        ) as mocked_check_url_func:
            found = brute_force_paths(base_url, custom_wordlist=test_words, extensions=test_extensions,
                                      num_threads=1, delay=0, follow_redirects=True, max_redirects=1, verbose=False)

            self.assertEqual(len(found), 3, f"Expected 3 found paths (admin, test.php, backup_new_location), got {len(found)}. Found: {found}")

            urls_found = [item['url'] for item in found]
            self.assertIn("http://testserver.com/admin", urls_found)
            self.assertIn("http://testserver.com/test.php", urls_found)
            self.assertIn("http://testserver.com/backup_new_location/", urls_found) # Redirected path

            # Check call count: 6 original paths + 1 redirected path = 7 calls to process_url (which calls check_url)
            # Each process_url might call check_url twice (HEAD then GET if HEAD fails appropriately)
            # This assertion is tricky due to HEAD/GET logic in process_url.
            # Let's check that it was called for the base URLs.
            self.assertGreaterEqual(mocked_check_url_func.call_count, len(test_words) * len(test_extensions))


    def test_08_brute_force_paths_wordlist_file(self):
        print("\nRunning test_08_brute_force_paths_wordlist_file...")
        base_url = "http://fileserver.com"
        wordlist_content = "docs\nscripts\nimages\n#commentline\n\nprivate"
        mock_wordlist_file = "mock_wordlist.txt"

        # Expected words: docs, scripts, images, private

        def mock_check_url_for_filetest(url, timeout, custom_headers=None, method="HEAD"):
            if url == "http://fileserver.com/docs":
                return {"url": url, "status_code": 200, "final_url": url}
            if url == "http://fileserver.com/private.txt": # Assuming "" and ".txt" are default exts if not specified
                return {"url": url, "status_code": 403, "final_url": url}
            return {"url": url, "status_code": 404, "final_url": url}

        # We use mock_open to simulate reading from a file.
        # And patch check_url to control its behavior.
        with patch('builtins.open', mock_open(read_data=wordlist_content)) as mocked_file, \
             patch(
                 'core.scanning.wordlist_scanning.directory_bruteforce.check_url',
                 side_effect=mock_check_url_for_filetest,
             ):

            found = brute_force_paths(base_url, wordlist_path=mock_wordlist_file,
                                      extensions=["", ".txt"], # Test with specific extensions
                                      num_threads=1, delay=0, verbose=False)

            mocked_file.assert_called_once_with(mock_wordlist_file, 'r', encoding='utf-8', errors='ignore')
            self.assertEqual(len(found), 2, f"Expected 2 found paths, got {found}")

            found_urls = {item['url'] for item in found}
            self.assertIn("http://fileserver.com/docs", found_urls)
            self.assertIn("http://fileserver.com/private.txt", found_urls)

    def test_09_url_construction_trailing_slashes(self):
        print("\nRunning test_09_url_construction_trailing_slashes...")
        # Test URL joining logic (implicitly tested by brute_force_paths, but good to be specific)
        # brute_force_paths adds a trailing slash to base_url if missing.
        # urllib.parse.urljoin then handles further slashes correctly.

        # Mock check_url to just return what it was called with for verification
        def capture_url_side_effect(url, timeout, custom_headers=None, method="HEAD"):
            return {"url": url, "status_code": 200, "final_url": url} # Simulate found

        with patch(
            'core.scanning.wordlist_scanning.directory_bruteforce.check_url',
            side_effect=capture_url_side_effect,
        ) as mocked_check_url:
            brute_force_paths("http://normalslash.com/", custom_wordlist=["path"], extensions=[""], num_threads=1, delay=0)
            mocked_check_url.assert_any_call("http://normalslash.com/path", unittest.mock.ANY, custom_headers=unittest.mock.ANY, method=unittest.mock.ANY)

            mocked_check_url.reset_mock()
            brute_force_paths("http://noendslash.com", custom_wordlist=["path"], extensions=[""], num_threads=1, delay=0)
            mocked_check_url.assert_any_call("http://noendslash.com/path", unittest.mock.ANY, custom_headers=unittest.mock.ANY, method=unittest.mock.ANY)

            mocked_check_url.reset_mock()
            brute_force_paths("http://withsubdir/", custom_wordlist=["item"], extensions=[".html"], num_threads=1, delay=0)
            mocked_check_url.assert_any_call("http://withsubdir/item.html", unittest.mock.ANY, custom_headers=unittest.mock.ANY, method=unittest.mock.ANY)

            mocked_check_url.reset_mock()
            brute_force_paths("http://withsubdir/", custom_wordlist=["/leadingword/"], extensions=[""], num_threads=1, delay=0)
            # word "/leadingword/" becomes "leadingword" after strip('/')
            # urljoin("http://withsubdir/", "leadingword") == "http://withsubdir/leadingword"
            mocked_check_url.assert_any_call("http://withsubdir/leadingword", unittest.mock.ANY, custom_headers=unittest.mock.ANY, method=unittest.mock.ANY)


if __name__ == '__main__':
    suite = unittest.TestSuite()
    tests_to_run = [
        TestDirectoryBruteforcer('test_01_check_url_found_200'),
        TestDirectoryBruteforcer('test_02_check_url_not_found_404'),
        TestDirectoryBruteforcer('test_03_check_url_redirect_301'),
        TestDirectoryBruteforcer('test_04_check_url_timeout'),
        TestDirectoryBruteforcer('test_05_check_url_ssl_context_https'),
        TestDirectoryBruteforcer('test_06_check_url_head_then_get'),
        TestDirectoryBruteforcer('test_07_brute_force_paths_basic'),
        TestDirectoryBruteforcer('test_08_brute_force_paths_wordlist_file'),
        TestDirectoryBruteforcer('test_09_url_construction_trailing_slashes'),
    ]
    for test in tests_to_run:
        suite.addTest(test)
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)
    # unittest.main(verbosity=2)
