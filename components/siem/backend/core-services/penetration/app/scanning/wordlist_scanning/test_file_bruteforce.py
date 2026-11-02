import unittest
from unittest.mock import patch

from .file_bruteforce import brute_force_files


class TestFileBruteforce(unittest.TestCase):
    """Tests for the ``brute_force_files`` wrapper function."""

    def test_brute_force_files_basic(self):
        """Verify that files are discovered using the provided wordlist and extensions."""

        base_url = "http://test.com"

        def mock_check_url(url, timeout, custom_headers=None, method="HEAD"):
            if url == "http://test.com/admin.php":
                return {"url": url, "status_code": 200, "reason": "OK", "final_url": url}
            if url == "http://test.com/config.txt":
                return {"url": url, "status_code": 403, "reason": "Forbidden", "final_url": url}
            return {"url": url, "status_code": 404, "reason": "Not Found", "final_url": url}

        with patch(
            "core.scanning.wordlist_scanning.directory_bruteforce.check_url",
            side_effect=mock_check_url,
        ):
            found = brute_force_files(
                base_url,
                custom_wordlist=["admin", "config", "missing"],
                extensions=[".php", ".txt"],
                num_threads=1,
                delay=0,
                follow_redirects=False,
                verbose=False,
            )

        urls = {item["url"] for item in found}
        self.assertEqual(len(urls), 2)
        self.assertIn("http://test.com/admin.php", urls)
        self.assertIn("http://test.com/config.txt", urls)

    def test_brute_force_files_missing_wordlist_uses_default(self):
        """If the wordlist file cannot be read the default list should be used."""

        base_url = "http://example.com"

        def mock_check_url(url, timeout, custom_headers=None, method="HEAD"):
            if url == "http://example.com/admin.php":
                return {"url": url, "status_code": 200, "reason": "OK", "final_url": url}
            return {"url": url, "status_code": 404, "reason": "Not Found", "final_url": url}

        with patch("builtins.open", side_effect=FileNotFoundError), \
             patch(
                 "core.scanning.wordlist_scanning.directory_bruteforce.check_url",
                 side_effect=mock_check_url,
             ):
            found = brute_force_files(
                base_url,
                wordlist_path="missing.txt",
                extensions=[".php"],
                num_threads=1,
                delay=0,
                follow_redirects=False,
                verbose=False,
            )

        urls = {item["url"] for item in found}
        self.assertIn("http://example.com/admin.php", urls)


if __name__ == "__main__":
    unittest.main(verbosity=2)

