import unittest
import time
import socket # For checking if target is resolvable

# Assuming os_fingerprinter.py is in the same directory or PYTHONPATH is set up
# from .os_fingerprinter import fingerprint_os_single_target, get_os_from_ttl, get_os_from_window_size, HAS_SCAPY
from os_fingerprinter import fingerprint_os_single_target, get_os_from_ttl, get_os_from_window_size, HAS_SCAPY

# Target for live tests
TARGET_HOST_OS = "scanme.nmap.org" # Known to be Linux
# TARGET_HOST_OS = "127.0.0.1" # For local testing against a known OS

NETWORK_TEST_DELAY_OS = 1.5

class TestOSFingerprinter(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Check if target host is resolvable before running tests."""
        cls.host_resolvable_os = False
        try:
            socket.gethostbyname(TARGET_HOST_OS)
            cls.host_resolvable_os = True
            print(f"\nTarget host {TARGET_HOST_OS} is resolvable. Proceeding with OS fingerprinting tests.")
        except socket.gaierror:
            print(f"\nWARNING: Target host {TARGET_HOST_OS} is not resolvable. OS fingerprinting tests will be skipped.")

    def test_01_get_os_from_ttl(self):
        print("\nRunning test_01_get_os_from_ttl...")
        self.assertIn("Linux/Unix", get_os_from_ttl(64))
        self.assertIn("Linux/Unix", get_os_from_ttl(50)) # Typical TTL after some hops for Linux
        self.assertIn("Windows", get_os_from_ttl(128))
        self.assertIn("Windows", get_os_from_ttl(110)) # Typical TTL after some hops for Windows
        self.assertIn("Other/Network Device", get_os_from_ttl(255))
        self.assertIn("Unknown", get_os_from_ttl(0))
        self.assertIn("Unknown", get_os_from_ttl(300))


    def test_02_get_os_from_window_size(self):
        print("\nRunning test_02_get_os_from_window_size...")
        self.assertIn("Windows XP/2000", get_os_from_window_size(5840))
        self.assertIn("Windows 7/Vista/Server 2008", get_os_from_window_size(8192))
        self.assertIn("Linux (Many versions", get_os_from_window_size(65535))
        self.assertIn("Linux (Common with window scaling)", get_os_from_window_size(64240))
        self.assertIn("less common OS", get_os_from_window_size(12345)) # A non-mapped size


    @unittest.skipIf(not HAS_SCAPY, "Scapy not available, skipping OS fingerprinting live test.")
    def test_03_fingerprint_os_scanme(self):
        if not self.host_resolvable_os:
            self.skipTest(f"Target host {TARGET_HOST_OS} not resolvable.")

        print(f"\nRunning test_03_fingerprint_os_scanme on {TARGET_HOST_OS} (requires Scapy & privileges)...")

        # scanme.nmap.org usually has port 22 (SSH) and 80 (HTTP) open.
        # Providing an open port helps the TCP-based part of the fingerprinting.
        # If these ports are closed, the TCP part might not yield results.
        known_open_port = 22

        results = fingerprint_os_single_target(TARGET_HOST_OS, open_tcp_port=known_open_port, timeout=2.5)
        self.assertIsNotNone(results)
        print(f"  OS Fingerprint results for {TARGET_HOST_OS}: {results}")

        self.assertEqual(results.get("ip"), TARGET_HOST_OS)

        # Check TTL guess
        ttl_guess = results.get("ttl_os_guess", "N/A")
        print(f"  TTL OS Guess: {ttl_guess}")
        # scanme.nmap.org is Linux. TTL might be ~40-60 depending on routes.
        # This assertion is a bit loose due to network variability.
        self.assertTrue("Linux/Unix" in ttl_guess or "Requires Scapy" in ttl_guess or "Could not determine TTL" in ttl_guess or "No ICMP Echo reply" in results.get("errors",[""])[0],
                        f"Expected Linux/Unix like TTL guess or known failure for {TARGET_HOST_OS}, got: {ttl_guess}. Errors: {results.get('errors')}")

        # Check Window size guess (can be less reliable)
        window_guess = results.get("window_os_guess", "N/A")
        print(f"  Window OS Guess: {window_guess}")
        # If TCP details were captured, window guess should be more specific than "N/A" or "Failed"
        if results.get("tcp_details") and results["tcp_details"].get("window"):
            self.assertTrue("N/A" not in window_guess and "Failed" not in window_guess, f"Expected a specific window guess if TCP details are present, got {window_guess}")

        if "Requires Scapy" in ttl_guess:
            self.assertIn("Scapy not available, OS fingerprinting limited.", results.get("errors", []))

        time.sleep(NETWORK_TEST_DELAY_OS)

if __name__ == '__main__':
    host_is_currently_resolvable_os_main = False
    try:
        socket.gethostbyname(TARGET_HOST_OS)
        host_is_currently_resolvable_os_main = True
    except socket.gaierror:
        pass

    if not host_is_currently_resolvable_os_main:
        print(f"CRITICAL: Target host {TARGET_HOST_OS} for OS fingerprinting tests is not resolvable. Aborting test run.")
        TestOSFingerprinter.host_resolvable_os = False # Set for completeness for test methods
    else:
        TestOSFingerprinter.host_resolvable_os = True # Ensure it's set for script execution and test methods
        suite = unittest.TestSuite()
        tests_to_run = [
            TestOSFingerprinter('test_01_get_os_from_ttl'),
            TestOSFingerprinter('test_02_get_os_from_window_size'),
            TestOSFingerprinter('test_03_fingerprint_os_scanme'),
        ]
        for test in tests_to_run:
            suite.addTest(test)
        runner = unittest.TextTestRunner(verbosity=2)
        runner.run(suite)
        # unittest.main(verbosity=2)
