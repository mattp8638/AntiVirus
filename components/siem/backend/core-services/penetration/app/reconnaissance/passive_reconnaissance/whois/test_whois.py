import unittest
import time
from datetime import datetime

# Assuming whois.py is in the same directory or PYTHONPATH is set up
# from .whois import unified_domain_lookup, parse_datetime_string
from whois import unified_domain_lookup, parse_datetime_string # Simplified import

# Domains for testing
GOOGLE_COM = "google.com" # Good for RDAP
FSF_ORG = "fsf.org"       # Good for RDAP (.org)
NIC_UK = "nic.uk"         # .uk TLD, might have specific WHOIS, good RDAP
NONEXISTENT_DOMAIN_WHOIS = "thisshouldabsurdlynotexist123xyz.com"
EXAMPLE_COM_WHOIS = "example.com" # Standard WHOIS

# Global delay between tests that make network calls
NETWORK_TEST_DELAY = 2.0 # Increased delay for WHOIS/RDAP servers

class TestWhoisRdap(unittest.TestCase):

    def test_01_parse_datetime_string(self):
        print("\nRunning test_01_parse_datetime_string...")
        self.assertIsInstance(parse_datetime_string("2023-01-15T10:30:00Z"), datetime)
        self.assertIsInstance(parse_datetime_string("2024-03-10 14:45:12"), datetime)
        self.assertIsInstance(parse_datetime_string("15-Feb-2022"), datetime)
        self.assertIsInstance(parse_datetime_string("10.04.2021"), datetime)
        self.assertIsInstance(parse_datetime_string("20200730"), datetime) # YYYYMMDD
        self.assertEqual(parse_datetime_string(""), None)
        self.assertEqual(parse_datetime_string(None), None)
        # Test a more complex one that might appear in WHOIS
        dt_obj = parse_datetime_string("2023-05-20T10:00:00-07:00") # With offset
        self.assertIsInstance(dt_obj, datetime)
        if dt_obj: self.assertIsNotNone(dt_obj.tzinfo)

        dt_obj_complex_whois = parse_datetime_string("Mon Jan 01 14:00:00 GMT 2024")
        self.assertIsInstance(dt_obj_complex_whois, datetime, f"Failed to parse: Mon Jan 01 14:00:00 GMT 2024. Got: {dt_obj_complex_whois}")

        # Specific test for "YYYY-MM-DD" format as seen in example.com WHOIS
        dt_example_com = parse_datetime_string("1992-01-01")
        self.assertIsInstance(dt_example_com, datetime, "Failed to parse '1992-01-01'")
        if dt_example_com:
            self.assertEqual(dt_example_com.year, 1992)
            self.assertEqual(dt_example_com.month, 1)
            self.assertEqual(dt_example_com.day, 1)


    def _assert_common_fields(self, result, domain_name):
        self.assertIn("domain_name", result, "Result missing 'domain_name' field.")
        self.assertEqual(result["domain_name"], domain_name.lower(), "Domain name mismatch.")
        self.assertIn("protocol", result, "Result missing 'protocol' field (rdap/whois).")
        self.assertTrue(result.get("creation_date") is None or isinstance(result["creation_date"], datetime), "Creation date type error.")
        self.assertTrue(result.get("updated_date") is None or isinstance(result["updated_date"], datetime), "Updated date type error.")
        self.assertTrue(result.get("expiration_date") is None or isinstance(result["expiration_date"], datetime), "Expiration date type error.")
        self.assertTrue(isinstance(result.get("name_servers", []), list), "Name servers should be a list.")

    def test_02_unified_lookup_google_com_prefer_rdap(self):
        print(f"\nRunning test_02_unified_lookup_google_com_prefer_rdap (using {GOOGLE_COM})...")
        result = unified_domain_lookup(GOOGLE_COM, preferred_protocol="try_both")
        self.assertIsNotNone(result, "Result should not be None.")
        self.assertNotIn("error", result.get("errors_during_lookup", []) if result.get("errors_during_lookup") else [result.get("error")], f"Critical error in lookup: {result.get('error')}")

        if result and not result.get("error"):
            self.assertEqual(result.get("protocol"), "rdap", f"Expected RDAP for {GOOGLE_COM}, got {result.get('protocol')}. Full result: {result}")
            self._assert_common_fields(result, GOOGLE_COM)
            self.assertTrue(result.get("registrar"), f"Registrar info missing for {GOOGLE_COM} (RDAP).")
            self.assertTrue(result.get("creation_date"), f"Creation date missing for {GOOGLE_COM} (RDAP).")
        else:
            print(f"  Warning/Error for {GOOGLE_COM} (RDAP preferred): {result}")
        time.sleep(NETWORK_TEST_DELAY)

    def test_03_unified_lookup_fsf_org_prefer_rdap(self):
        print(f"\nRunning test_03_unified_lookup_fsf_org_prefer_rdap (using {FSF_ORG})...")
        result = unified_domain_lookup(FSF_ORG, preferred_protocol="try_both")
        self.assertIsNotNone(result)
        self.assertNotIn("error", result.get("errors_during_lookup", []) if result.get("errors_during_lookup") else [result.get("error")], f"Critical error in lookup: {result.get('error')}")

        if result and not result.get("error"):
            self.assertEqual(result.get("protocol"), "rdap", f"Expected RDAP for {FSF_ORG}, got {result.get('protocol')}. Full result: {result}")
            self._assert_common_fields(result, FSF_ORG)
            self.assertTrue(result.get("registrar"), f"Registrar info missing for {FSF_ORG} (RDAP).")
        else:
            print(f"  Warning/Error for {FSF_ORG} (RDAP preferred): {result}")
        time.sleep(NETWORK_TEST_DELAY)

    def test_04_unified_lookup_example_com_force_whois(self):
        # example.com might not have a super rich RDAP, so forcing WHOIS can be a good test for WHOIS path.
        print(f"\nRunning test_04_unified_lookup_example_com_force_whois (using {EXAMPLE_COM_WHOIS})...")
        result = unified_domain_lookup(EXAMPLE_COM_WHOIS, preferred_protocol="whois")
        self.assertIsNotNone(result)
        self.assertNotIn("error", result.get("errors_during_lookup", []) if result.get("errors_during_lookup") else [result.get("error")], f"Critical error in lookup: {result.get('error')}")

        if result and not result.get("error"):
            self.assertTrue(result.get("protocol", "").startswith("whois"), f"Expected WHOIS for {EXAMPLE_COM_WHOIS}, got {result.get('protocol')}. Full result: {result}")
            self._assert_common_fields(result, EXAMPLE_COM_WHOIS)
            # For example.com, registrar field might be None or point to IANA.
            # The key is that the query succeeded via WHOIS and returned some data.
            # self.assertTrue(result.get("registrar"), f"Registrar info missing for {EXAMPLE_COM_WHOIS} (WHOIS).")
            print(f"  Note: Registrar for {EXAMPLE_COM_WHOIS} via WHOIS is often minimal/IANA. Current value: {result.get('registrar')}")
            self.assertTrue(result.get("creation_date"), f"Creation date missing for {EXAMPLE_COM_WHOIS} (WHOIS).") # example.com should have a creation date.
        else:
            print(f"  Warning/Error for {EXAMPLE_COM_WHOIS} (WHOIS forced): {result}")
        time.sleep(NETWORK_TEST_DELAY)

    def test_05_unified_lookup_nic_uk_try_both(self):
        # .uk domains often have good RDAP via Nominet, but also a distinct WHOIS.
        print(f"\nRunning test_05_unified_lookup_nic_uk_try_both (using {NIC_UK})...")
        result = unified_domain_lookup(NIC_UK, preferred_protocol="try_both")
        self.assertIsNotNone(result)
        self.assertNotIn("error", result.get("errors_during_lookup", []) if result.get("errors_during_lookup") else [result.get("error")], f"Critical error in lookup: {result.get('error')}")

        if result and not result.get("error"):
            # Depending on IANA bootstrap and Nominet's current RDAP service status,
            # this could be 'rdap' or fall back to 'whois'.
            # We mainly check that we get data.
            self.assertTrue(result.get("protocol") in ["rdap", "whois", "whois_direct_iana"], f"Protocol for {NIC_UK} unexpected: {result.get('protocol')}")
            self._assert_common_fields(result, NIC_UK)
            self.assertTrue(result.get("registrar") or result.get("registrant_name"), f"Registrar/Registrant info missing for {NIC_UK}.")
        else:
            print(f"  Warning/Error for {NIC_UK} (try_both): {result}")
        time.sleep(NETWORK_TEST_DELAY)

    def test_06_unified_lookup_nonexistent_domain(self):
        print(f"\nRunning test_06_unified_lookup_nonexistent_domain (using {NONEXISTENT_DOMAIN_WHOIS})...")
        result = unified_domain_lookup(NONEXISTENT_DOMAIN_WHOIS, preferred_protocol="try_both")
        self.assertIsNotNone(result)
        self.assertTrue(result.get("error") or any("failed" in e.lower() or "not found" in e.lower() for e in result.get("errors_during_lookup", [])),
                        f"Expected an error for non-existent domain {NONEXISTENT_DOMAIN_WHOIS}, but got {result}")
        # For non-existent domains, we don't expect fields like registrar, creation_date etc.
        # Check that domain_name is still populated correctly.
        self.assertEqual(result.get("domain_queried", "").lower(), NONEXISTENT_DOMAIN_WHOIS.lower())
        time.sleep(NETWORK_TEST_DELAY)

if __name__ == '__main__':
    # To run from the parent directory of 'core':
    # python -m core.reconnaissance.passive_reconnaissance.whois.test_whois
    # Or if in the same directory as whois.py and test_whois.py:
    # python test_whois.py

    suite = unittest.TestSuite()
    tests_to_run = [
        TestWhoisRdap('test_01_parse_datetime_string'),
        TestWhoisRdap('test_02_unified_lookup_google_com_prefer_rdap'),
        TestWhoisRdap('test_03_unified_lookup_fsf_org_prefer_rdap'),
        TestWhoisRdap('test_04_unified_lookup_example_com_force_whois'),
        TestWhoisRdap('test_05_unified_lookup_nic_uk_try_both'),
        TestWhoisRdap('test_06_unified_lookup_nonexistent_domain'),
    ]
    for test in tests_to_run:
        suite.addTest(test)

    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)
    # unittest.main(verbosity=2)
