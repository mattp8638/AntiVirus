import unittest
from .dns_enumeration import (
    single_dns_lookup,
    get_authoritative_ns,
    enumerate_dns_records,
)


class TestDNSReturns(unittest.TestCase):
    def test_single_lookup_structure(self):
        res = single_dns_lookup('example.com', 'A')
        self.assertTrue(hasattr(res, 'result'))
        self.assertTrue(hasattr(res, 'error'))

    def test_get_authoritative_ns_error(self):
        res = get_authoritative_ns('nonexistentdomain.tld')
        self.assertIsNotNone(res.error)

    def test_enumerate_records_structure(self):
        res = enumerate_dns_records('example.com', ['A'])
        self.assertTrue(hasattr(res, 'result'))
        self.assertIn('A', res.result)
        self.assertTrue(hasattr(res.result['A'], 'result'))


if __name__ == '__main__':
    unittest.main()
