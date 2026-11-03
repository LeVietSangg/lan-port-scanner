"""Kiểm thử tính năng xác thực IP và phân tích cổng trong src.core.validator."""

import unittest
from src.core.validator import validate_ip, resolve_host, parse_ports


class TestValidator(unittest.TestCase):

    def test_validate_ip_valid(self):
        self.assertTrue(validate_ip("127.0.0.1"))
        self.assertTrue(validate_ip("192.168.1.1"))
        self.assertTrue(validate_ip("10.0.0.254"))
        self.assertTrue(validate_ip(" 8.8.8.8 "))

    def test_validate_ip_invalid(self):
        self.assertFalse(validate_ip("256.0.0.1"))
        self.assertFalse(validate_ip("192.168.1"))
        self.assertFalse(validate_ip("abc.def.ghi.jkl"))
        self.assertFalse(validate_ip(""))

    def test_resolve_host_ip(self):
        ok, res = resolve_host("127.0.0.1")
        self.assertTrue(ok)
        self.assertEqual(res, "127.0.0.1")

    def test_resolve_host_localhost(self):
        ok, res = resolve_host("localhost")
        self.assertTrue(ok)
        self.assertIn(res, ["127.0.0.1", "::1"])

    def test_resolve_host_empty(self):
        ok, res = resolve_host("")
        self.assertFalse(ok)

    def test_parse_ports_single_and_list(self):
        ports = parse_ports("80, 443, 22")
        self.assertEqual(ports, [22, 80, 443])

    def test_parse_ports_range(self):
        ports = parse_ports("20-23, 80")
        self.assertEqual(ports, [20, 21, 22, 23, 80])

    def test_parse_ports_invalid_and_out_of_range(self):
        ports = parse_ports("0, 80, 70000, abc, 443")
        self.assertEqual(ports, [80, 443])


if __name__ == "__main__":
    unittest.main()

