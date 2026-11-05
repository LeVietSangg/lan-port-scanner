"""Kiểm thử toàn diện tính năng nhập và xác thực IP cho nhiệm vụ ngày 04/11."""

import ipaddress
import unittest

from src.core.validator import (
    TYPE_INVALID,
    TYPE_LINK_LOCAL,
    TYPE_LOOPBACK,
    TYPE_MULTICAST,
    TYPE_PRIVATE_LAN,
    TYPE_PUBLIC,
    TYPE_RESERVED,
    classify_ipv4,
    parse_ports,
    resolve_host,
    validate_hostname_syntax,
    validate_ip,
    validate_ipv4_syntax,
    validate_target,
)


class TestValidatorDetailed(unittest.TestCase):
    """Bộ kiểm thử cho chức năng nhập và xác thực địa chỉ IP (Ngày 04/11)."""

    # --- 1. Kiểm tra cú pháp IPv4 (validate_ipv4_syntax) ---

    def test_syntax_valid_ips(self):
        valid_cases = [
            "127.0.0.1",
            "192.168.1.1",
            "10.0.0.254",
            "172.16.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "8.8.8.8",
            " 192.168.1.100 ",  # Cho phép khoảng trắng thừa ở 2 đầu
        ]
        for ip in valid_cases:
            ok, msg = validate_ipv4_syntax(ip)
            self.assertTrue(ok, f"IP hợp lệ bị báo sai: {ip} ({msg})")

    def test_syntax_empty_and_whitespace(self):
        ok, msg = validate_ipv4_syntax("")
        self.assertFalse(ok)
        self.assertIn("không được để trống", msg)

        ok, msg = validate_ipv4_syntax("   ")
        self.assertFalse(ok)

    def test_syntax_incorrect_octet_count(self):
        # Thiếu octet
        ok, msg = validate_ipv4_syntax("192.168.1")
        self.assertFalse(ok)
        self.assertIn("đúng 4 octet", msg)

        # Thừa octet
        ok, msg = validate_ipv4_syntax("192.168.1.1.1")
        self.assertFalse(ok)
        self.assertIn("đúng 4 octet", msg)

    def test_syntax_non_digits(self):
        cases = ["192.168.1.a", "abc.def.ghi.jkl", "192.168.1.1$", "192.168.-1.1"]
        for ip in cases:
            ok, msg = validate_ipv4_syntax(ip)
            self.assertFalse(ok, f"IP chứa ký tự không phải số lại báo hợp lệ: {ip}")

    def test_syntax_leading_zeros(self):
        # Số 0 ở đầu (leading zero) dễ gây nhầm lẫn sang hệ bát phân (octal)
        cases = ["192.168.01.1", "010.0.0.1", "192.168.1.005"]
        for ip in cases:
            ok, msg = validate_ipv4_syntax(ip)
            self.assertFalse(ok, f"IP chứa leading zero lại báo hợp lệ: {ip}")
            self.assertIn("leading zero", msg)

    def test_syntax_out_of_range(self):
        cases = ["256.0.0.1", "192.168.1.300", "999.999.999.999"]
        for ip in cases:
            ok, msg = validate_ipv4_syntax(ip)
            self.assertFalse(ok, f"IP ngoài dải 0-255 lại báo hợp lệ: {ip}")
            self.assertIn("vượt quá", msg)

    # --- 2. Kiểm tra phân loại địa chỉ IP (classify_ipv4) ---

    def test_classify_loopback(self):
        ip = ipaddress.IPv4Address("127.0.0.1")
        ip_type, is_lan_local, warning = classify_ipv4(ip)
        self.assertEqual(ip_type, TYPE_LOOPBACK)
        self.assertTrue(is_lan_local)
        self.assertIn("Loopback", warning)

    def test_classify_private_lan(self):
        lan_ips = ["192.168.1.1", "10.0.0.1", "172.16.50.1"]
        for ip_str in lan_ips:
            ip = ipaddress.IPv4Address(ip_str)
            ip_type, is_lan_local, warning = classify_ipv4(ip)
            self.assertEqual(ip_type, TYPE_PRIVATE_LAN)
            self.assertTrue(is_lan_local)
            self.assertIn("RFC 1918", warning)

    def test_classify_link_local(self):
        ip = ipaddress.IPv4Address("169.254.10.20")
        ip_type, is_lan_local, _ = classify_ipv4(ip)
        self.assertEqual(ip_type, TYPE_LINK_LOCAL)
        self.assertTrue(is_lan_local)

    def test_classify_public_ip(self):
        ip = ipaddress.IPv4Address("8.8.8.8")
        ip_type, is_lan_local, warning = classify_ipv4(ip)
        self.assertEqual(ip_type, TYPE_PUBLIC)
        self.assertFalse(is_lan_local)
        self.assertIn("CẢNH BÁO", warning)

    def test_classify_multicast_and_reserved(self):
        ip_multi = ipaddress.IPv4Address("224.0.0.1")
        ip_type, is_lan_local, _ = classify_ipv4(ip_multi)
        self.assertEqual(ip_type, TYPE_MULTICAST)
        self.assertFalse(is_lan_local)

        ip_res = ipaddress.IPv4Address("0.0.0.0")
        ip_type2, is_lan_local2, _ = classify_ipv4(ip_res)
        self.assertEqual(ip_type2, TYPE_RESERVED)
        self.assertFalse(is_lan_local2)

    # --- 3. Kiểm tra tên miền và hostname (validate_hostname_syntax) ---

    def test_hostname_syntax_valid(self):
        valid_hosts = ["localhost", "router.local", "server-01.lan", "google.com"]
        for host in valid_hosts:
            self.assertTrue(validate_hostname_syntax(host), f"Hostname hợp lệ: {host}")

    def test_hostname_syntax_invalid(self):
        invalid_hosts = ["", "-invalid", "invalid-", "host..name", "a" * 300]
        for host in invalid_hosts:
            self.assertFalse(validate_hostname_syntax(host), f"Hostname không hợp lệ: {host}")

    # --- 4. Kiểm tra hàm tổng hợp validate_target ---

    def test_validate_target_lan_ip(self):
        res = validate_target("192.168.1.1")
        self.assertTrue(res.is_valid)
        self.assertEqual(res.resolved_ip, "192.168.1.1")
        self.assertEqual(res.ip_type, TYPE_PRIVATE_LAN)
        self.assertTrue(res.is_lan_or_local)

    def test_validate_target_localhost(self):
        res = validate_target("localhost")
        self.assertTrue(res.is_valid)
        self.assertIn(res.resolved_ip, ["127.0.0.1", "::1"])
        self.assertEqual(res.ip_type, TYPE_LOOPBACK)

    def test_validate_target_public_ip_has_warning(self):
        res = validate_target("1.1.1.1")
        self.assertTrue(res.is_valid)
        self.assertEqual(res.ip_type, TYPE_PUBLIC)
        self.assertFalse(res.is_lan_or_local)
        self.assertIsNotNone(res.warning_message)
        self.assertIn("CẢNH BÁO", res.warning_message)

    def test_validate_target_multicast_rejected(self):
        res = validate_target("224.0.0.5")
        self.assertFalse(res.is_valid)
        self.assertIn("Multicast", res.error_message)

    def test_validate_target_invalid_string(self):
        res = validate_target("256.300.1.1")
        self.assertFalse(res.is_valid)
        self.assertIsNotNone(res.error_message)

    # --- 5. Kiểm tra phân tích danh sách cổng (parse_ports) ---

    def test_parse_ports_valid(self):
        ports = parse_ports("80, 443, 22")
        self.assertEqual(ports, [22, 80, 443])

    def test_parse_ports_range(self):
        ports = parse_ports("20-23, 80")
        self.assertEqual(ports, [20, 21, 22, 23, 80])

    def test_parse_ports_filtering_invalid(self):
        ports = parse_ports("0, 80, 70000, abc, 443, -5")
        self.assertEqual(ports, [80, 443])


if __name__ == "__main__":
    unittest.main()
