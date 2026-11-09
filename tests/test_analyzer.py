"""Kiểm thử toàn diện tính năng nhận diện dịch vụ và phân tích cảnh báo an toàn (Mốc 08/11)."""

import unittest
from src.config import (
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_INFO,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_NONE,
    STATUS_CLOSED,
    STATUS_FILTERED,
    STATUS_OPEN,
)
from src.core.analyzer import (
    analyze_all_results,
    analyze_security,
    filter_results_by_risk,
    get_security_posture_summary,
    identify_service,
    refine_service_with_banner,
)
from src.core.scanner import ScanResult


class TestAnalyzerDetailed(unittest.TestCase):
    """Bộ kiểm thử cho chức năng nhận diện dịch vụ và cảnh báo an toàn cơ bản."""

    # 1. Kiểm thử nhận diện dịch vụ qua số hiệu cổng (identify_service)
    def test_identify_service_common_ports(self):
        self.assertEqual(identify_service(21), "FTP")
        self.assertEqual(identify_service(22), "SSH")
        self.assertEqual(identify_service(23), "Telnet")
        self.assertEqual(identify_service(80), "HTTP")
        self.assertEqual(identify_service(443), "HTTPS")
        self.assertEqual(identify_service(445), "SMB")
        self.assertEqual(identify_service(3306), "MySQL")
        self.assertEqual(identify_service(3389), "RDP")
        self.assertEqual(identify_service(5432), "PostgreSQL")
        self.assertEqual(identify_service(6379), "Redis")
        self.assertEqual(identify_service(27017), "MongoDB")

    def test_identify_service_with_banner_ssh(self):
        service = identify_service(22, banner="SSH-2.0-OpenSSH_9.0p1 Ubuntu")
        self.assertIn("OpenSSH_9.0p1", service)

    def test_identify_service_with_banner_web(self):
        service = identify_service(80, banner="HTTP/1.1 200 OK\r\nServer: nginx/1.24.0")
        self.assertIn("nginx", service)

    def test_refine_service_with_banner_ftp(self):
        refined = refine_service_with_banner("FTP", "220 (vsFTPd 3.0.3)")
        self.assertIn("vsFTPd 3.0.3", refined)

    # 2. Kiểm thử phân tích cảnh báo an toàn (analyze_security)
    def test_analyze_security_critical_telnet(self):
        res = ScanResult(target_ip="192.168.1.1", port=23, status=STATUS_OPEN)
        analyzed = analyze_security(res)
        self.assertEqual(analyzed.risk_level, RISK_CRITICAL)
        self.assertIn("Telnet", analyzed.recommendation)
        self.assertIn("không mã hóa", analyzed.notes)

    def test_analyze_security_critical_smb(self):
        res = ScanResult(target_ip="192.168.1.1", port=445, status=STATUS_OPEN)
        analyzed = analyze_security(res)
        self.assertEqual(analyzed.risk_level, RISK_CRITICAL)
        self.assertIn("SMB", analyzed.notes)
        self.assertIn("WannaCry", analyzed.notes)

    def test_analyze_security_critical_redis(self):
        res = ScanResult(target_ip="192.168.1.1", port=6379, status=STATUS_OPEN)
        analyzed = analyze_security(res)
        self.assertEqual(analyzed.risk_level, RISK_CRITICAL)
        self.assertIn("requirepass", analyzed.recommendation)

    def test_analyze_security_high_database(self):
        res = ScanResult(target_ip="192.168.1.1", port=3306, status=STATUS_OPEN)
        analyzed = analyze_security(res)
        self.assertEqual(analyzed.risk_level, RISK_HIGH)
        self.assertIn("127.0.0.1", analyzed.recommendation)

    def test_analyze_security_medium_http(self):
        res = ScanResult(target_ip="192.168.1.1", port=80, status=STATUS_OPEN)
        analyzed = analyze_security(res)
        self.assertEqual(analyzed.risk_level, RISK_MEDIUM)
        self.assertIn("HTTPS", analyzed.recommendation)

    def test_analyze_security_low_https(self):
        res = ScanResult(target_ip="192.168.1.1", port=443, status=STATUS_OPEN)
        analyzed = analyze_security(res)
        self.assertEqual(analyzed.risk_level, RISK_LOW)
        self.assertIn("TLS", analyzed.recommendation)

    def test_analyze_security_unknown_privileged_port(self):
        res = ScanResult(target_ip="192.168.1.1", port=777, status=STATUS_OPEN)
        analyzed = analyze_security(res)
        self.assertEqual(analyzed.risk_level, RISK_MEDIUM)
        self.assertIn("< 1024", analyzed.recommendation)

    def test_analyze_security_closed_and_filtered(self):
        res_closed = ScanResult(target_ip="192.168.1.1", port=80, status=STATUS_CLOSED)
        self.assertEqual(analyze_security(res_closed).risk_level, RISK_NONE)

        res_filtered = ScanResult(target_ip="192.168.1.1", port=443, status=STATUS_FILTERED)
        self.assertEqual(analyze_security(res_filtered).risk_level, RISK_NONE)

    # 3. Kiểm thử tổng kết đánh giá mức độ an toàn (get_security_posture_summary)
    def test_security_posture_summary_high_risk(self):
        results = [
            ScanResult(target_ip="192.168.1.1", port=23, status=STATUS_OPEN),  # Critical
            ScanResult(target_ip="192.168.1.1", port=80, status=STATUS_OPEN),  # Medium
            ScanResult(target_ip="192.168.1.1", port=443, status=STATUS_OPEN), # Low
        ]
        analyzed = analyze_all_results(results)
        summary = get_security_posture_summary(analyzed)

        self.assertEqual(summary["total_open"], 3)
        self.assertEqual(summary["critical_count"], 1)
        self.assertEqual(summary["medium_count"], 1)
        self.assertEqual(summary["low_count"], 1)
        self.assertIn("HIGH RISK", summary["posture_rating"])
        self.assertTrue(len(summary["cleartext_ports"]) >= 2)  # Telnet and HTTP

    def test_security_posture_summary_secure(self):
        results = [
            ScanResult(target_ip="192.168.1.1", port=443, status=STATUS_OPEN), # Low
            ScanResult(target_ip="192.168.1.1", port=22, status=STATUS_OPEN),  # Low
        ]
        analyzed = analyze_all_results(results)
        summary = get_security_posture_summary(analyzed)

        self.assertEqual(summary["critical_count"], 0)
        self.assertEqual(summary["high_count"], 0)
        self.assertIn("ACCEPTABLE", summary["posture_rating"])

    # 4. Kiểm thử bộ lọc kết quả theo mức độ rủi ro (filter_results_by_risk)
    def test_filter_results_by_risk(self):
        results = [
            ScanResult(target_ip="192.168.1.1", port=23, status=STATUS_OPEN, risk_level=RISK_CRITICAL),
            ScanResult(target_ip="192.168.1.1", port=3306, status=STATUS_OPEN, risk_level=RISK_HIGH),
            ScanResult(target_ip="192.168.1.1", port=80, status=STATUS_OPEN, risk_level=RISK_MEDIUM),
            ScanResult(target_ip="192.168.1.1", port=443, status=STATUS_OPEN, risk_level=RISK_LOW),
        ]

        crit = filter_results_by_risk(results, "CRITICAL")
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0].port, 23)

        high = filter_results_by_risk(results, "HIGH")
        self.assertEqual(len(high), 1)
        self.assertEqual(high[0].port, 3306)

        all_res = filter_results_by_risk(results, "ALL")
        self.assertEqual(len(all_res), 4)


if __name__ == "__main__":
    unittest.main()
