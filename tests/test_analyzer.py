"""Kiểm thử tính năng nhận diện dịch vụ và phân tích rủi ro trong src.core.analyzer."""

import unittest
from src.core.analyzer import identify_service, analyze_security
from src.core.scanner import ScanResult
from src.config import STATUS_OPEN, STATUS_CLOSED


class TestAnalyzer(unittest.TestCase):

    def test_identify_service(self):
        self.assertEqual(identify_service(80), "HTTP")
        self.assertEqual(identify_service(443), "HTTPS")
        self.assertEqual(identify_service(22), "SSH")
        self.assertEqual(identify_service(3306), "MySQL")
        self.assertEqual(identify_service(9999), "Unknown")

    def test_analyze_security_open_ftp(self):
        result = ScanResult(target_ip="192.168.1.10", port=21, status=STATUS_OPEN)
        analyzed = analyze_security(result)
        self.assertEqual(analyzed.service, "FTP")
        self.assertEqual(analyzed.risk_level, "High")
        self.assertIn("SFTP", analyzed.recommendation)

    def test_analyze_security_closed_port(self):
        result = ScanResult(target_ip="192.168.1.10", port=80, status=STATUS_CLOSED)
        analyzed = analyze_security(result)
        self.assertEqual(analyzed.risk_level, "None")


if __name__ == "__main__":
    unittest.main()

