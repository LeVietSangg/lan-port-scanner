"""Kiểm thử kịch bản thực nghiệm Lab & Localhost (Mốc 12/11).

Bao gồm các kịch bản kiểm thử tích hợp (End-to-End Integration Testing):
1. Kịch bản 1: Quét Localhost (127.0.0.1) với các dịch vụ Web, SSH, Dev-App mở.
2. Kịch bản 2: Quét máy chủ Lab mở các dịch vụ rủi ro cao (Telnet, SMB, MySQL, Redis).
3. Kịch bản 3: Quét qua hệ thống có Tường lửa (Firewall) can thiệp lọc cổng.
4. Kịch bản 4: Kiểm thử quy trình toàn diện từ quét, phân tích, thế trận an ninh đến xuất báo cáo CSV/TXT.
"""

from datetime import datetime
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from src.config import (
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    STATUS_CLOSED,
    STATUS_FILTERED,
    STATUS_OPEN,
)
from src.core.analyzer import analyze_all_results, get_security_posture_summary
from src.core.classifier import get_classification_stats
from src.core.exporter import export_to_csv, export_to_txt
from src.core.scanner import PortScanner, ScanResult
from src.core.validator import validate_target


class TestLabScenarios(unittest.TestCase):
    """Bộ kiểm thử các kịch bản thực nghiệm môi trường mạng Lab và Localhost."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_scenario_localhost_web_and_ssh(self):
        """Kịch bản 1: Quét máy cục bộ Localhost với cổng 22 (SSH) và 80 (HTTP) mở."""
        target = "127.0.0.1"
        target_res = validate_target(target)
        self.assertTrue(target_res.is_valid)
        self.assertTrue(target_res.is_lan_or_local)

        # Mô phỏng kết quả quét cổng 22 (OPEN), 80 (OPEN), 443 (CLOSED)
        mock_results = [
            ScanResult(target_ip=target, port=22, status=STATUS_OPEN, banner="SSH-2.0-OpenSSH_9.0"),
            ScanResult(target_ip=target, port=80, status=STATUS_OPEN, banner="Server: nginx/1.24.0"),
            ScanResult(target_ip=target, port=443, status=STATUS_CLOSED, notes="RST"),
        ]

        analyzed = analyze_all_results(mock_results)
        self.assertIn("OpenSSH", analyzed[0].service)
        self.assertIn("nginx", analyzed[1].service)

        stats = get_classification_stats(analyzed)
        self.assertEqual(stats["open_count"], 2)
        self.assertEqual(stats["closed_count"], 1)
        self.assertFalse(stats["firewall_detected"])

        sec = get_security_posture_summary(analyzed)
        self.assertEqual(sec["total_open"], 2)
        self.assertEqual(sec["critical_count"], 0)

    def test_scenario_lab_vulnerable_server(self):
        """Kịch bản 2: Quét máy chủ Lab cấu hình dịch vụ nguy hiểm (Telnet 23, SMB 445, Redis 6379)."""
        target = "192.168.1.100"
        target_res = validate_target(target)
        self.assertTrue(target_res.is_valid)
        self.assertTrue(target_res.is_lan_or_local)

        mock_results = [
            ScanResult(target_ip=target, port=23, status=STATUS_OPEN),    # Telnet -> Critical
            ScanResult(target_ip=target, port=445, status=STATUS_OPEN),   # SMB -> Critical
            ScanResult(target_ip=target, port=3306, status=STATUS_OPEN),  # MySQL -> High
            ScanResult(target_ip=target, port=6379, status=STATUS_OPEN),  # Redis -> Critical
            ScanResult(target_ip=target, port=80, status=STATUS_OPEN),    # HTTP -> Medium
        ]

        analyzed = analyze_all_results(mock_results)
        sec = get_security_posture_summary(analyzed)

        # Đánh giá thế trận phải là NGUY CƠ CAO
        self.assertIn("NGUY CƠ CAO", sec["posture_rating"])
        self.assertGreaterEqual(sec["critical_count"], 3)
        self.assertGreaterEqual(sec["high_count"], 1)

        # Kiểm tra phát hiện dịch vụ cleartext và database
        self.assertTrue(len(sec["cleartext_ports"]) > 0)
        self.assertTrue(len(sec["database_ports"]) > 0)

    def test_scenario_firewall_filtered_network(self):
        """Kịch bản 3: Quét qua hệ thống có Firewall kích hoạt lọc gói tin."""
        target = "10.0.0.1"
        mock_results = [
            ScanResult(target_ip=target, port=80, status=STATUS_OPEN),
            ScanResult(target_ip=target, port=22, status=STATUS_FILTERED, notes="Timeout (WSAETIMEDOUT)"),
            ScanResult(target_ip=target, port=443, status=STATUS_FILTERED, notes="Timeout (WSAETIMEDOUT)"),
            ScanResult(target_ip=target, port=3389, status=STATUS_FILTERED, notes="Timeout (WSAETIMEDOUT)"),
        ]

        stats = get_classification_stats(mock_results)
        self.assertEqual(stats["filtered_count"], 3)
        self.assertTrue(stats["firewall_detected"])

    def test_scenario_end_to_end_pipeline(self):
        """Kịch bản 4: Kiểm thử toàn trình End-to-End từ quét đến xuất báo cáo."""
        target = "192.168.1.50"
        ports = [21, 22, 80, 443]

        # 1. Validate
        v_res = validate_target(target)
        self.assertTrue(v_res.is_valid)

        # 2. Mock Scan results
        raw_results = [
            ScanResult(target_ip=target, port=21, status=STATUS_OPEN, response_time_ms=4.2),
            ScanResult(target_ip=target, port=22, status=STATUS_OPEN, response_time_ms=6.1),
            ScanResult(target_ip=target, port=80, status=STATUS_OPEN, response_time_ms=3.5),
            ScanResult(target_ip=target, port=443, status=STATUS_CLOSED, response_time_ms=1.2),
        ]

        # 3. Analyze
        analyzed = analyze_all_results(raw_results)
        sec = get_security_posture_summary(analyzed)

        # 4. Export CSV
        csv_path = os.path.join(self.test_dir, "lab_report.csv")
        saved_csv = export_to_csv(analyzed, file_path=csv_path, scan_duration_sec=0.25, threads_used=10)
        self.assertTrue(os.path.exists(saved_csv))

        # 5. Export TXT
        txt_path = os.path.join(self.test_dir, "lab_report.txt")
        saved_txt = export_to_txt(analyzed, file_path=txt_path, scan_duration_sec=0.25, threads_used=10, security_summary=sec)
        self.assertTrue(os.path.exists(saved_txt))

        # Đọc lại file và kiểm tra
        with open(saved_csv, "r", encoding="utf-8-sig") as f:
            csv_text = f.read()
        self.assertIn("192.168.1.50", csv_text)
        self.assertIn("FTP", csv_text)

        with open(saved_txt, "r", encoding="utf-8") as f:
            txt_text = f.read()
        self.assertIn("THÔNG TIN PHIÊN QUÉT", txt_text)
        self.assertIn("FTP", txt_text)


if __name__ == "__main__":
    unittest.main()
