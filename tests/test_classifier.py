"""Kiểm thử tính năng phân loại trạng thái cổng mạng (OPEN, CLOSED, FILTERED/UNKNOWN) cho nhiệm vụ ngày 06/11."""

import errno
import unittest

from src.config import STATUS_CLOSED, STATUS_FILTERED, STATUS_OPEN
from src.core.classifier import (
    STATUS_DEFINITIONS,
    classify_status,
    filter_results_by_status,
    get_classification_stats,
)
from src.core.scanner import ScanResult


class TestPortClassifier(unittest.TestCase):
    """Bộ kiểm thử cho bộ phân loại trạng thái cổng mạng."""

    def test_classify_status_open(self):
        """Mã lỗi 0 phải được phân loại là OPEN với độ tin cậy tuyệt đối (1.0)."""
        cls = classify_status(0)
        self.assertEqual(cls.status, STATUS_OPEN)
        self.assertEqual(cls.confidence, 1.0)
        self.assertEqual(cls.packet_type, "TCP SYN-ACK")
        self.assertFalse(cls.firewall_suspected)
        self.assertIn("SYN-ACK", cls.reason)

    def test_classify_status_closed_windows(self):
        """Mã lỗi 10061 (WSAECONNREFUSED) phải được phân loại là CLOSED."""
        cls = classify_status(10061)
        self.assertEqual(cls.status, STATUS_CLOSED)
        self.assertEqual(cls.confidence, 1.0)
        self.assertEqual(cls.packet_type, "TCP RST")
        self.assertFalse(cls.firewall_suspected)
        self.assertIn("RST", cls.reason)

    def test_classify_status_closed_posix(self):
        """Mã lỗi ECONNREFUSED phải được phân loại là CLOSED."""
        cls = classify_status(errno.ECONNREFUSED)
        self.assertEqual(cls.status, STATUS_CLOSED)
        self.assertEqual(cls.packet_type, "TCP RST")

    def test_classify_status_filtered_timeout(self):
        """Mã lỗi 10060 (WSAETIMEDOUT) hoặc ETIMEDOUT phải là FILTERED/UNKNOWN và nghi ngờ có tường lửa."""
        cls = classify_status(10060, timeout=1.5)
        self.assertEqual(cls.status, STATUS_FILTERED)
        self.assertTrue(cls.firewall_suspected)
        self.assertIn("1.5s", cls.reason)

        cls_none = classify_status(None, timeout=2.0)
        self.assertEqual(cls_none.status, STATUS_FILTERED)
        self.assertTrue(cls_none.firewall_suspected)

    def test_classify_status_filtered_host_unreachable(self):
        """Mã lỗi 10065 (WSAEHOSTUNREACH) phản ánh cổng bị lọc do không đến được host."""
        cls = classify_status(10065)
        self.assertEqual(cls.status, STATUS_FILTERED)
        self.assertEqual(cls.packet_type, "ICMP Host Unreachable")
        self.assertTrue(cls.firewall_suspected)

    def test_classify_status_filtered_net_unreachable(self):
        """Mã lỗi 10051 (WSAENETUNREACH) phản ánh mạng không tiếp cận được."""
        cls = classify_status(10051)
        self.assertEqual(cls.status, STATUS_FILTERED)
        self.assertEqual(cls.packet_type, "ICMP Net Unreachable")
        self.assertTrue(cls.firewall_suspected)

    def test_classify_status_filtered_access_denied(self):
        """Mã lỗi 10013 (WSAEACCES) phản ánh việc bị phần mềm an ninh chặn cục bộ."""
        cls = classify_status(10013)
        self.assertEqual(cls.status, STATUS_FILTERED)
        self.assertEqual(cls.packet_type, "Local Security Block")
        self.assertTrue(cls.firewall_suspected)

    def test_classify_status_unknown_error(self):
        """Các mã lỗi không xác định khác vẫn phải trả về FILTERED an toàn."""
        cls = classify_status(99999)
        self.assertEqual(cls.status, STATUS_FILTERED)
        self.assertIn("99999", cls.reason)

    def test_get_classification_stats_empty(self):
        """Kiểm thử thống kê với danh sách rỗng."""
        stats = get_classification_stats([])
        self.assertEqual(stats["total"], 0)
        self.assertEqual(stats["open_count"], 0)
        self.assertFalse(stats["firewall_detected"])

    def test_get_classification_stats_populated(self):
        """Kiểm thử thống kê tỷ lệ phần trăm các trạng thái cổng."""
        mock_results = [
            ScanResult(target_ip="192.168.1.1", port=80, status=STATUS_OPEN),
            ScanResult(target_ip="192.168.1.1", port=443, status=STATUS_OPEN),
            ScanResult(target_ip="192.168.1.1", port=21, status=STATUS_CLOSED),
            ScanResult(target_ip="192.168.1.1", port=445, status=STATUS_FILTERED),
        ]
        stats = get_classification_stats(mock_results)
        self.assertEqual(stats["total"], 4)
        self.assertEqual(stats["open_count"], 2)
        self.assertEqual(stats["closed_count"], 1)
        self.assertEqual(stats["filtered_count"], 1)
        self.assertEqual(stats["open_percent"], 50.0)
        self.assertEqual(stats["closed_percent"], 25.0)
        self.assertEqual(stats["filtered_percent"], 25.0)
        self.assertTrue(stats["firewall_detected"])

    def test_filter_results_by_status(self):
        """Kiểm thử lọc danh sách kết quả theo trạng thái."""
        mock_results = [
            ScanResult(target_ip="127.0.0.1", port=80, status=STATUS_OPEN),
            ScanResult(target_ip="127.0.0.1", port=443, status=STATUS_OPEN),
            ScanResult(target_ip="127.0.0.1", port=21, status=STATUS_CLOSED),
            ScanResult(target_ip="127.0.0.1", port=445, status=STATUS_FILTERED),
        ]

        all_res = filter_results_by_status(mock_results, "ALL")
        self.assertEqual(len(all_res), 4)

        open_res = filter_results_by_status(mock_results, "OPEN")
        self.assertEqual(len(open_res), 2)
        self.assertTrue(all(r.status == STATUS_OPEN for r in open_res))

        closed_res = filter_results_by_status(mock_results, "CLOSED")
        self.assertEqual(len(closed_res), 1)
        self.assertEqual(closed_res[0].port, 21)

        filtered_res = filter_results_by_status(mock_results, "FILTERED")
        self.assertEqual(len(filtered_res), 1)
        self.assertEqual(filtered_res[0].port, 445)

    def test_status_definitions_structure(self):
        """Kiểm tra cấu trúc và tính đầy đủ của STATUS_DEFINITIONS."""
        for status in (STATUS_OPEN, STATUS_CLOSED, STATUS_FILTERED):
            self.assertIn(status, STATUS_DEFINITIONS)
            self.assertIn("title", STATUS_DEFINITIONS[status])
            self.assertIn("summary", STATUS_DEFINITIONS[status])
            self.assertIn("badge_color", STATUS_DEFINITIONS[status])
            self.assertIn("description", STATUS_DEFINITIONS[status])


if __name__ == "__main__":
    unittest.main()

