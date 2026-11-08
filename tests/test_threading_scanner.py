"""Kiểm thử tính năng quét đồng thời bằng Threading cho nhiệm vụ ngày 07/11."""

import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from src.config import STATUS_CLOSED, STATUS_FILTERED, STATUS_OPEN
from src.core.scanner import (
    PortScanner,
    ScanResult,
    benchmark_scan,
    scan_ports_threaded_queue,
)


class TestThreadingScanner(unittest.TestCase):
    """Bộ kiểm thử cho cơ chế quét đa luồng (Threading / ThreadPoolExecutor & Queue)."""

    @patch("src.core.scanner.scan_single_port")
    def test_port_scanner_multithreading(self, mock_scan_single):
        """Kiểm thử quét đa luồng bằng ThreadPoolExecutor với số lượng cổng lớn."""
        ports = list(range(1, 21))  # 20 cổng
        mock_scan_single.side_effect = lambda ip, port, timeout=1.0, enable_banner=False: ScanResult(
            target_ip=ip, port=port, status=STATUS_OPEN if port % 2 == 0 else STATUS_CLOSED
        )

        progress_records = []

        def callback(res, completed, total):
            progress_records.append((completed, total, res.port))

        scanner = PortScanner(target="127.0.0.1", ports=ports, max_threads=5, timeout=0.5)
        results = scanner.scan(progress_callback=callback)

        # 1. Đảm bảo toàn bộ 20 cổng đều nhận được kết quả
        self.assertEqual(len(results), 20)
        self.assertEqual([r.port for r in results], ports)

        # 2. Đảm bảo callback được gọi đúng 20 lần
        self.assertEqual(len(progress_records), 20)
        self.assertEqual(progress_records[-1][1], 20)

        # 3. Đảm bảo các chỉ số đo đạc hiệu năng được ghi nhận
        self.assertGreaterEqual(scanner.scan_duration_sec, 0)
        self.assertGreaterEqual(scanner.scan_rate, 0)

    @patch("src.core.scanner.scan_single_port")
    def test_port_scanner_stop_early(self, mock_scan_single):
        """Kiểm thử cơ chế dừng quét sớm bằng stop() và threading.Event."""
        ports = list(range(1, 51))  # 50 cổng

        def slow_scan(ip, port, timeout=1.0, enable_banner=False):
            time.sleep(0.02)
            return ScanResult(target_ip=ip, port=port, status=STATUS_OPEN)

        mock_scan_single.side_effect = slow_scan

        scanner = PortScanner(target="127.0.0.1", ports=ports, max_threads=2, timeout=0.5)

        def stop_after_delay():
            time.sleep(0.04)
            scanner.stop()

        stop_thread = threading.Thread(target=stop_after_delay)
        stop_thread.start()

        results = scanner.scan()
        stop_thread.join()

        # Vì quét bị dừng giữa chừng, số kết quả trả về phải nhỏ hơn 50
        self.assertLess(len(results), 50)
        self.assertFalse(scanner.is_running)

    @patch("src.core.scanner.scan_single_port")
    def test_scan_ports_threaded_queue(self, mock_scan_single):
        """Kiểm thử mô hình Producer-Consumer (Queue Worker Pool)."""
        ports = [21, 22, 80, 443, 8080]
        mock_scan_single.side_effect = lambda ip, port, timeout=1.0, enable_banner=False: ScanResult(
            target_ip=ip, port=port, status=STATUS_OPEN
        )

        callback_calls = []

        def callback(res, completed, total):
            callback_calls.append(completed)

        results = scan_ports_threaded_queue(
            target_ip="192.168.1.1",
            ports=ports,
            max_threads=3,
            timeout=0.5,
            progress_callback=callback
        )

        self.assertEqual(len(results), 5)
        self.assertEqual([r.port for r in results], sorted(ports))
        self.assertEqual(len(callback_calls), 5)

    @patch("src.core.scanner.scan_single_port")
    def test_benchmark_scan(self, mock_scan_single):
        """Kiểm thử tính năng benchmark so sánh hiệu năng các mức luồng."""
        ports = [80, 443, 8080, 8443]
        mock_scan_single.side_effect = lambda ip, port, timeout=1.0, enable_banner=False: ScanResult(
            target_ip=ip, port=port, status=STATUS_OPEN
        )

        records = benchmark_scan(
            target_ip="127.0.0.1",
            ports=ports,
            thread_counts=[1, 2],
            timeout=0.1
        )

        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["threads"], 1)
        self.assertEqual(records[1]["threads"], 2)
        self.assertEqual(records[0]["total_ports"], 4)
        self.assertIn("duration_sec", records[0])
        self.assertIn("rate_ports_per_sec", records[0])


if __name__ == "__main__":
    unittest.main()

