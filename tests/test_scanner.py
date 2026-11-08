"""Kiểm thử tính năng quét cổng TCP bằng Socket cho nhiệm vụ ngày 05/11."""

import errno
import socket
import unittest
from unittest.mock import MagicMock, patch

from src.config import STATUS_CLOSED, STATUS_FILTERED, STATUS_OPEN
from src.core.scanner import (
    SOCKET_ERROR_DESCRIPTIONS,
    PortScanner,
    grab_banner,
    scan_ports_sequential,
    scan_single_port,
)


class TestSocketScanner(unittest.TestCase):
    """Bộ kiểm thử cho chức năng quét cổng mạng bằng Socket (TCP Connect Scan)."""

    @patch("socket.socket")
    def test_scan_single_port_open(self, mock_socket_cls):
        """Kiểm thử cổng mở (OPEN) khi connect_ex trả về mã 0 (bắt tay 3 bước thành công)."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        result = scan_single_port("192.168.1.1", 80, timeout=1.0)

        self.assertEqual(result.target_ip, "192.168.1.1")
        self.assertEqual(result.port, 80)
        self.assertEqual(result.status, STATUS_OPEN)
        self.assertEqual(result.error_code, 0)
        self.assertGreaterEqual(result.response_time_ms, 0)
        self.assertIn("thành công", result.notes)
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_scan_single_port_closed_windows(self, mock_socket_cls):
        """Kiểm thử cổng đóng (CLOSED) trên Windows khi connect_ex trả về WSAECONNREFUSED (10061)."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 10061  # WSAECONNREFUSED
        mock_socket_cls.return_value = mock_sock

        result = scan_single_port("192.168.1.1", 21, timeout=0.5)

        self.assertEqual(result.status, STATUS_CLOSED)
        self.assertEqual(result.error_code, 10061)
        self.assertIn("từ chối kết nối", result.notes)
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_scan_single_port_closed_posix(self, mock_socket_cls):
        """Kiểm thử cổng đóng (CLOSED) trên Linux/POSIX khi connect_ex trả về ECONNREFUSED."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = errno.ECONNREFUSED
        mock_socket_cls.return_value = mock_sock

        result = scan_single_port("192.168.1.1", 23, timeout=0.5)

        self.assertEqual(result.status, STATUS_CLOSED)
        self.assertEqual(result.error_code, errno.ECONNREFUSED)
        self.assertIn("từ chối kết nối", result.notes)

    @patch("socket.socket")
    def test_scan_single_port_filtered_timeout(self, mock_socket_cls):
        """Kiểm thử trạng thái FILTERED khi hết thời gian chờ (WSAETIMEDOUT / 10060 hoặc socket.timeout)."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 10060  # WSAETIMEDOUT
        mock_socket_cls.return_value = mock_sock

        result = scan_single_port("192.168.1.1", 445, timeout=0.5)

        self.assertEqual(result.status, STATUS_FILTERED)
        self.assertEqual(result.error_code, 10060)
        self.assertIn("thời gian chờ", result.notes)

    @patch("socket.socket")
    def test_scan_single_port_filtered_access_denied(self, mock_socket_cls):
        """Kiểm thử trạng thái FILTERED khi gặp lỗi quyền truy cập mạng (WSAEACCES 10013)."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 10013
        mock_socket_cls.return_value = mock_sock

        result = scan_single_port("192.168.1.1", 80, timeout=0.5)

        self.assertEqual(result.status, STATUS_FILTERED)
        self.assertEqual(result.error_code, 10013)
        self.assertIn("WSAEACCES", result.notes)

    @patch("socket.socket")
    def test_scan_single_port_exception_handling(self, mock_socket_cls):
        """Kiểm thử bắt ngoại lệ kết nối socket không xác định."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = RuntimeError("Sự cố phần cứng socket")
        mock_socket_cls.return_value = mock_sock

        result = scan_single_port("192.168.1.1", 80, timeout=0.5)

        self.assertEqual(result.status, STATUS_FILTERED)
        self.assertIn("Sự cố phần cứng socket", result.notes)

    @patch("src.core.scanner.grab_banner")
    @patch("socket.socket")
    def test_scan_single_port_with_banner_enabled(self, mock_socket_cls, mock_grab):
        """Kiểm thử thu thập banner khi cổng OPEN và enable_banner=True."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock
        mock_grab.return_value = "SSH-2.0-OpenSSH_8.9p1"

        result = scan_single_port("192.168.1.1", 22, timeout=1.0, enable_banner=True)

        self.assertEqual(result.status, STATUS_OPEN)
        self.assertEqual(result.banner, "SSH-2.0-OpenSSH_8.9p1")
        self.assertIn("Banner: SSH-2.0-OpenSSH_8.9p1", result.notes)
        mock_grab.assert_called_once_with("192.168.1.1", 22, timeout=1.0)

    @patch("src.core.scanner.scan_single_port")
    def test_scan_ports_sequential(self, mock_scan_single):
        """Kiểm thử quét tuần tự danh sách cổng (chức năng đơn luồng cốt lõi ngày 05/11)."""
        from src.core.scanner import ScanResult

        mock_scan_single.side_effect = [
            ScanResult(target_ip="192.168.1.1", port=80, status=STATUS_OPEN),
            ScanResult(target_ip="192.168.1.1", port=443, status=STATUS_CLOSED),
            ScanResult(target_ip="192.168.1.1", port=8080, status=STATUS_FILTERED),
        ]

        progress_calls = []

        def callback(res, current, total):
            progress_calls.append((current, total, res.port, res.status))

        results = scan_ports_sequential(
            "192.168.1.1",
            [80, 443, 8080],
            timeout=0.5,
            progress_callback=callback
        )

        self.assertEqual(len(results), 3)
        self.assertEqual(results[0].port, 80)
        self.assertEqual(results[0].status, STATUS_OPEN)
        self.assertEqual(results[1].port, 443)
        self.assertEqual(results[1].status, STATUS_CLOSED)
        self.assertEqual(results[2].port, 8080)
        self.assertEqual(results[2].status, STATUS_FILTERED)

        # Kiểm tra callback được gọi đúng số lần và thứ tự
        self.assertEqual(len(progress_calls), 3)
        self.assertEqual(progress_calls[0], (1, 3, 80, STATUS_OPEN))
        self.assertEqual(progress_calls[2], (3, 3, 8080, STATUS_FILTERED))

    @patch("socket.socket")
    def test_grab_banner_http(self, mock_socket_cls):
        """Kiểm thử hàm grab_banner với dịch vụ HTTP."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"
        mock_socket_cls.return_value = mock_sock

        banner = grab_banner("192.168.1.1", 80, timeout=0.5)

        self.assertEqual(banner, "HTTP/1.1 200 OK")
        mock_sock.sendall.assert_called_once()
        mock_sock.close.assert_called_once()

    def test_socket_error_descriptions_keys(self):
        """Kiểm thử từ điển diễn giải mã lỗi socket phong phú."""
        self.assertIn(0, SOCKET_ERROR_DESCRIPTIONS)
        self.assertIn(10061, SOCKET_ERROR_DESCRIPTIONS)
        self.assertIn(10060, SOCKET_ERROR_DESCRIPTIONS)
        self.assertIn(10013, SOCKET_ERROR_DESCRIPTIONS)


if __name__ == "__main__":
    unittest.main()
