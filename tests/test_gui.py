"""Kiểm thử các thành phần giao diện người dùng Tkinter cho nhiệm vụ ngày 09/11."""

import tkinter as tk
import unittest

from src.config import RISK_CRITICAL, RISK_LOW, STATUS_CLOSED, STATUS_OPEN
from src.core.scanner import ScanResult
from src.gui.app import PortScannerApp


class TestPortScannerAppGUI(unittest.TestCase):
    """Bộ kiểm thử cho lớp PortScannerApp (Tkinter GUI)."""

    @classmethod
    def setUpClass(cls):
        """Khởi tạo cửa sổ Tkinter ẩn để kiểm thử không cần hiển thị màn hình."""
        try:
            cls.root = tk.Tk()
            cls.root.withdraw()
            cls.app = PortScannerApp(cls.root)
            cls.gui_supported = True
        except Exception:
            cls.gui_supported = False

    @classmethod
    def tearDownClass(cls):
        """Hủy cửa sổ sau khi hoàn thành kiểm thử."""
        if cls.gui_supported and hasattr(cls, "root"):
            try:
                cls.root.destroy()
            except Exception:
                pass

    def setUp(self):
        if not self.gui_supported:
            self.skipTest("Môi trường không hỗ trợ khởi tạo Tkinter GUI.")
        self.app.clear_results()

    def test_gui_initialization(self):
        """Kiểm tra khởi tạo giao diện và các biến giao diện."""
        self.assertIsNotNone(self.app.tree)
        self.assertIsNotNone(self.app.notebook)
        self.assertEqual(len(self.app.scan_results), 0)
        self.assertFalse(self.app.is_scanning)

    def test_preset_change(self):
        """Kiểm tra chức năng chọn mẫu cổng nhanh (Presets)."""
        self.app._set_preset("Web (80, 443, 8080, 8443)")
        self.assertIn("80", self.app.ports_entry.get())
        self.assertIn("443", self.app.ports_entry.get())

        self.app._set_preset("Database (1433, 1521, 3306, 5432, 27017)")
        self.assertIn("3306", self.app.ports_entry.get())

    def test_check_ip_target_valid_local(self):
        """Kiểm tra cập nhật nhãn trạng thái với IP hợp lệ."""
        self.app.target_entry.delete(0, tk.END)
        self.app.target_entry.insert(0, "127.0.0.1")
        is_ok, res = self.app.check_ip_target(silent=True)
        self.assertTrue(is_ok)
        self.assertEqual(res.resolved_ip, "127.0.0.1")
        self.assertIn("Loopback", self.app.lbl_ip_feedback.cget("text"))

    def test_check_ip_target_invalid(self):
        """Kiểm tra cập nhật nhãn trạng thái với IP sai định dạng."""
        self.app.target_entry.delete(0, tk.END)
        self.app.target_entry.insert(0, "300.1.1.1")
        is_ok, res = self.app.check_ip_target(silent=True)
        self.assertFalse(is_ok)
        self.assertIn("❌", self.app.lbl_ip_feedback.cget("text"))

    def test_update_row_and_stats(self):
        """Kiểm tra cập nhật tiến trình và thống kê khi nhận kết quả quét."""
        mock_res1 = ScanResult(
            target_ip="192.168.1.1",
            port=23,
            status=STATUS_OPEN,
            service="Telnet",
            risk_level=RISK_CRITICAL,
            notes="Cleartext",
            recommendation="Tắt Telnet"
        )
        mock_res2 = ScanResult(
            target_ip="192.168.1.1",
            port=80,
            status=STATUS_CLOSED,
            service="HTTP",
            risk_level=RISK_LOW,
            notes="RST",
            recommendation="N/A"
        )

        self.app._update_row_and_progress(mock_res1, 1, 2)
        self.app._update_row_and_progress(mock_res2, 2, 2)

        self.assertEqual(len(self.app.scan_results), 2)
        items = self.app.tree.get_children()
        self.assertEqual(len(items), 2)

        # Kiểm tra nhãn thống kê
        self.assertIn("Mở: 1", self.app.lbl_stat_open.cget("text"))
        self.assertIn("Đóng: 1", self.app.lbl_stat_closed.cget("text"))

        # Kiểm tra Tab Báo cáo an ninh
        self.assertIn("Critical", self.app.lbl_risk_counts.cget("text"))

    def test_filter_changed_gui(self):
        """Kiểm tra bộ lọc trạng thái và rủi ro trên bảng Treeview."""
        mock_res_open = ScanResult(
            target_ip="127.0.0.1", port=22, status=STATUS_OPEN, risk_level=RISK_LOW
        )
        mock_res_closed = ScanResult(
            target_ip="127.0.0.1", port=80, status=STATUS_CLOSED, risk_level="None"
        )
        self.app._update_row_and_progress(mock_res_open, 1, 2)
        self.app._update_row_and_progress(mock_res_closed, 2, 2)

        # Lọc chỉ cổng OPEN
        self.app.status_filter_var.set("Chỉ cổng MỞ (OPEN)")
        self.app._on_filter_changed()
        items = self.app.tree.get_children()
        self.assertEqual(len(items), 1)

        # Lọc lại tất cả
        self.app.status_filter_var.set("Tất cả trạng thái")
        self.app._on_filter_changed()
        items = self.app.tree.get_children()
        self.assertEqual(len(items), 2)

    def test_clear_results(self):
        """Kiểm tra chức năng xóa bảng kết quả."""
        mock_res = ScanResult(target_ip="127.0.0.1", port=80, status=STATUS_OPEN)
        self.app._update_row_and_progress(mock_res, 1, 1)
        self.assertEqual(len(self.app.tree.get_children()), 1)

        self.app.clear_results()
        self.assertEqual(len(self.app.tree.get_children()), 0)
        self.assertEqual(len(self.app.scan_results), 0)

    def test_activity_logging(self):
        """Kiểm tra ghi log hoạt động trên Tab 3."""
        self.app._log("Kiểm thử thông điệp nhật ký", level="TEST")
        log_content = self.app.txt_logs.get("1.0", tk.END)
        self.assertIn("Kiểm thử thông điệp nhật ký", log_content)


if __name__ == "__main__":
    unittest.main()
