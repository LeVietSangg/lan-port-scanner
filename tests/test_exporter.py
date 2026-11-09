"""Kiểm thử đầy đủ module xuất báo cáo CSV và TXT (Mốc 10/11).

Bộ kiểm thử bao gồm:
- Xuất CSV cơ bản và kiểm tra nội dung cột
- Xuất CSV với metadata header và summary footer
- Xuất danh sách rỗng (edge case)
- Xuất một kết quả duy nhất (edge case)
- Tự động tạo tên file khi không chỉ định
- Tự động tạo thư mục cha
- Xuất báo cáo TXT đầy đủ
- Sinh báo cáo văn bản console
- Kiểm tra mã hóa UTF-8 BOM cho CSV
"""

import csv
import os
import shutil
import tempfile
import unittest

from src.core.scanner import ScanResult
from src.core.exporter import (
    export_to_csv,
    export_to_txt,
    generate_console_report,
    _build_scan_metadata,
    _compute_summary_stats,
)


def _make_result(
    port=80,
    status="OPEN",
    service="HTTP",
    risk_level="Medium",
    target_ip="192.168.1.50",
    response_time_ms=15.5,
    error_code=None,
    banner="",
    notes="Phản hồi HTTP",
    recommendation="Chuyển sang HTTPS",
):
    """Hàm tiện ích tạo đối tượng ScanResult cho test."""
    return ScanResult(
        target_ip=target_ip,
        port=port,
        status=status,
        service=service,
        risk_level=risk_level,
        response_time_ms=response_time_ms,
        error_code=error_code,
        banner=banner,
        notes=notes,
        recommendation=recommendation,
    )


class TestExportToCSV(unittest.TestCase):
    """Kiểm thử chức năng xuất file CSV."""

    def setUp(self):
        """Tạo thư mục tạm để lưu file test."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Dọn dẹp thư mục tạm sau mỗi test."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_export_creates_file(self):
        """Kiểm tra file CSV được tạo thành công."""
        results = [_make_result()]
        path = os.path.join(self.test_dir, "test.csv")
        exported = export_to_csv(results, file_path=path)
        self.assertTrue(os.path.exists(exported))
        self.assertEqual(exported, path)

    def test_export_content_basic(self):
        """Kiểm tra nội dung dữ liệu cơ bản trong CSV."""
        results = [
            _make_result(port=80, status="OPEN", service="HTTP"),
            _make_result(port=443, status="OPEN", service="HTTPS", risk_level="Low"),
        ]
        path = os.path.join(self.test_dir, "test.csv")
        export_to_csv(results, file_path=path)

        with open(path, mode="r", encoding="utf-8-sig") as f:
            content = f.read()

        # Kiểm tra header metadata
        self.assertIn("BÁO CÁO QUÉT CỔNG MẠNG", content)
        self.assertIn("Mục tiêu (IP)", content)

        # Kiểm tra dữ liệu cổng
        self.assertIn("80", content)
        self.assertIn("443", content)
        self.assertIn("OPEN", content)
        self.assertIn("HTTP", content)

        # Kiểm tra summary footer
        self.assertIn("THỐNG KÊ TỔNG HỢP", content)

    def test_export_csv_data_rows(self):
        """Kiểm tra số dòng dữ liệu trong CSV khớp với số kết quả."""
        results = [
            _make_result(port=22, service="SSH", risk_level="Low"),
            _make_result(port=80, service="HTTP"),
            _make_result(port=3306, service="MySQL", risk_level="High"),
        ]
        path = os.path.join(self.test_dir, "test.csv")
        export_to_csv(results, file_path=path)

        # Đọc và đếm dòng dữ liệu (bỏ qua comment/metadata)
        with open(path, mode="r", encoding="utf-8-sig") as f:
            all_lines = f.readlines()

        data_lines = [
            line for line in all_lines
            if line.strip() and not line.startswith("#") and "Mục tiêu (IP)" not in line
        ]
        # Phải có ít nhất 3 dòng dữ liệu (3 kết quả)
        self.assertGreaterEqual(len(data_lines), 3)

    def test_export_empty_results(self):
        """Kiểm tra xuất danh sách rỗng không gây lỗi."""
        path = os.path.join(self.test_dir, "empty.csv")
        exported = export_to_csv([], file_path=path)
        self.assertTrue(os.path.exists(exported))

        with open(exported, mode="r", encoding="utf-8-sig") as f:
            content = f.read()

        self.assertIn("BÁO CÁO QUÉT CỔNG MẠNG", content)
        self.assertIn("Tổng số cổng đã quét", content)

    def test_export_single_result(self):
        """Kiểm tra xuất đúng khi chỉ có 1 kết quả."""
        results = [_make_result(port=22, service="SSH")]
        path = os.path.join(self.test_dir, "single.csv")
        export_to_csv(results, file_path=path)

        with open(path, mode="r", encoding="utf-8-sig") as f:
            content = f.read()

        self.assertIn("22", content)
        self.assertIn("SSH", content)

    def test_export_auto_filename(self):
        """Kiểm tra tự động tạo tên file khi không chỉ định đường dẫn."""
        results = [_make_result()]
        # Ghi đè REPORTS_DIR tạm thời bằng cách chỉ rõ thư mục
        exported = export_to_csv(results)
        self.assertTrue(os.path.exists(exported))
        self.assertIn("scan_report_", os.path.basename(exported))
        self.assertTrue(exported.endswith(".csv"))
        # Dọn dẹp file tự động tạo
        os.remove(exported)

    def test_export_creates_parent_directory(self):
        """Kiểm tra tự động tạo thư mục cha khi chưa tồn tại."""
        nested_path = os.path.join(self.test_dir, "subdir", "nested", "report.csv")
        results = [_make_result()]
        exported = export_to_csv(results, file_path=nested_path)
        self.assertTrue(os.path.exists(exported))

    def test_export_csv_with_metadata(self):
        """Kiểm tra CSV có chứa thông tin scan_duration và threads_used."""
        results = [_make_result()]
        path = os.path.join(self.test_dir, "meta.csv")
        export_to_csv(results, file_path=path, scan_duration_sec=2.5, threads_used=10)

        with open(path, mode="r", encoding="utf-8-sig") as f:
            content = f.read()

        self.assertIn("2.500", content)  # scan duration
        self.assertIn("10", content)  # threads

    def test_export_csv_utf8_bom(self):
        """Kiểm tra file CSV có BOM (Byte Order Mark) cho tương thích Excel."""
        results = [_make_result()]
        path = os.path.join(self.test_dir, "bom.csv")
        export_to_csv(results, file_path=path)

        with open(path, mode="rb") as f:
            first_bytes = f.read(3)

        # UTF-8 BOM: EF BB BF
        self.assertEqual(first_bytes, b"\xef\xbb\xbf")

    def test_export_csv_all_fields(self):
        """Kiểm tra tất cả các trường ScanResult được ghi đầy đủ vào CSV."""
        results = [
            _make_result(
                port=21,
                status="OPEN",
                service="FTP",
                risk_level="High",
                response_time_ms=5.32,
                error_code=0,
                banner="220 vsFTPd 3.0.5",
                notes="Kết nối TCP thành công",
                recommendation="Vô hiệu hóa FTP",
            )
        ]
        path = os.path.join(self.test_dir, "fields.csv")
        export_to_csv(results, file_path=path)

        with open(path, mode="r", encoding="utf-8-sig") as f:
            content = f.read()

        self.assertIn("FTP", content)
        self.assertIn("High", content)
        self.assertIn("5.32", content)
        self.assertIn("vsFTPd", content)
        self.assertIn("Vô hiệu hóa FTP", content)


class TestExportToTXT(unittest.TestCase):
    """Kiểm thử chức năng xuất báo cáo TXT."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_export_txt_creates_file(self):
        """Kiểm tra file TXT được tạo thành công."""
        results = [_make_result()]
        path = os.path.join(self.test_dir, "report.txt")
        exported = export_to_txt(results, file_path=path)
        self.assertTrue(os.path.exists(exported))

    def test_export_txt_content(self):
        """Kiểm tra nội dung báo cáo TXT."""
        results = [
            _make_result(port=80, service="HTTP", status="OPEN"),
            _make_result(port=22, service="SSH", status="CLOSED", risk_level="None"),
        ]
        path = os.path.join(self.test_dir, "report.txt")
        export_to_txt(results, file_path=path)

        with open(path, mode="r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("BÁO CÁO QUÉT VÀ PHÂN TÍCH CỔNG MẠNG LAN", content)
        self.assertIn("80", content)
        self.assertIn("HTTP", content)
        self.assertIn("THỐNG KÊ TỔNG HỢP", content)

    def test_export_txt_with_security_summary(self):
        """Kiểm tra báo cáo TXT có phần đánh giá an ninh."""
        results = [_make_result()]
        sec_summary = {
            "posture_rating": "NGUY CƠ CAO (HIGH RISK)",
            "posture_summary": "Hệ thống có dịch vụ tiềm ẩn rủi ro.",
            "cleartext_ports": ["Cổng 80 (HTTP)"],
            "database_ports": [],
            "priority_recommendations": [
                {
                    "port": 80,
                    "service": "HTTP",
                    "risk_level": "Medium",
                    "recommendation": "Chuyển sang HTTPS",
                }
            ],
        }
        path = os.path.join(self.test_dir, "security.txt")
        export_to_txt(results, file_path=path, security_summary=sec_summary)

        with open(path, mode="r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("ĐÁNH GIÁ THẾ TRẬN AN NINH", content)
        self.assertIn("NGUY CƠ CAO", content)
        self.assertIn("Cleartext", content)
        self.assertIn("KHUYẾN NGHỊ AN NINH ƯU TIÊN", content)

    def test_export_txt_auto_filename(self):
        """Kiểm tra tự động tạo tên file TXT."""
        results = [_make_result()]
        exported = export_to_txt(results)
        self.assertTrue(os.path.exists(exported))
        self.assertTrue(exported.endswith(".txt"))
        os.remove(exported)

    def test_export_txt_empty_results(self):
        """Kiểm tra xuất TXT với danh sách rỗng."""
        path = os.path.join(self.test_dir, "empty.txt")
        exported = export_to_txt([], file_path=path)
        self.assertTrue(os.path.exists(exported))


class TestGenerateConsoleReport(unittest.TestCase):
    """Kiểm thử chức năng sinh báo cáo dạng văn bản console."""

    def test_console_report_basic(self):
        """Kiểm tra báo cáo console có đầy đủ các phần."""
        results = [
            _make_result(port=80, status="OPEN"),
            _make_result(port=443, status="CLOSED", risk_level="None"),
        ]
        report = generate_console_report(results)
        self.assertIn("BÁO CÁO QUÉT VÀ PHÂN TÍCH CỔNG MẠNG LAN", report)
        self.assertIn("BẢNG KẾT QUẢ QUÉT CHI TIẾT", report)
        self.assertIn("THỐNG KÊ TỔNG HỢP", report)
        self.assertIn("80", report)

    def test_console_report_with_scan_metadata(self):
        """Kiểm tra báo cáo console có thông tin thời gian và luồng."""
        results = [_make_result()]
        report = generate_console_report(results, scan_duration_sec=3.456, threads_used=25)
        self.assertIn("3.456", report)
        self.assertIn("25", report)

    def test_console_report_empty_results(self):
        """Kiểm tra báo cáo console với danh sách rỗng."""
        report = generate_console_report([])
        self.assertIn("BÁO CÁO QUÉT", report)
        self.assertIn("0", report)


class TestHelperFunctions(unittest.TestCase):
    """Kiểm thử các hàm tiện ích nội bộ."""

    def test_build_scan_metadata(self):
        """Kiểm tra sinh siêu dữ liệu phiên quét."""
        results = [_make_result(port=80), _make_result(port=443)]
        meta = _build_scan_metadata(results, scan_duration_sec=1.5, threads_used=10)
        self.assertEqual(meta["Mục tiêu (IP)"], "192.168.1.50")
        self.assertEqual(meta["Tổng số cổng đã quét"], "2")
        self.assertIn("80-443", meta["Phạm vi cổng"])
        self.assertEqual(meta["Thời gian quét (giây)"], "1.500")
        self.assertEqual(meta["Số luồng sử dụng"], "10")

    def test_build_scan_metadata_empty(self):
        """Kiểm tra sinh siêu dữ liệu với danh sách rỗng."""
        meta = _build_scan_metadata([])
        self.assertEqual(meta["Mục tiêu (IP)"], "N/A")

    def test_compute_summary_stats(self):
        """Kiểm tra tính toán thống kê tổng hợp."""
        results = [
            _make_result(port=80, status="OPEN", risk_level="Medium"),
            _make_result(port=443, status="OPEN", risk_level="Low"),
            _make_result(port=22, status="CLOSED", risk_level="None"),
            _make_result(port=23, status="CLOSED", risk_level="None"),
        ]
        stats = _compute_summary_stats(results)
        self.assertEqual(stats["total"], 4)
        self.assertEqual(stats["open_count"], 2)
        self.assertEqual(stats["closed_count"], 2)
        self.assertEqual(stats["filtered_count"], 0)
        self.assertEqual(stats["open_percent"], "50.0")
        self.assertEqual(stats["risk_counts"]["Medium"], 1)
        self.assertEqual(stats["risk_counts"]["Low"], 1)

    def test_compute_summary_stats_empty(self):
        """Kiểm tra thống kê với danh sách rỗng."""
        stats = _compute_summary_stats([])
        self.assertEqual(stats["total"], 0)
        self.assertEqual(stats["open_count"], 0)
        self.assertEqual(stats["open_percent"], "0.0")


if __name__ == "__main__":
    unittest.main()
