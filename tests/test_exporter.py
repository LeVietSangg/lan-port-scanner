"""Kiểm thử tính năng xuất báo cáo CSV trong src.core.exporter."""

import csv
import os
import tempfile
import unittest
from src.core.scanner import ScanResult
from src.core.exporter import export_to_csv


class TestExporter(unittest.TestCase):

    def test_export_to_csv(self):
        results = [
            ScanResult(
                target_ip="192.168.1.50",
                port=80,
                status="OPEN",
                service="HTTP",
                risk_level="Medium",
                notes="Phản hồi HTTP",
                recommendation="Chuyển sang HTTPS",
            ),
            ScanResult(
                target_ip="192.168.1.50",
                port=443,
                status="OPEN",
                service="HTTPS",
                risk_level="Low",
                notes="TLS kết nối thành công",
                recommendation="Định kỳ cập nhật chứng chỉ",
            ),
        ]

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            exported_path = export_to_csv(results, file_path=tmp_path)
            self.assertTrue(os.path.exists(exported_path))

            with open(exported_path, mode="r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["Mục tiêu (IP)"], "192.168.1.50")
            self.assertEqual(rows[0]["Cổng (Port)"], "80")
            self.assertEqual(rows[0]["Trạng thái"], "OPEN")
            self.assertEqual(rows[0]["Dịch vụ dự đoán"], "HTTP")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()

