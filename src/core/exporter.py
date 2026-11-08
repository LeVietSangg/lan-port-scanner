"""Module xuất báo cáo kết quả quét ra file định dạng CSV."""

import csv
from datetime import datetime
import os
from pathlib import Path
from typing import List, Optional

from src.config import REPORTS_DIR
from src.core.scanner import ScanResult


def export_to_csv(results: List[ScanResult], file_path: Optional[str] = None) -> str:
    """Xuất danh sách kết quả quét ra file CSV.

    Args:
        results: Danh sách các đối tượng ScanResult.
        file_path: Đường dẫn file CSV xuất ra. Nếu để None, tự tạo tên file theo timestamp trong thư mục reports.

    Returns:
        str: Đường dẫn file CSV đã xuất.
    """
    if file_path is None:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_slug = results[0].target_ip.replace(".", "_") if results else "scan"
        file_path = str(REPORTS_DIR / f"scan_report_{target_slug}_{timestamp}.csv")
    else:
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "Mục tiêu (IP)",
        "Cổng (Port)",
        "Trạng thái",
        "Độ trễ phản hồi (ms)",
        "Dịch vụ dự đoán",
        "Mức độ rủi ro",
        "Mã lỗi Socket",
        "Ghi chú kỹ thuật",
        "Khuyến nghị an toàn",
    ]

    with open(file_path, mode="w", newline="", encoding="utf-8-sig") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "Mục tiêu (IP)": r.target_ip,
                "Cổng (Port)": r.port,
                "Trạng thái": r.status,
                "Độ trễ phản hồi (ms)": r.response_time_ms,
                "Dịch vụ dự đoán": r.service,
                "Mức độ rủi ro": r.risk_level,
                "Mã lỗi Socket": r.error_code if r.error_code is not None else "",
                "Ghi chú kỹ thuật": r.notes,
                "Khuyến nghị an toàn": r.recommendation,
            })

    return file_path

