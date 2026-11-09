"""Module xuất báo cáo kết quả quét cổng mạng ra file CSV và TXT (Mốc 10/11).

Chức năng chính:
- export_to_csv(): Xuất bảng kết quả quét chi tiết ra định dạng CSV chuẩn UTF-8 BOM,
  kèm phần header metadata (thông tin mục tiêu, thời gian quét, cấu hình)
  và phần tổng kết thống kê cuối file.
- export_to_txt(): Xuất báo cáo dạng văn bản thuần túy (Plain Text Report) bao gồm
  bảng kết quả, thống kê phân loại trạng thái, đánh giá thế trận an ninh
  và danh sách khuyến nghị ưu tiên.
- generate_console_report(): Sinh báo cáo dạng văn bản để hiển thị trên CLI console.
"""

import csv
from datetime import datetime
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.config import REPORTS_DIR
from src.core.scanner import ScanResult


# ---------------------------------------------------------------------------
# Thông tin siêu dữ liệu (Scan Metadata) kèm theo báo cáo
# ---------------------------------------------------------------------------

def _build_scan_metadata(
    results: List[ScanResult],
    scan_duration_sec: Optional[float] = None,
    threads_used: Optional[int] = None,
    extra_info: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Tổng hợp siêu dữ liệu phiên quét để ghi vào phần đầu báo cáo.

    Args:
        results: Danh sách kết quả quét.
        scan_duration_sec: Thời gian quét thực tế (giây).
        threads_used: Số lượng worker threads đã sử dụng.
        extra_info: Thông tin bổ sung tùy ý.

    Returns:
        Dict[str, str]: Từ điển các trường siêu dữ liệu.
    """
    target_ip = results[0].target_ip if results else "N/A"
    ports_scanned = sorted(set(r.port for r in results))
    port_range_str = f"{ports_scanned[0]}-{ports_scanned[-1]}" if ports_scanned else "N/A"

    metadata: Dict[str, str] = {
        "Thời gian xuất báo cáo": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Mục tiêu (IP)": target_ip,
        "Tổng số cổng đã quét": str(len(results)),
        "Phạm vi cổng": port_range_str,
    }
    if scan_duration_sec is not None:
        metadata["Thời gian quét (giây)"] = f"{scan_duration_sec:.3f}"
    if threads_used is not None:
        metadata["Số luồng sử dụng"] = str(threads_used)
    if extra_info:
        metadata.update(extra_info)

    return metadata


def _compute_summary_stats(results: List[ScanResult]) -> Dict[str, Any]:
    """Tính toán thống kê tổng hợp từ danh sách kết quả quét.

    Returns:
        Dict chứa số lượng và tỷ lệ phần trăm theo trạng thái và mức rủi ro.
    """
    total = len(results)
    open_count = sum(1 for r in results if r.status == "OPEN")
    closed_count = sum(1 for r in results if r.status == "CLOSED")
    filtered_count = total - open_count - closed_count

    def pct(count: int) -> str:
        return f"{(count / total * 100):.1f}" if total > 0 else "0.0"

    # Thống kê theo mức rủi ro (chỉ tính cổng OPEN)
    open_results = [r for r in results if r.status == "OPEN"]
    risk_counts: Dict[str, int] = {}
    for r in open_results:
        risk_counts[r.risk_level] = risk_counts.get(r.risk_level, 0) + 1

    return {
        "total": total,
        "open_count": open_count,
        "closed_count": closed_count,
        "filtered_count": filtered_count,
        "open_percent": pct(open_count),
        "closed_percent": pct(closed_count),
        "filtered_percent": pct(filtered_count),
        "risk_counts": risk_counts,
    }


# ---------------------------------------------------------------------------
# Xuất báo cáo CSV
# ---------------------------------------------------------------------------

def export_to_csv(
    results: List[ScanResult],
    file_path: Optional[str] = None,
    scan_duration_sec: Optional[float] = None,
    threads_used: Optional[int] = None,
) -> str:
    """Xuất danh sách kết quả quét ra file CSV chuẩn UTF-8 BOM (tương thích Excel).

    File CSV bao gồm 3 phần:
    1. **Header metadata**: Thông tin phiên quét (mục tiêu, thời gian, cấu hình).
    2. **Bảng dữ liệu**: Chi tiết từng cổng đã quét với 9 cột thông tin.
    3. **Summary footer**: Thống kê tổng hợp trạng thái và phân bố rủi ro.

    Args:
        results: Danh sách các đối tượng ScanResult.
        file_path: Đường dẫn file CSV xuất ra. Nếu để None, tự tạo tên file theo
                   timestamp trong thư mục reports/.
        scan_duration_sec: Thời gian quét thực tế (giây) để ghi vào metadata.
        threads_used: Số lượng worker threads đã sử dụng.

    Returns:
        str: Đường dẫn tuyệt đối đến file CSV đã xuất.
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
        "Banner",
        "Mã lỗi Socket",
        "Ghi chú kỹ thuật",
        "Khuyến nghị an toàn",
    ]

    with open(file_path, mode="w", newline="", encoding="utf-8-sig") as csvfile:
        writer = csv.writer(csvfile)

        # --- PHẦN 1: HEADER METADATA ---
        metadata = _build_scan_metadata(results, scan_duration_sec, threads_used)
        writer.writerow(["# BÁO CÁO QUÉT CỔNG MẠNG LAN - LAN PORT SCANNER"])
        for key, value in metadata.items():
            writer.writerow([f"# {key}", value])
        writer.writerow([])  # Dòng trống phân cách

        # --- PHẦN 2: BẢNG DỮ LIỆU ---
        dict_writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        dict_writer.writeheader()
        for r in results:
            rtt_display = f"{r.response_time_ms:.2f}" if r.response_time_ms > 0 else "0.00"
            dict_writer.writerow({
                "Mục tiêu (IP)": r.target_ip,
                "Cổng (Port)": r.port,
                "Trạng thái": r.status,
                "Độ trễ phản hồi (ms)": rtt_display,
                "Dịch vụ dự đoán": r.service,
                "Mức độ rủi ro": r.risk_level,
                "Banner": r.banner if r.banner else "",
                "Mã lỗi Socket": r.error_code if r.error_code is not None else "",
                "Ghi chú kỹ thuật": r.notes,
                "Khuyến nghị an toàn": r.recommendation,
            })

        # --- PHẦN 3: SUMMARY FOOTER ---
        stats = _compute_summary_stats(results)
        writer.writerow([])  # Dòng trống phân cách
        writer.writerow(["# THỐNG KÊ TỔNG HỢP"])
        writer.writerow(["# Tổng số cổng đã quét", stats["total"]])
        writer.writerow(["# Cổng MỞ (OPEN)", f"{stats['open_count']} ({stats['open_percent']}%)"])
        writer.writerow(["# Cổng ĐÓNG (CLOSED)", f"{stats['closed_count']} ({stats['closed_percent']}%)"])
        writer.writerow(["# Cổng BỊ LỌC (FILTERED)", f"{stats['filtered_count']} ({stats['filtered_percent']}%)"])
        if stats["risk_counts"]:
            writer.writerow(["# PHÂN BỐ MỨC RỦI RO (cổng OPEN)"])
            for risk, count in sorted(stats["risk_counts"].items()):
                writer.writerow([f"#   - {risk}", count])

    return file_path


# ---------------------------------------------------------------------------
# Xuất báo cáo TXT (Plain Text Report)
# ---------------------------------------------------------------------------

def export_to_txt(
    results: List[ScanResult],
    file_path: Optional[str] = None,
    scan_duration_sec: Optional[float] = None,
    threads_used: Optional[int] = None,
    security_summary: Optional[Dict[str, Any]] = None,
) -> str:
    """Xuất báo cáo đánh giá an toàn mạng dạng văn bản thuần túy (Plain Text Report).

    Báo cáo bao gồm:
    1. Tiêu đề và thông tin phiên quét.
    2. Bảng kết quả quét dạng ASCII.
    3. Thống kê trạng thái và hiệu năng.
    4. Đánh giá thế trận an ninh (Security Posture) nếu có.
    5. Danh sách khuyến nghị ưu tiên.

    Args:
        results: Danh sách các đối tượng ScanResult đã phân tích.
        file_path: Đường dẫn file TXT xuất ra. Nếu None, tự tạo.
        scan_duration_sec: Thời gian quét thực tế (giây).
        threads_used: Số lượng worker threads đã sử dụng.
        security_summary: Kết quả từ get_security_posture_summary() nếu có.

    Returns:
        str: Đường dẫn tuyệt đối đến file TXT đã xuất.
    """
    if file_path is None:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_slug = results[0].target_ip.replace(".", "_") if results else "scan"
        file_path = str(REPORTS_DIR / f"scan_report_{target_slug}_{timestamp}.txt")
    else:
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)

    report_text = generate_console_report(
        results,
        scan_duration_sec=scan_duration_sec,
        threads_used=threads_used,
        security_summary=security_summary,
    )

    with open(file_path, mode="w", encoding="utf-8") as f:
        f.write(report_text)

    return file_path


# ---------------------------------------------------------------------------
# Sinh báo cáo văn bản (Console / TXT Report Generator)
# ---------------------------------------------------------------------------

def generate_console_report(
    results: List[ScanResult],
    scan_duration_sec: Optional[float] = None,
    threads_used: Optional[int] = None,
    security_summary: Optional[Dict[str, Any]] = None,
) -> str:
    """Sinh nội dung báo cáo dạng văn bản thuần túy (dùng cho CLI và xuất TXT).

    Args:
        results: Danh sách các đối tượng ScanResult đã phân tích.
        scan_duration_sec: Thời gian quét thực tế (giây).
        threads_used: Số lượng worker threads đã sử dụng.
        security_summary: Kết quả từ get_security_posture_summary() nếu có.

    Returns:
        str: Nội dung báo cáo đã định dạng.
    """
    lines: List[str] = []
    separator = "=" * 80
    thin_sep = "-" * 80

    # ===== TIÊU ĐỀ =====
    lines.append(separator)
    lines.append("  BÁO CÁO QUÉT VÀ PHÂN TÍCH CỔNG MẠNG LAN")
    lines.append("  LAN Port Scanner & Security Analyzer Report")
    lines.append(separator)

    # ===== THÔNG TIN PHIÊN QUÉT =====
    metadata = _build_scan_metadata(results, scan_duration_sec, threads_used)
    lines.append("")
    lines.append("  THÔNG TIN PHIÊN QUÉT:")
    lines.append(thin_sep)
    for key, value in metadata.items():
        lines.append(f"  {key:<30s}: {value}")

    # ===== BẢNG KẾT QUẢ =====
    lines.append("")
    lines.append(separator)
    lines.append("  BẢNG KẾT QUẢ QUÉT CHI TIẾT")
    lines.append(separator)

    # Header bảng
    header = f"  {'CỔNG':<8}{'TRẠNG THÁI':<18}{'ĐỘ TRỄ':<10}{'DỊCH VỤ':<22}{'RỦI RO':<12}{'GHI CHÚ'}"
    lines.append(header)
    lines.append("  " + thin_sep[2:])

    for r in results:
        rtt_str = f"{r.response_time_ms:.1f}ms" if r.response_time_ms > 0 else "-"
        notes_short = (r.notes[:30] + "...") if r.notes and len(r.notes) > 30 else (r.notes or "")
        line = f"  {r.port:<8}{r.status:<18}{rtt_str:<10}{r.service:<22}{r.risk_level:<12}{notes_short}"
        lines.append(line)

    # ===== THỐNG KÊ TỔNG HỢP =====
    stats = _compute_summary_stats(results)
    lines.append("")
    lines.append(separator)
    lines.append("  THỐNG KÊ TỔNG HỢP")
    lines.append(separator)
    lines.append(f"  Tổng số cổng đã quét       : {stats['total']}")
    lines.append(f"  Cổng MỞ (OPEN)             : {stats['open_count']} ({stats['open_percent']}%)")
    lines.append(f"  Cổng ĐÓNG (CLOSED)         : {stats['closed_count']} ({stats['closed_percent']}%)")
    lines.append(f"  Cổng BỊ LỌC (FILTERED)     : {stats['filtered_count']} ({stats['filtered_percent']}%)")
    if scan_duration_sec is not None and scan_duration_sec > 0:
        scan_rate = len(results) / scan_duration_sec
        lines.append(f"  Tốc độ quét                : {scan_rate:.1f} cổng/giây")
    if stats["risk_counts"]:
        lines.append("")
        lines.append("  Phân bố mức rủi ro (cổng OPEN):")
        for risk, count in sorted(stats["risk_counts"].items()):
            lines.append(f"    - {risk:<15}: {count}")

    # ===== ĐÁNH GIÁ AN NINH =====
    if security_summary:
        lines.append("")
        lines.append(separator)
        lines.append("  ĐÁNH GIÁ THẾ TRẬN AN NINH MẠNG (SECURITY POSTURE)")
        lines.append(separator)
        lines.append(f"  Mức đánh giá tổng thể : {security_summary.get('posture_rating', 'N/A')}")
        lines.append(f"  Nhận định chuyên môn   : {security_summary.get('posture_summary', 'N/A')}")

        cleartext = security_summary.get("cleartext_ports", [])
        if cleartext:
            lines.append("")
            lines.append("  [!] Dịch vụ truyền văn bản rõ (Cleartext):")
            for cp in cleartext:
                lines.append(f"      • {cp}")

        database = security_summary.get("database_ports", [])
        if database:
            lines.append("")
            lines.append("  [!] Cơ sở dữ liệu đang mở cổng mạng:")
            for dp in database:
                lines.append(f"      • {dp}")

        priority_recs = security_summary.get("priority_recommendations", [])
        if priority_recs:
            lines.append("")
            lines.append("  KHUYẾN NGHỊ AN NINH ƯU TIÊN:")
            lines.append("  " + thin_sep[2:])
            for idx, rec in enumerate(priority_recs, start=1):
                lines.append(f"  {idx}. [{rec['risk_level'].upper()}] Cổng {rec['port']} ({rec['service']}):")
                lines.append(f"     → {rec['recommendation']}")
                lines.append("")

    # ===== FOOTER =====
    lines.append(separator)
    lines.append("  Báo cáo được tạo bởi: LAN Port Scanner & Security Analyzer")
    lines.append(f"  Thời gian xuất: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(separator)
    lines.append("")

    return "\n".join(lines)
