"""Module nhận diện dịch vụ phổ biến và phân tích cảnh báo an toàn mạng (Mốc 08/11)."""

import re
import socket
from typing import Any, Dict, List, Optional

from src.config import (
    COMMON_PORTS,
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_INFO,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_NONE,
    SECURITY_RECOMMENDATIONS,
    STATUS_OPEN,
)
from src.core.scanner import ScanResult


def refine_service_with_banner(base_service: str, banner: str) -> str:
    """Tinh chỉnh và làm phong phú tên dịch vụ dựa trên chuỗi biểu ngữ (Banner) thu thập được.

    Args:
        base_service: Tên dịch vụ suy đoán dựa trên số hiệu cổng (ví dụ: 'HTTP', 'SSH').
        banner: Chuỗi biểu ngữ dịch vụ thực tế nhận được từ socket.

    Returns:
        str: Tên dịch vụ cụ thể kèm phiên bản nếu nhận diện được.
    """
    if not banner:
        return base_service

    banner_clean = banner.strip()

    # Nhận diện SSH Server (ví dụ: SSH-2.0-OpenSSH_9.0p1)
    if "SSH" in banner_clean.upper():
        match = re.search(r"(OpenSSH[_\s][\d\.\w]+|Dropbear[_\s][\d\.\w]+)", banner_clean, re.IGNORECASE)
        if match:
            return f"SSH ({match.group(1)})"
        return f"SSH ({banner_clean[:30]})"

    # Nhận diện Web Server từ header Server (ví dụ: Server: nginx/1.24.0)
    if "SERVER:" in banner_clean.upper() or base_service in ("HTTP", "HTTPS", "HTTP-Proxy / Tomcat"):
        match = re.search(r"Server:\s*([^\r\n]+)", banner_clean, re.IGNORECASE)
        if match:
            server_name = match.group(1).strip()
            return f"{base_service} ({server_name[:30]})"
        # Bắt các web server phổ biến
        for srv in ("nginx", "Apache", "Microsoft-IIS", "LiteSpeed", "Caddy", "Tomcat"):
            if srv.lower() in banner_clean.lower():
                return f"{base_service} ({srv})"

    # Nhận diện FTP Server (ví dụ: 220 (vsFTPd 3.0.3))
    if "FTP" in base_service or "220" in banner_clean:
        for ftp_srv in ("vsFTPd", "ProFTPD", "Pure-FTPd", "FileZilla"):
            match = re.search(rf"({ftp_srv}[\s/][\d\.]+)", banner_clean, re.IGNORECASE)
            if match:
                return f"FTP ({match.group(1)})"

    # Nhận diện Redis
    if "REDIS" in banner_clean.upper():
        return f"Redis ({banner_clean[:20]})"

    return base_service


def identify_service(port: int, banner: str = "") -> str:
    """Xác định tên dịch vụ dựa trên số hiệu cổng và thông tin biểu ngữ banner (nếu có).

    Thứ tự ưu tiên:
    1. Tra cứu trong cơ sở dữ liệu tùy chỉnh COMMON_PORTS của ứng dụng.
    2. Dự phòng tra cứu qua thư viện chuẩn socket.getservbyport() của hệ điều hành.
    3. Tinh chỉnh bằng chuỗi biểu ngữ banner thực tế.

    Args:
        port: Số hiệu cổng mạng (1-65535).
        banner: Chuỗi biểu ngữ banner thu thập được từ socket.

    Returns:
        str: Tên dịch vụ dự đoán.
    """
    base_service = "Unknown"

    if port in COMMON_PORTS:
        base_service = COMMON_PORTS[port]
    else:
        # Dự phòng tra cứu danh bạ dịch vụ hệ điều hành
        try:
            base_service = socket.getservbyport(port, "tcp").upper()
        except (OSError, socket.error):
            base_service = "Unknown"

    if banner:
        return refine_service_with_banner(base_service, banner)

    return base_service


def analyze_security(result: ScanResult) -> ScanResult:
    """Phân tích mức độ rủi ro và sinh khuyến nghị an toàn cơ bản cho cổng đã quét (Mốc 08/11).

    Args:
        result: Đối tượng ScanResult sau khi quét socket.

    Returns:
        ScanResult: Đối tượng đã được bổ sung thông tin dịch vụ, mức độ rủi ro và khuyến nghị.
    """
    # 1. Nhận diện dịch vụ
    result.service = identify_service(result.port, result.banner)

    # 2. Phân tích an toàn nếu cổng OPEN
    if result.status == STATUS_OPEN:
        rec_data = SECURITY_RECOMMENDATIONS.get(result.port)
        if rec_data:
            result.risk_level = rec_data.get("risk_level", RISK_MEDIUM)
            note_text = rec_data.get("note", "")
            rec_text = rec_data.get("recommendation", "")

            # Bổ sung ghi chú an toàn vào notes
            if note_text:
                result.notes = f"{result.notes} | [Lưu ý: {note_text}]" if result.notes else note_text
            result.recommendation = rec_text
        else:
            # Cổng không nằm trong danh mục định nghĩa sẵn
            if result.port < 1024:
                result.risk_level = RISK_MEDIUM
                result.recommendation = (
                    "Cổng đặc quyền hệ thống (< 1024) đang mở. Cần rà soát tiến trình đang chạy "
                    "và cấu hình firewall giới hạn truy cập trong subnet quản lý."
                )
            else:
                result.risk_level = RISK_INFO
                result.recommendation = "Cần kiểm tra sự cần thiết của dịch vụ và phân quyền truy cập phù hợp."
    else:
        result.risk_level = RISK_NONE
        result.recommendation = "Không có khuyến nghị do cổng đang đóng hoặc bị lọc."

    return result


def analyze_all_results(results: List[ScanResult]) -> List[ScanResult]:
    """Phân tích danh sách toàn bộ kết quả quét mạng.

    Args:
        results: Danh sách kết quả quét.

    Returns:
        List[ScanResult]: Danh sách kết quả đã được gán nhãn dịch vụ và khuyến nghị.
    """
    return [analyze_security(r) for r in results]


def get_security_posture_summary(results: List[ScanResult]) -> Dict[str, Any]:
    """Tổng hợp báo cáo đánh giá mức độ an toàn (Security Posture Assessment) toàn diện.

    Args:
        results: Danh sách các kết quả ScanResult đã được phân tích an toàn.

    Returns:
        Dict[str, Any]: Thống kê chi tiết số cổng theo mức rủi ro, danh sách rủi ro chính và đánh giá chung.
    """
    open_results = [r for r in results if r.status == STATUS_OPEN]

    critical_list = [r for r in open_results if r.risk_level == RISK_CRITICAL]
    high_list = [r for r in open_results if r.risk_level == RISK_HIGH]
    medium_list = [r for r in open_results if r.risk_level == RISK_MEDIUM]
    low_list = [r for r in open_results if r.risk_level == RISK_LOW]
    info_list = [r for r in open_results if r.risk_level == RISK_INFO]

    # Nhận diện dịch vụ không mã hóa (Cleartext) và cơ sở dữ liệu mở
    cleartext_ports = []
    database_ports = []

    for r in open_results:
        rec_data = SECURITY_RECOMMENDATIONS.get(r.port)
        if rec_data:
            if rec_data.get("is_cleartext"):
                cleartext_ports.append(f"Cổng {r.port} ({r.service})")
            if "Cơ sở dữ liệu" in rec_data.get("category", ""):
                database_ports.append(f"Cổng {r.port} ({r.service})")

    # Đánh giá chung
    if len(critical_list) > 0 or len(high_list) >= 2:
        posture_rating = "NGUY CƠ CAO (HIGH RISK)"
        posture_badge_color = "#cc0000"
        posture_summary = "Hệ thống có các dịch vụ tiềm ẩn rủi ro nghiêm trọng cần khắc phục khẩn cấp."
    elif len(high_list) == 1 or len(medium_list) >= 2:
        posture_rating = "CẦN LƯU Ý (MEDIUM RISK)"
        posture_badge_color = "#e67300"
        posture_summary = "Hệ thống mở các dịch vụ quản trị hoặc chưa mã hóa, cần rà soát chính sách truy cập."
    elif len(open_results) > 0:
        posture_rating = "AN TOÀN CƠ BẢN (LOW RISK / ACCEPTABLE)"
        posture_badge_color = "#008000"
        posture_summary = "Các dịch vụ mở đều có cơ chế mã hóa hoặc rủi ro ở mức thấp."
    else:
        posture_rating = "KHÔNG CÓ DỊCH VỤ MỞ (SECURE)"
        posture_badge_color = "#666666"
        posture_summary = "Không phát hiện cổng mở nào trong phạm vi quét."

    # Top khuyến nghị an ninh cấp bách nhất
    priority_recommendations = []
    for r in critical_list + high_list + medium_list:
        priority_recommendations.append({
            "port": r.port,
            "service": r.service,
            "risk_level": r.risk_level,
            "recommendation": r.recommendation,
        })

    return {
        "total_open": len(open_results),
        "critical_count": len(critical_list),
        "high_count": len(high_list),
        "medium_count": len(medium_list),
        "low_count": len(low_list),
        "info_count": len(info_list),
        "cleartext_ports": cleartext_ports,
        "database_ports": database_ports,
        "posture_rating": posture_rating,
        "posture_badge_color": posture_badge_color,
        "posture_summary": posture_summary,
        "priority_recommendations": priority_recommendations,
    }


def filter_results_by_risk(results: List[ScanResult], risk_level: str) -> List[ScanResult]:
    """Lọc danh sách kết quả theo mức độ rủi ro (Critical, High, Medium, Low, Info).

    Args:
        results: Danh sách ScanResult.
        risk_level: Chuỗi mức độ rủi ro cần lọc ('ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW').

    Returns:
        List[ScanResult]: Danh sách kết quả thỏa mãn.
    """
    risk_upper = risk_level.strip().upper()
    if risk_upper in ("ALL", "TẤT CẢ", "*"):
        return results
    return [r for r in results if r.risk_level.upper() == risk_upper]
