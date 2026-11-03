"""Module nhận diện dịch vụ phổ biến và phân tích cảnh báo an toàn cơ bản."""

from typing import List
from src.config import COMMON_PORTS, SECURITY_RECOMMENDATIONS, STATUS_OPEN
from src.core.scanner import ScanResult


def identify_service(port: int) -> str:
    """Xác định tên dịch vụ phổ biến theo số hiệu cổng.

    Args:
        port: Số hiệu cổng mạng.

    Returns:
        str: Tên dịch vụ dự đoán (hoặc 'Unknown' nếu không có trong cơ sở dữ liệu).
    """
    return COMMON_PORTS.get(port, "Unknown")


def analyze_security(result: ScanResult) -> ScanResult:
    """Phân tích mức độ rủi ro và khuyến nghị an toàn cho cổng đã quét.

    Args:
        result: Đối tượng ScanResult sau khi quét.

    Returns:
        ScanResult: Đối tượng đã được cập nhật thông tin dịch vụ và khuyến nghị.
    """
    result.service = identify_service(result.port)

    if result.status == STATUS_OPEN:
        rec_data = SECURITY_RECOMMENDATIONS.get(result.port)
        if rec_data:
            result.risk_level = rec_data.get("risk_level", "Medium")
            rec_text = rec_data.get("recommendation", "")
            note_text = rec_data.get("note", "")
            result.notes = f"{result.notes} | {note_text}" if result.notes else note_text
            result.recommendation = rec_text
        else:
            result.risk_level = "Info"
            result.recommendation = "Cần kiểm tra sự cần thiết của dịch vụ và phân quyền truy cập phù hợp."
    else:
        result.risk_level = "None"
        result.recommendation = "Không có khuyến nghị do cổng đang đóng hoặc bị lọc."

    return result


def analyze_all_results(results: List[ScanResult]) -> List[ScanResult]:
    """Phân tích danh sách toàn bộ kết quả quét.

    Args:
        results: Danh sách kết quả quét.

    Returns:
        List[ScanResult]: Danh sách kết quả đã được gán nhãn dịch vụ và khuyến nghị.
    """
    return [analyze_security(r) for r in results]

