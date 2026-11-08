"""Module phân loại và phân tích trạng thái cổng mạng (OPEN, CLOSED, FILTERED/UNKNOWN)."""

from dataclasses import dataclass
import errno
from typing import Any, Dict, List, Optional

from src.config import STATUS_CLOSED, STATUS_FILTERED, STATUS_OPEN


@dataclass
class PortClassification:
    """Đối tượng biểu diễn chi tiết phân loại trạng thái của một cổng mạng."""
    status: str
    reason: str
    packet_type: str
    confidence: float  # Độ tin cậy từ 0.0 đến 1.0
    firewall_suspected: bool
    description: str


# Định nghĩa chi tiết ngữ nghĩa và thông tin hiển thị cho từng trạng thái
STATUS_DEFINITIONS: Dict[str, Dict[str, str]] = {
    STATUS_OPEN: {
        "title": "Cổng đang mở (OPEN)",
        "summary": "Ứng dụng hoặc dịch vụ đang tích cực lắng nghe và chấp nhận kết nối TCP.",
        "badge_color": "#008000",
        "description": "Gói tin SYN gửi đi đã nhận được phản hồi SYN-ACK từ máy đích. Quá trình bắt tay 3 bước hoàn tất."
    },
    STATUS_CLOSED: {
        "title": "Cổng đang đóng (CLOSED)",
        "summary": "Máy đích tiếp nhận gói tin nhưng không có dịch vụ nào đang lắng nghe.",
        "badge_color": "#666666",
        "description": "Máy đích gửi lại gói tin RST (Reset) từ chối kết nối. Thiết bị đích đang hoạt động bình thường (Alive)."
    },
    STATUS_FILTERED: {
        "title": "Cổng bị lọc hoặc không xác định (FILTERED/UNKNOWN)",
        "summary": "Không nhận được phản hồi rõ ràng, gói tin có thể bị tường lửa hoặc bộ lọc mạng hủy (DROP).",
        "badge_color": "#d97706",
        "description": "Gói tin không có phản hồi trong thời gian timeout hoặc bị phần mềm an ninh / tường lửa chặn."
    }
}


def classify_status(
    error_code: Optional[int],
    elapsed_time: float = 0.0,
    timeout: float = 1.0
) -> PortClassification:
    """Phân loại trạng thái cổng dựa trên mã lỗi tầng socket và thời gian phản hồi.

    Quy tắc phân loại:
    1. error_code == 0:
       -> OPEN (Bắt tay 3 bước TCP SYN-ACK thành công).
    2. error_code in (10061, ECONNREFUSED):
       -> CLOSED (Máy đích gửi gói TCP RST từ chối kết nối).
    3. error_code in (10060, ETIMEDOUT) hoặc error_code is None:
       -> FILTERED/UNKNOWN (Timeout, gói tin bị drop bởi firewall).
    4. error_code in (10065, EHOSTUNREACH):
       -> FILTERED/UNKNOWN (ICMP Host Unreachable - không tìm thấy máy chủ).
    5. error_code in (10051, ENETUNREACH):
       -> FILTERED/UNKNOWN (ICMP Net Unreachable - không tìm thấy mạng).
    6. error_code in (10013, EACCES):
       -> FILTERED/UNKNOWN (Bị chặn bởi quyền bảo mật / tường lửa cục bộ).
    7. Các mã lỗi khác:
       -> FILTERED/UNKNOWN (Lỗi kết nối socket hệ thống).

    Args:
        error_code: Mã lỗi trả về từ socket.connect_ex hoặc None nếu timeout.
        elapsed_time: Thời gian thực hiện kết nối (giây).
        timeout: Ngưỡng thời gian chờ cấu hình (giây).

    Returns:
        PortClassification: Kết quả phân loại chi tiết.
    """
    # 1. Trạng thái OPEN
    if error_code == 0:
        return PortClassification(
            status=STATUS_OPEN,
            reason="Nhận phản hồi TCP SYN-ACK từ máy đích (Bắt tay thành công).",
            packet_type="TCP SYN-ACK",
            confidence=1.0,
            firewall_suspected=False,
            description="Cổng đang mở và có dịch vụ ứng dụng sẵn sàng nhận kết nối."
        )

    # 2. Trạng thái CLOSED
    if error_code in (errno.ECONNREFUSED, 10061):
        return PortClassification(
            status=STATUS_CLOSED,
            reason="Máy đích chủ động từ chối kết nối bằng gói tin TCP RST.",
            packet_type="TCP RST",
            confidence=1.0,
            firewall_suspected=False,
            description="Thiết bị đích đang hoạt động nhưng không có dịch vụ lắng nghe trên cổng này."
        )

    # 3. Trạng thái FILTERED do Timeout
    if error_code in (errno.ETIMEDOUT, 10060) or error_code is None:
        return PortClassification(
            status=STATUS_FILTERED,
            reason=f"Hết thời gian chờ phản hồi ({timeout}s). Gói tin có thể bị tường lửa DROP.",
            packet_type="No Response / Dropped",
            confidence=0.85,
            firewall_suspected=True,
            description="Tường lửa (Stateful / Packet Filter) đã chặn gói tin hoặc máy đích không phản hồi."
        )

    # 4. Trạng thái FILTERED do không tiếp cận được Host (ICMP Type 3 Code 1)
    if error_code in (getattr(errno, "EHOSTUNREACH", 113), 10065):
        return PortClassification(
            status=STATUS_FILTERED,
            reason="Không có đường truyền đến máy chủ đích (Host Unreachable).",
            packet_type="ICMP Host Unreachable",
            confidence=0.9,
            firewall_suspected=True,
            description="Router hoặc thiết bị định tuyến trung gian báo không thể tiếp cận máy đích."
        )

    # 5. Trạng thái FILTERED do không tiếp cận được Network (ICMP Type 3 Code 0)
    if error_code in (getattr(errno, "ENETUNREACH", 101), 10051):
        return PortClassification(
            status=STATUS_FILTERED,
            reason="Mạng đích không thể tiếp cận (Network Unreachable).",
            packet_type="ICMP Net Unreachable",
            confidence=0.9,
            firewall_suspected=True,
            description="Không tìm thấy đường định tuyến đến mạng chứa mục tiêu."
        )

    # 6. Trạng thái FILTERED do quyền truy cập / Bảo mật cục bộ chặn
    if error_code in (getattr(errno, "EACCES", 13), 10013):
        return PortClassification(
            status=STATUS_FILTERED,
            reason="Quyền truy cập socket bị hạn chế hoặc bị phần mềm an ninh / tường lửa chặn (WSAEACCES).",
            packet_type="Local Security Block",
            confidence=0.95,
            firewall_suspected=True,
            description="Tường lửa cục bộ (Windows Defender / Antivirus) ngăn chặn kết nối socket."
        )

    # 7. Các mã lỗi khác
    return PortClassification(
        status=STATUS_FILTERED,
        reason=f"Lỗi kết nối socket hệ thống (Mã lỗi {error_code}).",
        packet_type=f"Socket Error {error_code}",
        confidence=0.7,
        firewall_suspected=True,
        description="Không nhận được phản hồi hợp lệ từ máy đích do sự cố giao vận socket."
    )


def get_classification_stats(results: List[Any]) -> Dict[str, Any]:
    """Tổng hợp thống kê tỷ lệ phân loại các trạng thái cổng sau khi quét.

    Args:
        results: Danh sách đối tượng ScanResult.

    Returns:
        Dict[str, Any]: Từ điển chứa số lượng và tỷ lệ % của từng trạng thái.
    """
    total = len(results)
    if total == 0:
        return {
            "total": 0,
            "open_count": 0,
            "closed_count": 0,
            "filtered_count": 0,
            "open_percent": 0.0,
            "closed_percent": 0.0,
            "filtered_percent": 0.0,
            "firewall_detected": False,
        }

    open_count = sum(1 for r in results if r.status == STATUS_OPEN)
    closed_count = sum(1 for r in results if r.status == STATUS_CLOSED)
    filtered_count = sum(1 for r in results if r.status == STATUS_FILTERED)

    return {
        "total": total,
        "open_count": open_count,
        "closed_count": closed_count,
        "filtered_count": filtered_count,
        "open_percent": round((open_count / total) * 100, 1),
        "closed_percent": round((closed_count / total) * 100, 1),
        "filtered_percent": round((filtered_count / total) * 100, 1),
        "firewall_detected": filtered_count > 0,
    }


def filter_results_by_status(results: List[Any], status_filter: str) -> List[Any]:
    """Lọc danh sách kết quả quét theo trạng thái mong muốn.

    Args:
        results: Danh sách ScanResult.
        status_filter: Chuỗi trạng thái cần lọc ('ALL', 'OPEN', 'CLOSED', 'FILTERED').

    Returns:
        List[Any]: Danh sách các kết quả thỏa mãn điều kiện lọc.
    """
    filter_upper = status_filter.strip().upper()
    if filter_upper in ("ALL", "TẤT CẢ", "*"):
        return results
    if filter_upper in ("OPEN", "MỞ"):
        return [r for r in results if r.status == STATUS_OPEN]
    if filter_upper in ("CLOSED", "ĐÓNG"):
        return [r for r in results if r.status == STATUS_CLOSED]
    if filter_upper in ("FILTERED", "FILTERED/UNKNOWN", "LỌC", "BỊ LỌC"):
        return [r for r in results if r.status == STATUS_FILTERED]
    return results

