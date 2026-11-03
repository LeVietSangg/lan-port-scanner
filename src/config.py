"""Cấu hình và hằng số dùng chung trong hệ thống LAN Port Scanner."""

import os
from pathlib import Path

# Thư mục gốc dự án
BASE_DIR = Path(__file__).resolve().parent.parent

# Thư mục chứa báo cáo xuất ra
REPORTS_DIR = BASE_DIR / "reports"

# Cấu hình quét mạng mặc định
DEFAULT_TIMEOUT = 1.0  # Thời gian chờ kết nối (giây)
DEFAULT_MAX_THREADS = 50  # Số luồng quét đồng thời tối đa

# Trạng thái cổng mạng
STATUS_OPEN = "OPEN"
STATUS_CLOSED = "CLOSED"
STATUS_FILTERED = "FILTERED/UNKNOWN"

# Danh mục các cổng dịch vụ phổ biến (Well-known & Common ports)
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Cảnh báo an toàn và khuyến nghị cho từng cổng/dịch vụ
SECURITY_RECOMMENDATIONS = {
    21: {
        "service": "FTP",
        "risk_level": "High",
        "note": "FTP truyền tải dữ liệu và mật khẩu dưới dạng văn bản rõ (cleartext).",
        "recommendation": "Cân nhắc chuyển sang SFTP (cổng 22) hoặc FTPS để mã hóa đường truyền.",
    },
    22: {
        "service": "SSH",
        "risk_level": "Low",
        "note": "Cổng quản trị từ xa an toàn qua SSH.",
        "recommendation": "Tắt xác thực bằng mật khẩu root, sử dụng SSH Key và đổi cổng mặc định nếu cần.",
    },
    23: {
        "service": "Telnet",
        "risk_level": "Critical",
        "note": "Giao thức không mã hóa dữ liệu nhạy cảm và thông tin đăng nhập.",
        "recommendation": "Vô hiệu hóa Telnet ngay lập tức và thay thế hoàn toàn bằng SSH.",
    },
    80: {
        "service": "HTTP",
        "risk_level": "Medium",
        "note": "Dịch vụ Web không mã hóa (HTTP).",
        "recommendation": "Cấu hình chuyển hướng toàn bộ lưu lượng sang HTTPS (cổng 443) với chứng chỉ TLS/SSL.",
    },
    445: {
        "service": "SMB",
        "risk_level": "High",
        "note": "Chia sẻ file Windows SMB, có nguy cơ bị khai thác trong mạng nội bộ nếu không vá lỗi.",
        "recommendation": "Không mở ra Internet, giới hạn truy cập trong subnet quản lý và cập nhật bản vá hệ điều hành.",
    },
    3389: {
        "service": "RDP",
        "risk_level": "Medium",
        "note": "Dịch vụ điều khiển máy tính từ xa Remote Desktop Protocol.",
        "recommendation": "Sử dụng VPN để truy cập, bật Network Level Authentication (NLA) và hạn chế IP truy cập.",
    },
    3306: {
        "service": "MySQL",
        "risk_level": "High",
        "note": "Cơ sở dữ liệu MySQL đang lắng nghe kết nối mạng.",
        "recommendation": "Chỉ lắng nghe trên 127.0.0.1 hoặc giới hạn truy cập từ máy chủ ứng dụng thông qua Firewall.",
    },
}

