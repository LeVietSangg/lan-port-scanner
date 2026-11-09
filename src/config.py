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

# Các cấp độ rủi ro an toàn thông tin
RISK_CRITICAL = "Critical"  # Nguy cơ nghiêm trọng (dịch vụ cleartext, mật khẩu truyền rõ, RCE)
RISK_HIGH = "High"          # Nguy cơ cao (CSDL lộ mạng, dịch vụ nhạy cảm không chứng thực mạnh)
RISK_MEDIUM = "Medium"      # Nguy cơ trung bình (dịch vụ quản trị từ xa, HTTP chưa mã hóa)
RISK_LOW = "Low"            # Nguy cơ thấp (dịch vụ đã mã hóa chuẩn TLS/SSH)
RISK_INFO = "Info"          # Thông tin ghi nhận, cần kiểm kê dịch vụ
RISK_NONE = "None"          # Cổng đóng hoặc bị lọc

# Danh mục các cổng dịch vụ phổ biến (Well-known & Common ports chuẩn IANA)
COMMON_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    111: "RPCBind",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP-Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    2049: "NFS",
    2375: "Docker-REST",
    2376: "Docker-TLS",
    3000: "Dev-App (Node/React)",
    3306: "MySQL",
    3389: "RDP",
    5000: "Flask-App",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6379: "Redis",
    8000: "HTTP-Dev",
    8080: "HTTP-Proxy / Tomcat",
    8443: "HTTPS-Alt",
    8888: "Jupyter / HTTP-Alt",
    9000: "PHP-FPM / SonarQube",
    9090: "Prometheus",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

# Cảnh báo an toàn và khuyến nghị chi tiết cho từng cổng/dịch vụ (Mốc 08/11)
SECURITY_RECOMMENDATIONS = {
    21: {
        "service": "FTP",
        "category": "Truyền file",
        "risk_level": RISK_HIGH,
        "is_cleartext": True,
        "note": "FTP truyền tải thông tin đăng nhập và dữ liệu hoàn toàn dưới dạng văn bản rõ (cleartext).",
        "recommendation": "Vô hiệu hóa FTP; chuyển sang SFTP (cổng 22) hoặc FTPS (cổng 990/TLS) để mã hóa đường truyền.",
    },
    22: {
        "service": "SSH",
        "category": "Quản trị từ xa",
        "risk_level": RISK_LOW,
        "is_cleartext": False,
        "note": "Dịch vụ đăng nhập dòng lệnh từ xa có mã hóa an toàn (SSH).",
        "recommendation": "Vô hiệu hóa đăng nhập root trực tiếp, tắt mật khẩu và sử dụng khóa công khai SSH Key.",
    },
    23: {
        "service": "Telnet",
        "category": "Quản trị từ xa",
        "risk_level": RISK_CRITICAL,
        "is_cleartext": True,
        "note": "Giao thức Telnet rất nguy hiểm vì truyền tài khoản và mật khẩu quản trị không mã hóa.",
        "recommendation": "Tắt dịch vụ Telnet ngay lập tức trên mọi thiết bị mạng; thay thế hoàn toàn bằng SSH.",
    },
    25: {
        "service": "SMTP",
        "category": "Thư điện tử",
        "risk_level": RISK_MEDIUM,
        "is_cleartext": True,
        "note": "Dịch vụ chuyển tiếp thư điện tử không mã hóa mặc định, có nguy cơ trở thành Open Relay nếu cấu hình sai.",
        "recommendation": "Bật xác thực STARTTLS, cấu hình SPF/DKIM/DMARC và giới hạn quyền gửi thư trong mạng LAN.",
    },
    53: {
        "service": "DNS",
        "category": "Hạ tầng mạng",
        "risk_level": RISK_LOW,
        "is_cleartext": True,
        "note": "Dịch vụ phân giải tên miền hệ thống mạng.",
        "recommendation": "Kiểm tra quyền đệ quy (Disable Open Recursion) để tránh bị lợi dụng trong tấn công DNS Amplification.",
    },
    69: {
        "service": "TFTP",
        "category": "Truyền file",
        "risk_level": RISK_HIGH,
        "is_cleartext": True,
        "note": "Giao thức truyền file giản đơn không có xác thực tài khoản và không mã hóa.",
        "recommendation": "Chỉ bật tạm thời khi boot thiết bị/cập nhật firmware mạng; tắt ngay sau khi hoàn tất.",
    },
    80: {
        "service": "HTTP",
        "category": "Dịch vụ Web",
        "risk_level": RISK_MEDIUM,
        "is_cleartext": True,
        "note": "Trang Web truyền thông tin không mã hóa, dễ bị nghe lén (Sniffing) và giả mạo (MitM).",
        "recommendation": "Cài đặt chứng chỉ số SSL/TLS và cấu hình chuyển hướng bắt buộc (Redirect HTTP 301 sang HTTPS 443).",
    },
    110: {
        "service": "POP3",
        "category": "Thư điện tử",
        "risk_level": RISK_HIGH,
        "is_cleartext": True,
        "note": "Giao thức nhận thư truyền mật khẩu ở dạng văn bản rõ.",
        "recommendation": "Chuyển sang sử dụng POP3S (cổng 995 với mã hóa SSL/TLS).",
    },
    135: {
        "service": "MSRPC",
        "category": "Hệ thống Windows",
        "risk_level": RISK_MEDIUM,
        "is_cleartext": True,
        "note": "Dịch vụ Microsoft RPC Endpoint Mapper thường bị dùng để thu thập thông tin người dùng trong mạng nội bộ.",
        "recommendation": "Chặn cổng 135 ở tường lửa biên và chỉ cho phép trong phân vùng máy chủ Active Directory nội bộ.",
    },
    139: {
        "service": "NetBIOS-SSN",
        "category": "Chia sẻ mạng",
        "risk_level": RISK_HIGH,
        "is_cleartext": True,
        "note": "Dịch vụ chia sẻ file và máy in đời cũ trên Windows, dễ bị dò quét tên máy tính và user.",
        "recommendation": "Vô hiệu hóa NetBIOS qua giao thức TCP/IP nếu mạng đã sử dụng chuẩn DNS và Active Directory hiện đại.",
    },
    143: {
        "service": "IMAP",
        "category": "Thư điện tử",
        "risk_level": RISK_HIGH,
        "is_cleartext": True,
        "note": "Giao thức đồng bộ hộp thư không mã hóa credentials.",
        "recommendation": "Chuyển sang sử dụng IMAPS (cổng 993) có mã hóa SSL/TLS.",
    },
    161: {
        "service": "SNMP",
        "category": "Quản trị mạng",
        "risk_level": RISK_HIGH,
        "is_cleartext": True,
        "note": "Giao thức quản lý thiết bị mạng SNMPv1/v2c sử dụng chuỗi Community String ở dạng rõ (thường là 'public'/'private').",
        "recommendation": "Nâng cấp lên SNMPv3 hỗ trợ xác thực mã hóa (AuthPriv), đổi chuỗi community mặc định.",
    },
    443: {
        "service": "HTTPS",
        "category": "Dịch vụ Web",
        "risk_level": RISK_LOW,
        "is_cleartext": False,
        "note": "Dịch vụ Web an toàn được mã hóa bằng TLS/SSL.",
        "recommendation": "Đảm bảo sử dụng TLS 1.2/1.3, vô hiệu hóa SSLv3/TLS 1.0/1.1 và định kỳ gia hạn chứng chỉ số.",
    },
    445: {
        "service": "SMB",
        "category": "Chia sẻ mạng",
        "risk_level": RISK_CRITICAL,
        "is_cleartext": False,
        "note": "Dịch vụ chia sẻ tệp Windows SMB. Là mục tiêu hàng đầu của mã độc tống tiền (Ransomware WannaCry qua MS17-010 EternalBlue).",
        "recommendation": "Tuyệt đối không mở ra ngoài Internet; kích hoạt SMB Signing, tắt SMBv1 và cập nhật đầy đủ các bản vá bảo mật Windows.",
    },
    1433: {
        "service": "MSSQL",
        "category": "Cơ sở dữ liệu",
        "risk_level": RISK_HIGH,
        "is_cleartext": False,
        "note": "Cơ sở dữ liệu Microsoft SQL Server đang lắng nghe kết nối mạng.",
        "recommendation": "Không gán IP Public; chỉ cho phép IP của máy chủ ứng dụng kết nối, tắt tài khoản sa mặc định và bật mã hóa TLS.",
    },
    1521: {
        "service": "Oracle DB",
        "category": "Cơ sở dữ liệu",
        "risk_level": RISK_HIGH,
        "is_cleartext": False,
        "note": "Cơ sở dữ liệu Oracle Listener đang mở cổng tiếp nhận kết nối.",
        "recommendation": "Đổi cổng mặc định nếu có thể, đặt mật khẩu mạnh cho Listener và hạn chế truy cập bằng firewall.",
    },
    2049: {
        "service": "NFS",
        "category": "Chia sẻ mạng",
        "risk_level": RISK_HIGH,
        "is_cleartext": True,
        "note": "Hệ thống tệp mạng Network File System (Linux/Unix), dễ bị truy cập trái phép nếu cấu hình IP xuất khẩu lỏng lẻo.",
        "recommendation": "Cấu hình /etc/exports chặt chẽ, sử dụng NFSv4 có xác thực Kerberos.",
    },
    2375: {
        "service": "Docker-REST",
        "category": "Ảo hóa / Container",
        "risk_level": RISK_CRITICAL,
        "is_cleartext": True,
        "note": "Docker Daemon API không xác thực đang mở. Kẻ tấn công có thể chiếm toàn quyền điều khiển máy chủ (Root Host Takeover).",
        "recommendation": "Đóng cổng 2375 ngay lập tức; chỉ sử dụng Unix socket cục bộ hoặc bật Docker TLS mutual auth trên cổng 2376.",
    },
    3306: {
        "service": "MySQL",
        "category": "Cơ sở dữ liệu",
        "risk_level": RISK_HIGH,
        "is_cleartext": False,
        "note": "Hệ quản trị cơ sở dữ liệu MySQL/MariaDB đang lắng nghe cổng mạng.",
        "recommendation": "Thiết lập bind-address = 127.0.0.1 nếu chỉ dùng nội bộ; nếu cần truy cập từ xa, hãy giới hạn Firewall theo IP và tắt quyền truy cập từ xa của user root.",
    },
    3389: {
        "service": "RDP",
        "category": "Quản trị từ xa",
        "risk_level": RISK_HIGH,
        "is_cleartext": False,
        "note": "Dịch vụ điều khiển máy tính từ xa Windows RDP. Thường xuyên bị tấn công dò quét mật khẩu (Brute-force) và khai thác lỗ hổng (BlueKeep).",
        "recommendation": "Bắt buộc kích hoạt Network Level Authentication (NLA), sử dụng VPN khi truy cập từ xa, đặt mật khẩu phức tạp và giới hạn số lần đăng nhập sai.",
    },
    5432: {
        "service": "PostgreSQL",
        "category": "Cơ sở dữ liệu",
        "risk_level": RISK_HIGH,
        "is_cleartext": False,
        "note": "Cơ sở dữ liệu PostgreSQL đang lắng nghe kết nối.",
        "recommendation": "Cấu hình pg_hba.conf chỉ cho phép IP tin cậy, bắt buộc dùng mật khẩu scram-sha-256 và kích hoạt SSL.",
    },
    5900: {
        "service": "VNC",
        "category": "Quản trị từ xa",
        "risk_level": RISK_HIGH,
        "is_cleartext": True,
        "note": "Dịch vụ chia sẻ màn hình VNC thường có xác thực yếu (giới hạn 8 ký tự) và truyền dữ liệu không mã hóa.",
        "recommendation": "Không mở VNC trực tiếp ra mạng; truyền dữ liệu qua SSH Tunnel hoặc VPN.",
    },
    6379: {
        "service": "Redis",
        "category": "Cơ sở dữ liệu In-Memory",
        "risk_level": RISK_CRITICAL,
        "is_cleartext": True,
        "note": "Cơ sở dữ liệu Redis In-Memory mặc định không có mật khẩu. Có thể bị ghi file đè SSH Key để chiếm quyền Root.",
        "recommendation": "Bật tham số requirepass, cấu hình bind 127.0.0.1 và bật chế độ protected-mode yes.",
    },
    8080: {
        "service": "HTTP-Proxy / Alt",
        "category": "Dịch vụ Web",
        "risk_level": RISK_MEDIUM,
        "is_cleartext": True,
        "note": "Cổng thay thế của HTTP thường dùng cho ứng dụng Java (Tomcat, Jenkins) hoặc Proxy.",
        "recommendation": "Kiểm tra bảng điều khiển quản trị (Admin Console), bảo vệ bằng mật khẩu mạnh và đưa về HTTPS.",
    },
    9200: {
        "service": "Elasticsearch",
        "category": "Cơ sở dữ liệu / Search",
        "risk_level": RISK_HIGH,
        "is_cleartext": True,
        "note": "Dịch vụ tìm kiếm dữ liệu Elasticsearch REST API, nếu không bật X-Pack Security thì bất kỳ ai cũng có thể đọc/xóa dữ liệu.",
        "recommendation": "Kích hoạt xác thực người dùng (Elasticsearch Security) và mã hóa TLS kết nối.",
    },
    27017: {
        "service": "MongoDB",
        "category": "Cơ sở dữ liệu NoSQL",
        "risk_level": RISK_CRITICAL,
        "is_cleartext": True,
        "note": "Cơ sở dữ liệu NoSQL MongoDB nếu cấu hình mặc định không bật auth sẽ bị truy cập tự do toàn bộ dữ liệu.",
        "recommendation": "Bật tùy chọn security.authorization: enabled trong mongod.conf và giới hạn IP kết nối.",
    },
}
