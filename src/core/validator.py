"""Module kiểm tra, xác thực và phân tích tính hợp lệ của địa chỉ IP, tên miền và danh sách cổng."""

from dataclasses import dataclass, field
import ipaddress
import re
import socket
from typing import Dict, List, Optional, Tuple, Union


# Định nghĩa các phân loại địa chỉ IP
TYPE_LOOPBACK = "Loopback (Máy cục bộ)"
TYPE_PRIVATE_LAN = "Mạng nội bộ LAN (RFC 1918)"
TYPE_LINK_LOCAL = "Link-Local / APIPA (169.254.x.x)"
TYPE_PUBLIC = "Địa chỉ Internet công cộng (Public IP)"
TYPE_MULTICAST = "Địa chỉ Multicast (Dải D)"
TYPE_RESERVED = "Địa chỉ dành riêng / Không xác định"
TYPE_INVALID = "Địa chỉ không hợp lệ"


@dataclass
class IPValidationResult:
    """Đối tượng lưu trữ thông tin phân tích và xác thực của mục tiêu IP/Host."""
    is_valid: bool
    original_input: str
    resolved_ip: Optional[str] = None
    ip_type: str = TYPE_INVALID
    is_lan_or_local: bool = False
    error_message: Optional[str] = None
    warning_message: Optional[str] = None
    details: Dict[str, Union[str, int, bool]] = field(default_factory=dict)


def validate_ipv4_syntax(ip_str: str) -> Tuple[bool, str]:
    """Kiểm tra cú pháp chuỗi IPv4 chi tiết và trả về lý do cụ thể nếu không hợp lệ.

    Args:
        ip_str: Chuỗi biểu diễn IPv4 cần kiểm tra.

    Returns:
        Tuple[bool, str]: (Hợp lệ hay không, Thông báo kết quả hoặc nguyên nhân lỗi).
    """
    cleaned = ip_str.strip()
    if not cleaned:
        return False, "Địa chỉ IP không được để trống."

    octets = cleaned.split(".")
    if len(octets) != 4:
        return False, f"Địa chỉ IPv4 phải có đúng 4 octet phân tách bởi dấu chấm (nhận được {len(octets)} phần)."

    for idx, octet in enumerate(octets, start=1):
        if not octet:
            return False, f"Octet thứ {idx} bị để trống."
        if not octet.isdigit():
            return False, f"Octet thứ {idx} ('{octet}') chứa ký tự không phải chữ số."
        if len(octet) > 1 and octet.startswith("0"):
            return False, f"Octet thứ {idx} ('{octet}') chứa số 0 ở đầu không hợp lệ (leading zero)."
        
        val = int(octet)
        if val < 0 or val > 255:
            return False, f"Giá trị octet thứ {idx} ({val}) vượt quá dải cho phép (0-255)."

    return True, "Cú pháp IPv4 hoàn toàn hợp lệ."


def validate_ip(ip_str: str) -> bool:
    """Kiểm tra nhanh xem chuỗi đầu vào có phải là địa chỉ IPv4 hợp lệ hay không.

    Args:
        ip_str: Chuỗi địa chỉ IP (ví dụ: '192.168.1.1').

    Returns:
        bool: True nếu là IPv4 hợp lệ, False nếu không hợp lệ.
    """
    valid_syntax, _ = validate_ipv4_syntax(ip_str)
    return valid_syntax


# Các dải mạng LAN nội bộ chuẩn RFC 1918
RFC1918_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]


def is_rfc1918_lan(ip_obj: ipaddress.IPv4Address) -> bool:
    """Kiểm tra xem địa chỉ IP có thuộc dải mạng nội bộ LAN RFC 1918 hay không."""
    return any(ip_obj in net for net in RFC1918_NETWORKS)


def classify_ipv4(ip_obj: ipaddress.IPv4Address) -> Tuple[str, bool, Optional[str]]:
    """Phân loại phạm vi địa chỉ IPv4 và đưa ra cảnh báo an toàn tương ứng.

    Args:
        ip_obj: Đối tượng IPv4Address.

    Returns:
        Tuple[str, bool, Optional[str]]: (Loại IP, Có phải LAN/Local hay không, Cảnh báo an toàn nếu có).
    """
    if ip_obj.is_loopback:
        return (
            TYPE_LOOPBACK,
            True,
            "Mục tiêu là máy cục bộ (Loopback). Thích hợp cho mục đích kiểm thử phần mềm an toàn."
        )

    if ip_obj.is_link_local:
        return (
            TYPE_LINK_LOCAL,
            True,
            "Địa chỉ Link-Local (APIPA), thiết bị có thể chưa nhận được cấu hình DHCP."
        )

    if ip_obj.is_multicast:
        return (
            TYPE_MULTICAST,
            False,
            "Địa chỉ Multicast không hỗ trợ quét kết nối TCP đơn kênh (Unicast TCP Connect)."
        )

    if ip_obj.is_reserved or ip_obj.is_unspecified:
        return (
            TYPE_RESERVED,
            False,
            "Địa chỉ dành riêng hoặc chưa xác định (0.0.0.0 / Reserved), không thể quét cổng."
        )

    if is_rfc1918_lan(ip_obj) or ip_obj.is_private:
        return (
            TYPE_PRIVATE_LAN,
            True,
            "Mục tiêu thuộc dải mạng LAN nội bộ (RFC 1918). Đảm bảo bạn có quyền quản trị mạng này."
        )

    # Nếu không thuộc các nhóm trên, đây là Public IP
    return (
        TYPE_PUBLIC,
        False,
        "⚠️ CẢNH BÁO: Đây là địa chỉ IP công cộng (Public Internet IP). "
        "Việc quét các máy chủ công cộng không có sự đồng ý bằng văn bản có thể vi phạm pháp luật!"
    )


def validate_hostname_syntax(hostname: str) -> bool:
    """Kiểm tra cú pháp tên miền/hostname cơ bản theo chuẩn RFC 1123.

    Args:
        hostname: Tên máy chủ (ví dụ: 'router.lan', 'localhost').

    Returns:
        bool: True nếu hợp lệ, False nếu sai định dạng.
    """
    cleaned = hostname.strip()
    if not cleaned or len(cleaned) > 253:
        return False
    # Cho phép chữ cái, chữ số, dấu gạch ngang và dấu chấm
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
    return bool(re.match(pattern, cleaned))


def resolve_host(host_str: str) -> Tuple[bool, str]:
    """Phân giải tên miền hoặc trả về địa chỉ IP nếu đầu vào là IP.

    Args:
        host_str: Tên miền hoặc địa chỉ IP.

    Returns:
        Tuple[bool, str]: (Thành công/Thất bại, Địa chỉ IP phân giải được hoặc thông báo lỗi).
    """
    cleaned_host = host_str.strip()
    if not cleaned_host:
        return False, "Địa chỉ mục tiêu không được để trống."

    if validate_ip(cleaned_host):
        return True, cleaned_host

    if not validate_hostname_syntax(cleaned_host):
        return False, f"Tên máy chủ '{cleaned_host}' không đúng định dạng chuẩn."

    try:
        resolved_ip = socket.gethostbyname(cleaned_host)
        return True, resolved_ip
    except socket.gaierror as e:
        return False, f"Không thể phân giải mục tiêu '{cleaned_host}' qua DNS: {e}"
    except Exception as e:
        return False, f"Lỗi hệ thống khi phân giải '{cleaned_host}': {e}"


def validate_target(target_input: str) -> IPValidationResult:
    """Hàm toàn diện kiểm tra tính hợp lệ, phân giải và phân tích phân loại cho mục tiêu (IP / Hostname).

    Args:
        target_input: Chuỗi địa chỉ IP hoặc hostname do người dùng nhập.

    Returns:
        IPValidationResult: Đối tượng chứa đầy đủ thông tin phân tích mục tiêu.
    """
    cleaned = target_input.strip()
    if not cleaned:
        return IPValidationResult(
            is_valid=False,
            original_input=target_input,
            ip_type=TYPE_INVALID,
            error_message="Vui lòng nhập địa chỉ IP hoặc tên máy chủ (không được để trống)."
        )

    # Trường hợp 1: Người dùng nhập trực tiếp địa chỉ IPv4
    syntax_ok, syntax_msg = validate_ipv4_syntax(cleaned)
    if syntax_ok:
        ip_obj = ipaddress.IPv4Address(cleaned)
        ip_type, is_lan_local, warning_msg = classify_ipv4(ip_obj)

        if ip_type in (TYPE_MULTICAST, TYPE_RESERVED):
            return IPValidationResult(
                is_valid=False,
                original_input=cleaned,
                resolved_ip=cleaned,
                ip_type=ip_type,
                is_lan_or_local=is_lan_local,
                error_message=warning_msg,
                details={
                    "is_loopback": ip_obj.is_loopback,
                    "is_private": ip_obj.is_private,
                    "is_multicast": ip_obj.is_multicast,
                }
            )

        return IPValidationResult(
            is_valid=True,
            original_input=cleaned,
            resolved_ip=cleaned,
            ip_type=ip_type,
            is_lan_or_local=is_lan_local,
            warning_message=warning_msg,
            details={
                "is_loopback": ip_obj.is_loopback,
                "is_private": ip_obj.is_private,
                "is_multicast": ip_obj.is_multicast,
            }
        )

    # Trường hợp 2: Có thể là tên miền / hostname cần phân giải DNS
    resolved_ok, resolved_val = resolve_host(cleaned)
    if not resolved_ok:
        # Nếu cũng không phải tên miền hợp lệ hoặc DNS thất bại, báo lỗi cụ thể
        return IPValidationResult(
            is_valid=False,
            original_input=cleaned,
            ip_type=TYPE_INVALID,
            error_message=f"Định dạng IP không hợp lệ ({syntax_msg}) và {resolved_val}"
        )

    # Phân giải thành công tên miền -> phân tích IP vừa phân giải được
    try:
        ip_obj = ipaddress.IPv4Address(resolved_val)
        ip_type, is_lan_local, warning_msg = classify_ipv4(ip_obj)
        host_warning = f"Tên máy chủ '{cleaned}' được phân giải thành IP {resolved_val}."
        if warning_msg:
            combined_warning = f"{host_warning} {warning_msg}"
        else:
            combined_warning = host_warning

        return IPValidationResult(
            is_valid=True,
            original_input=cleaned,
            resolved_ip=resolved_val,
            ip_type=ip_type,
            is_lan_or_local=is_lan_local,
            warning_message=combined_warning,
            details={
                "hostname": cleaned,
                "resolved_ip": resolved_val,
                "is_loopback": ip_obj.is_loopback,
                "is_private": ip_obj.is_private,
            }
        )
    except Exception as e:
        return IPValidationResult(
            is_valid=False,
            original_input=cleaned,
            resolved_ip=resolved_val,
            ip_type=TYPE_INVALID,
            error_message=f"Lỗi kiểm tra IP phân giải: {str(e)}"
        )


def parse_ports(ports_input: Union[str, List[int]]) -> List[int]:
    """Chuyển đổi chuỗi danh sách cổng (ví dụ: '80, 443, 8000-8080') thành danh sách các số cổng duy nhất đã sắp xếp.

    Args:
        ports_input: Chuỗi biểu diễn cổng hoặc danh sách số nguyên.

    Returns:
        List[int]: Danh sách các cổng hợp lệ (1-65535).
    """
    if isinstance(ports_input, list):
        return sorted(list({p for p in ports_input if 1 <= p <= 65535}))

    ports = set()
    cleaned = ports_input.strip()
    if not cleaned:
        return []

    parts = cleaned.split(",")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            sub_parts = part.split("-")
            if len(sub_parts) == 2:
                try:
                    start_port = int(sub_parts[0].strip())
                    end_port = int(sub_parts[1].strip())
                    if start_port > end_port:
                        start_port, end_port = end_port, start_port
                    for p in range(start_port, end_port + 1):
                        if 1 <= p <= 65535:
                            ports.add(p)
                except ValueError:
                    continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue

    return sorted(list(ports))


def prompt_user_for_ip() -> IPValidationResult:
    """Hàm giao tiếp dòng lệnh tương tác (CLI): Nhắc người dùng nhập IP và kiểm tra hợp lệ tại chỗ.

    Returns:
        IPValidationResult: Kết quả sau khi người dùng nhập thành công IP hợp lệ.
    """
    print("\n" + "=" * 60)
    print(" [CHỨC NĂNG 04/11] NHẬP VÀ XÁC THỰC ĐỊA CHỈ IP MỤC TIÊU")
    print("=" * 60)
    print("(*) Nhập địa chỉ IPv4 (ví dụ: 192.168.1.1, 127.0.0.1) hoặc tên miền (localhost).")
    print("(*) Nhấn 'q' hoặc 'exit' để hủy.\n")

    while True:
        try:
            user_input = input(">> Nhập địa chỉ mục tiêu (IP / Host): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Đã hủy thao tác.")
            return IPValidationResult(is_valid=False, original_input="", error_message="Người dùng hủy.")

        if user_input.lower() in ("q", "exit", "quit"):
            print("[*] Đã thoát khỏi chức năng nhập IP.")
            return IPValidationResult(is_valid=False, original_input=user_input, error_message="Người dùng thoát.")

        result = validate_target(user_input)
        if result.is_valid:
            print(f"\n[+] XÁC THỰC THÀNH CÔNG:")
            print(f"    - Mục tiêu nhập: {result.original_input}")
            print(f"    - Địa chỉ IP   : {result.resolved_ip}")
            print(f"    - Phân loại    : {result.ip_type}")
            print(f"    - Mạng LAN/Local: {'Có' if result.is_lan_or_local else 'Không (Internet Public)'}")
            if result.warning_message:
                print(f"    - Ghi chú/Lưu ý: {result.warning_message}")
            print("-" * 60)
            return result
        else:
            print(f"\n[-] LỖI XÁC THỰC: {result.error_message}")
            print("[?] Vui lòng kiểm tra lại định dạng và thử lại.\n")
