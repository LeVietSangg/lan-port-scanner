"""Module kiểm tra và xử lý hợp lệ cho địa chỉ IP, tên miền và danh sách cổng."""

import ipaddress
import re
import socket
from typing import List, Tuple, Union


def validate_ip(ip_str: str) -> bool:
    """Kiểm tra xem chuỗi đầu vào có phải là địa chỉ IPv4 hợp lệ hay không.

    Args:
        ip_str: Chuỗi địa chỉ IP (ví dụ: '192.168.1.1').

    Returns:
        bool: True nếu là IPv4 hợp lệ, False nếu không hợp lệ.
    """
    try:
        ipaddress.IPv4Address(ip_str.strip())
        return True
    except ValueError:
        return False


def resolve_host(host_str: str) -> Tuple[bool, str]:
    """Phân giải tên miền hoặc kiểm tra IP hợp lệ.

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

    try:
        resolved_ip = socket.gethostbyname(cleaned_host)
        return True, resolved_ip
    except socket.gaierror as e:
        return False, f"Không thể phân giải mục tiêu '{cleaned_host}': {e}"


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

