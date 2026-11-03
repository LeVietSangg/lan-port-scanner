"""Module quét cổng mạng sử dụng Socket và quét đồng thời bằng Threading."""

from dataclasses import dataclass
import errno
import socket
from typing import Callable, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.config import DEFAULT_MAX_THREADS, DEFAULT_TIMEOUT, STATUS_CLOSED, STATUS_FILTERED, STATUS_OPEN


@dataclass
class ScanResult:
    """Đối tượng lưu trữ kết quả quét của một cổng."""
    target_ip: str
    port: int
    status: str
    service: str = "Unknown"
    risk_level: str = "Info"
    notes: str = ""
    recommendation: str = ""


def scan_single_port(target_ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> ScanResult:
    """Thực hiện TCP Connect Scan đến một cổng duy nhất và phân loại trạng thái.

    - OPEN: Kết nối thành công (errno == 0)
    - CLOSED: Kết nối bị từ chối (WSAECONNREFUSED / ECONNREFUSED)
    - FILTERED/UNKNOWN: Hết thời gian chờ (timeout) hoặc lỗi mạng/tường lửa chặn

    Args:
        target_ip: Địa chỉ IP mục tiêu.
        port: Số hiệu cổng cần quét (1-65535).
        timeout: Thời gian chờ phản hồi (giây).

    Returns:
        ScanResult: Kết quả quét cổng.
    """
    status = STATUS_FILTERED
    notes = ""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            status = STATUS_OPEN
            notes = "Cổng phản hồi kết nối TCP thành công"
        elif result in (errno.ECONNREFUSED, 10061):  # 10061 là WSAECONNREFUSED trên Windows
            status = STATUS_CLOSED
            notes = "Máy đích chủ động từ chối kết nối (RST)"
        elif result in (errno.ETIMEDOUT, 10060):  # 10060 là WSAETIMEDOUT trên Windows
            status = STATUS_FILTERED
            notes = "Không nhận được phản hồi trong thời gian chờ (Timeout/Firewall)"
        else:
            status = STATUS_FILTERED
            notes = f"Phản hồi mã lỗi socket: {result}"
    except socket.timeout:
        status = STATUS_FILTERED
        notes = "Hết thời gian chờ (Socket Timeout)"
    except Exception as e:
        status = STATUS_FILTERED
        notes = f"Lỗi kết nối: {str(e)}"
    finally:
        sock.close()

    return ScanResult(
        target_ip=target_ip,
        port=port,
        status=status,
        notes=notes
    )


class PortScanner:
    """Bộ điều phối quét cổng hỗ trợ đa luồng (Threading / ThreadPoolExecutor)."""

    def __init__(self, target: str, ports: List[int], timeout: float = DEFAULT_TIMEOUT, max_threads: int = DEFAULT_MAX_THREADS):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.max_threads = max_threads
        self.is_running = False
        self.results: List[ScanResult] = []

    def scan(self, progress_callback: Optional[Callable[[ScanResult, int, int], None]] = None) -> List[ScanResult]:
        """Bắt đầu quét danh sách cổng bằng đa luồng.

        Args:
            progress_callback: Hàm callback nhận (ScanResult, số cổng đã quét, tổng số cổng).

        Returns:
            List[ScanResult]: Danh sách kết quả quét.
        """
        self.is_running = True
        self.results = []
        total = len(self.ports)
        completed = 0

        with ThreadPoolExecutor(max_workers=min(self.max_threads, max(1, total))) as executor:
            future_to_port = {
                executor.submit(scan_single_port, self.target, port, self.timeout): port
                for port in self.ports
            }

            for future in as_completed(future_to_port):
                if not self.is_running:
                    break
                try:
                    result = future.result()
                    self.results.append(result)
                    completed += 1
                    if progress_callback:
                        progress_callback(result, completed, total)
                except Exception as e:
                    port = future_to_port[future]
                    err_result = ScanResult(
                        target_ip=self.target,
                        port=port,
                        status=STATUS_FILTERED,
                        notes=f"Lỗi thực thi luồng: {str(e)}"
                    )
                    self.results.append(err_result)
                    completed += 1
                    if progress_callback:
                        progress_callback(err_result, completed, total)

        # Sắp xếp kết quả theo thứ tự cổng
        self.results.sort(key=lambda r: r.port)
        self.is_running = False
        return self.results

    def stop(self):
        """Dừng tiến trình quét."""
        self.is_running = False

