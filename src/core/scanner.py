"""Module quét cổng mạng sử dụng Socket TCP (TCP Connect Scan)."""

from dataclasses import dataclass, field
import errno
import socket
import time
from typing import Callable, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.config import DEFAULT_MAX_THREADS, DEFAULT_TIMEOUT, STATUS_CLOSED, STATUS_FILTERED, STATUS_OPEN

# Bản đồ giải mã chi tiết các mã lỗi Socket phổ biến (POSIX & Windows Winsock)
SOCKET_ERROR_DESCRIPTIONS: Dict[int, str] = {
    0: "Kết nối TCP thành công (Cổng mở - Nhận SYN-ACK)",
    errno.ECONNREFUSED: "Máy đích từ chối kết nối (Gói tin TCP RST)",
    10061: "Máy đích từ chối kết nối (WSAECONNREFUSED - Nhận RST)",
    errno.ETIMEDOUT: "Hết thời gian chờ phản hồi (ETIMEDOUT)",
    10060: "Không nhận được phản hồi trong thời gian chờ (WSAETIMEDOUT - Tường lửa lọc/DROP)",
    errno.EHOSTUNREACH: "Không thể tiếp cận máy chủ đích (EHOSTUNREACH)",
    10065: "Không thể tiếp cận máy chủ đích (WSAEHOSTUNREACH)",
    errno.ENETUNREACH: "Không thể tiếp cận mạng (ENETUNREACH)",
    10051: "Không thể tiếp cận mạng (WSAENETUNREACH)",
    10013: "Quyền truy cập socket bị hạn chế hoặc bị phần mềm an ninh chặn (WSAEACCES)",
}


@dataclass
class ScanResult:
    """Đối tượng lưu trữ kết quả kiểm tra trạng thái cổng mạng."""
    target_ip: str
    port: int
    status: str
    response_time_ms: float = 0.0
    error_code: Optional[int] = None
    banner: str = ""
    service: str = "Unknown"
    risk_level: str = "Info"
    notes: str = ""
    recommendation: str = ""


def grab_banner(target_ip: str, port: int, timeout: float = 0.5) -> str:
    """Thử thu thập biểu ngữ dịch vụ (Banner Grabbing) cơ bản qua kết nối TCP socket.

    Args:
        target_ip: Địa chỉ IP mục tiêu.
        port: Số hiệu cổng đã xác định là OPEN.
        timeout: Thời gian chờ nhận banner (giây).

    Returns:
        str: Chuỗi biểu ngữ thu thập được, hoặc chuỗi rỗng nếu không nhận được.
    """
    banner = ""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))

        # Đối với các cổng dịch vụ Web, chủ động gửi yêu cầu HEAD ngắn
        if port in (80, 8080, 8000, 8888, 3000, 5000):
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            except Exception:
                pass

        raw_data = sock.recv(512)
        if raw_data:
            # Lọc các ký tự nhị phân và chuẩn hóa về 1 dòng hiển thị gọn
            decoded = raw_data.decode("utf-8", errors="replace").strip()
            first_line = decoded.split("\r\n")[0].split("\n")[0].strip()
            # Cắt ngắn nếu banner quá dài
            banner = first_line[:120]
    except Exception:
        pass
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return banner


def scan_single_port(
    target_ip: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    enable_banner: bool = False
) -> ScanResult:
    """Thực hiện TCP Connect Scan đến một cổng duy nhất bằng thư viện Socket.

    Quy trình:
    1. Tạo socket TCP: socket(AF_INET, SOCK_STREAM).
    2. Cấu hình timeout kết nối.
    3. Gọi connect_ex((target_ip, port)) để thực hiện bắt tay 3 bước TCP (SYN -> SYN-ACK -> ACK).
    4. Đo lường thời gian phản hồi (response_time_ms).
    5. Phân loại trạng thái:
       - OPEN (0): Kết nối thành công.
       - CLOSED (10061/ECONNREFUSED): Máy đích trả về TCP RST.
       - FILTERED/UNKNOWN (10060/ETIMEDOUT hoặc lỗi mạng): Gói tin bị drop hoặc timeout.

    Args:
        target_ip: Địa chỉ IP mục tiêu.
        port: Số hiệu cổng cần quét (1-65535).
        timeout: Thời gian chờ phản hồi (giây).
        enable_banner: Có thực hiện thu thập banner nếu cổng mở hay không.

    Returns:
        ScanResult: Đối tượng kết quả quét chi tiết.
    """
    status = STATUS_FILTERED
    notes = ""
    error_code = None
    response_time_ms = 0.0
    banner = ""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    start_time = time.perf_counter()
    try:
        error_code = sock.connect_ex((target_ip, port))
        end_time = time.perf_counter()
        response_time_ms = round((end_time - start_time) * 1000, 2)

        if error_code == 0:
            status = STATUS_OPEN
            notes = SOCKET_ERROR_DESCRIPTIONS.get(0, "Kết nối TCP thành công")
        elif error_code in (errno.ECONNREFUSED, 10061):
            status = STATUS_CLOSED
            notes = SOCKET_ERROR_DESCRIPTIONS.get(error_code, "Máy đích chủ động từ chối kết nối (RST)")
        elif error_code in (errno.ETIMEDOUT, 10060):
            status = STATUS_FILTERED
            notes = SOCKET_ERROR_DESCRIPTIONS.get(error_code, "Hết thời gian chờ phản hồi (Timeout/Firewall)")
        elif error_code in SOCKET_ERROR_DESCRIPTIONS:
            status = STATUS_FILTERED
            notes = SOCKET_ERROR_DESCRIPTIONS[error_code]
        else:
            status = STATUS_FILTERED
            notes = f"Phản hồi mã lỗi socket hệ thống: {error_code}"
    except socket.timeout:
        end_time = time.perf_counter()
        response_time_ms = round((end_time - start_time) * 1000, 2)
        status = STATUS_FILTERED
        notes = "Hết thời gian chờ (Socket Timeout)"
    except Exception as e:
        end_time = time.perf_counter()
        response_time_ms = round((end_time - start_time) * 1000, 2)
        status = STATUS_FILTERED
        notes = f"Lỗi socket kết nối: {str(e)}"
    finally:
        try:
            sock.close()
        except Exception:
            pass

    # Nếu cổng mở và người dùng kích hoạt nhận diện banner
    if status == STATUS_OPEN and enable_banner:
        banner = grab_banner(target_ip, port, timeout=min(timeout, 1.0))
        if banner:
            notes = f"{notes} | Banner: {banner}"

    return ScanResult(
        target_ip=target_ip,
        port=port,
        status=status,
        response_time_ms=response_time_ms,
        error_code=error_code,
        banner=banner,
        notes=notes
    )


def scan_ports_sequential(
    target_ip: str,
    ports: List[int],
    timeout: float = DEFAULT_TIMEOUT,
    progress_callback: Optional[Callable[[ScanResult, int, int], None]] = None,
    enable_banner: bool = False
) -> List[ScanResult]:
    """Quét tuần tự từng cổng bằng Socket đơn luồng (Chức năng nền tảng ngày 05/11).

    Args:
        target_ip: Địa chỉ IP mục tiêu.
        ports: Danh sách số hiệu cổng cần quét.
        timeout: Thời gian chờ phản hồi cho từng cổng.
        progress_callback: Hàm callback nhận (ScanResult, số cổng hoàn thành, tổng số).
        enable_banner: Bật/tắt thu thập banner.

    Returns:
        List[ScanResult]: Danh sách kết quả quét đã sắp xếp theo thứ tự cổng.
    """
    results: List[ScanResult] = []
    total = len(ports)

    for idx, port in enumerate(ports, start=1):
        res = scan_single_port(target_ip, port, timeout=timeout, enable_banner=enable_banner)
        results.append(res)
        if progress_callback:
            progress_callback(res, idx, total)

    results.sort(key=lambda r: r.port)
    return results


class PortScanner:
    """Bộ điều phối quét cổng hỗ trợ cả đơn luồng và đa luồng (ThreadPoolExecutor)."""

    def __init__(
        self,
        target: str,
        ports: List[int],
        timeout: float = DEFAULT_TIMEOUT,
        max_threads: int = DEFAULT_MAX_THREADS,
        enable_banner: bool = False
    ):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.max_threads = max_threads
        self.enable_banner = enable_banner
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

        # Nếu chỉ có 1 cổng hoặc số luồng là 1, dùng quét tuần tự
        if len(self.ports) == 1 or self.max_threads <= 1:
            self.results = scan_ports_sequential(
                self.target,
                self.ports,
                timeout=self.timeout,
                progress_callback=progress_callback,
                enable_banner=self.enable_banner
            )
            self.is_running = False
            return self.results

        with ThreadPoolExecutor(max_workers=min(self.max_threads, max(1, total))) as executor:
            future_to_port = {
                executor.submit(
                    scan_single_port,
                    self.target,
                    port,
                    self.timeout,
                    self.enable_banner
                ): port
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
