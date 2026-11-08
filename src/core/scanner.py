"""Module quét cổng mạng sử dụng Socket TCP (TCP Connect Scan)."""

from dataclasses import dataclass, field
import errno
import queue
import socket
import threading
import time
from typing import Callable, Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.config import DEFAULT_MAX_THREADS, DEFAULT_TIMEOUT, STATUS_CLOSED, STATUS_FILTERED, STATUS_OPEN
from src.core.classifier import classify_status, PortClassification

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
    classification: Optional[PortClassification] = None


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
    exception_caught = None
    try:
        error_code = sock.connect_ex((target_ip, port))
        end_time = time.perf_counter()
        response_time_ms = round((end_time - start_time) * 1000, 2)
    except socket.timeout:
        end_time = time.perf_counter()
        response_time_ms = round((end_time - start_time) * 1000, 2)
        error_code = getattr(errno, "ETIMEDOUT", 10060)
    except Exception as e:
        end_time = time.perf_counter()
        response_time_ms = round((end_time - start_time) * 1000, 2)
        exception_caught = str(e)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    # Áp dụng bộ phân loại trạng thái chuyên biệt (Chức năng ngày 06/11)
    classification = classify_status(
        error_code=error_code,
        elapsed_time=response_time_ms / 1000.0,
        timeout=timeout
    )
    status = classification.status
    notes = classification.reason

    if exception_caught:
        notes = f"Lỗi ngoại lệ socket: {exception_caught}"
        classification.reason = notes

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
        notes=notes,
        classification=classification
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


def scan_ports_threaded_queue(
    target_ip: str,
    ports: List[int],
    timeout: float = DEFAULT_TIMEOUT,
    max_threads: int = DEFAULT_MAX_THREADS,
    progress_callback: Optional[Callable[[ScanResult, int, int], None]] = None,
    enable_banner: bool = False,
    stop_event: Optional[threading.Event] = None
) -> List[ScanResult]:
    """Quét đồng thời bằng mô hình Threading kết hợp Queue (Producer - Consumer Pattern).

    Args:
        target_ip: Địa chỉ IP mục tiêu.
        ports: Danh sách số hiệu cổng cần quét.
        timeout: Thời gian chờ phản hồi cho từng cổng.
        max_threads: Số lượng worker thread chạy đồng thời tối đa.
        progress_callback: Hàm callback nhận (ScanResult, số cổng hoàn thành, tổng số).
        enable_banner: Bật/tắt thu thập banner.
        stop_event: Đối tượng threading.Event để nhận diện tín hiệu hủy quét.

    Returns:
        List[ScanResult]: Danh sách kết quả quét đã sắp xếp theo thứ tự cổng.
    """
    results: List[ScanResult] = []
    total = len(ports)
    completed_count = 0
    lock = threading.Lock()
    port_queue: queue.Queue = queue.Queue()

    for p in ports:
        port_queue.put(p)

    def worker():
        nonlocal completed_count
        while not port_queue.empty():
            if stop_event and stop_event.is_set():
                break
            try:
                port = port_queue.get_nowait()
            except queue.Empty:
                break

            if stop_event and stop_event.is_set():
                port_queue.task_done()
                break

            result = scan_single_port(target_ip, port, timeout=timeout, enable_banner=enable_banner)

            with lock:
                results.append(result)
                completed_count += 1
                current_completed = completed_count

            if progress_callback:
                progress_callback(result, current_completed, total)

            port_queue.task_done()

    threads: List[threading.Thread] = []
    num_workers = min(max_threads, max(1, total))

    for _ in range(num_workers):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

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
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self.results: List[ScanResult] = []
        self.scan_duration_sec: float = 0.0
        self.scan_rate: float = 0.0

    def scan(self, progress_callback: Optional[Callable[[ScanResult, int, int], None]] = None) -> List[ScanResult]:
        """Bắt đầu quét danh sách cổng bằng đa luồng ThreadPoolExecutor.

        Args:
            progress_callback: Hàm callback nhận (ScanResult, số cổng đã quét, tổng số cổng).

        Returns:
            List[ScanResult]: Danh sách kết quả quét.
        """
        self.is_running = True
        self._stop_event.clear()
        self.results = []
        total = len(self.ports)
        completed = 0

        t_start = time.perf_counter()

        # Nếu chỉ có 1 cổng hoặc cấu hình 1 luồng, dùng quét tuần tự
        if len(self.ports) == 1 or self.max_threads <= 1:
            self.results = scan_ports_sequential(
                self.target,
                self.ports,
                timeout=self.timeout,
                progress_callback=progress_callback,
                enable_banner=self.enable_banner
            )
            t_end = time.perf_counter()
            self.scan_duration_sec = round(t_end - t_start, 3)
            self.scan_rate = round(len(self.results) / max(0.001, self.scan_duration_sec), 1)
            self.is_running = False
            return self.results

        worker_count = min(self.max_threads, max(1, total))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
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
                if self._stop_event.is_set():
                    break
                try:
                    result = future.result()
                    with self._lock:
                        self.results.append(result)
                        completed += 1
                        current_comp = completed

                    if progress_callback:
                        progress_callback(result, current_comp, total)
                except Exception as e:
                    port = future_to_port[future]
                    err_result = ScanResult(
                        target_ip=self.target,
                        port=port,
                        status=STATUS_FILTERED,
                        notes=f"Lỗi thực thi luồng: {str(e)}"
                    )
                    with self._lock:
                        self.results.append(err_result)
                        completed += 1
                        current_comp = completed

                    if progress_callback:
                        progress_callback(err_result, current_comp, total)

        t_end = time.perf_counter()
        self.scan_duration_sec = round(t_end - t_start, 3)
        self.scan_rate = round(len(self.results) / max(0.001, self.scan_duration_sec), 1)

        # Sắp xếp kết quả theo thứ tự cổng
        self.results.sort(key=lambda r: r.port)
        self.is_running = False
        return self.results

    def stop(self):
        """Dừng tiến trình quét ngay lập tức bằng threading.Event."""
        self.is_running = False
        self._stop_event.set()


def benchmark_scan(
    target_ip: str,
    ports: List[int],
    thread_counts: Optional[List[int]] = None,
    timeout: float = 0.5
) -> List[Dict[str, Any]]:
    """Đo đạc và đối chiếu hiệu năng quét giữa đơn luồng và các mức đa luồng khác nhau (Mốc 07/11).

    Args:
        target_ip: Địa chỉ IP mục tiêu.
        ports: Danh sách cổng phục vụ đo đạc.
        thread_counts: Danh sách số lượng luồng cần thử nghiệm (Mặc định: [1, 5, 20, 50]).
        timeout: Thời gian timeout cho mỗi cổng.

    Returns:
        List[Dict[str, Any]]: Danh sách thống kê thời gian và tốc độ cho từng cấu hình luồng.
    """
    if thread_counts is None:
        thread_counts = [1, 5, 20, 50]

    benchmark_records = []
    total_ports = len(ports)

    for threads in thread_counts:
        scanner = PortScanner(target=target_ip, ports=ports, timeout=timeout, max_threads=threads)
        start_time = time.perf_counter()
        results = scanner.scan()
        duration = time.perf_counter() - start_time
        rate = total_ports / max(0.001, duration)

        benchmark_records.append({
            "threads": threads,
            "mode": "Đơn luồng (Sequential)" if threads == 1 else f"Đa luồng ({threads} threads)",
            "total_ports": total_ports,
            "duration_sec": round(duration, 3),
            "rate_ports_per_sec": round(rate, 1),
            "open_count": sum(1 for r in results if r.status == STATUS_OPEN)
        })

    return benchmark_records
