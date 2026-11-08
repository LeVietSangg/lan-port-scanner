# TÀI LIỆU KỸ THUẬT: NGUYÊN LÝ QUÉT CỔNG TCP BẰNG SOCKET (MỐC 05/11)

---

## 1. Cơ sở lý thuyết về TCP Connect Scan

### 1.1. Bắt tay 3 bước TCP (TCP 3-Way Handshake)
Giao thức TCP (Transmission Control Protocol) là giao thức hướng kết nối tin cậy thuộc tầng Giao vận (Transport Layer) trong mô hình OSI/TCP-IP. Trước khi truyền tải dữ liệu, hai thiết bị phải thiết lập kết nối thông qua quy trình bắt tay 3 bước:
1. **Bước 1 (SYN):** Máy quét gửi một gói tin có cờ `SYN` (Synchronize) với số thứ tự ngẫu nhiên ban đầu đến cổng đích.
2. **Bước 2 (SYN-ACK hoặc RST):**
   - **Nếu cổng MỞ (OPEN):** Ứng dụng/dịch vụ tại máy đích chấp nhận kết nối và phản hồi bằng gói tin bật cờ `SYN-ACK`.
   - **Nếu cổng ĐÓNG (CLOSED):** Hệ điều hành máy đích không có tiến trình nào lắng nghe tại cổng đó, sẽ gửi lại gói tin `RST` (Reset) để từ chối kết nối.
   - **Nếu cổng BỊ LỌC (FILTERED/UNKNOWN):** Tường lửa (Firewall) hoặc thiết bị mạng chặn và âm thầm hủy gói tin (`DROP`), máy quét không nhận được bất kỳ phản hồi nào trong khoảng thời gian chờ (Timeout).
3. **Bước 3 (ACK):** Khi nhận được `SYN-ACK`, hệ thống máy quét hoàn tất bắt tay bằng gói tin `ACK`, chính thức mở phiên kết nối TCP. Sau đó, socket sẽ gửi gói tin `RST` hoặc `FIN` để đóng kết nối giải phóng tài nguyên.

---

## 2. Triển khai bằng thư viện Socket trong Python

### 2.1. Tại sao sử dụng `socket.connect_ex` thay vì `socket.connect`?
- Hàm `socket.connect((ip, port))` ném ra ngoại lệ (`socket.error` / `OSError`) mỗi khi kết nối thất bại, việc liên tục tạo và xử lý exception khi quét hàng nghìn cổng đóng gây suy giảm hiệu năng.
- Hàm `socket.connect_ex((ip, port))` là lời gọi hàm C cấp thấp của hệ điều hành. Thay vì ném ngoại lệ, hàm trả về mã lỗi số nguyên theo chuẩn POSIX/Winsock:
  - Trả về `0`: Kết nối thành công.
  - Trả về mã lỗi `errno`: Cho biết chính xác lý do thất bại.

### 2.2. Bảng ánh xạ mã lỗi Socket hệ điều hành (POSIX & Winsock)
| Mã lỗi | Tên mã lỗi | Nền tảng | Ý nghĩa kỹ thuật | Trạng thái cổng |
| :---: | :--- | :--- | :--- | :---: |
| **0** | `SUCCESS` | Tất cả | Bắt tay 3 bước thành công | **OPEN** |
| **10061** | `WSAECONNREFUSED` | Windows | Máy đích phản hồi từ chối bằng cờ TCP RST | **CLOSED** |
| **111** | `ECONNREFUSED` | Linux / POSIX | Máy đích phản hồi từ chối bằng cờ TCP RST | **CLOSED** |
| **10060** | `WSAETIMEDOUT` | Windows | Hết thời gian chờ, không có phản hồi (Firewall DROP) | **FILTERED/UNKNOWN** |
| **110** | `ETIMEDOUT` | Linux / POSIX | Hết thời gian chờ, không có phản hồi | **FILTERED/UNKNOWN** |
| **10065** | `WSAEHOSTUNREACH` | Windows | Không có tuyến đường mạng đến máy chủ đích | **FILTERED/UNKNOWN** |
| **10013** | `WSAEACCES` | Windows | Quyền socket bị hạn chế hoặc bị phần mềm an ninh chặn | **FILTERED/UNKNOWN** |

---

## 3. Kiến trúc các hàm quét Socket (`src/core/scanner.py`)

1. **`scan_single_port(target_ip, port, timeout, enable_banner)`**:
   - Khởi tạo socket TCP: `sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)`.
   - Cấu hình thời gian timeout `sock.settimeout(timeout)`.
   - Đo đạc độ trễ phản hồi (Round-Trip Time - RTT) chính xác bằng `time.perf_counter()`.
   - Gọi `sock.connect_ex((target_ip, port))` và phân loại trạng thái.
   - Luôn đảm bảo đóng socket trong khối `finally:` để tránh cạn kiệt socket descriptor của hệ thống.

2. **`grab_banner(target_ip, port, timeout)`**:
   - Khi phát hiện cổng OPEN, gửi yêu cầu đọc dữ liệu đầu tiên (hoặc gửi `HEAD / HTTP/1.0` nếu là dịch vụ Web).
   - Thu thập chuỗi định danh dịch vụ để nâng cao độ chính xác so với việc chỉ đối chiếu số cổng thông thường.

3. **`scan_ports_sequential(target_ip, ports, timeout, progress_callback, enable_banner)`**:
   - Quét tuần tự từng cổng một theo đúng nguyên mẫu đơn luồng cơ bản.
   - Thích hợp để phân tích nguyên lý hoạt động, kiểm tra các thiết bị nhạy cảm hoặc đối chiếu hiệu năng với quét đa luồng (Threading ở mốc 07/11).

---

## 4. Kiểm thử tự động (Unit Tests)
Tại file `tests/test_scanner.py`:
- Sử dụng `unittest.mock` để giả lập các trạng thái phản hồi của tầng socket (`return_value = 0`, `10061`, `10060`, `10013`).
- Kiểm tra tính toàn vẹn của dữ liệu trả về `ScanResult`: `status`, `error_code`, `response_time_ms`, `notes`, `banner`.
- Đảm bảo socket luôn được đóng (`close()`) sau khi hoàn tất kiểm tra.

