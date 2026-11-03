# TÀI LIỆU KIẾN TRÚC VÀ THIẾT KẾ HỆ THỐNG
## CÔNG CỤ QUÉT VÀ PHÂN TÍCH CỔNG MẠNG LAN

---

### 1. Sơ đồ phân tầng kiến trúc (Layered Architecture)

Hệ thống được thiết kế theo kiến trúc phân tầng (Layered Architecture) nhằm tách biệt logic xử lý mạng, nghiệp vụ phân tích và giao diện hiển thị:

```text
+-----------------------------------------------------------+
|               TẦNG GIAO DIỆN (PRESENTATION)               |
|      Tkinter GUI (src/gui/app.py)  /  CLI (main.py)       |
+-----------------------------------------------------------+
                             |
                             v
+-----------------------------------------------------------+
|              TẦNG ĐIỀU PHỐI VÀ NGHIỆP VỤ (CORE)           |
|                                                           |
|  [Validator]  ->  [PortScanner]  ->  [Analyzer]  -> [CSV] |
|   Kiểm tra IP      Socket & Luồng     Dịch vụ &      Xuất |
|   & parse port     TCP Connect Scan   Cảnh báo       file |
+-----------------------------------------------------------+
                             |
                             v
+-----------------------------------------------------------+
|             TẦNG HẠ TẦNG & HỆ THỐNG MẠNG (OS / NETWORK)   |
|   Python Socket (AF_INET, SOCK_STREAM) | TCP/IP Stack     |
+-----------------------------------------------------------+
```

---

### 2. Chi tiết các thành phần chính

1. **`src.config`**:
   - Quản lý cấu hình toàn cục: thời gian timeout mặc định, giới hạn số luồng (ThreadPool), định nghĩa các hằng số trạng thái cổng (`OPEN`, `CLOSED`, `FILTERED/UNKNOWN`).
   - Bảng tra cứu các cổng dịch vụ chuẩn và danh sách khuyến nghị an toàn.

2. **`src.core.validator`**:
   - Sử dụng thư viện `ipaddress` và `socket.gethostbyname` để xác thực địa chỉ IPv4, kiểm tra định dạng tên miền.
   - Chuyển đổi định dạng dải cổng (ví dụ: `80, 443, 8000-8080`) thành mảng số nguyên duy nhất từ `1` đến `65535`.

3. **`src.core.scanner`**:
   - Thực hiện kỹ thuật **TCP Connect Scan** (`socket.connect_ex`).
   - Phân loại trạng thái:
     - `OPEN`: Kết nối thành công (`result == 0`).
     - `CLOSED`: Máy chủ từ chối kết nối (`ECONNREFUSED` / `WSAECONNREFUSED 10061`).
     - `FILTERED/UNKNOWN`: Hết thời gian chờ (`ETIMEDOUT` / `WSAETIMEDOUT 10060`) hoặc gói tin bị firewall thả (drop).
   - Đa luồng: Tận dụng `concurrent.futures.ThreadPoolExecutor` để quét đồng thời nhiều cổng, hỗ trợ hàm gọi lại (callback) cập nhật tiến độ theo thời gian thực.

4. **`src.core.analyzer`**:
   - Đối chiếu số hiệu cổng với bảng dịch vụ thông dụng (`COMMON_PORTS`).
   - Gán mức độ rủi ro (`High`, `Medium`, `Low`, `Info`) và đưa ra khuyến nghị an toàn mạng (ví dụ: tắt Telnet, dùng HTTPS/SFTP thay vì HTTP/FTP, bảo vệ cổng cơ sở dữ liệu và RDP).

5. **`src.core.exporter`**:
   - Xuất dữ liệu sang định dạng CSV có UTF-8 with BOM (`utf-8-sig`) để hiển thị chính xác tiếng Việt trong Microsoft Excel.

6. **`src.gui.app`**:
   - Giao diện thân thiện dựa trên `Tkinter` và `ttk.Treeview`.
   - Có thanh tiến trình (Progress Bar), gắn màu sắc trạng thái (Xanh lá: OPEN, Xám: CLOSED, Cam: FILTERED).
   - Tích hợp cảnh báo pháp lý và lưu ý an toàn ngay trên đầu ứng dụng.

---

### 3. Nguyên tắc an toàn
- Giới hạn quét tại một thời điểm cho một máy đích.
- Tốc độ quét được điều tiết thông qua số lượng Worker Thread có thể cấu hình để tránh làm nghẽn băng thông hệ thống mạng nội bộ.
- Nhắc nhở người dùng chỉ kiểm thử trên các thiết bị được cấp phép.

