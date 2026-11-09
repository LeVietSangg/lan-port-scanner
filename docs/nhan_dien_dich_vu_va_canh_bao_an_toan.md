# TÀI LIỆU KỸ THUẬT: NHẬN DIỆN DỊCH VỤ VÀ PHÂN TÍCH CẢNH BÁO AN TOÀN (MỐC 08/11)
## NGUYÊN LÝ NHẬN DIỆN DỊCH VỤ VÀ MA TRẬN ĐÁNH GIÁ RỦI RO MẠNG LAN

---

## 1. Cơ chế Nhận diện Dịch vụ (Service Identification)

Nhận diện dịch vụ là bước chuyển hóa các con số cổng TCP khô khan thành thông tin ứng dụng có ngữ nghĩa để người quản trị mạng dễ dàng kiểm kê và đánh giá.

### 1.1. Thứ tự ưu tiên nhận diện 3 lớp
1. **Lớp 1 - Cơ sở dữ liệu chuyên biệt (`COMMON_PORTS`):**
   - Định nghĩa trước hơn 50 cổng dịch vụ thiết yếu nhất trong hệ thống mạng doanh nghiệp và LAN (Web, Mail, CSDL, Quản trị từ xa, File Server).
2. **Lớp 2 - Tra cứu danh bạ dịch vụ hệ điều hành (`socket.getservbyport`):**
   - Đối với các số cổng không có trong danh mục riêng, hệ thống tự động gọi hàm chuẩn của OS để ánh xạ tới hàng trăm cổng dịch vụ IANA đã đăng ký (ví dụ: port 631 $\rightarrow$ IPP, port 873 $\rightarrow$ RSYNC).
3. **Lớp 3 - Tinh chỉnh bằng biểu ngữ thực tế (`refine_service_with_banner`):**
   - Khắc phục triệt để nhược điểm "đoán cổng theo số hiệu" bằng cách phân tích chuỗi phản hồi thực tế từ dịch vụ:
     - Bắt phiên bản máy chủ Web từ `Server: nginx/1.24.0`, `Apache/2.4.52`, `Microsoft-IIS/10.0`.
     - Bắt phiên bản SSH từ banner chào: `SSH-2.0-OpenSSH_8.9p1`.
     - Bắt phiên bản FTP server: `220 (vsFTPd 3.0.3)`.

---

## 2. Ma trận Phân tích Rủi ro và Cảnh báo An toàn

Đề tài phân cấp mức độ rủi ro thành 5 bậc chuẩn mực:

| Mức độ rủi ro | Tiêu chí kỹ thuật | Các dịch vụ tiêu biểu | Hành động khuyến nghị |
| :---: | :--- | :--- | :--- |
| **CRITICAL** | Giao thức hoàn toàn không mã hóa truyền tài khoản quản trị; hoặc dịch vụ có nguy cơ thực thi mã từ xa (RCE) / chiếm quyền điều khiển root. | **Telnet (23)**<br>**SMB (445)**<br>**Redis (6379)**<br>**MongoDB (27017)**<br>**Docker REST (2375)** | - Tắt Telnet ngay lập tức, chuyển sang SSH.<br>- Chặn SMB ra ngoài, vá EternalBlue (MS17-010).<br>- Bật `requirepass` và `bind 127.0.0.1` cho Redis.<br>- Bật xác thực người dùng cho MongoDB. |
| **HIGH** | Cơ sở dữ liệu lắng nghe trực tiếp trên card mạng; dịch vụ truyền file không mã hóa credentials. | **FTP (21)**<br>**MySQL (3306)**<br>**PostgreSQL (5432)**<br>**MSSQL (1433)**<br>**VNC (5900)** | - Chuyển sang SFTP/FTPS.<br>- Giới hạn IP truy cập CSDL bằng Firewall.<br>- Vô hiệu hóa truy cập từ xa của tài khoản `root`/`sa`. |
| **MEDIUM** | Dịch vụ Web không mã hóa; cổng quản trị đồ họa từ xa; dịch vụ hệ thống đặc quyền (< 1024). | **HTTP (80)**<br>**RDP (3389)**<br>**SNMP (161)**<br>**HTTP-Alt (8080)** | - Cài chứng chỉ SSL/TLS, bắt buộc chuyển hướng sang HTTPS (443).<br>- Kích hoạt NLA cho RDP, truy cập qua VPN.<br>- Đổi SNMP community string, nâng cấp lên SNMPv3. |
| **LOW** | Dịch vụ đã triển khai mã hóa mạnh mẽ bằng giao thức hiện đại (TLS 1.2/1.3, SSHv2). | **HTTPS (443)**<br>**SSH (22)**<br>**SMTPS (465)**<br>**IMAPS (993)** | - Vô hiệu hóa các cipher suite yếu (SSLv3, TLS 1.0/1.1).<br>- Tắt đăng nhập SSH bằng mật khẩu, dùng SSH Key. |
| **INFO** | Các cổng ứng dụng nội bộ hoặc cổng tùy chỉnh mở, chưa ghi nhận rủi ro an ninh trực tiếp. | Cổng $> 1024$ không có trong danh mục cảnh báo | - Kiểm tra danh tính tiến trình đang lắng nghe.<br>- Giới hạn dải mạng nội bộ được phép kết nối. |

---

## 3. Báo cáo Tổng thể Thế trận An ninh (`get_security_posture_summary`)

Hệ thống tự động chấm điểm và đánh giá thế trận an ninh:
1. **NGUY CƠ CAO (HIGH RISK):** Khi phát hiện ít nhất 1 cổng `CRITICAL` hoặc $\ge 2$ cổng `HIGH`.
2. **CẦN LƯU Ý (MEDIUM RISK):** Khi phát hiện 1 cổng `HIGH` hoặc $\ge 2$ cổng `MEDIUM`.
3. **AN TOÀN CƠ BẢN (ACCEPTABLE):** Tất cả cổng mở đều ở mức `LOW` hoặc `INFO`.
4. **DANH SÁCH BÁO ĐỘNG ĐẶC BIỆT:**
   - Liệt kê riêng các dịch vụ truyền rõ (**Cleartext Services**) dễ bị nghe lén (Sniffing) trong mạng LAN.
   - Liệt kê riêng các cổng Cơ sở dữ liệu (**Databases**) không được phép để lộ ra mạng diện rộng.
   - Trích xuất danh sách các **Khuyến nghị ưu tiên (Priority Recommendations)** để quản trị viên có kế hoạch khắc phục nhanh nhất.

---

## 4. Kiểm thử tự động (Unit Tests)
Tại file `tests/test_analyzer.py` gồm 16 bài kiểm tra:
- Độ chính xác của bảng tra cứu dịch vụ và cơ chế dự phòng `getservbyport`.
- Xử lý regex bóc tách banner SSH, HTTP, FTP.
- Phân tích mức độ rủi ro chính xác cho từng cổng nhạy cảm (Telnet, SMB, Redis, MySQL, HTTP, HTTPS).
- Tính toán đúng tổng kết thế trận an ninh (High Risk, Medium Risk, Acceptable).
- Lọc kết quả quét theo mức độ rủi ro (`filter_results_by_risk`).

