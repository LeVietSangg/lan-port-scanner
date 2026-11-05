# TÀI LIỆU KỸ THUẬT: CHỨC NĂNG NHẬP VÀ KIỂM TRA ĐỊA CHỈ IP HỢP LỆ (MỐC 04/11)

---

## 1. Mục tiêu và Ý nghĩa nghiệp vụ
Trong bài toán **"Xây dựng công cụ quét và phân tích cổng mạng nhằm hỗ trợ đánh giá an toàn hệ thống mạng LAN"**, việc nhập và xác thực địa chỉ IP mục tiêu là bước kiểm soát đầu vào tối quan trọng:
1. **Đảm bảo tính toàn vẹn kỹ thuật:** Ngăn chặn các lỗi cú pháp (chữ cái, số âm, số vượt quá 255, thiếu/thừa octet, leading zeros) trước khi truyền vào thư viện tầng socket, tránh gây ra Exception không mong muốn.
2. **Tuân thủ an toàn thông tin và pháp lý:** Đề tài tập trung vào phạm vi mạng nội bộ (LAN). Hệ thống cần nhận diện và phân loại rõ ràng các dải địa chỉ IP (Loopback, Mạng nội bộ RFC 1918, APIPA Link-Local, Public Internet, Multicast, Reserved). Nếu người dùng quét một Public IP trên Internet, ứng dụng sẽ đưa ra cảnh báo pháp lý và yêu cầu xác nhận rõ ràng.
3. **Hỗ trợ phân giải tên miền (DNS Hostname Resolution):** Cho phép người dùng nhập hostname như `localhost`, `router.local` hoặc tên máy chủ nội bộ và tự động phân giải sang IPv4 tương ứng.

---

## 2. Tiêu chuẩn xác thực IPv4 và Phân loại

### 2.1. Cú pháp IPv4 (IPv4 Syntax Standard)
Một chuỗi IPv4 hợp lệ tuân thủ:
- Gồm đúng **4 octets**, ngăn cách bởi dấu chấm `.` (Dotted-decimal notation).
- Mỗi octet chỉ chứa các ký tự chữ số `0-9`.
- Giá trị mỗi octet nằm trong khoảng số nguyên: `[0, 255]`.
- **Không chứa leading zero** (ví dụ: `01.02.03.04` là không hợp lệ để tránh nhầm lẫn sang hệ bát phân octal trong một số hệ điều hành).

### 2.2. Phân loại không gian địa chỉ IPv4
| Phân loại | Dải địa chỉ mạng | Đặc điểm trong hệ thống |
| :--- | :--- | :--- |
| **Loopback** | `127.0.0.0/8` | Máy cục bộ (localhost), an toàn tuyệt đối cho thử nghiệm. |
| **Mạng LAN nội bộ (RFC 1918)** | `10.0.0.0/8`<br>`172.16.0.0/12`<br>`192.168.0.0/16` | Đối tượng trọng tâm của đề tài. Thích hợp quét trong mạng nội bộ thuộc quyền quản lý. |
| **Link-Local / APIPA** | `169.254.0.0/16` | Địa chỉ tự động cấp phát khi DHCP không phản hồi. |
| **Multicast** | `224.0.0.0/4` | Địa chỉ phát đa hướng. Hệ thống sẽ từ chối quét vì TCP Connect chỉ dùng unicast. |
| **Reserved / Unspecified** | `0.0.0.0`, `240.0.0.0/4` | Địa chỉ dành riêng hoặc chưa gán, không hợp lệ để quét cổng. |
| **Public IP** | Còn lại trên Internet | Địa chỉ công cộng. Hệ thống hiển thị cảnh báo an toàn và pháp lý. |

---

## 3. Kiến trúc Code & Các hàm chính (`src/core/validator.py`)

1. **`validate_ipv4_syntax(ip_str: str) -> Tuple[bool, str]`**:
   - Kiểm tra định dạng chuỗi và trả về nguyên nhân lỗi chi tiết (nếu có) bằng tiếng Việt.
2. **`classify_ipv4(ip_obj: ipaddress.IPv4Address) -> Tuple[str, bool, Optional[str]]`**:
   - Sử dụng thư viện chuẩn `ipaddress` kết hợp danh sách mạng RFC 1918 để phân loại chính xác bản chất mạng.
3. **`validate_hostname_syntax(hostname: str) -> bool`**:
   - Kiểm tra định dạng tên máy chủ theo chuẩn RFC 1123.
4. **`resolve_host(host_str: str) -> Tuple[bool, str]`**:
   - Phân giải DNS an toàn với `socket.gethostbyname`, bắt lỗi ngoại lệ `socket.gaierror`.
5. **`validate_target(target_input: str) -> IPValidationResult`**:
   - Hàm cấp cao (Facade) kiểm tra toàn diện, trả về đối tượng `IPValidationResult` gồm: `is_valid`, `resolved_ip`, `ip_type`, `is_lan_or_local`, `warning_message`, `error_message`.
6. **`prompt_user_for_ip() -> IPValidationResult`**:
   - Chế độ dòng lệnh tương tác giúp người dùng nhập và kiểm tra IP trực tiếp.

---

## 4. Kiểm thử tự động (Unit Tests)
Toàn bộ 25 bài kiểm tra trong file `tests/test_validator.py` đã bao phủ:
- Các trường hợp IP hợp lệ (Class A, B, C, Loopback, Broadcast, Public).
- Các trường hợp lỗi: thiếu/thừa octet, ký tự đặc biệt, octet > 255, leading zero.
- Phân loại mạng: Private LAN, Public, Link-Local, Loopback.
- Phân giải tên miền: `localhost`, hostname hợp lệ, hostname sai quy cách.
- Phân tích danh sách và dải cổng: lọc cổng hợp lệ từ 1 đến 65535.

