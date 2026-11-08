# TÀI LIỆU KỸ THUẬT: PHÂN LOẠI TRẠNG THÁI CỔNG MẠNG (MỐC 06/11)
## OPEN, CLOSED VÀ FILTERED/UNKNOWN TRONG ĐÁNH GIÁ AN TOÀN MẠNG LAN

---

## 1. Cơ sở lý thuyết và Mô hình phân loại trạng thái cổng TCP

Trong các công cụ rà soát và đánh giá an ninh mạng (Network Reconnaissance & Auditing), việc phân loại chính xác trạng thái của từng cổng TCP là cơ sở cốt lõi để người quản trị nhận biết bề mặt tấn công (Attack Surface).

Dự án áp dụng mô hình phân loại 3 trạng thái chuẩn:

```text
                  +--------------------------------+
                  |  Gửi gói tin TCP Connect (SYN) |
                  +--------------------------------+
                                   |
         +-------------------------+-------------------------+
         |                         |                         |
         v                         v                         v
   [Nhận SYN-ACK]             [Nhận RST]            [Timeout / Lỗi ICMP]
         |                         |                         |
         v                         v                         v
   +------------+           +--------------+       +-------------------+
   |    OPEN    |           |    CLOSED    |       | FILTERED / UNKNOWN|
   | (Cổng Mở)  |           | (Cổng Đóng)  |       |   (Cổng Bị Lọc)   |
   +------------+           +--------------+       +-------------------+
```

---

## 2. Ý nghĩa kỹ thuật và An ninh thông tin của từng trạng thái

### 2.1. Trạng thái OPEN (Cổng Mở)
- **Cơ chế mạng:** Socket nhận được gói phản hồi `SYN-ACK` (mã lỗi `0`). Quá trình bắt tay 3 bước hoàn tất thành công.
- **Bản chất hệ thống:** Có một tiến trình hoặc ứng dụng dịch vụ (ví dụ: HTTP Server trên cổng 80, SSH Server trên cổng 22, MySQL trên cổng 3306) đang chủ động lắng nghe (LISTEN) và chấp nhận kết nối trên socket đó.
- **Ý nghĩa an ninh mạng:** 
  - Cổng mở là điểm tiếp nhận dữ liệu từ bên ngoài, do đó đây là bề mặt có thể bị khai thác nếu dịch vụ chứa lỗ hổng bảo mật, cấu hình sai hoặc sử dụng mật khẩu yếu.
  - Quản trị viên cần rà soát: Dịch vụ này có thực sự cần thiết mở trong mạng LAN không? Có áp dụng mã hóa không? Có cần giới hạn IP truy cập không?

### 2.2. Trạng thái CLOSED (Cổng Đóng)
- **Cơ chế mạng:** Máy đích gửi lại gói tin `TCP RST` (Reset) từ chối kết nối (Mã lỗi `10061 WSAECONNREFUSED` trên Windows hoặc `111 ECONNREFUSED` trên Linux/POSIX).
- **Bản chất hệ thống:** Thiết bị máy đích đang hoạt động (Online/Alive) và nhận được gói tin, nhưng ngăn xếp TCP/IP xác định không có tiến trình nào đang lắng nghe trên số hiệu cổng đó.
- **Ý nghĩa an ninh mạng:**
  - Xác nhận máy chủ đích tồn tại và đang hoạt động trong mạng LAN.
  - Cổng hiện tại không có dịch vụ lắng nghe, không phải là bề mặt tấn công trực tiếp ở thời điểm kiểm tra.

### 2.3. Trạng thái FILTERED / UNKNOWN (Cổng Bị Lọc hoặc Không Xác Định)
- **Cơ chế mạng:** Socket không nhận được bất kỳ phản hồi nào trong khoảng thời gian chờ (Timeout - Mã lỗi `10060 WSAETIMEDOUT` / `110 ETIMEDOUT`), hoặc nhận bản tin ICMP Unreachable (Host Unreachable `10065`, Net Unreachable `10051`), hoặc bị chặn bởi quyền bảo mật cục bộ (`10013 WSAEACCES`).
- **Bản chất hệ thống:**
  - Tường lửa phần cứng, tường lửa hệ điều hành (Windows Defender Firewall, Linux iptables/nftables) hoặc bộ lọc mạng đã âm thầm hủy bỏ (`DROP`) gói tin mà không gửi phản hồi RST.
  - Hoặc thiết bị trung gian chặn gói tin và trả về ICMP Type 3 (Destination Unreachable) Code 13 (Communication Administratively Prohibited).
- **Ý nghĩa an ninh mạng:**
  - Tường lửa đang hoạt động hiệu quả để che giấu trạng thái thực của dịch vụ.
  - Quản trị viên cần kiểm tra xem chính sách tường lửa (Firewall Rules) đã áp dụng đúng cho phân vùng mạng nội bộ hay chưa.

---

## 3. Kiến trúc Module Phân loại (`src/core/classifier.py`)

Module `src/core/classifier.py` được thiết kế theo nguyên tắc Single Responsibility Principle (SRP):

1. **`PortClassification` (Dataclass):**
   - Chứa thông tin: `status`, `reason`, `packet_type`, `confidence`, `firewall_suspected`, `description`.

2. **`classify_status(error_code, elapsed_time, timeout)`:**
   - Đánh giá mã phản hồi tầng socket và thời gian kết nối.
   - Trả về đối tượng `PortClassification` với lý do kỹ thuật chi tiết.

3. **`get_classification_stats(results)`:**
   - Tính toán tổng số lượng cổng, số lượng và tỷ lệ % của từng trạng thái `OPEN`, `CLOSED`, `FILTERED/UNKNOWN`.
   - Đưa ra cờ `firewall_detected` báo hiệu sự xuất hiện của tường lửa mạng.

4. **`filter_results_by_status(results, status_filter)`:**
   - Cho phép người dùng lọc nhanh kết quả theo trạng thái mong muốn (`ALL`, `OPEN`, `CLOSED`, `FILTERED`).

---

## 4. Kiểm thử tự động (Unit Tests)
Tại file `tests/test_classifier.py` gồm 12 test cases:
- Kiểm tra tính đúng đắn của việc phân loại cho từng mã lỗi: 0, 10061, ECONNREFUSED, 10060, ETIMEDOUT, 10065, 10051, 10013, None, mã lỗi lạ.
- Kiểm tra tính toán tỷ lệ phần trăm thống kê và cờ phát hiện tường lửa.
- Kiểm tra bộ lọc danh sách kết quả theo trạng thái.

