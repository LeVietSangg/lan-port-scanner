# TÀI LIỆU KỸ THUẬT: THIẾT KẾ GIAO DIỆN ĐỒ HỌA TKINTER (MỐC 09/11)
## KIẾN TRÚC GIAO DIỆN ĐA TÁC VỤ VÀ NGUYÊN TẮC THIẾT KẾ CÔNG THÁI HỌC

---

## 1. Mục tiêu và Nguyên tắc Thiết kế Giao diện (GUI Principles)

Theo mục tiêu tổng thể của đề tài, ứng dụng hướng tới đối tượng người học và quản trị viên hệ thống mạng nội bộ. Do đó, giao diện đồ họa bằng **Tkinter** cần đáp ứng các tiêu chuẩn:
1. **Tính trực quan (Intuitiveness):** Các trường nhập liệu mục tiêu, cổng mạng và các nút bấm được bố trí hợp lý theo luồng thao tác tự nhiên từ trên xuống dưới.
2. **Tính phản hồi mượt mà (Responsive UI):** Giao diện không bao giờ bị đơ (Not Responding) trong quá trình quét hàng trăm cổng TCP nhờ kiến trúc tách luồng.
3. **Tính an toàn và cảnh báo chủ động (Safety & Security Warnings):** Cảnh báo an toàn thông tin luôn hiện diện rõ ràng, tích hợp kiểm tra IP mục tiêu và hộp thoại cảnh báo khi quét Public IP.
4. **Phân cấp dữ liệu khoa học (Layered Data Presentation):** Tổ chức dữ liệu theo hệ thống Tabs (Bảng kết quả, Báo cáo an ninh mạng, Nhật ký thời gian thực).

---

## 2. Sơ đồ Cấu trúc Thành phần Giao diện (UI Hierarchy)

```text
+---------------------------------------------------------------------------------+
| Thanh Menu Cấp Cao: Tệp (File) | Công cụ (Tools) | Trợ giúp (Help)               |
+---------------------------------------------------------------------------------+
| ⚠️ Khung Cảnh Báo An Toàn & Điều Khoản Pháp Lý                                  |
+---------------------------------------------------------------------------------+
| Khung Cấu hình:                                                                 |
|   [Mục tiêu IP / Host]  [Nút: Kiểm tra IP]  [Nhãn trạng thái IP: ✅/⚠️/❌]       |
|   [Danh sách cổng]      [Mẫu cổng nhanh: Web, DB, Common...]                    |
|   [Timeout] [Số luồng]  [☑ Lấy Banner]                                          |
|   [▶ Bắt đầu quét (F5)] [⏹ Dừng quét (Esc)] [🗑 Xóa kết quả] [💾 Xuất CSV]       |
+---------------------------------------------------------------------------------+
| Thanh Tiến trình (Progress Bar: 0% -> 100%) & Nhãn tiến độ quét                  |
+---------------------------------------------------------------------------------+
| Hệ Thống Tab (ttk.Notebook):                                                    |
| +-----------------------------------------------------------------------------+ |
| | Tab 1: 📋 Bảng Kết Quả Quét                                                 | |
| |   [Lọc Trạng thái: All/Open/Closed/Filtered] [Lọc Rủi ro: All/Crit/High...] | |
| |   [Huy hiệu: 🟢 Mở: X  |  ⚪ Đóng: Y  |  🟠 Bị lọc: Z  |  🛡️ Firewall Note]  | |
| |   +-----------------------------------------------------------------------+ | |
| |   | Treeview: IP | Cổng | Trạng thái | RTT | Dịch vụ | Rủi ro | Ghi chú...| | |
| |   +-----------------------------------------------------------------------+ | |
| |   Khung chi tiết & Khuyến nghị an toàn khi chọn một dòng                    | |
| +-----------------------------------------------------------------------------+ |
| | Tab 2: 🛡️ Báo Cáo An Ninh Mạng (Thế trận an ninh, CSDL mở, Cleartext, Recs)  | |
| +-----------------------------------------------------------------------------+ |
| | Tab 3: 📜 Nhật Ký Hoạt Động Thời Gian Thực (Timestamped Socket Event Logs)  | |
| +-----------------------------------------------------------------------------+ |
+---------------------------------------------------------------------------------+
| Thanh Trạng thái (Status Bar): Mục tiêu | Tốc độ quét | Thời gian | Số luồng     |
+---------------------------------------------------------------------------------+
```

---

## 3. Kiến trúc Đa luồng Tích hợp Tkinter (Multi-threading in Tkinter)

### 3.1. Vấn đề nghẽn Main Thread
Tkinter hoạt động dựa trên một vòng lặp sự kiện duy nhất (`mainloop`). Nếu các tác vụ quét mạng I/O socket chạy trực tiếp trên luồng chính, cửa sổ ứng dụng sẽ bị đóng băng ngay lập tức, người dùng không thể di chuyển chuột, bấm nút "Dừng quét" hoặc xem thanh tiến trình cập nhật.

### 3.2. Cơ chế giải quyết bằng Background Worker & `root.after()`
- **Tách luồng Worker:** Toàn bộ quá trình quét mạng được thực thi trong một `threading.Thread(target=..., daemon=True)` riêng biệt.
- **Giao tiếp an toàn luồng (Thread-Safe UI Update):** Luồng phụ không được trực tiếp gọi các phương thức sửa đổi widget của Tkinter. Thay vào đó, luồng phụ truyền kết quả thông qua:
  ```python
  self.root.after(0, self._update_row_and_progress, analyzed, completed, total)
  ```
  Hàm `after(0, ...)` đẩy lời gọi hàm vào hàng đợi sự kiện của Main Thread, giúp giao diện vẽ lại từng dòng kết quả tức thời mà không gây crash hay xung đột bộ nhớ.

---

## 4. Hệ thống Phím tắt Tiện ích (Keyboard Shortcuts)
| Phím tắt | Tác vụ |
| :---: | :--- |
| **`F5`** | Bắt đầu quét cổng mới |
| **`Escape`** | Dừng tiến trình quét ngay lập tức |
| **`Ctrl + S`** | Mở hộp thoại xuất báo cáo kết quả quét ra file CSV |
| **`Ctrl + L`** | Xóa sạch dữ liệu bảng kết quả và đặt lại trạng thái |
| **`Ctrl + Q`** | Thoát ứng dụng |

---

## 5. Kiểm thử Giao diện (Unit Testing GUI)
Tại file `tests/test_gui.py` gồm 8 bài kiểm tra:
- Khởi tạo cửa sổ Tkinter không đầu (Headless GUI) an toàn.
- Kiểm thử phản hồi khi đổi mẫu cổng nhanh (Presets).
- Kiểm thử nhãn phản hồi xác thực IP hợp lệ / không hợp lệ.
- Kiểm thử cập nhật dòng dữ liệu và tính toán thống kê số lượng mở/đóng/bị lọc.
- Kiểm thử lọc dữ liệu động trên Treeview.
- Kiểm thử xóa bảng dữ liệu và ghi nhật ký hoạt động.

