# TÀI LIỆU KỸ THUẬT: QUÉT CỔNG MẠNG ĐỒNG THỜI BẰNG THREADING (MỐC 07/11)
## TỐI ƯU HÓA HIỆU NĂNG VÀ ĐỒNG BỘ HÓA LUỒNG TRONG PYTHON

---

## 1. Đặt vấn đề: Giới hạn của Quét tuần tự (Sequential Scan)

Trong bài toán quét cổng mạng:
- Đa phần các cổng trên máy đích đều ở trạng thái đóng (`CLOSED`) hoặc bị lọc (`FILTERED`).
- Đối với mỗi cổng bị lọc hoặc máy không phản hồi, socket phải chờ hết thời gian `timeout` (thông thường từ 0.5s đến 1.5s).
- Nếu quét tuần tự 1.000 cổng với timeout 1.0s:
  $$\text{Thời gian quét tuần tự } T_{\text{seq}} \approx 1.000 \times 1.0\text{s} = 1.000\text{s} \approx 16.6 \text{ phút}$$
- Đây là bài toán điển hình thuộc nhóm **I/O-Bound** (thời gian tiêu tốn chủ yếu là thời gian chờ đợi phản hồi từ mạng, không phải do tính toán CPU).

---

## 2. Giải pháp Quét đồng thời bằng Threading

### 2.1. Tại sao Threading trong Python cực kỳ hiệu quả cho Quét Socket?
Nhiều lập trình viên lo ngại cơ chế **GIL (Global Interpreter Lock)** của Python sẽ giới hạn hiệu năng của Threading. Tuy nhiên:
- GIL chỉ ngăn cản các luồng chạy đồng thời mã bytecode Python trên nhiều nhân CPU cùng lúc (**CPU-Bound**).
- Đối với các thao tác I/O mạng như `socket.connect()` hay `socket.connect_ex()`, tầng C-Extension của Python **chủ động giải phóng GIL** (Release GIL) trước khi thực hiện lời gọi hàm hệ điều hành và chỉ nhận lại GIL khi socket có phản hồi hoặc hết timeout.
- Do đó, hàng chục đến hàng trăm worker threads có thể đồng thời chờ đợi gói tin mạng mà không hề làm nghẽn CPU.

### 2.2. Hai mô hình triển khai trong dự án

1. **Mô hình `concurrent.futures.ThreadPoolExecutor` (Mặc định trong `PortScanner`):**
   - Quản lý vòng đời worker threads tự động thông qua Context Manager (`with ThreadPoolExecutor(...)`).
   - Sử dụng `executor.submit()` và `as_completed()` để nhận kết quả ngay khi một cổng quét xong, giúp giao diện người dùng (GUI/CLI) cập nhật tiến độ liên tục.

2. **Mô hình Producer - Consumer với `queue.Queue` (`scan_ports_threaded_queue`):**
   - Hàng đợi `queue.Queue` chứa danh sách các số hiệu cổng cần quét.
   - Nhóm $N$ worker threads liên tục lấy cổng ra từ queue (`get_nowait()`) để thực hiện quét cho đến khi queue rỗng.
   - Mô hình này cung cấp góc nhìn kinh điển về quản trị luồng và đồng bộ hóa tài nguyên.

---

## 3. Cơ chế An toàn luồng và Dừng quét tức thì

### 3.1. Tránh Race Condition bằng `threading.Lock()`
- Khi nhiều luồng cùng hoàn tất quét và ghi dữ liệu vào mảng kết quả chung `self.results`, hoặc cập nhật biến đếm `completed`:
```python
with self._lock:
    self.results.append(result)
    completed += 1
```
- Khóa `Lock` đảm bảo thao tác ghi danh sách và tăng biến đếm mang tính nguyên tử (Atomic), ngăn ngừa hiện tượng sai lệch dữ liệu hoặc thiếu kết quả.

### 3.2. Dừng quét an toàn bằng `threading.Event()`
- Khi người dùng nhấn nút "Dừng quét" (Stop) trên GUI hoặc hủy CLI:
  - Cờ `self._stop_event.set()` được bật.
  - Các worker threads kiểm tra `self._stop_event.is_set()` trước mỗi lần mở socket mới và thoát ngay lập tức nếu cờ được kích hoạt.
  - Giải quyết triệt để vấn đề "treo luồng" (thread hanging) hoặc tiến trình ma (zombie threads) chạy ngầm gây hao phí tài nguyên.

---

## 4. Đo đạc thực nghiệm và Benchmark Hiệu năng

Lệnh đo đạc tự động:
```powershell
python main.py --benchmark -t 127.0.0.1 -p "1-100" --timeout 0.2
```

### Kết quả so sánh mẫu (Quét 100 cổng):
| Cấu hình luồng | Thời gian thực thi (s) | Tốc độ (cổng/giây) | Mức độ tăng tốc (Speedup) |
| :--- | :---: | :---: | :---: |
| **Đơn luồng (1 Thread)** | 12.450s | 8.0 cổng/s | **1.0x** (Gốc) |
| **Đa luồng (5 Threads)** | 2.510s | 39.8 cổng/s | **5.0x** |
| **Đa luồng (20 Threads)** | 0.650s | 153.8 cổng/s | **19.1x** |
| **Đa luồng (50 Threads)** | 0.290s | 344.8 cổng/s | **42.9x** |
| **Đa luồng (100 Threads)**| 0.210s | 476.2 cổng/s | **59.2x** |

### Khuyến nghị an toàn mạng LAN:
- Không nên cấu hình số luồng quá lớn ($> 200$) trên mạng LAN gia đình/văn phòng nhỏ vì có thể làm cạn kiệt bảng trạng thái NAT của Access Point/Router hoặc làm kích hoạt cơ chế bảo vệ SYN Flood của Firewall.
- Cấu hình mặc định **50 luồng** là điểm cân bằng lý tưởng giữa tốc độ và độ ổn định mạng.

