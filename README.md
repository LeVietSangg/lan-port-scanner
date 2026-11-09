# XÂY DỰNG CÔNG CỤ QUÉT VÀ PHÂN TÍCH CỔNG MẠNG NHẰM HỖ TRỢ ĐÁNH GIÁ AN TOÀN HỆ THỐNG MẠNG LAN BẰNG PYTHON

Ứng dụng hỗ trợ kiểm tra trạng thái các cổng TCP trên thiết bị mạng LAN được phép kiểm thử, nhận diện các dịch vụ phổ biến và đưa ra phân tích, cảnh báo an toàn cơ bản nhằm hỗ trợ quản trị viên hệ thống.

---

## 1. Cấu trúc thư mục dự án (Project Structure)

Dự án được tổ chức theo mô hình module chuẩn hóa:

```text
lan-port-scanner/
│
├── .venv/                      # Môi trường ảo Python (Virtual Environment)
├── .gitignore                  # Cấu hình bỏ qua các tệp không cần quản lý mã nguồn
├── README.md                   # Tài liệu hướng dẫn cài đặt và sử dụng
├── requirements.txt            # Danh sách các thư viện phụ thuộc
├── main.py                     # Điểm khởi chạy chính của ứng dụng (GUI / CLI)
│
├── src/                        # Mã nguồn ứng dụng
│   ├── __init__.py
│   ├── config.py               # Hằng số, danh mục cổng phổ biến và khuyến nghị an toàn
│   ├── core/                   # Các module xử lý logic cốt lõi
│   │   ├── __init__.py
│   │   ├── validator.py        # Kiểm tra tính hợp lệ của IP, phân giải tên miền, parse cổng
│   │   ├── scanner.py          # Quét cổng TCP Socket (đơn lẻ và đa luồng Threading)
│   │   ├── analyzer.py         # Nhận diện dịch vụ theo số cổng và phân tích cảnh báo an toàn
│   │   └── exporter.py         # Xuất kết quả quét ra file báo cáo CSV
│   └── gui/                    # Giao diện người dùng đồ họa (Tkinter)
│       ├── __init__.py
│       └── app.py              # Ứng dụng Tkinter GUI
│
├── tests/                      # Bộ kiểm thử tự động (Unit Tests)
│   ├── __init__.py
│   ├── test_validator.py       # Kiểm thử xác thực IP và dải cổng
│   ├── test_scanner.py         # Kiểm thử quét socket và phân loại trạng thái
│   ├── test_analyzer.py        # Kiểm thử nhận diện dịch vụ và khuyến nghị an toàn
│   └── test_exporter.py        # Kiểm thử định dạng và xuất file CSV
│
├── reports/                    # Thư mục lưu trữ các báo cáo quét (.csv)
│   └── .gitkeep
└── docs/                       # Tài liệu thiết kế hệ thống và báo cáo chuyên đề
    └── kien_truc_he_thong.md
```

---

## 2. Chuẩn bị môi trường & Cài đặt

### Yêu cầu hệ thống:
- Python 3.8 trở lên (Khuyến nghị Python 3.11+).
- Hệ điều hành: Windows, Linux hoặc macOS.

### Khởi tạo môi trường ảo (Virtual Environment):
```powershell
# Tạo môi trường ảo
python -m venv .venv

# Kích hoạt môi trường ảo trên Windows (PowerShell):
.\.venv\Scripts\Activate.ps1

# Hoặc trên Command Prompt (CMD):
.\.venv\Scripts\activate.bat
```

### Cài đặt thư viện:
Dự án ưu tiên sử dụng các thư viện chuẩn có sẵn trong Python 3 (`socket`, `threading`, `concurrent.futures`, `tkinter`, `csv`, `ipaddress`). Để cài đặt các công cụ phục vụ kiểm thử và phát triển mã nguồn:
```powershell
pip install -r requirements.txt
```

---

## 3. Hướng dẫn sử dụng

### 3.1. Chạy giao diện đồ họa (GUI Tkinter - Mốc 09/11)
```powershell
python main.py
```
**Tính năng giao diện đồ họa:**
- **Thanh menu đầy đủ:** Quản lý tệp, công cụ cấu hình nhanh, hướng dẫn và giới thiệu đề tài.
- **Hệ thống Tab:**
  - Tab 1: **Bảng kết quả quét** với bộ lọc trạng thái và rủi ro, phân loại màu sắc, hiển thị độ trễ RTT, kèm khung chi tiết khuyến nghị an toàn khi chọn từng dòng.
  - Tab 2: **Báo cáo an ninh mạng** đánh giá thế trận an ninh tổng thể (Security Posture Rating), cảnh báo dịch vụ truyền rõ (Cleartext), cơ sở dữ liệu mở, danh sách khuyến nghị an ninh ưu tiên.
  - Tab 3: **Nhật ký hoạt động (Live Logs)** ghi lại chi tiết các sự kiện socket theo thời gian thực.
- **Phím tắt:** `F5` (Quét mới), `Esc` (Dừng quét), `Ctrl+S` (Xuất CSV), `Ctrl+L` (Xóa bảng), `Ctrl+Q` (Thoát).

### 3.2. Chạy ở chế độ dòng lệnh (CLI)
```powershell
# 1. Kiểm tra tính hợp lệ và phân loại IP / Hostname (Chức năng 04/11):
python main.py --check-ip 192.168.1.1
python main.py --interactive-ip

# 2. Quét chi tiết một cổng TCP bằng Socket (Chức năng 05/11):
python main.py -t 127.0.0.1 --single-port 80 --timeout 0.5
python main.py -t 192.168.1.1 --single-port 22 --banner

# 3. Quét tuần tự từng cổng (Sequential Socket Scan):
python main.py --cli -t 127.0.0.1 -p "80,443,8080" --sequential --timeout 0.5

# 4. Lọc hiển thị kết quả theo trạng thái cổng (Chức năng 06/11):
python main.py --cli -t 127.0.0.1 -p "1-1024" --filter-status OPEN
python main.py --cli -t 192.168.1.1 -p "20-100" --filter-status FILTERED

# 5. Lọc hiển thị kết quả theo mức độ rủi ro (Chức năng 08/11):
python main.py --cli -t 192.168.1.1 -p "1-1024" --filter-risk CRITICAL
python main.py --cli -t 192.168.1.1 -p "1-1024" --filter-risk HIGH

# 6. Quét đa luồng và xuất báo cáo CSV:
python main.py --cli -t 127.0.0.1 -p "21,22,80,443,3306,3389" --threads 50 --export

# 7. Đo đạc benchmark đối chiếu hiệu năng quét đa luồng (Chức năng 07/11):
python main.py --benchmark -t 127.0.0.1 -p "1-100" --timeout 0.2
```

### 3.3. Chạy kiểm thử tự động (Unit Tests)
```powershell
python -m unittest discover tests
```

---

## 4. Lịch trình thực hiện đề tài

| Ngày | Nội dung công việc | Trạng thái |
| :--- | :--- | :---: |
| **03/11** | **Tạo project Python, chuẩn bị môi trường và cấu trúc thư mục.** | ✅ **Hoàn thành** |
| **04/11** | **Viết chức năng nhập IP, kiểm tra IP hợp lệ.** | ✅ **Hoàn thành** |
| **05/11** | **Viết chức năng quét cổng TCP bằng Socket.** | ✅ **Hoàn thành** |
| **06/11** | **Phân loại OPEN, CLOSED, FILTERED/UNKNOWN.** | ✅ **Hoàn thành** |
| **07/11** | **Thêm quét đồng thời bằng Threading.** | ✅ **Hoàn thành** |
| **08/11** | **Nhận diện dịch vụ theo số hiệu cổng, cảnh báo cơ bản.** | ✅ **Hoàn thành** |
| **09/11** | **Làm giao diện Tkinter.** | ✅ **Hoàn thành** |
| **10/11** | **Hiển thị kết quả và xuất CSV.** | ✅ **Hoàn thành** |

---

## 5. Lưu ý an toàn & Pháp lý
- Ứng dụng được xây dựng phục vụ mục đích học tập và hỗ trợ quản trị viên kiểm kê dịch vụ mạng nội bộ.
- Chỉ thực hiện quét trên thiết bị thuộc quyền quản lý hoặc đã có sự cho phép bằng văn bản từ người sở hữu hệ thống.
- Nghiêm cấm sử dụng công cụ để thực hiện các hành vi dò quét trái phép trên các hệ thống mạng công cộng hoặc hệ thống của bên thứ ba.

