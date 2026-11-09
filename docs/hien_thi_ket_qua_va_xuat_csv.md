# Chương 3.5: Hiển Thị Kết Quả Và Xuất Báo Cáo (Mốc 10/11)

## 1. Tổng quan chức năng

Module `exporter.py` đảm nhận việc xuất kết quả quét cổng mạng ra các định dạng file báo cáo phục vụ lưu trữ, phân tích và đối chiếu. Đây là bước cuối cùng trong quy trình quét, cho phép quản trị viên:

- **Lưu trữ dài hạn** kết quả quét dưới dạng file CSV (mở được trong Microsoft Excel) hoặc TXT (văn bản thuần túy).
- **Đối chiếu và so sánh** kết quả giữa các lần quét khác nhau.
- **Chia sẻ báo cáo** với đội ngũ an ninh mạng hoặc ban quản lý.

### 1.1. Kiến trúc module xuất báo cáo

```
src/core/exporter.py
├── _build_scan_metadata()        # Tổng hợp siêu dữ liệu phiên quét
├── _compute_summary_stats()      # Tính toán thống kê tổng hợp
├── export_to_csv()               # Xuất báo cáo CSV chuẩn UTF-8 BOM
├── export_to_txt()               # Xuất báo cáo văn bản thuần túy
└── generate_console_report()     # Sinh nội dung báo cáo dạng văn bản
```

## 2. Định dạng CSV (Comma-Separated Values)

### 2.1. Cấu trúc file CSV

File CSV gồm 3 phần logic:

```
┌─────────────────────────────────────────────┐
│  PHẦN 1: HEADER METADATA                    │
│  - Tiêu đề báo cáo                         │
│  - Thời gian xuất, Mục tiêu (IP)           │
│  - Số cổng, Phạm vi, Thời gian quét        │
│  - Số luồng sử dụng                        │
├─────────────────────────────────────────────┤
│  PHẦN 2: BẢNG DỮ LIỆU (10 CỘT)           │
│  Mục tiêu (IP) | Cổng | Trạng thái | ...   │
│  192.168.1.1    | 80   | OPEN       | ...   │
│  192.168.1.1    | 443  | CLOSED     | ...   │
├─────────────────────────────────────────────┤
│  PHẦN 3: SUMMARY FOOTER                     │
│  - Thống kê tổng hợp (OPEN/CLOSED/FILTERED)│
│  - Phân bố mức rủi ro                      │
└─────────────────────────────────────────────┘
```

### 2.2. Danh sách 10 cột dữ liệu CSV

| STT | Tên cột | Kiểu dữ liệu | Mô tả |
|-----|---------|---------------|-------|
| 1 | Mục tiêu (IP) | Chuỗi | Địa chỉ IP mục tiêu đã quét |
| 2 | Cổng (Port) | Số nguyên | Số hiệu cổng TCP (1-65535) |
| 3 | Trạng thái | Chuỗi | OPEN, CLOSED, hoặc FILTERED/UNKNOWN |
| 4 | Độ trễ phản hồi (ms) | Số thực | Thời gian phản hồi TCP Round-Trip Time |
| 5 | Dịch vụ dự đoán | Chuỗi | Tên dịch vụ nhận diện (HTTP, SSH, FTP...) |
| 6 | Mức độ rủi ro | Chuỗi | Critical, High, Medium, Low, Info, None |
| 7 | Banner | Chuỗi | Biểu ngữ dịch vụ thu thập được (nếu có) |
| 8 | Mã lỗi Socket | Số nguyên | Mã lỗi hệ điều hành (0, 10061, 10060...) |
| 9 | Ghi chú kỹ thuật | Chuỗi | Diễn giải chi tiết phản hồi socket |
| 10 | Khuyến nghị an toàn | Chuỗi | Đề xuất khắc phục rủi ro bảo mật |

### 2.3. Mã hóa ký tự

File CSV được mã hóa theo chuẩn **UTF-8 với BOM** (Byte Order Mark - 3 byte `EF BB BF` ở đầu file). Lý do:

- Microsoft Excel trên Windows mặc định đọc file CSV theo mã hóa ANSI (Windows-1252).
- Nếu không có BOM, các ký tự tiếng Việt (Unicode) sẽ bị hiển thị sai (mojibake).
- BOM giúp Excel tự động nhận diện và chuyển sang chế độ đọc UTF-8.

```python
with open(file_path, mode="w", newline="", encoding="utf-8-sig") as csvfile:
    # utf-8-sig = UTF-8 + BOM (Byte Order Mark)
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
```

## 3. Định dạng TXT (Plain Text Report)

### 3.1. Cấu trúc báo cáo văn bản

Báo cáo TXT được thiết kế để đọc trực tiếp trên terminal/console hoặc in ra giấy, gồm 5 phần:

1. **Tiêu đề** - Tên ứng dụng và loại báo cáo
2. **Thông tin phiên quét** - Mục tiêu, thời gian, cấu hình
3. **Bảng kết quả** - Bảng ASCII với 6 cột chính
4. **Thống kê tổng hợp** - Số liệu phân loại trạng thái và rủi ro
5. **Đánh giá an ninh** - Security Posture Rating, cảnh báo và khuyến nghị

### 3.2. Ví dụ báo cáo TXT

```
================================================================================
  BÁO CÁO QUÉT VÀ PHÂN TÍCH CỔNG MẠNG LAN
  LAN Port Scanner & Security Analyzer Report
================================================================================

  THÔNG TIN PHIÊN QUÉT:
--------------------------------------------------------------------------------
  Thời gian xuất báo cáo        : 2024-11-10 14:30:00
  Mục tiêu (IP)                 : 192.168.1.1
  Tổng số cổng đã quét          : 9
  Phạm vi cổng                  : 21-8080
  Thời gian quét (giây)         : 2.345
  Số luồng sử dụng              : 50

================================================================================
  BẢNG KẾT QUẢ QUÉT CHI TIẾT
================================================================================
  CỔNG    TRẠNG THÁI        ĐỘ TRỄ    DỊCH VỤ               RỦI RO      GHI CHÚ
  --------------------------------------------------------------------------------------
  22      OPEN              5.2ms     SSH                    Low         Kết nối thành công
  80      OPEN              3.1ms     HTTP                   Medium      Phản hồi HTTP
  443     CLOSED            -         HTTPS                  None        TCP RST
  3306    OPEN              8.5ms     MySQL                  High        CSDL mở cổng

================================================================================
  THỐNG KÊ TỔNG HỢP
================================================================================
  Tổng số cổng đã quét       : 9
  Cổng MỞ (OPEN)             : 3 (33.3%)
  Cổng ĐÓNG (CLOSED)         : 4 (44.4%)
  Cổng BỊ LỌC (FILTERED)    : 2 (22.2%)
  Tốc độ quét                : 3.8 cổng/giây
```

## 4. Hiển thị kết quả trên giao diện GUI

### 4.1. Tab 1: Bảng kết quả quét (Treeview)

Kết quả quét được hiển thị trên bảng `ttk.Treeview` với 8 cột thông tin:

| Cột | Tên hiển thị | Độ rộng | Mô tả |
|-----|-------------|---------|-------|
| ip | Mục tiêu (IP) | 110px | Địa chỉ IP mục tiêu |
| port | Cổng | 65px | Số hiệu cổng |
| status | Trạng thái | 95px | OPEN / CLOSED / FILTERED |
| rtt | Độ trễ | 75px | Round-Trip Time (ms) |
| service | Dịch vụ dự đoán | 110px | Tên dịch vụ nhận diện |
| risk | Mức rủi ro | 85px | Critical → None |
| notes | Ghi chú | 220px | Thông tin kỹ thuật socket |
| recommendation | Khuyến nghị | 260px | Đề xuất an toàn |

### 4.2. Mã hóa màu sắc theo mức rủi ro

Hệ thống sử dụng `tag_configure()` để phân biệt trực quan:

```python
# Màu theo trạng thái cổng
self.tree.tag_configure("OPEN", foreground="#007700")        # Xanh lá
self.tree.tag_configure("CLOSED", foreground="#666666")      # Xám
self.tree.tag_configure("FILTERED/UNKNOWN", foreground="#b37400")  # Cam

# Màu theo mức rủi ro (ưu tiên hơn)
self.tree.tag_configure("Risk_Critical", foreground="#cc0000", font=("Arial", 9, "bold"))
self.tree.tag_configure("Risk_High", foreground="#b30000")
self.tree.tag_configure("Risk_Medium", foreground="#b35900")
self.tree.tag_configure("Risk_Low", foreground="#008000")
```

### 4.3. Bộ lọc kết quả trực tuyến

Người dùng có thể lọc bảng kết quả theo 2 tiêu chí:

- **Bộ lọc trạng thái**: Tất cả / Chỉ OPEN / Chỉ CLOSED / Chỉ FILTERED
- **Bộ lọc rủi ro**: Tất cả / CRITICAL / HIGH / MEDIUM / LOW / INFO

Khi thay đổi bộ lọc, hàm `_on_filter_changed()` được kích hoạt:
1. Xóa toàn bộ dòng hiện tại trên Treeview
2. Áp dụng `filter_results_by_status()` từ module classifier
3. Áp dụng `filter_results_by_risk()` từ module analyzer
4. Chèn lại các dòng thỏa mãn điều kiện lọc

### 4.4. Xuất báo cáo từ GUI

Nút **"💾 Xuất báo cáo CSV"** (hoặc phím tắt `Ctrl+S`) mở hộp thoại `filedialog.asksaveasfilename()` cho phép người dùng chọn:

- **Định dạng CSV** (*.csv): Xuất bảng dữ liệu kèm metadata và thống kê.
- **Định dạng TXT** (*.txt): Xuất báo cáo văn bản đầy đủ kèm đánh giá an ninh.

## 5. Xuất báo cáo từ CLI

### 5.1. Cờ `--export`

Khi chạy với cờ `--export`, ứng dụng tự động xuất cả file CSV và TXT sau khi quét:

```powershell
python main.py --cli -t 127.0.0.1 -p "21,22,80,443,3306" --export
```

Kết quả:
```
[+] Báo cáo CSV đã được lưu tại: reports/scan_report_127_0_0_1_20241110_143000.csv
[+] Báo cáo TXT đã được lưu tại: reports/scan_report_127_0_0_1_20241110_143000.txt
```

### 5.2. Thư mục lưu trữ

Mặc định, file báo cáo được lưu trong thư mục `reports/` ở gốc dự án. Tên file tự động theo định dạng:

```
scan_report_{IP_dấu_gạch_dưới}_{YYYYMMDD_HHMMSS}.csv
scan_report_{IP_dấu_gạch_dưới}_{YYYYMMDD_HHMMSS}.txt
```

## 6. Kiểm thử tự động (Unit Tests)

### 6.1. Danh sách test cases

Bộ kiểm thử `tests/test_exporter.py` bao gồm **22 test cases** chia thành 4 nhóm:

| Nhóm | Số test | Mô tả |
|------|---------|-------|
| TestExportToCSV | 10 | Xuất CSV: tạo file, nội dung, metadata, BOM, edge cases |
| TestExportToTXT | 5 | Xuất TXT: tạo file, nội dung, đánh giá an ninh |
| TestGenerateConsoleReport | 3 | Sinh báo cáo console: cơ bản, metadata, rỗng |
| TestHelperFunctions | 4 | Hàm tiện ích: metadata, thống kê |

### 6.2. Chạy kiểm thử

```powershell
python -m unittest tests.test_exporter -v
```

## 7. Thư viện chuẩn Python sử dụng

| Thư viện | Mô đun | Mục đích sử dụng |
|----------|--------|-------------------|
| `csv` | csv.DictWriter, csv.writer | Ghi file CSV với định dạng chuẩn RFC 4180 |
| `datetime` | datetime.now(), strftime() | Tạo timestamp cho tên file và metadata |
| `os` | os.makedirs(), os.path | Quản lý thư mục và đường dẫn file |
| `pathlib` | Path.mkdir(), Path.parent | Xử lý đường dẫn đa nền tảng |

## 8. Tổng kết

Module xuất báo cáo hoàn thành vòng lặp xử lý dữ liệu của ứng dụng:

```
Nhập IP → Quét Socket → Phân loại → Nhận diện dịch vụ → Hiển thị GUI → Xuất báo cáo
(04/11)    (05/11)       (06/11)     (08/11)              (09/11)         (10/11)
```

Với hai định dạng xuất (CSV và TXT), ứng dụng đáp ứng đầy đủ nhu cầu:
- **CSV**: Phân tích dữ liệu bằng Excel, nhập vào hệ thống SIEM/Dashboard.
- **TXT**: Đọc nhanh trên terminal, in ấn, đính kèm email báo cáo.

