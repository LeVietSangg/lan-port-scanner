"""Giao diện đồ họa người dùng (GUI) hoàn chỉnh cho ứng dụng LAN Port Scanner bằng Tkinter (Mốc 09/11)."""

from datetime import datetime
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import List, Optional

from src.config import (
    COMMON_PORTS,
    DEFAULT_MAX_THREADS,
    DEFAULT_TIMEOUT,
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_INFO,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_NONE,
    STATUS_CLOSED,
    STATUS_FILTERED,
    STATUS_OPEN,
)
from src.core.validator import (
    parse_ports,
    resolve_host,
    validate_target,
    TYPE_LOOPBACK,
    TYPE_PRIVATE_LAN,
    TYPE_PUBLIC,
)
from src.core.scanner import PortScanner, ScanResult
from src.core.analyzer import (
    analyze_security,
    get_security_posture_summary,
    filter_results_by_risk,
)
from src.core.classifier import filter_results_by_status, get_classification_stats
from src.core.exporter import export_to_csv, export_to_txt


class PortScannerApp:
    """Ứng dụng giao diện đồ họa Tkinter hoàn chỉnh cho LAN Port Scanner & Analyzer."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("LAN Port Scanner & Security Analyzer - Công cụ Quét & Phân tích An toàn Cổng Mạng")
        self.root.geometry("1040x720")
        self.root.minsize(860, 600)

        self.scanner: Optional[PortScanner] = None
        self.scan_results: List[ScanResult] = []
        self.is_scanning: bool = False
        self.scan_start_time: float = 0.0

        self._setup_style()
        self._build_menu()
        self._build_ui()
        self._bind_shortcuts()

    def _setup_style(self):
        """Khởi tạo cấu hình theme và màu sắc bảng kết quả."""
        self.style = ttk.Style(self.root)
        available_themes = self.style.theme_names()
        if "clam" in available_themes:
            self.style.theme_use("clam")

        self.style.configure("Treeview.Heading", font=("Arial", 9, "bold"))
        self.style.configure("Treeview", rowheight=24, font=("Arial", 9))
        self.style.configure("Bold.TLabel", font=("Arial", 9, "bold"))

    def _build_menu(self):
        """Xây dựng thanh thực đơn cấp cao (Menu Bar)."""
        menu_bar = tk.Menu(self.root)

        # Menu Tệp (File)
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Bắt đầu quét mới (F5)", command=self.start_scan)
        file_menu.add_command(label="Dừng quét (Esc)", command=self.stop_scan)
        file_menu.add_separator()
        file_menu.add_command(label="Xuất báo cáo CSV (Ctrl+S)", command=self.export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Thoát (Ctrl+Q)", command=self.root.quit)
        menu_bar.add_cascade(label="Tệp (File)", menu=file_menu)

        # Menu Công cụ (Tools)
        tools_menu = tk.Menu(menu_bar, tearoff=0)
        tools_menu.add_command(label="Kiểm tra IP mục tiêu", command=lambda: self.check_ip_target(silent=False))
        tools_menu.add_command(label="Xóa dữ liệu bảng kết quả (Ctrl+L)", command=self.clear_results)
        tools_menu.add_separator()
        tools_menu.add_command(label="Thiết lập cổng mặc định (Common)", command=lambda: self._set_preset("Cổng phổ biến"))
        tools_menu.add_command(label="Thiết lập cổng Web (80, 443...)", command=lambda: self._set_preset("Web (80, 443, 8080, 8443)"))
        tools_menu.add_command(label="Thiết lập cổng Database (3306...)", command=lambda: self._set_preset("Database (1433, 1521, 3306, 5432, 27017)"))
        menu_bar.add_cascade(label="Công cụ (Tools)", menu=tools_menu)

        # Menu Trợ giúp (Help)
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="Hướng dẫn sử dụng", command=self._show_usage_guide)
        help_menu.add_command(label="Lưu ý pháp lý & An toàn", command=self._show_safety_notes)
        help_menu.add_separator()
        help_menu.add_command(label="Giới thiệu đề tài (About)", command=self._show_about)
        menu_bar.add_cascade(label="Trợ giúp (Help)", menu=help_menu)

        self.root.config(menu=menu_bar)

    def _bind_shortcuts(self):
        """Gán các phím tắt bàn phím."""
        self.root.bind("<F5>", lambda event: self.start_scan())
        self.root.bind("<Escape>", lambda event: self.stop_scan())
        self.root.bind("<Control-s>", lambda event: self.export_report())
        self.root.bind("<Control-l>", lambda event: self.clear_results())
        self.root.bind("<Control-q>", lambda event: self.root.quit())

    def _build_ui(self):
        """Xây dựng bố cục giao diện chính."""
        # 1. Khung cảnh báo / Điều khoản an toàn
        disclaimer_frame = ttk.LabelFrame(self.root, text="Lưu ý an toàn & Pháp lý", padding=6)
        disclaimer_frame.pack(fill=tk.X, padx=10, pady=(4, 2))

        disclaimer_text = (
            "⚠️ CHÚ Ý AN TOÀN: Ứng dụng phục vụ học tập và quản trị mạng nội bộ. "
            "Chỉ quét thiết bị localhost (127.0.0.1), máy ảo lab hoặc hệ thống được cho phép bằng văn bản. "
            "Nghiêm cấm thực hiện dò quét trái phép trên mạng Internet."
        )
        ttk.Label(disclaimer_frame, text=disclaimer_text, foreground="#b35900", wraplength=1000).pack(anchor=tk.W)

        # 2. Khung cấu hình mục tiêu và tham số quét
        input_frame = ttk.LabelFrame(self.root, text="Cấu hình quét mục tiêu", padding=8)
        input_frame.pack(fill=tk.X, padx=10, pady=4)

        # Hàng 1: Mục tiêu IP và Cổng
        row1 = ttk.Frame(input_frame)
        row1.pack(fill=tk.X, pady=3)

        ttk.Label(row1, text="Mục tiêu (IP / Host):", width=18).pack(side=tk.LEFT)
        self.target_entry = ttk.Entry(row1, width=22)
        self.target_entry.insert(0, "127.0.0.1")
        self.target_entry.pack(side=tk.LEFT, padx=(5, 2))
        self.target_entry.bind("<KeyRelease>", lambda event: self.check_ip_target(silent=True))
        self.target_entry.bind("<FocusOut>", lambda event: self.check_ip_target(silent=True))

        self.btn_check_ip = ttk.Button(row1, text="Kiểm tra IP", width=11, command=lambda: self.check_ip_target(silent=False))
        self.btn_check_ip.pack(side=tk.LEFT, padx=3)

        ttk.Label(row1, text="Danh sách cổng:").pack(side=tk.LEFT, padx=(15, 5))
        self.ports_entry = ttk.Entry(row1, width=32)
        self.ports_entry.insert(0, "21, 22, 23, 80, 443, 445, 3306, 3389, 8080")
        self.ports_entry.pack(side=tk.LEFT, padx=5)

        # Hàng 1.5: Nhãn trạng thái xác thực IP thời gian thực
        row1_info = ttk.Frame(input_frame)
        row1_info.pack(fill=tk.X, pady=(1, 3))
        self.lbl_ip_feedback = ttk.Label(
            row1_info,
            text="● Mục tiêu: 127.0.0.1 (Loopback - Máy cục bộ kiểm thử an toàn)",
            foreground="#008000",
            font=("Arial", 8, "italic")
        )
        self.lbl_ip_feedback.pack(side=tk.LEFT, padx=(140, 5))

        # Hàng 2: Mẫu cổng nhanh, Timeout, Số luồng, Banner Grabbing
        row2 = ttk.Frame(input_frame)
        row2.pack(fill=tk.X, pady=4)

        ttk.Label(row2, text="Mẫu cổng nhanh:", width=18).pack(side=tk.LEFT)
        self.port_preset_var = tk.StringVar(value="Cổng phổ biến")
        presets = ["Cổng phổ biến", "Web (80, 443, 8080, 8443)", "Database (1433, 1521, 3306, 5432, 27017)", "Khoảng 1-1024"]
        preset_menu = ttk.Combobox(row2, textvariable=self.port_preset_var, values=presets, state="readonly", width=25)
        preset_menu.pack(side=tk.LEFT, padx=5)
        preset_menu.bind("<<ComboboxSelected>>", self._on_preset_change)

        ttk.Label(row2, text="Timeout (s):").pack(side=tk.LEFT, padx=(10, 4))
        self.timeout_spin = ttk.Spinbox(row2, from_=0.1, to=10.0, increment=0.2, width=5)
        self.timeout_spin.set(str(DEFAULT_TIMEOUT))
        self.timeout_spin.pack(side=tk.LEFT, padx=4)

        ttk.Label(row2, text="Số luồng:").pack(side=tk.LEFT, padx=(10, 4))
        self.threads_spin = ttk.Spinbox(row2, from_=1, to=200, increment=5, width=5)
        self.threads_spin.set(str(DEFAULT_MAX_THREADS))
        self.threads_spin.pack(side=tk.LEFT, padx=4)

        self.banner_var = tk.BooleanVar(value=False)
        self.chk_banner = ttk.Checkbutton(row2, text="Lấy Banner", variable=self.banner_var)
        self.chk_banner.pack(side=tk.LEFT, padx=(12, 5))

        # Hàng 3: Các nút điều khiển thao tác
        btn_frame = ttk.Frame(input_frame)
        btn_frame.pack(fill=tk.X, pady=(4, 0))

        self.btn_scan = ttk.Button(btn_frame, text="▶ Bắt đầu quét (F5)", command=self.start_scan)
        self.btn_scan.pack(side=tk.LEFT, padx=4)

        self.btn_stop = ttk.Button(btn_frame, text="⏹ Dừng quét (Esc)", command=self.stop_scan, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=4)

        self.btn_clear = ttk.Button(btn_frame, text="🗑 Xóa kết quả", command=self.clear_results)
        self.btn_clear.pack(side=tk.LEFT, padx=4)

        self.btn_export = ttk.Button(btn_frame, text="💾 Xuất báo cáo CSV", command=self.export_report, state=tk.DISABLED)
        self.btn_export.pack(side=tk.RIGHT, padx=4)

        # 3. Thanh tiến trình và thông báo trạng thái
        progress_frame = ttk.Frame(self.root, padding=(10, 2))
        progress_frame.pack(fill=tk.X)

        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, side=tk.TOP, pady=2)

        self.status_label = ttk.Label(progress_frame, text="Sẵn sàng quét.", font=("Arial", 9, "italic"))
        self.status_label.pack(side=tk.LEFT)

        # 4. Khu vực nội dung dạng Tabs (Notebook)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(4, 4))

        # --- Tab 1: Bảng kết quả quét & Khuyến nghị ---
        self.tab_results = ttk.Frame(self.notebook, padding=6)
        self.notebook.add(self.tab_results, text="📋 Bảng Kết Quả Quét")
        self._build_tab_results()

        # --- Tab 2: Đánh giá thế trận an ninh (Security Assessment) ---
        self.tab_security = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_security, text="🛡️ Báo Cáo An Ninh Mạng")
        self._build_tab_security()

        # --- Tab 3: Nhật ký hoạt động (Activity Log) ---
        self.tab_logs = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_logs, text="📜 Nhật Ký Hoạt Động")
        self._build_tab_logs()

        # 5. Thanh trạng thái dưới đáy cửa sổ (Status Bar)
        self.status_bar = ttk.Frame(self.root, relief=tk.SUNKEN, padding=(8, 3))
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        self.lbl_sb_target = ttk.Label(self.status_bar, text="Mục tiêu: Chưa chọn", font=("Arial", 8))
        self.lbl_sb_target.pack(side=tk.LEFT, padx=10)

        self.lbl_sb_speed = ttk.Label(self.status_bar, text="Tốc độ: 0.0 cổng/s", font=("Arial", 8))
        self.lbl_sb_speed.pack(side=tk.LEFT, padx=10)

        self.lbl_sb_time = ttk.Label(self.status_bar, text="Thời gian: 0.0s", font=("Arial", 8))
        self.lbl_sb_time.pack(side=tk.LEFT, padx=10)

        self.lbl_sb_threads = ttk.Label(self.status_bar, text=f"Luồng: {DEFAULT_MAX_THREADS}", font=("Arial", 8))
        self.lbl_sb_threads.pack(side=tk.RIGHT, padx=10)

    def _build_tab_results(self):
        """Xây dựng nội dung Tab 1: Bảng kết quả quét."""
        # Thanh công cụ lọc trạng thái và rủi ro
        toolbar = ttk.Frame(self.tab_results)
        toolbar.pack(fill=tk.X, pady=(0, 4))

        ttk.Label(toolbar, text="Trạng thái:").pack(side=tk.LEFT, padx=(0, 4))
        self.status_filter_var = tk.StringVar(value="Tất cả trạng thái")
        status_opts = ["Tất cả trạng thái", "Chỉ cổng MỞ (OPEN)", "Chỉ cổng ĐÓNG (CLOSED)", "Chỉ cổng BỊ LỌC (FILTERED)"]
        self.combo_status_filter = ttk.Combobox(toolbar, textvariable=self.status_filter_var, values=status_opts, state="readonly", width=18)
        self.combo_status_filter.pack(side=tk.LEFT, padx=(0, 10))
        self.combo_status_filter.bind("<<ComboboxSelected>>", self._on_filter_changed)

        ttk.Label(toolbar, text="Rủi ro:").pack(side=tk.LEFT, padx=(0, 4))
        self.risk_filter_var = tk.StringVar(value="Tất cả mức rủi ro")
        risk_opts = ["Tất cả mức rủi ro", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        self.combo_risk_filter = ttk.Combobox(toolbar, textvariable=self.risk_filter_var, values=risk_opts, state="readonly", width=16)
        self.combo_risk_filter.pack(side=tk.LEFT, padx=(0, 15))
        self.combo_risk_filter.bind("<<ComboboxSelected>>", self._on_filter_changed)

        # Huy hiệu thống kê trạng thái
        self.lbl_stat_open = ttk.Label(toolbar, text="🟢 Mở: 0 (0%)", foreground="#007700", font=("Arial", 9, "bold"))
        self.lbl_stat_open.pack(side=tk.LEFT, padx=6)

        self.lbl_stat_closed = ttk.Label(toolbar, text="⚪ Đóng: 0 (0%)", foreground="#555555", font=("Arial", 9, "bold"))
        self.lbl_stat_closed.pack(side=tk.LEFT, padx=6)

        self.lbl_stat_filtered = ttk.Label(toolbar, text="🟠 Bị lọc: 0 (0%)", foreground="#b37400", font=("Arial", 9, "bold"))
        self.lbl_stat_filtered.pack(side=tk.LEFT, padx=6)

        self.lbl_firewall_hint = ttk.Label(toolbar, text="", foreground="#b35900", font=("Arial", 8, "italic"))
        self.lbl_firewall_hint.pack(side=tk.RIGHT, padx=5)

        # Bảng Treeview
        tree_container = ttk.Frame(self.tab_results)
        tree_container.pack(fill=tk.BOTH, expand=True)

        columns = ("ip", "port", "status", "rtt", "service", "risk", "notes", "recommendation")
        self.tree = ttk.Treeview(tree_container, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("ip", text="Mục tiêu (IP)")
        self.tree.heading("port", text="Cổng")
        self.tree.heading("status", text="Trạng thái")
        self.tree.heading("rtt", text="Độ trễ")
        self.tree.heading("service", text="Dịch vụ dự đoán")
        self.tree.heading("risk", text="Mức rủi ro")
        self.tree.heading("notes", text="Ghi chú phản hồi socket")
        self.tree.heading("recommendation", text="Khuyến nghị an toàn")

        self.tree.column("ip", width=110, anchor=tk.CENTER)
        self.tree.column("port", width=65, anchor=tk.CENTER)
        self.tree.column("status", width=95, anchor=tk.CENTER)
        self.tree.column("rtt", width=75, anchor=tk.CENTER)
        self.tree.column("service", width=110, anchor=tk.CENTER)
        self.tree.column("risk", width=85, anchor=tk.CENTER)
        self.tree.column("notes", width=220)
        self.tree.column("recommendation", width=260)

        y_scroll = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=self.tree.yview)
        x_scroll = ttk.Scrollbar(tree_container, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

        tree_container.rowconfigure(0, weight=1)
        tree_container.columnconfigure(0, weight=1)

        # Cấu hình màu cho trạng thái & rủi ro
        self.tree.tag_configure(STATUS_OPEN, foreground="#007700")
        self.tree.tag_configure(STATUS_CLOSED, foreground="#666666")
        self.tree.tag_configure(STATUS_FILTERED, foreground="#b37400")
        self.tree.tag_configure("Risk_Critical", foreground="#cc0000", font=("Arial", 9, "bold"))
        self.tree.tag_configure("Risk_High", foreground="#b30000")
        self.tree.tag_configure("Risk_Medium", foreground="#b35900")
        self.tree.tag_configure("Risk_Low", foreground="#008000")

        # Khung thông tin chi tiết cổng & khuyến nghị an toàn
        detail_frame = ttk.LabelFrame(self.tab_results, text="Chi tiết dịch vụ & Khuyến nghị an toàn (Mốc 08/11)", padding=6)
        detail_frame.pack(fill=tk.X, pady=(4, 0))

        self.txt_recommendation = tk.Text(detail_frame, height=3, wrap=tk.WORD, font=("Arial", 9), relief=tk.SOLID, borderwidth=1)
        self.txt_recommendation.pack(fill=tk.X)
        self.txt_recommendation.insert(tk.END, "Chọn một dòng trong bảng kết quả để xem chi tiết nhận diện dịch vụ, rủi ro và khuyến nghị an toàn.")
        self.txt_recommendation.config(state=tk.DISABLED)

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

    def _build_tab_security(self):
        """Xây dựng nội dung Tab 2: Báo cáo an ninh mạng tổng thể."""
        # Tiêu đề đánh giá thế trận an ninh
        sec_header_frame = ttk.Frame(self.tab_security)
        sec_header_frame.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(sec_header_frame, text="Đánh giá thế trận an ninh: ", font=("Arial", 11, "bold")).pack(side=tk.LEFT)
        self.lbl_posture_rating = ttk.Label(sec_header_frame, text="CHƯA CÓ DỮ LIỆU", font=("Arial", 11, "bold"), foreground="#666666")
        self.lbl_posture_rating.pack(side=tk.LEFT, padx=5)

        self.lbl_posture_summary = ttk.Label(self.tab_security, text="Chưa thực hiện quét cổng nào.", font=("Arial", 9, "italic"))
        self.lbl_posture_summary.pack(anchor=tk.W, pady=(0, 8))

        # Khung phân bổ mức độ rủi ro
        dist_frame = ttk.LabelFrame(self.tab_security, text="Phân bố rủi ro các cổng đang mở", padding=8)
        dist_frame.pack(fill=tk.X, pady=4)

        self.lbl_risk_counts = ttk.Label(
            dist_frame,
            text="🔴 Nghiêm trọng (Critical): 0  |  🟠 Cao (High): 0  |  🟡 Trung bình (Medium): 0  |  🟢 Thấp (Low): 0",
            font=("Arial", 9)
        )
        self.lbl_risk_counts.pack(anchor=tk.W)

        # Khung danh sách cảnh báo đặc biệt
        warn_frame = ttk.LabelFrame(self.tab_security, text="Cảnh báo an ninh dịch vụ nhạy cảm", padding=8)
        warn_frame.pack(fill=tk.X, pady=4)

        self.lbl_warn_cleartext = ttk.Label(warn_frame, text="• Dịch vụ không mã hóa (Cleartext): Không phát hiện", foreground="#333333")
        self.lbl_warn_cleartext.pack(anchor=tk.W, pady=2)

        self.lbl_warn_database = ttk.Label(warn_frame, text="• Cơ sở dữ liệu mở cổng mạng (Databases): Không phát hiện", foreground="#333333")
        self.lbl_warn_database.pack(anchor=tk.W, pady=2)

        # Khung các hành động ưu tiên khắc phục
        rec_frame = ttk.LabelFrame(self.tab_security, text="Khuyến nghị an ninh ưu tiên khắc phục", padding=8)
        rec_frame.pack(fill=tk.BOTH, expand=True, pady=4)

        self.txt_security_recs = tk.Text(rec_frame, wrap=tk.WORD, font=("Arial", 9), relief=tk.SOLID, borderwidth=1)
        self.txt_security_recs.pack(fill=tk.BOTH, expand=True)
        self.txt_security_recs.insert(tk.END, "Thực hiện quét để sinh báo cáo an ninh mạng và khuyến nghị chi tiết.")
        self.txt_security_recs.config(state=tk.DISABLED)

    def _build_tab_logs(self):
        """Xây dựng nội dung Tab 3: Nhật ký hoạt động thời gian thực."""
        log_toolbar = ttk.Frame(self.tab_logs)
        log_toolbar.pack(fill=tk.X, pady=(0, 4))

        ttk.Button(log_toolbar, text="Xóa nhật ký", command=self._clear_logs).pack(side=tk.LEFT)
        self.chk_autoscroll = tk.BooleanVar(value=True)
        ttk.Checkbutton(log_toolbar, text="Tự động cuộn", variable=self.chk_autoscroll).pack(side=tk.RIGHT)

        self.txt_logs = tk.Text(self.tab_logs, wrap=tk.WORD, font=("Consolas", 9), bg="#1e1e1e", fg="#d4d4d4", insertbackground="white")
        log_scroll = ttk.Scrollbar(self.tab_logs, orient=tk.VERTICAL, command=self.txt_logs.yview)
        self.txt_logs.configure(yscrollcommand=log_scroll.set)

        self.txt_logs.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self._log("Khởi động ứng dụng LAN Port Scanner GUI thành công.")

    def _log(self, message: str, level: str = "INFO"):
        """Ghi dòng thông báo vào khung nhật ký."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_line = f"[{timestamp}] [{level}] {message}\n"
        self.txt_logs.config(state=tk.NORMAL)
        self.txt_logs.insert(tk.END, log_line)
        if self.chk_autoscroll.get():
            self.txt_logs.see(tk.END)
        self.txt_logs.config(state=tk.DISABLED)

    def _clear_logs(self):
        self.txt_logs.config(state=tk.NORMAL)
        self.txt_logs.delete("1.0", tk.END)
        self.txt_logs.config(state=tk.DISABLED)

    def _set_preset(self, preset_name: str):
        self.port_preset_var.set(preset_name)
        self._on_preset_change()

    def _on_preset_change(self, event=None):
        choice = self.port_preset_var.get()
        if choice == "Cổng phổ biến":
            self.ports_entry.delete(0, tk.END)
            self.ports_entry.insert(0, ", ".join(str(p) for p in sorted(COMMON_PORTS.keys())[:15]))
        elif choice == "Web (80, 443, 8080, 8443)":
            self.ports_entry.delete(0, tk.END)
            self.ports_entry.insert(0, "80, 443, 8080, 8443")
        elif choice == "Database (1433, 1521, 3306, 5432, 27017)":
            self.ports_entry.delete(0, tk.END)
            self.ports_entry.insert(0, "1433, 1521, 3306, 5432, 27017")
        elif choice == "Khoảng 1-1024":
            self.ports_entry.delete(0, tk.END)
            self.ports_entry.insert(0, "1-1024")

    def check_ip_target(self, silent: bool = False):
        """Xác thực và cập nhật nhãn trạng thái của IP mục tiêu trên giao diện."""
        target_input = self.target_entry.get().strip()
        if not target_input:
            self.lbl_ip_feedback.config(text="● Vui lòng nhập địa chỉ IP hoặc tên máy chủ.", foreground="#888888")
            if not silent:
                messagebox.showwarning("Nhắc nhở", "Vui lòng nhập địa chỉ IP hoặc tên máy chủ.")
            return False, None

        res = validate_target(target_input)
        if res.is_valid:
            if res.is_lan_or_local:
                color = "#008000"
                icon = "✅"
            else:
                color = "#cc6600"
                icon = "⚠️"
            display_text = f"{icon} {res.resolved_ip} ({res.ip_type})"
            self.lbl_ip_feedback.config(text=display_text, foreground=color)
            self.lbl_sb_target.config(text=f"Mục tiêu: {res.resolved_ip}")
            if not silent:
                detail_msg = (
                    f"Mục tiêu hợp lệ!\n\n"
                    f"- Địa chỉ IP : {res.resolved_ip}\n"
                    f"- Phân loại  : {res.ip_type}\n"
                    f"- Mạng LAN/Local: {'Đúng' if res.is_lan_or_local else 'Không (Public Internet)'}\n"
                )
                if res.warning_message:
                    detail_msg += f"\nLưu ý: {res.warning_message}"
                messagebox.showinfo("Xác thực IP thành công", detail_msg)
            return True, res
        else:
            self.lbl_ip_feedback.config(text=f"❌ {res.error_message}", foreground="#cc0000")
            if not silent:
                messagebox.showerror("Lỗi địa chỉ IP", res.error_message)
            return False, None

    def start_scan(self):
        """Bắt đầu tiến trình quét cổng."""
        target_input = self.target_entry.get().strip()
        ports_input = self.ports_entry.get().strip()

        # 1. Xác thực mục tiêu bằng validator
        is_ok, target_res = self.check_ip_target(silent=True)
        if not is_ok or not target_res:
            res = validate_target(target_input)
            messagebox.showerror("Lỗi mục tiêu", res.error_message or "Địa chỉ mục tiêu không hợp lệ.")
            return

        resolved_ip = target_res.resolved_ip

        # Nếu là Public IP, hiển thị hộp thoại xác nhận an toàn
        if not target_res.is_lan_or_local:
            confirm = messagebox.askyesno(
                "Cảnh báo quét IP công cộng",
                f"{target_res.warning_message}\n\nBạn có chắc chắn rằng bạn có quyền kiểm thử mục tiêu này?",
                icon=messagebox.WARNING
            )
            if not confirm:
                return

        # 2. Phân tích danh sách cổng
        ports = parse_ports(ports_input)
        if not ports:
            messagebox.showerror("Lỗi cổng", "Vui lòng nhập ít nhất một cổng hợp lệ (1-65535).")
            return

        try:
            timeout = float(self.timeout_spin.get())
            max_threads = int(self.threads_spin.get())
        except ValueError:
            messagebox.showerror("Lỗi tham số", "Timeout hoặc số luồng không hợp lệ.")
            return

        # Dọn dẹp dữ liệu cũ trên bảng
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.scan_results = []
        self._update_stats_display()
        self.is_scanning = True
        self.scan_start_time = time.perf_counter()

        self.btn_scan.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.btn_export.config(state=tk.DISABLED)
        self.root.config(cursor="watch")
        self.progress_var.set(0)
        self.status_label.config(text=f"Đang quét mục tiêu {resolved_ip} ({len(ports)} cổng)...")
        self.lbl_sb_threads.config(text=f"Luồng: {max_threads}")

        self._log(f"Bắt đầu quét {resolved_ip} ({len(ports)} cổng, timeout {timeout}s, {max_threads} luồng).")

        self.scanner = PortScanner(
            target=resolved_ip,
            ports=ports,
            timeout=timeout,
            max_threads=max_threads,
            enable_banner=self.banner_var.get()
        )

        thread = threading.Thread(target=self._run_scan_thread, daemon=True)
        thread.start()

    def _run_scan_thread(self):
        """Hàm chạy quét trong luồng riêng để không làm đơ giao diện người dùng."""
        def on_progress(result: ScanResult, completed: int, total: int):
            analyzed = analyze_security(result)
            self.root.after(0, self._update_row_and_progress, analyzed, completed, total)

        results = self.scanner.scan(progress_callback=on_progress)
        self.scan_results = sorted(self.scan_results, key=lambda r: r.port)
        self.root.after(0, self._on_scan_finished)

    def _update_row_and_progress(self, result: ScanResult, completed: int, total: int):
        """Cập nhật tiến trình và thêm dòng mới vào bảng kết quả."""
        percent = (completed / total) * 100
        self.progress_var.set(percent)

        elapsed = time.perf_counter() - self.scan_start_time
        rate = completed / max(0.001, elapsed)
        self.status_label.config(text=f"Đã kiểm tra {completed}/{total} cổng ({percent:.1f}%) - Tốc độ: {rate:.1f} cổng/s")
        self.lbl_sb_speed.config(text=f"Tốc độ: {rate:.1f} cổng/s")
        self.lbl_sb_time.config(text=f"Thời gian: {elapsed:.1f}s")

        self.scan_results.append(result)
        self._update_stats_display()

        row_tags = (result.status,)
        if result.status == STATUS_OPEN and result.risk_level in ("Critical", "High", "Medium", "Low"):
            row_tags = (f"Risk_{result.risk_level}", result.status)

        rtt_str = f"{result.response_time_ms}ms" if result.response_time_ms > 0 else "-"
        self.tree.insert(
            "",
            tk.END,
            values=(
                result.target_ip,
                result.port,
                result.status,
                rtt_str,
                result.service,
                result.risk_level,
                result.notes,
                result.recommendation,
            ),
            tags=row_tags
        )

        if result.status == STATUS_OPEN:
            self._log(f"Phát hiện cổng MỞ: Cổng {result.port} ({result.service}) - Rủi ro: {result.risk_level}", level="WARN")

    def _on_filter_changed(self, event=None):
        """Lọc và cập nhật lại bảng hiển thị kết quả theo lựa chọn người dùng (Mốc 06/11 & 08/11)."""
        status_choice = self.status_filter_var.get()
        if status_choice == "Chỉ cổng MỞ (OPEN)":
            status_key = "OPEN"
        elif status_choice == "Chỉ cổng ĐÓNG (CLOSED)":
            status_key = "CLOSED"
        elif status_choice == "Chỉ cổng BỊ LỌC (FILTERED)":
            status_key = "FILTERED"
        else:
            status_key = "ALL"

        risk_choice = self.risk_filter_var.get()
        risk_key = "ALL" if risk_choice == "Tất cả mức rủi ro" else risk_choice

        for item in self.tree.get_children():
            self.tree.delete(item)

        filtered = filter_results_by_status(self.scan_results, status_key)
        if risk_key != "ALL":
            filtered = filter_results_by_risk(filtered, risk_key)

        for result in filtered:
            row_tags = (result.status,)
            if result.status == STATUS_OPEN and result.risk_level in ("Critical", "High", "Medium", "Low"):
                row_tags = (f"Risk_{result.risk_level}", result.status)

            rtt_str = f"{result.response_time_ms}ms" if result.response_time_ms > 0 else "-"
            self.tree.insert(
                "",
                tk.END,
                values=(
                    result.target_ip,
                    result.port,
                    result.status,
                    rtt_str,
                    result.service,
                    result.risk_level,
                    result.notes,
                    result.recommendation,
                ),
                tags=row_tags
            )

    def _on_tree_select(self, event=None):
        """Hiển thị chi tiết thông tin và khuyến nghị khi người dùng chọn một dòng."""
        selected = self.tree.selection()
        if not selected:
            return
        item = self.tree.item(selected[0])
        vals = item.get("values", [])
        if not vals or len(vals) < 8:
            return

        port = vals[1]
        status = vals[2]
        rtt = vals[3]
        service = vals[4]
        risk = vals[5]
        notes = vals[6]
        recommendation = vals[7]

        detail_text = (
            f"📌 CỔNG: {port}  |  Dịch vụ: {service}  |  Trạng thái: {status} (Độ trễ: {rtt})  |  Mức rủi ro: {risk}\n"
            f"🔍 Ghi chú kỹ thuật: {notes}\n"
            f"🛡️ Khuyến nghị an toàn: {recommendation}"
        )
        self.txt_recommendation.config(state=tk.NORMAL)
        self.txt_recommendation.delete("1.0", tk.END)
        self.txt_recommendation.insert(tk.END, detail_text)
        self.txt_recommendation.config(state=tk.DISABLED)

    def _update_stats_display(self):
        """Cập nhật các số liệu thống kê trạng thái và báo cáo an ninh."""
        stats = get_classification_stats(self.scan_results)
        self.lbl_stat_open.config(text=f"🟢 Mở: {stats['open_count']} ({stats['open_percent']}%)")
        self.lbl_stat_closed.config(text=f"⚪ Đóng: {stats['closed_count']} ({stats['closed_percent']}%)")
        self.lbl_stat_filtered.config(text=f"🟠 Bị lọc: {stats['filtered_count']} ({stats['filtered_percent']}%)")
        if stats["firewall_detected"]:
            self.lbl_firewall_hint.config(text="🛡️ Có dấu hiệu tường lửa/bộ lọc mạng")
        else:
            self.lbl_firewall_hint.config(text="")

        # Cập nhật Tab 2 (Báo cáo an ninh)
        sec_summary = get_security_posture_summary(self.scan_results)
        self.lbl_posture_rating.config(text=sec_summary["posture_rating"], foreground=sec_summary["posture_badge_color"])
        self.lbl_posture_summary.config(text=sec_summary["posture_summary"])
        self.lbl_risk_counts.config(
            text=f"🔴 Nghiêm trọng (Critical): {sec_summary['critical_count']}  |  "
                 f"🟠 Cao (High): {sec_summary['high_count']}  |  "
                 f"🟡 Trung bình (Medium): {sec_summary['medium_count']}  |  "
                 f"🟢 Thấp (Low): {sec_summary['low_count']}"
        )

        # Cảnh báo dịch vụ nhạy cảm
        if sec_summary["cleartext_ports"]:
            self.lbl_warn_cleartext.config(
                text=f"• Dịch vụ không mã hóa (Cleartext): {', '.join(sec_summary['cleartext_ports'])}",
                foreground="#cc0000"
            )
        else:
            self.lbl_warn_cleartext.config(
                text="• Dịch vụ không mã hóa (Cleartext): Không phát hiện",
                foreground="#008000"
            )

        if sec_summary["database_ports"]:
            self.lbl_warn_database.config(
                text=f"• Cơ sở dữ liệu mở cổng mạng: {', '.join(sec_summary['database_ports'])}",
                foreground="#cc0000"
            )
        else:
            self.lbl_warn_database.config(
                text="• Cơ sở dữ liệu mở cổng mạng: Không phát hiện",
                foreground="#008000"
            )

        # Danh sách khuyến nghị chi tiết
        self.txt_security_recs.config(state=tk.NORMAL)
        self.txt_security_recs.delete("1.0", tk.END)
        if sec_summary["priority_recommendations"]:
            for idx, r in enumerate(sec_summary["priority_recommendations"], start=1):
                rec_block = (
                    f"{idx}. [{r['risk_level'].upper()}] Cổng {r['port']} ({r['service']}):\n"
                    f"   Khuyến nghị: {r['recommendation']}\n\n"
                )
                self.txt_security_recs.insert(tk.END, rec_block)
        else:
            self.txt_security_recs.insert(tk.END, "Không có khuyến nghị an ninh cấp bách nào cần xử lý.")
        self.txt_security_recs.config(state=tk.DISABLED)

    def _on_scan_finished(self):
        """Xử lý sự kiện khi toàn bộ tiến trình quét hoàn tất."""
        self.is_scanning = False
        self.btn_scan.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.btn_export.config(state=tk.NORMAL)
        self.root.config(cursor="")

        total_time = round(time.perf_counter() - self.scan_start_time, 2)
        stats = get_classification_stats(self.scan_results)
        self._update_stats_display()

        self.status_label.config(
            text=f"Hoàn thành quét trong {total_time}s! Tổng số: {stats['total']} cổng | "
                 f"Mở (OPEN): {stats['open_count']} | Đóng: {stats['closed_count']} | "
                 f"Bị lọc: {stats['filtered_count']}"
        )
        self._log(f"Hoàn tất quét trong {total_time}s. Tìm thấy {stats['open_count']} cổng mở.")

    def stop_scan(self):
        """Dừng tiến trình quét đang chạy."""
        if self.scanner and self.is_scanning:
            self.scanner.stop()
            self.status_label.config(text="Đang dừng tiến trình quét...")
            self._log("Người dùng yêu cầu dừng quét.", level="WARN")

    def clear_results(self):
        """Xóa toàn bộ dữ liệu trên bảng và reset trạng thái."""
        if self.is_scanning:
            messagebox.showwarning("Cảnh báo", "Vui lòng dừng quét trước khi xóa dữ liệu.")
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.scan_results = []
        self._update_stats_display()
        self.progress_var.set(0)
        self.status_label.config(text="Đã xóa kết quả. Sẵn sàng quét mới.")
        self.btn_export.config(state=tk.DISABLED)
        self._log("Đã xóa dữ liệu bảng kết quả.")

    def export_report(self):
        """Xuất báo cáo kết quả quét ra file CSV hoặc TXT (Mốc 10/11)."""
        if not self.scan_results:
            messagebox.showwarning("Cảnh báo", "Không có dữ liệu để xuất báo cáo.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[
                ("CSV Files (*.csv)", "*.csv"),
                ("Text Report (*.txt)", "*.txt"),
                ("All Files (*.*)", "*.*"),
            ],
            title="Lưu báo cáo quét cổng mạng"
        )
        if file_path:
            try:
                # Lấy thông tin metadata từ scanner hiện tại
                duration = None
                threads = None
                if self.scanner:
                    duration = self.scanner.scan_duration_sec
                    threads = self.scanner.max_threads

                if file_path.lower().endswith(".txt"):
                    sec_summary = get_security_posture_summary(self.scan_results)
                    saved_path = export_to_txt(
                        self.scan_results,
                        file_path,
                        scan_duration_sec=duration,
                        threads_used=threads,
                        security_summary=sec_summary,
                    )
                else:
                    saved_path = export_to_csv(
                        self.scan_results,
                        file_path,
                        scan_duration_sec=duration,
                        threads_used=threads,
                    )
                messagebox.showinfo("Thành công", f"Đã xuất báo cáo thành công ra file:\n{saved_path}")
                self._log(f"Đã xuất báo cáo ra file: {saved_path}")
            except Exception as e:
                messagebox.showerror("Lỗi", f"Không thể xuất file: {str(e)}")
                self._log(f"Lỗi khi xuất file: {str(e)}", level="ERROR")

    def _show_about(self):
        about_msg = (
            "ỨNG DỤNG QUÉT VÀ PHÂN TÍCH CỔNG MẠNG LAN\n"
            "Hỗ Trợ Đánh Giá An Toàn Hệ Thống Mạng Bằng Python\n"
            "Phiên bản: 1.0.0 (Giao diện Tkinter hoàn chỉnh)\n\n"
            "Đặc điểm chính:\n"
            "• Quét cổng TCP Connect Scan đa luồng bằng Socket\n"
            "• Phân loại trạng thái OPEN, CLOSED, FILTERED/UNKNOWN\n"
            "• Nhận diện dịch vụ chuẩn IANA & Banner Grabbing\n"
            "• Phân tích ma trận rủi ro & khuyến nghị an toàn mạng\n"
            "• Báo cáo thế trận an ninh và xuất file CSV chuẩn UTF-8"
        )
        messagebox.showinfo("Giới thiệu đề tài", about_msg)

    def _show_usage_guide(self):
        guide_msg = (
            "HƯỚNG DẪN SỬ DỤNG NHANH:\n\n"
            "1. Nhập mục tiêu: Điền địa chỉ IP (ví dụ: 127.0.0.1, 192.168.1.1) hoặc hostname.\n"
            "2. Nhấn nút 'Kiểm tra IP' để xác thực và phân loại mạng LAN.\n"
            "3. Chọn mẫu cổng nhanh hoặc điền cổng tùy ý (ví dụ: 80, 443 hoặc 1-1000).\n"
            "4. Nhấn 'Bắt đầu quét' (F5) để tiến hành quét đa luồng.\n"
            "5. Sử dụng bộ lọc trạng thái và rủi ro để xem kết quả mong muốn.\n"
            "6. Chuyển sang tab 'Báo Cáo An Ninh Mạng' để xem đánh giá tổng thể.\n"
            "7. Nhấn 'Xuất báo cáo CSV' (Ctrl+S) để lưu kết quả."
        )
        messagebox.showinfo("Hướng dẫn sử dụng", guide_msg)

    def _show_safety_notes(self):
        safety_msg = (
            "LƯU Ý AN TOÀN & PHÁP LÝ:\n\n"
            "• Công cụ chỉ phục vụ mục đích học tập và quản trị mạng nội bộ.\n"
            "• Chỉ quét thiết bị mà bạn có quyền quản trị hoặc đã được cho phép bằng văn bản.\n"
            "• Nghiêm cấm sử dụng công cụ để dò quét xâm nhập trái phép các hệ thống công cộng."
        )
        messagebox.showwarning("Lưu ý an toàn", safety_msg)


def run_gui():
    """Khởi chạy ứng dụng giao diện Tkinter."""
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()
