"""Giao diện đồ họa (GUI) cho ứng dụng quét cổng mạng bằng Tkinter."""

import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import List

from src.config import COMMON_PORTS, DEFAULT_MAX_THREADS, DEFAULT_TIMEOUT, STATUS_OPEN, STATUS_CLOSED, STATUS_FILTERED
from src.core.validator import (
    parse_ports,
    resolve_host,
    validate_target,
    TYPE_LOOPBACK,
    TYPE_PRIVATE_LAN,
    TYPE_PUBLIC,
)
from src.core.scanner import PortScanner, ScanResult
from src.core.analyzer import analyze_security
from src.core.exporter import export_to_csv


class PortScannerApp:
    """Ứng dụng GUI chính sử dụng Tkinter."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("LAN Port Scanner & Analyzer - Đánh giá an toàn cổng mạng")
        self.root.geometry("980x680")
        self.root.minsize(800, 550)

        self.scanner: PortScanner = None
        self.scan_results: List[ScanResult] = []
        self.is_scanning = False

        self._setup_style()
        self._build_ui()

    def _setup_style(self):
        self.style = ttk.Style(self.root)
        self.style.theme_use("clam")

        # Cấu hình màu sắc cho bảng kết quả
        self.style.configure("Treeview.Heading", font=("Arial", 10, "bold"))
        self.style.configure("Treeview", rowheight=24, font=("Arial", 9))

    def _build_ui(self):
        # 1. Khung cảnh báo / Điều khoản an toàn
        disclaimer_frame = ttk.LabelFrame(self.root, text="Lưu ý an toàn & Pháp lý", padding=8)
        disclaimer_frame.pack(fill=tk.X, padx=10, pady=5)

        disclaimer_text = (
            "⚠️ CHÚ Ý: Chỉ thực hiện quét trên máy localhost (127.0.0.1), máy ảo lab "
            "hoặc hệ thống mạng mà bạn được phân quyền quản trị/cho phép bằng văn bản. "
            "Hành vi quét không được phép có thể vi phạm quy chế an toàn thông tin."
        )
        ttk.Label(disclaimer_frame, text=disclaimer_text, foreground="#b35900", wraplength=920).pack(anchor=tk.W)

        # 2. Khung cấu hình quét mục tiêu
        input_frame = ttk.LabelFrame(self.root, text="Cấu hình quét mục tiêu", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=5)

        # Hàng 1: Mục tiêu IP và Cổng
        row1 = ttk.Frame(input_frame)
        row1.pack(fill=tk.X, pady=4)

        ttk.Label(row1, text="Mục tiêu (IP / Host):", width=18).pack(side=tk.LEFT)
        self.target_entry = ttk.Entry(row1, width=24)
        self.target_entry.insert(0, "127.0.0.1")
        self.target_entry.pack(side=tk.LEFT, padx=(5, 2))
        self.target_entry.bind("<KeyRelease>", lambda event: self.check_ip_target(silent=True))

        self.btn_check_ip = ttk.Button(row1, text="Kiểm tra IP", width=12, command=lambda: self.check_ip_target(silent=False))
        self.btn_check_ip.pack(side=tk.LEFT, padx=3)

        ttk.Label(row1, text="Danh sách cổng:").pack(side=tk.LEFT, padx=(15, 5))
        self.ports_entry = ttk.Entry(row1, width=32)
        self.ports_entry.insert(0, "21, 22, 80, 443, 3306, 3389, 8080")
        self.ports_entry.pack(side=tk.LEFT, padx=5)

        # Hàng 1.5: Nhãn thông tin xác thực IP trực tiếp
        row1_info = ttk.Frame(input_frame)
        row1_info.pack(fill=tk.X, pady=(1, 4))
        self.lbl_ip_feedback = ttk.Label(
            row1_info,
            text="● Mục tiêu: 127.0.0.1 (Loopback - Máy cục bộ kiểm thử an toàn)",
            foreground="#008000",
            font=("Arial", 8, "italic")
        )
        self.lbl_ip_feedback.pack(side=tk.LEFT, padx=(140, 5))

        # Hàng 2: Tùy chọn sẵn cổng & Tham số kết nối
        row2 = ttk.Frame(input_frame)
        row2.pack(fill=tk.X, pady=6)

        ttk.Label(row2, text="Mẫu cổng nhanh:", width=18).pack(side=tk.LEFT)
        self.port_preset_var = tk.StringVar(value="Cổng phổ biến")
        presets = ["Cổng phổ biến", "Web (80, 443, 8080, 8443)", "Database (1433, 1521, 3306, 5432, 27017)", "Khoảng 1-1024"]
        preset_menu = ttk.Combobox(row2, textvariable=self.port_preset_var, values=presets, state="readonly", width=30)
        preset_menu.pack(side=tk.LEFT, padx=5)
        preset_menu.bind("<<ComboboxSelected>>", self._on_preset_change)

        ttk.Label(row2, text="Timeout (giây):").pack(side=tk.LEFT, padx=(15, 5))
        self.timeout_spin = ttk.Spinbox(row2, from_=0.2, to=10.0, increment=0.2, width=6)
        self.timeout_spin.set(str(DEFAULT_TIMEOUT))
        self.timeout_spin.pack(side=tk.LEFT, padx=5)

        ttk.Label(row2, text="Số luồng:").pack(side=tk.LEFT, padx=(15, 5))
        self.threads_spin = ttk.Spinbox(row2, from_=1, to=200, increment=5, width=6)
        self.threads_spin.set(str(DEFAULT_MAX_THREADS))
        self.threads_spin.pack(side=tk.LEFT, padx=5)

        self.banner_var = tk.BooleanVar(value=False)
        self.chk_banner = ttk.Checkbutton(row2, text="Lấy Banner", variable=self.banner_var)
        self.chk_banner.pack(side=tk.LEFT, padx=(15, 5))

        # Nút điều khiển
        btn_frame = ttk.Frame(input_frame)
        btn_frame.pack(fill=tk.X, pady=(6, 0))

        self.btn_scan = ttk.Button(btn_frame, text="Bắt đầu quét", command=self.start_scan)
        self.btn_scan.pack(side=tk.LEFT, padx=5)

        self.btn_stop = ttk.Button(btn_frame, text="Dừng quét", command=self.stop_scan, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        self.btn_export = ttk.Button(btn_frame, text="Xuất báo cáo CSV", command=self.export_report, state=tk.DISABLED)
        self.btn_export.pack(side=tk.RIGHT, padx=5)

        # 3. Tiến trình
        progress_frame = ttk.Frame(self.root, padding=(10, 2))
        progress_frame.pack(fill=tk.X)

        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, side=tk.TOP, pady=2)

        self.status_label = ttk.Label(progress_frame, text="Sẵn sàng quét.", font=("Arial", 9, "italic"))
        self.status_label.pack(side=tk.LEFT)

        # 4. Bảng kết quả (Treeview)
        table_frame = ttk.LabelFrame(self.root, text="Bảng kết quả quét", padding=8)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        columns = ("ip", "port", "status", "service", "risk", "notes", "recommendation")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("ip", text="Mục tiêu (IP)")
        self.tree.heading("port", text="Cổng")
        self.tree.heading("status", text="Trạng thái")
        self.tree.heading("service", text="Dịch vụ")
        self.tree.heading("risk", text="Mức rủi ro")
        self.tree.heading("notes", text="Ghi chú phản hồi")
        self.tree.heading("recommendation", text="Khuyến nghị an toàn")

        self.tree.column("ip", width=110, anchor=tk.CENTER)
        self.tree.column("port", width=70, anchor=tk.CENTER)
        self.tree.column("status", width=95, anchor=tk.CENTER)
        self.tree.column("service", width=90, anchor=tk.CENTER)
        self.tree.column("risk", width=80, anchor=tk.CENTER)
        self.tree.column("notes", width=220)
        self.tree.column("recommendation", width=260)

        # Scrollbars
        y_scroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        x_scroll = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        # Tags màu cho trạng thái
        self.tree.tag_configure(STATUS_OPEN, foreground="#007700")
        self.tree.tag_configure(STATUS_CLOSED, foreground="#888888")
        self.tree.tag_configure(STATUS_FILTERED, foreground="#b37400")

    def _on_preset_change(self, event=None):
        choice = self.port_preset_var.get()
        if choice == "Cổng phổ biến":
            self.ports_entry.delete(0, tk.END)
            self.ports_entry.insert(0, ", ".join(str(p) for p in sorted(COMMON_PORTS.keys())))
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
            if not silent:
                detail_msg = (
                    f"Mục tiêu hợp lệ!\n\n"
                    f"- Địa chỉ IP: {res.resolved_ip}\n"
                    f"- Phân loại: {res.ip_type}\n"
                    f"- Thuộc LAN/Local: {'Có' if res.is_lan_or_local else 'Không (Public Internet)'}\n"
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
        target_input = self.target_entry.get().strip()
        ports_input = self.ports_entry.get().strip()

        # 1. Xác thực mục tiêu bằng validator ngày 04/11
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
        self.is_scanning = True
        self.btn_scan.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.btn_export.config(state=tk.DISABLED)
        self.progress_var.set(0)
        self.status_label.config(text=f"Đang quét mục tiêu {resolved_ip} ({len(ports)} cổng)...")

        self.scanner = PortScanner(
            target=resolved_ip,
            ports=ports,
            timeout=timeout,
            max_threads=max_threads,
            enable_banner=self.banner_var.get()
        )

        # Chạy trong luồng riêng để không treo giao diện
        thread = threading.Thread(target=self._run_scan_thread, daemon=True)
        thread.start()

    def _run_scan_thread(self):
        def on_progress(result: ScanResult, completed: int, total: int):
            # Phân tích an toàn ngay khi có kết quả
            analyzed = analyze_security(result)
            self.root.after(0, self._update_row_and_progress, analyzed, completed, total)

        results = self.scanner.scan(progress_callback=on_progress)
        self.scan_results = results
        self.root.after(0, self._on_scan_finished)

    def _update_row_and_progress(self, result: ScanResult, completed: int, total: int):
        percent = (completed / total) * 100
        self.progress_var.set(percent)
        self.status_label.config(text=f"Đã kiểm tra {completed}/{total} cổng ({percent:.1f}%)")

        self.tree.insert(
            "",
            tk.END,
            values=(
                result.target_ip,
                result.port,
                result.status,
                result.service,
                result.risk_level,
                result.notes,
                result.recommendation,
            ),
            tags=(result.status,)
        )

    def _on_scan_finished(self):
        self.is_scanning = False
        self.btn_scan.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.btn_export.config(state=tk.NORMAL)

        open_count = sum(1 for r in self.scan_results if r.status == STATUS_OPEN)
        self.status_label.config(
            text=f"Hoàn thành quét! Tổng số: {len(self.scan_results)} cổng | Mở (OPEN): {open_count} cổng."
        )

    def stop_scan(self):
        if self.scanner and self.is_scanning:
            self.scanner.stop()
            self.status_label.config(text="Đang dừng tiến trình quét...")

    def export_report(self):
        if not self.scan_results:
            messagebox.showwarning("Cảnh báo", "Không có dữ liệu để xuất báo cáo.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            title="Lưu báo cáo quét cổng"
        )
        if file_path:
            try:
                saved_path = export_to_csv(self.scan_results, file_path)
                messagebox.showinfo("Thành công", f"Đã xuất báo cáo ra file:\n{saved_path}")
            except Exception as e:
                messagebox.showerror("Lỗi", f"Không thể xuất file: {str(e)}")


def run_gui():
    """Khởi chạy giao diện Tkinter."""
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()

