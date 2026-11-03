"""Điểm khởi chạy chính (Entry Point) của ứng dụng LAN Port Scanner."""

import argparse
import sys

# Đảm bảo mã hóa console hỗ trợ tiếng Việt trên Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from src.core.validator import resolve_host, parse_ports
from src.core.scanner import PortScanner
from src.core.analyzer import analyze_all_results
from src.core.exporter import export_to_csv
from src.config import DEFAULT_TIMEOUT, DEFAULT_MAX_THREADS


def run_cli_mode(target_input: str, ports_input: str, timeout: float, threads: int, export: bool):
    """Chạy chế độ quét dòng lệnh (CLI)."""
    print("=" * 60)
    print(" LAN PORT SCANNER & ANALYZER (CLI MODE)")
    print("=" * 60)

    # 1. Phân giải host
    ok, resolved_ip = resolve_host(target_input)
    if not ok:
        print(f"[!] Lỗi phân giải mục tiêu: {resolved_ip}")
        sys.exit(1)

    # 2. Phân giải danh sách cổng
    ports = parse_ports(ports_input)
    if not ports:
        print("[!] Không tìm thấy cổng hợp lệ nào trong danh sách.")
        sys.exit(1)

    print(f"[*] Mục tiêu: {resolved_ip} (từ '{target_input}')")
    print(f"[*] Tổng số cổng cần quét: {len(ports)}")
    print(f"[*] Cấu hình: Timeout = {timeout}s, Số luồng = {threads}")
    print("=" * 60)

    scanner = PortScanner(target=resolved_ip, ports=ports, timeout=timeout, max_threads=threads)
    raw_results = scanner.scan()
    analyzed_results = analyze_all_results(raw_results)

    print(f"{'CỔNG':<8} | {'TRẠNG THÁI':<15} | {'DỊCH VỤ':<12} | {'RỦI RO':<8} | {'KHUYẾN NGHỊ'}")
    print("-" * 75)
    for r in analyzed_results:
        rec_summary = (r.recommendation[:30] + "...") if len(r.recommendation) > 30 else r.recommendation
        print(f"{r.port:<8} | {r.status:<15} | {r.service:<12} | {r.risk_level:<8} | {rec_summary}")

    if export:
        file_path = export_to_csv(analyzed_results)
        print("=" * 60)
        print(f"[+] Báo cáo đã được lưu tại: {file_path}")


def main():
    parser = argparse.ArgumentParser(description="Công cụ quét và phân tích cổng mạng LAN hỗ trợ đánh giá an toàn.")
    parser.add_argument("--cli", action="store_true", help="Chạy ở chế độ dòng lệnh (CLI)")
    parser.add_argument("-t", "--target", type=str, default="127.0.0.1", help="Địa chỉ IP hoặc tên miền mục tiêu")
    parser.add_argument("-p", "--ports", type=str, default="21,22,80,443,3306,3389,8080", help="Danh sách hoặc dải cổng (ví dụ: '80,443' hoặc '1-100')")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Thời gian chờ kết nối (giây)")
    parser.add_argument("--threads", type=int, default=DEFAULT_MAX_THREADS, help="Số luồng quét đồng thời tối đa")
    parser.add_argument("--export", action="store_true", help="Tự động xuất báo cáo CSV sau khi quét")

    args = parser.parse_args()

    if args.cli:
        run_cli_mode(args.target, args.ports, args.timeout, args.threads, args.export)
    else:
        try:
            from src.gui.app import run_gui
            run_gui()
        except ImportError as e:
            print(f"[!] Không thể mở giao diện đồ họa Tkinter: {e}")
            print("[*] Chuyển hướng sang chế độ dòng lệnh (CLI)...")
            run_cli_mode(args.target, args.ports, args.timeout, args.threads, args.export)


if __name__ == "__main__":
    main()
