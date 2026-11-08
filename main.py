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

from src.core.validator import (
    parse_ports,
    prompt_user_for_ip,
    resolve_host,
    validate_target,
)
from src.core.scanner import PortScanner, scan_single_port, scan_ports_sequential
from src.core.analyzer import analyze_all_results, analyze_security
from src.core.exporter import export_to_csv
from src.config import DEFAULT_TIMEOUT, DEFAULT_MAX_THREADS


def run_single_port_scan_cli(target_input: str, port: int, timeout: float, enable_banner: bool):
    """Kiểm tra chi tiết một cổng TCP đơn lẻ bằng Socket"""
    print("=" * 65)
    print(" CHI TIẾT QUÉT CỔNG TCP BẰNG SOCKET")
    print("=" * 65)

    target_res = validate_target(target_input)
    if not target_res.is_valid:
        print(f"[!] Lỗi xác thực mục tiêu: {target_res.error_message}")
        sys.exit(1)

    resolved_ip = target_res.resolved_ip
    print(f"[*] Mục tiêu       : {resolved_ip} ({target_res.original_input})")
    print(f"[*] Cổng kiểm tra  : {port}")
    print(f"[*] Timeout        : {timeout}s")
    print(f"[*] Banner Grabbing: {'Bật' if enable_banner else 'Tắt'}")
    print("-" * 65)

    res = scan_single_port(resolved_ip, port, timeout=timeout, enable_banner=enable_banner)
    analyzed = analyze_security(res)

    print(f"[+] Trạng thái cổng: {analyzed.status}")
    print(f"[+] Mã lỗi Socket  : {analyzed.error_code} ({analyzed.notes})")
    print(f"[+] Độ trễ (RTT)   : {analyzed.response_time_ms} ms")
    print(f"[+] Dịch vụ dự đoán: {analyzed.service}")
    if analyzed.banner:
        print(f"[+] Banner dịch vụ : {analyzed.banner}")
    print(f"[+] Mức độ rủi ro  : {analyzed.risk_level}")
    print(f"[+] Khuyến nghị    : {analyzed.recommendation}")
    print("=" * 65)


def run_cli_mode(
    target_input: str,
    ports_input: str,
    timeout: float,
    threads: int,
    export: bool,
    sequential: bool = False,
    enable_banner: bool = False
):
    """Chạy chế độ quét dòng lệnh (CLI)."""
    print("=" * 65)
    print(" LAN PORT SCANNER & ANALYZER (CLI MODE)")
    print("=" * 65)

    # 1. Xác thực và phân loại mục tiêu
    target_res = validate_target(target_input)
    if not target_res.is_valid:
        print(f"[!] Lỗi xác thực mục tiêu: {target_res.error_message}")
        sys.exit(1)

    resolved_ip = target_res.resolved_ip

    # 2. Phân giải danh sách cổng
    ports = parse_ports(ports_input)
    if not ports:
        print("[!] Không tìm thấy cổng hợp lệ nào trong danh sách (1-65535).")
        sys.exit(1)

    mode_str = "Tuần tự đơn luồng (Sequential Socket)" if sequential else f"Đa luồng ({threads} worker threads)"
    print(f"[*] Mục tiêu: {resolved_ip} (từ '{target_input}')")
    print(f"[*] Phân loại: {target_res.ip_type}")
    if target_res.warning_message:
        print(f"[*] Lưu ý: {target_res.warning_message}")
    print(f"[*] Tổng số cổng cần quét: {len(ports)}")
    print(f"[*] Chế độ quét: {mode_str} | Timeout: {timeout}s | Banner: {'Bật' if enable_banner else 'Tắt'}")
    print("=" * 65)

    if sequential:
        raw_results = scan_ports_sequential(
            resolved_ip,
            ports,
            timeout=timeout,
            enable_banner=enable_banner
        )
    else:
        scanner = PortScanner(
            target=resolved_ip,
            ports=ports,
            timeout=timeout,
            max_threads=threads,
            enable_banner=enable_banner
        )
        raw_results = scanner.scan()

    analyzed_results = analyze_all_results(raw_results)

    print(f"{'CỔNG':<8} | {'TRẠNG THÁI':<16} | {'ĐỘ TRỄ':<9} | {'DỊCH VỤ':<12} | {'RỦI RO':<8} | {'KHUYẾN NGHỊ'}")
    print("-" * 85)
    for r in analyzed_results:
        rec_summary = (r.recommendation[:25] + "...") if len(r.recommendation) > 25 else r.recommendation
        rtt_str = f"{r.response_time_ms}ms"
        print(f"{r.port:<8} | {r.status:<16} | {r.rtt_str if hasattr(r, 'rtt_str') else rtt_str:<9} | {r.service:<12} | {r.risk_level:<8} | {rec_summary}")

    if export:
        file_path = export_to_csv(analyzed_results)
        print("=" * 65)
        print(f"[+] Báo cáo đã được lưu tại: {file_path}")


def main():
    parser = argparse.ArgumentParser(description="Công cụ quét và phân tích cổng mạng LAN hỗ trợ đánh giá an toàn.")
    parser.add_argument("--cli", action="store_true", help="Chạy ở chế độ dòng lệnh (CLI)")
    parser.add_argument("-t", "--target", type=str, default="127.0.0.1", help="Địa chỉ IP hoặc tên miền mục tiêu")
    parser.add_argument("-p", "--ports", type=str, default="21,22,80,443,3306,3389,8080", help="Danh sách hoặc dải cổng (ví dụ: '80,443' hoặc '1-100')")
    parser.add_argument("--single-port", type=int, help="Quét chi tiết một cổng TCP đơn lẻ bằng Socket (Chức năng 05/11)")
    parser.add_argument("--sequential", action="store_true", help="Sử dụng quét tuần tự đơn luồng (Socket Sequential Scan)")
    parser.add_argument("--banner", action="store_true", help="Bật thu thập biểu ngữ dịch vụ (Banner Grabbing)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Thời gian chờ kết nối (giây)")
    parser.add_argument("--threads", type=int, default=DEFAULT_MAX_THREADS, help="Số luồng quét đồng thời tối đa")
    parser.add_argument("--export", action="store_true", help="Tự động xuất báo cáo CSV sau khi quét")
    parser.add_argument("--check-ip", type=str, help="Kiểm tra tính hợp lệ và phân loại của một địa chỉ IP / Hostname")
    parser.add_argument("--interactive-ip", action="store_true", help="Chạy chế độ nhập IP tương tác với kiểm tra trực tiếp")

    args = parser.parse_args()

    if args.check_ip:
        run_ip_validation_cli(args.check_ip)
    elif args.interactive_ip:
        prompt_user_for_ip()
    elif args.single_port:
        run_single_port_scan_cli(args.target, args.single_port, args.timeout, args.banner)
    elif args.cli:
        run_cli_mode(
            args.target,
            args.ports,
            args.timeout,
            args.threads,
            args.export,
            sequential=args.sequential,
            enable_banner=args.banner
        )
    else:
        try:
            from src.gui.app import run_gui
            run_gui()
        except ImportError as e:
            print(f"[!] Không thể mở giao diện đồ họa Tkinter: {e}")
            print("[*] Chuyển hướng sang chế độ dòng lệnh (CLI)...")
            run_cli_mode(
                args.target,
                args.ports,
                args.timeout,
                args.threads,
                args.export,
                sequential=args.sequential,
                enable_banner=args.banner
            )


if __name__ == "__main__":
    main()
