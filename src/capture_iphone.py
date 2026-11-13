#!/usr/bin/env python3
"""
Capture iPhone network traffic to pcapng via pymobiledevice3.

Internal use only. Requires:
  - pymobiledevice3 installed (pip install pymobiledevice3)
  - iPhone connected via USB, unlocked, and trusted
"""

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
from datetime import datetime, timezone

TOOL_VERSION = "2.1.0-internal"


def require_operator():
    op = os.environ.get("PDT_OPERATOR", "").strip()
    if not op:
        sys.exit("ERROR: PDT_OPERATOR wajib diisi untuk mode internal.")
    return op


def check_backend():
    if shutil.which("pymobiledevice3") is None:
        sys.exit(
            "ERROR: pymobiledevice3 tidak ditemukan. "
            "Instal dengan: pip install pymobiledevice3"
        )


def default_output_path():
    os.makedirs("captures", exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return os.path.join("captures", f"iphone_{ts}.pcapng")


def write_audit(log_path, entry):
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def build_command(args, out_path):
    cmd = ["pymobiledevice3", "pcap", "--out", out_path]
    if args.process:
        cmd += ["--process", args.process]
    if args.interface:
        cmd += ["-i", args.interface]
    return cmd


def run_capture(args):
    operator = require_operator()
    check_backend()

    out_path = args.out or default_output_path()
    cmd = build_command(args, out_path)

    print(f"[PDT] Operator : {operator}")
    print(f"[PDT] Command  : {' '.join(cmd)}")
    print(f"[PDT] Output   : {out_path}")
    if args.duration:
        print(f"[PDT] Duration : {args.duration}s")
    print("[PDT] Mulai menangkap. Tekan Ctrl+C untuk berhenti.")

    proc = subprocess.Popen(cmd)

    def handle_sigint(signum, frame):
        print("\n[PDT] Menghentikan penangkapan...")
        proc.send_signal(signal.SIGINT)

    signal.signal(signal.SIGINT, handle_sigint)

    try:
        proc.wait(timeout=args.duration if args.duration else None)
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait()
        print(f"[PDT] Durasi {args.duration}s tercapai, penangkapan dihentikan.")

    exit_code = proc.returncode
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool_version": TOOL_VERSION,
        "operator": operator,
        "command": "capture-iphone",
        "output_file": out_path,
        "process_filter": args.process,
        "interface": args.interface,
        "duration": args.duration,
        "exit_code": exit_code,
    }
    write_audit(args.audit_log, entry)

    if exit_code not in (0, -15):
        sys.exit(f"ERROR: pymobiledevice3 keluar dengan kode {exit_code}")

    if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
        sys.exit("ERROR: file output tidak terbentuk atau kosong.")

    print(f"[PDT] Selesai. File: {out_path} ({os.path.getsize(out_path)} bytes)")


def main():
    parser = argparse.ArgumentParser(
        description="Capture iPhone traffic to pcapng (internal use)."
    )
    parser.add_argument("--out", help="Path output pcapng (default: captures/iphone_<ts>.pcapng)")
    parser.add_argument("--process", help="Filter berdasarkan nama proses (mis. MobileSafari)")
    parser.add_argument("--interface", help="Filter antarmuka (mis. en0, pdp_ip0)")
    parser.add_argument("--duration", type=int, help="Durasi penangkapan dalam detik")
    parser.add_argument(
        "--audit-log",
        default="logs/audit.jsonl",
        help="Path audit log JSON Lines (default: logs/audit.jsonl)",
    )
    args = parser.parse_args()
    run_capture(args)


if __name__ == "__main__":
    main()