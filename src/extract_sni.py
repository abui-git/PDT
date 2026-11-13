#!/usr/bin/env python3
"""Extract TLS SNI from pcap/pcapng using Scapy (internal use)."""

import os
import sys
from pathlib import Path

try:
    from scapy.all import PcapReader, TCP, Raw, UDP
except ImportError:
    sys.exit("Scapy tidak terinstal. Jalankan: pip install scapy")


def parse_client_hello(payload: bytes):
    """Kembalikan SNI dari ClientHello, atau None."""
    if len(payload) < 6 or payload[0] != 0x16 or payload[5] != 0x01:
        return None
    try:
        # TLS record header 5 byte, handshake header 4 byte
        p = 5 + 4
        p += 2 + 32  # version + random
        sid_len = payload[p]; p += 1 + sid_len
        cs_len = int.from_bytes(payload[p:p+2], "big"); p += 2 + cs_len
        cm_len = payload[p]; p += 1 + cm_len
        ext_total = int.from_bytes(payload[p:p+2], "big"); p += 2
        end = p + ext_total
        while p + 4 <= end and p + 4 <= len(payload):
            etype = int.from_bytes(payload[p:p+2], "big")
            elen = int.from_bytes(payload[p+2:p+4], "big")
            p += 4
            if etype == 0x0000 and p + 5 <= len(payload):
                # server_name_list
                name_len = int.from_bytes(payload[p+3:p+5], "big")
                name = payload[p+5:p+5+name_len].decode("ascii", errors="ignore")
                if name and "." in name:
                    return name
            p += elen
    except Exception:
        return None
    return None


def extract_sni_from_pcap(path: str):
    names = set()
    count = 0
    try:
        with PcapReader(path) as reader:
            for pkt in reader:
                count += 1
                if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                    sni = parse_client_hello(bytes(pkt[Raw].load))
                    if sni:
                        names.add(sni)
    except Exception as exc:
        print(f"[PDT] Peringatan: pembacaan berhenti di paket {count}: {exc}", file=sys.stderr)
    return sorted(names), count


def extract_sni(path, output=None):
    names, count = extract_sni_from_pcap(path)
    print(f"[PDT] Paket dibaca: {count}")
    print(f"[PDT] SNI ditemukan: {len(names)}")
    if output:
        os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
        Path(output).write_text("\n".join(names) + ("\n" if names else ""), encoding="utf-8")
        print(f"[PDT] Ditulis ke {output}")
    else:
        for n in names:
            print(n)
    return names


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Extract TLS SNI from pcap (internal use).")
    parser.add_argument("--file", required=True)
    parser.add_argument("--out", help="Path output teks (opsional)")
    args = parser.parse_args()
    extract_sni(args.file, args.out)


if __name__ == "__main__":
    main()
