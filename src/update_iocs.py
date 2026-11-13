#!/usr/bin/env python3
"""
Update IOC list from Amnesty International public sources.

Fetches domains.txt, converts to data/iocs.json format.
Internal use only. IOC match is not proof of infection.
"""

import json
import os
import sys
import urllib.request
from datetime import datetime, timezone

AMNESTY_DOMAINS_URL = (
    "https://raw.githubusercontent.com/AmnestyTech/investigations/"
    "master/2021-07-18_nso/domains.txt"
)

DEFAULT_OUTPUT = "data/iocs.json"
SOURCE_LABEL = "Amnesty International 2021-07-18_nso"


def fetch_domains(url=AMNESTY_DOMAINS_URL, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "PDT-internal/2.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    domains = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        domains.append(line)
    return domains


def build_iocs(domains, source=SOURCE_LABEL, confidence="high"):
    return [
        {
            "type": "domain",
            "value": d,
            "source": source,
            "confidence": confidence,
        }
        for d in domains
    ]


def update_iocs(output=DEFAULT_OUTPUT, force=False, url=AMNESTY_DOMAINS_URL):
    if os.path.exists(output) and not force:
        sys.exit(
            f"ERROR: {output} sudah ada. Gunakan --force untuk menimpa."
        )

    print(f"[PDT] Mengunduh: {url}")
    domains = fetch_domains(url)
    if not domains:
        sys.exit("ERROR: tidak ada domain yang berhasil diunduh.")

    iocs = build_iocs(domains)
    os.makedirs(os.path.dirname(output), exist_ok=True)

    with open(output, "w", encoding="utf-8") as f:
        json.dump(iocs, f, indent=2, ensure_ascii=False)

    print(f"[PDT] Selesai. {len(iocs)} domain ditulis ke {output}")
    print("[!] IOC match bukan bukti infeksi; no match bukan bukti bersih.")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Fetch latest IOC list from Amnesty International (internal use)."
    )
    parser.add_argument("--output", default=DEFAULT_OUTPUT,
                        help=f"Path output (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--force", action="store_true",
                        help="Timpa file yang sudah ada")
    parser.add_argument("--url", default=AMNESTY_DOMAINS_URL,
                        help="URL sumber domains.txt")
    args = parser.parse_args()
    update_iocs(output=args.output, force=args.force, url=args.url)


if __name__ == "__main__":
    main()
