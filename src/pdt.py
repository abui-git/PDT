#!/usr/bin/env python3
"""
Pegasus Defense Toolkit (PDT) v2.0
Defensive, offline-first IOC auditing and blocklist generation.

This tool does NOT detect or remove Pegasus comprehensively.
It does NOT change macOS firewall, router, DNS, or iPhone settings.
PCAP analysis is offline only.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from datetime import datetime, timezone

# --- Banner (merah-putih, internal) ---
RED = "\033[1;31m"
WHITE = "\033[1;97m"
RESET = "\033[0m"

BANNER = f"""{RED}
  █████╗ ██████╗ ██╗   ██╗██╗
 ██╔══██╗██╔══██╗██║   ██║██║
 ███████║██████╔╝██║   ██║██║
 ██╔══██║██╔══██╗██║   ██║██║
 ██║  ██║██████╔╝╚██████╔╝██║
 ╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝{WHITE}
        Pegasus Defense Toolkit
     internal · offline · reviewable{RESET}
"""


def print_banner():
    print(BANNER)

from capture_iphone import run_capture
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
REPORTS = ROOT / "reports"
OUTPUT = ROOT / "output"
IOC_FILE = DATA / "iocs.json"
APPROVED_FILE = DATA / "approved_iocs.json"

DOMAIN_RE = re.compile(
    r"(?i)(?<![a-z0-9_.-])"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}"
    r"(?![a-z0-9_.-])"
)
SHA256_RE = re.compile(r"(?i)^[a-f0-9]{64}$")
VALID_TYPES = {"domain", "ip", "sha256"}


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return now_utc().isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return []
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8") as handle:
        json.dump(obj, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    temp.replace(path)


def normalize_domain(value: str) -> str | None:
    value = value.strip().rstrip(".").lower()
    if not value or len(value) > 253 or "/" in value or ":" in value:
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = value.split(".")
    if len(labels) < 2:
        return None
    for label in labels:
        if not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
            label,
        ):
            return None
    return value


def normalize_ioc(item: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    kind = item.get("type")
    value = item.get("value")
    if kind not in VALID_TYPES or not isinstance(value, str):
        return None

    if kind == "domain":
        normalized = normalize_domain(value)
        if not normalized:
            return None
        value = normalized
    elif kind == "ip":
        try:
            value = str(ipaddress.ip_address(value.strip()))
        except ValueError:
            return None
    elif kind == "sha256":
        value = value.strip().lower()
        if not SHA256_RE.fullmatch(value):
            return None

    return {**item, "type": kind, "value": value}


def load_iocs(path: Path = IOC_FILE) -> tuple[list[dict[str, Any]], list[str]]:
    raw = load_json(path)
    if not isinstance(raw, list):
        raise ValueError(f"{path} must contain a JSON array")
    valid, rejected = [], []
    for index, item in enumerate(raw):
        normalized = normalize_ioc(item)
        if normalized is None:
            rejected.append(f"entry[{index}] invalid")
        else:
            valid.append(normalized)
    return valid, rejected


def is_expired(item: dict[str, Any]) -> bool:
    expires = item.get("expires_at")
    if not isinstance(expires, str):
        return True
    try:
        parsed = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return True
        return parsed <= now_utc()
    except ValueError:
        return True


def domain_matches(observed: str, indicator: str) -> bool:
    observed = normalize_domain(observed) or observed.lower().rstrip(".")
    indicator = normalize_domain(indicator) or indicator.lower().rstrip(".")
    return observed == indicator or observed.endswith("." + indicator)


def make_report(kind: str, source: Path, findings: list[dict[str, Any]],
                metadata: dict[str, Any] | None = None) -> Path:
    REPORTS.mkdir(parents=True, exist_ok=True)
    report = {
        "tool": "Pegasus Defense Toolkit",
        "version": "2.0",
        "analysis_type": kind,
        "timestamp_utc": iso_now(),
        "input_file": source.name,
        "input_sha256": sha256_file(source),
        "finding_count": len(findings),
        "findings": findings,
        "metadata": metadata or {},
        "interpretation": (
            "IOC_MATCH_REQUIRES_CONTEXTUAL_VALIDATION"
            if findings else "NO_KNOWN_IOC_MATCH"
        ),
        "limitations": [
            "An IOC match is not proof of Pegasus infection.",
            "No match does not prove a device is clean.",
            "Coverage depends on IOC quality, age, and available artifacts.",
            "This tool does not remove spyware or modify network settings."
        ]
    }
    name = f"{kind}_{now_utc().strftime('%Y%m%dT%H%M%SZ')}.json"
    destination = REPORTS / name
    save_json(destination, report)
    return destination


def scan_text(path: Path) -> Path:
    iocs, rejected = load_iocs()
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    observed_domains = {m.group(0).lower().rstrip(".") for m in DOMAIN_RE.finditer(text)}
    observed_ips: set[str] = set()

    # Extract IPv4 candidates, then validate with ipaddress.
    for candidate in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text):
        try:
            observed_ips.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            pass

    file_hash = hashlib.sha256(raw).hexdigest()
    findings = []
    for ioc in iocs:
        matched = False
        if ioc["type"] == "domain":
            matched = any(domain_matches(domain, ioc["value"]) for domain in observed_domains)
        elif ioc["type"] == "ip":
            matched = ioc["value"] in observed_ips
        elif ioc["type"] == "sha256":
            matched = ioc["value"] == file_hash

        if matched:
            findings.append({
                "type": ioc["type"],
                "value": ioc["value"],
                "source": ioc.get("source"),
                "confidence": ioc.get("confidence", "unspecified"),
                "context": "exact file hash or domain/IP token match"
            })

    return make_report(
        "text_audit", path, findings,
        {"ioc_count": len(iocs), "rejected_ioc_entries": rejected}
    )


def scan_pcap(path: Path) -> Path:
    try:
        from scapy.all import DNS, DNSQR, IP, IPv6, rdpcap
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is not installed. Run: python3 -m pip install -r requirements.txt"
        ) from exc

    iocs, rejected = load_iocs()
    pcap_sha = sha256_file(path)
    packets = rdpcap(str(path))
    observed_domains: set[str] = set()
    observed_ips: set[str] = set()
    dns_queries = 0
    packet_count = len(packets)

    for packet in packets:
        if IP in packet:
            observed_ips.add(packet[IP].src)
            observed_ips.add(packet[IP].dst)
        if IPv6 in packet:
            observed_ips.add(packet[IPv6].src)
            observed_ips.add(packet[IPv6].dst)
        if DNS in packet and packet[DNS].qd is not None:
            qd = packet[DNS].qd
            # DNS question sections may be chained.
            while qd:
                if DNSQR in qd:
                    dns_queries += 1
                    raw_name = qd[DNSQR].qname
                    if isinstance(raw_name, bytes):
                        raw_name = raw_name.decode("ascii", errors="ignore")
                    normalized = normalize_domain(str(raw_name))
                    if normalized:
                        observed_domains.add(normalized)
                qd = getattr(qd, "payload", None)
                if not qd or qd.__class__.__name__ == "NoPayload":
                    break

    findings = []
    for ioc in iocs:
        matched = False
        if ioc["type"] == "domain":
            matched = any(domain_matches(d, ioc["value"]) for d in observed_domains)
        elif ioc["type"] == "ip":
            matched = ioc["value"] in observed_ips
        # A PCAP file's SHA256 is not equivalent to a payload/file IOC.
        if matched:
            findings.append({
                "type": ioc["type"],
                "value": ioc["value"],
                "source": ioc.get("source"),
                "confidence": ioc.get("confidence", "unspecified"),
                "context": "observed in packet capture"
            })

    report = make_report(
        "pcap_audit", path, findings,
        {
            "packet_count": packet_count,
            "dns_query_count": dns_queries,
            "unique_dns_names": len(observed_domains),
            "unique_ip_addresses": len(observed_ips),
            "ioc_count": len(iocs),
            "rejected_ioc_entries": rejected,
            "pcap_sha256": pcap_sha
        }
    )
    return report


def scan_mvt_json(path: Path) -> Path:
    iocs, rejected = load_iocs()
    raw = path.read_bytes()
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("MVT input must be valid UTF-8 JSON") from exc

    # Collect string values recursively; do not treat arbitrary text as proof.
    strings: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                strings.append(str(k))
                walk(v)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, (str, int, float)):
            strings.append(str(value))

    walk(parsed)
    joined = "\n".join(strings)
    domains = {m.group(0).lower().rstrip(".") for m in DOMAIN_RE.finditer(joined)}
    ips: set[str] = set()
    for candidate in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", joined):
        try:
            ips.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            pass

    findings = []
    for ioc in iocs:
        matched = False
        if ioc["type"] == "domain":
            matched = any(domain_matches(d, ioc["value"]) for d in domains)
        elif ioc["type"] == "ip":
            matched = ioc["value"] in ips
        # Hash matching against MVT JSON strings is intentionally omitted:
        # artifact hashes and file hashes have different semantics.
        if matched:
            findings.append({
                "type": ioc["type"],
                "value": ioc["value"],
                "source": ioc.get("source"),
                "confidence": ioc.get("confidence", "unspecified"),
                "context": "indicator string found in MVT JSON output; review original MVT finding"
            })

    return make_report(
        "mvt_json_correlation", path, findings,
        {
            "ioc_count": len(iocs),
            "rejected_ioc_entries": rejected,
            "note": "Correlation aid only; does not replace MVT interpretation."
        }
    )


def generate_blocklists() -> tuple[Path, Path, Path]:
    approved, rejected = load_iocs(APPROVED_FILE)
    domains, ips = [], []
    excluded = []

    for item in approved:
        reason = None
        if item.get("verified") is not True:
            reason = "not explicitly verified"
        elif item.get("confidence") != "high":
            reason = "confidence is not high"
        elif not item.get("source"):
            reason = "missing source"
        elif is_expired(item):
            reason = "missing, invalid, or expired expires_at"

        if reason:
            excluded.append({"value": item.get("value"), "reason": reason})
            continue

        if item["type"] == "domain":
            domains.append(item["value"])
        elif item["type"] == "ip":
            ips.append(item["value"])
        else:
            excluded.append({"value": item["value"], "reason": "hashes are not network block rules"})

    domains = sorted(set(domains))
    ips = sorted(set(ips))
    OUTPUT.mkdir(parents=True, exist_ok=True)

    domain_path = OUTPUT / "domains_blocklist.txt"
    ip_path = OUTPUT / "ips_blocklist.txt"
    dnsmasq_path = OUTPUT / "dnsmasq_blocklist.conf"

    domain_path.write_text("".join(d + "\n" for d in domains), encoding="utf-8")
    ip_path.write_text("".join(i + "\n" for i in ips), encoding="utf-8")
    # Output is a reviewable config snippet; it is not installed or activated.
    dnsmasq_path.write_text(
        "# Review before deploying on a DNS resolver/router.\n"
        + "".join(f"address=/{d}/0.0.0.0\naddress=/{d}/::\n" for d in domains),
        encoding="utf-8"
    )

    manifest = {
        "generated_utc": iso_now(),
        "approved_domain_count": len(domains),
        "approved_ip_count": len(ips),
        "excluded": excluded,
        "rejected_entries": rejected,
        "warning": "Files are outputs for administrator review; no network settings were changed."
    }
    save_json(OUTPUT / "blocklist_manifest.json", manifest)
    return domain_path, ip_path, dnsmasq_path


def main() -> int:
    print_banner()
    parser = argparse.ArgumentParser(
        description="PDT: local defensive IOC audit and blocklist generator"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_text = sub.add_parser("audit-text", help="Audit a text/log file against local IOC data")
    p_text.add_argument("--file", required=True)

    p_pcap = sub.add_parser("audit-pcap", help="Offline analysis of an existing PCAP file")
    p_pcap.add_argument("--file", required=True)

    p_mvt = sub.add_parser("correlate-mvt", help="Correlate MVT JSON output with local IOC data")
    p_mvt.add_argument("--file", required=True)

    sub.add_parser("blocklist", help="Generate reviewable blocklist files from approved_iocs.json")

    p_cap = sub.add_parser("capture-iphone", help="Capture iPhone traffic to pcapng via USB")
    p_cap.add_argument("--out", help="Path output pcapng")
    p_cap.add_argument("--process", help="Filter by process name (e.g. MobileSafari)")
    p_cap.add_argument("--interface", help="Filter by interface (e.g. en0, pdp_ip0)")
    p_cap.add_argument("--duration", type=int, help="Capture duration in seconds")
    p_cap.add_argument("--audit-log", default="logs/audit.jsonl",
                       help="Path to audit log (default: logs/audit.jsonl)")

    p_man = sub.add_parser("manifest", help="Hash capture files and append to manifest")
    p_man.add_argument("files", nargs="+", help="One or more capture files")

    p_ioc = sub.add_parser("update-iocs", help="Fetch latest IOC list from Amnesty International")
    p_ioc.add_argument("--output", default="data/iocs.json")
    p_ioc.add_argument("--force", action="store_true")

    args = parser.parse_args()

    try:
        if args.command == "audit-text":
            report = scan_text(Path(args.file).expanduser())
            print(f"[+] Report: {report}")
        elif args.command == "audit-pcap":
            report = scan_pcap(Path(args.file).expanduser())
            print(f"[+] Report: {report}")
        elif args.command == "correlate-mvt":
            report = scan_mvt_json(Path(args.file).expanduser())
            print(f"[+] Report: {report}")
        elif args.command == "blocklist":
            outputs = generate_blocklists()
            for path in outputs:
                print(f"[+] Generated: {path}")
            print("[!] No firewall, DNS, router, or iPhone settings were changed.")
        elif args.command == "capture-iphone":
            run_capture(args)
        elif args.command == "manifest":
            from manifest import process_files
            process_files(args.files)
        elif args.command == "update-iocs":
            from update_iocs import update_iocs
            update_iocs(output=args.output, force=args.force)
        return 0
    except (OSError, ValueError, RuntimeError, FileNotFoundError) as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    for folder in (DATA, REPORTS, OUTPUT):
        folder.mkdir(parents=True, exist_ok=True)
    raise SystemExit(main())
