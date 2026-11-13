# Pegasus Defense Toolkit (PDT) v2.0

Defensive, offline-first IOC auditing and reviewable blocklist generation for macOS.

## Important limitations

- This is **not** a Pegasus detector or remover.
- An IOC match is not proof of infection; no match does not prove a device is clean.
- MVT correlation is a convenience layer and does not replace review of original MVT output.
- PCAP analysis is offline. It only sees traffic present in the supplied capture.
- The toolkit never changes macOS firewall, router, DNS, or iPhone settings.
- Blocklist files are generated for administrator review and manual deployment.

## Requirements

- macOS (Intel or Apple Silicon)
- Python 3.11+
- pip
- Scapy for PCAP analysis

## Setup

From Terminal:

```bash
cd ~/PDT
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If `python3` is older than 3.11, install a current Python from https://www.python.org/downloads/macos/ and reopen Terminal.

## IOC format

Edit `data/iocs.json`:

```json
[
  {
    "type": "domain",
    "value": "example.invalid",
    "source": "Example threat-intelligence report",
    "confidence": "high"
  }
]
```

Supported IOC types: `domain`, `ip`, `sha256`.

Only add indicators from trusted, attributable threat-intelligence sources. Do not treat sample/test indicators as real malicious infrastructure.

## Commands

### Audit a text log

```bash
python src/pdt.py audit-text --file /path/to/log.txt
```

### Analyze an existing PCAP offline

```bash
python src/pdt.py audit-pcap --file /path/to/capture.pcap
```

### Correlate MVT JSON output

```bash
python src/pdt.py correlate-mvt --file /path/to/mvt-output.json
```

This is a string-level correlation aid. Review the original MVT findings, artifact paths, timestamps, and IOC source before drawing conclusions.

### Generate blocklist files

Place only approved indicators in `data/approved_iocs.json`:

```json
[
  {
    "type": "domain",
    "value": "example.invalid",
    "source": "Trusted report URL or document reference",
    "confidence": "high",
    "verified": true,
    "expires_at": "2027-01-01T00:00:00Z"
  }
]
```

Then run:

```bash
python src/pdt.py blocklist
```

Outputs:
- `output/domains_blocklist.txt`
- `output/ips_blocklist.txt`
- `output/dnsmasq_blocklist.conf`
- `output/blocklist_manifest.json`

The generator excludes indicators that are not explicitly verified, are not high confidence, lack a source, or have missing/invalid/expired expiry timestamps. SHA-256 hashes are not network block rules.

**Do not deploy blocklists without administrator review.** Incorrect blocking can disrupt legitimate services. DNS blocking does not stop direct-IP traffic, cellular traffic, VPNs, encrypted DNS, or all alternate network paths.

## Internal capture and SNI audit workflow

These commands are for internal use on macOS with an iPhone connected via USB.
They require `pymobiledevice3`:

    pip install pymobiledevice3

Set the operator name before capture (required, fail-closed):

    export PDT_OPERATOR="your-name"

### Capture iPhone traffic

    python src/pdt.py capture-iphone --duration 60

Output is written to `captures/iphone_<timestamp>.pcapng`, and an audit entry
is appended to `logs/audit.jsonl`. Optional filters:

    python src/pdt.py capture-iphone --process MobileSafari --duration 30
    python src/pdt.py capture-iphone --interface en0 --duration 30

### Hash capture files into a manifest

    python src/pdt.py manifest captures/iphone_<timestamp>.pcapng

Entries are appended to `logs/capture_manifest.jsonl` with `file`, `size_bytes`,
and `sha256`, for chain-of-custody documentation.

### Extract TLS SNI from a capture

    python src/pdt.py extract-sni --file captures/iphone_<timestamp>.pcapng --out reports/sni.txt

Reads the pcap with Scapy and extracts SNI from TLS ClientHello packets.
If the capture contains no TLS handshakes (for example, because the device
uses QUIC), the output will report `SNI ditemukan: 0`. That is a coverage
limitation, not a bug.

### Audit SNI against local IOC data

    python src/pdt.py audit-text --file reports/sni.txt

A JSON report is written to `reports/text_audit_<timestamp>.json`.

### Update IOC data from Amnesty International

    python src/pdt.py update-iocs --force

Fetches `domains.txt` from the Amnesty International public repository and
writes it to `data/iocs.json` in the format expected by `audit-text`,
`audit-pcap`, and `correlate-mvt`. The `--force` flag is required to overwrite
an existing file.

### Known warnings and limitations

- **Invalid Block body length warning**: may appear when reading pcapng
  files produced by `pymobiledevice3`. It happens because the capture was
  stopped programmatically and the final pcapng block was not fully written.
  Analysis continues on all readable packets; the warning does not invalidate
  findings, but the last few packets of a capture may be missing.
- **DNS is often encrypted** on modern iOS (for example, iCloud Private Relay
  or DoH). `audit-pcap` relies on plaintext DNS for domain matching, so
  `dns_query_count` may be `0` even when the device is active.
- **SNI may be absent** if traffic uses QUIC/HTTP3 or Encrypted Client Hello
  (ECH). In that case, `extract-sni` will return no domains.
- The Amnesty IOC list contains **domains only** (no IP indicators). IP-based
  matching in `audit-pcap` will not produce findings against this list.
- An IOC match is not proof of infection, and no match does not prove a device
  is clean.

## iPhone / MVT workflow

1. Keep Lockdown Mode enabled.
2. Update iOS to the newest version supported by the iPhone.
3. Use the official MVT documentation: https://docs.mvt.re/en/latest/
4. Create and protect an encrypted local iPhone backup if appropriate.
5. Run MVT using its documented workflow.
6. Correlate an exported MVT JSON report with `correlate-mvt`.
7. Do not upload private backups or sensitive artifacts to public scanning services.

## Evidence hygiene

- Work on copies of logs and captures.
- Record source, collection time, timezone, and SHA-256.
- Keep original backup/capture files unchanged.
- Store reports securely; they may contain sensitive metadata.
