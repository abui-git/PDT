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
cd ~/pegasus-defense-v2
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
