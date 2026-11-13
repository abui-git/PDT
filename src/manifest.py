#!/usr/bin/env python3
"""Hitung SHA-256 file capture dan tulis ke manifest JSON Lines."""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def process_files(paths, manifest_path="logs/capture_manifest.jsonl"):
    os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
    results = []
    for path in paths:
        if not os.path.exists(path):
            raise FileNotFoundError(f"file tidak ditemukan: {path}")
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "file": path,
            "size_bytes": os.path.getsize(path),
            "sha256": sha256_file(path),
        }
        with open(manifest_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        results.append(entry)
        print(f"{entry['sha256']}  {path}  ({entry['size_bytes']} bytes)")
    return results


def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: python src/manifest.py <file1> [file2 ...]")
    process_files(sys.argv[1:])


if __name__ == "__main__":
    main()