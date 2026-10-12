#!/usr/bin/env python3
"""Fetch public chart dependencies and verify the repository's fixed hashes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def fetch(destination):
    destination.mkdir(parents=True, exist_ok=True)
    lock = json.loads((ROOT / "demo/charts.lock.json").read_text())
    for item in lock.values():
        target = destination / item["file"]
        if not target.exists():
            subprocess.run(["helm", "pull", item["registry"], "--version", item["version"],
                            "--destination", str(destination)], check=True, timeout=180)
        if hashlib.sha256(target.read_bytes()).hexdigest() != item["sha256"]:
            raise SystemExit("Chart checksum mismatch: " + target.name)
    return lock

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path)
    fetch(parser.parse_args().destination)
