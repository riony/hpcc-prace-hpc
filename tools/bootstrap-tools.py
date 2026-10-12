#!/usr/bin/env python3
"""Install fixed, checksum-verified Linux x86-64 development tools privately."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]

def main():
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        raise SystemExit("This installer supports Linux x86-64. Install tools manually elsewhere.")
    os.umask(0o077)
    target = Path.home() / ".local/state/hpcc-prace-hpc-public/tools"
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, item in json.loads((ROOT / "tools/binaries.lock.json").read_text()).items():
        data = urllib.request.urlopen(item["url"], timeout=180).read()
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise SystemExit("Download checksum mismatch: " + name)
        if item["member"]:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                data = archive.extractfile(item["member"]).read()
        path = target / name
        temporary = target / (name + ".new")
        with temporary.open("wb") as stream:
            stream.write(data)
        temporary.chmod(0o700)
        temporary.replace(path)
        print("Installed checksum-verified " + name)
    print("Add to PATH: " + str(target))

if __name__ == "__main__":
    main()
