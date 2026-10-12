#!/usr/bin/env python3
"""Block secrets from entering this repository.

Checks file NAMES (credential/bundle formats) and file CONTENTS (private keys,
known token formats, password assignments, crypt(3) password hashes, DSNs with
passwords). Internal identifiers (IPs, hostnames, serials) are NOT secrets here:
the internal GitLab copy may contain them; the GitHub code-only export has its
own sanitizer.

  secret-scan.py --tree [ROOT]   scan every file under ROOT (default: repo root)
  secret-scan.py --staged        scan files staged for commit (pre-commit hook)

Prints only file:line and the category, never the matched value. Exit 1 on any hit.
Adapted from ~/HPCC/llm-gateway-public-prep/scan_history_and_tree.py.
"""
import os
import re
import subprocess
import sys

BAD_NAMES = re.compile(
    r"(?i)(\.pw|\.key|\.pem|\.p12|\.pfx|\.p7b|\.jks|\.kdbx|\.keytab|\.env|"
    r"^id_(rsa|ecdsa|ed25519|dsa)(_[a-z0-9]+)?|initial_root_password|gitlab-secrets\.json)$")
CATS = {
    "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "token": r"\b(?:glpat-[A-Za-z0-9_-]{20,}|glrt-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{20,}"
             r"|github_pat_[A-Za-z0-9_]{20,}|tskey-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}"
             r"|lgw_[A-Za-z0-9]{8,}|AKIA[0-9A-Z]{16}|xox[bp]-[A-Za-z0-9-]{10,})",
    "password_hash": r"\$(?:6|5|2[aby]|y|gy)\$[./A-Za-z0-9$]{20,}",
    "secret_assign": r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"][^'\"\s]{8,}['\"]",
    "pgpassword": r"PGPASSWORD=[^\s$(\"']{6,}",
    "bearer": r"(?i)authorization:\s*bearer\s+[A-Za-z0-9._-]{20,}",
    "dsn_password": r"(?i)(postgres(ql)?|mysql|redis|amqp)://[^:\s/]+:[^@\s/]{4,}@",
}
RX = [(k, re.compile(v)) for k, v in CATS.items()]
SKIP_DIRS = {".git", "collections", "__pycache__"}
SELF = os.path.relpath(__file__)


def scan_file(path, rel):
    hits = []
    if BAD_NAMES.search(os.path.basename(rel)):
        hits.append((rel, 0, "credential_filename"))
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return hits
    if b"\0" in data[:8192]:          # binary (pptx, png): names only
        return hits
    for n, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
        for cat, rx in RX:
            if rx.search(line):
                hits.append((rel, n, cat))
    return hits


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "--tree"
    root = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True,
                          text=True).stdout.strip() or os.getcwd()
    files = []
    if mode == "--staged":
        out = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
                             capture_output=True, text=True, cwd=root).stdout
        files = [f for f in out.split("\0") if f]
    else:
        root = sys.argv[2] if len(sys.argv) > 2 else root
        for d, dirs, fs in os.walk(root):
            dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
            files += [os.path.relpath(os.path.join(d, f), root) for f in fs]
    hits = []
    for rel in sorted(files):
        if rel.endswith("infra/tools/secret-scan.py"):   # the patterns themselves
            continue
        hits += scan_file(os.path.join(root, rel), rel)
    for rel, n, cat in hits:
        print(f"SECRET? {rel}:{n}: {cat}")
    print(f"secret-scan: {len(files)} files checked, {len(hits)} finding(s)", file=sys.stderr)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
