#!/usr/bin/env python3
"""Publication guard. Prints locations/categories, never matched secret values."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SKIP = {".git", ".venv", ".cache", "__pycache__", "collections", ".ansible"}
# Optional, untracked site deny-list: one regular expression per line (# comments allowed).
# Keep your own host names, domains and project codes here instead of in this public file.
LOCAL = ROOT / "tools" / "public-check.local"
NAMES = re.compile(r"(?i)(\.(key|pem|crt|cer|pfx|p12|p7b|jks|keystore|ppk|kdbx|keytab|pw|vault)$|(?:^|/)(?:kubeconfig(?:\..*)?|tokens\.json|admin\.conf|slurmdbd\.conf|id_(?:rsa|ed25519|ecdsa).*|vault\.ya?ml|\.env)$|\.tfstate(?:\..*)?$|(?:^|/)\.terraform/)")
PATTERNS = {
    "private-key": re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
    "vault-payload": re.compile(r"\$ANSIBLE_" + "VAULT;"),
    "api-token": re.compile(r"\b(?:hf_[A-Za-z0-9]{20,}|nvapi-[A-Za-z0-9_-]{20,}|glpat-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}"),
    "tailnet-name": re.compile(r"(?i)\btail[0-9a-f]{6}\.ts\.net\b"),
    "encoded-kube-credential": re.compile(r"(?:client-key-data|client-certificate-data|certificate-authority-data):\s+[A-Za-z0-9+/=]{40,}"),
}

def site_patterns(local=LOCAL):
    """the untracked site deny-list, if present, as one combined pattern"""
    if not local.is_file():
        return {}
    rules = [line.strip() for line in local.read_text().splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    return {"site-binding": re.compile("(?i)(?:" + "|".join(rules) + ")")} if rules else {}


def check(root=ROOT):
    findings = []
    count = 0
    patterns = {**PATTERNS, **site_patterns()}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(p in SKIP for p in rel.parts) or path == LOCAL:
            continue
        if path.is_symlink():
            resolved = path.resolve()
            if not resolved.is_relative_to(root) or not resolved.exists():
                findings.append((str(rel), 0, "external-or-broken-symlink"))
            continue
        if not path.is_file():
            continue
        count += 1
        if NAMES.search(str(rel)):
            findings.append((str(rel), 0, "credential-filename"))
        data = path.read_bytes()
        if b"\0" in data or path.suffix in (".tgz", ".gz", ".zip", ".pptx", ".pdf"):
            findings.append((str(rel), 0, "unreviewed-binary-or-archive"))
            continue
        for number, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
            for category, pattern in patterns.items():
                if pattern.search(line):
                    findings.append((str(rel), number, category))
    for path, line, category in findings:
        print(f"{path}:{line}: {category}")
    print(f"Public check: {count} files, {len(findings)} findings")
    return bool(findings)

if __name__ == "__main__":
    sys.exit(check())
