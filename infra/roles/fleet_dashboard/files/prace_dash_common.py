"""Shared helpers of the read-only fleet dashboard collectors (roles/fleet_dashboard).

Python 3.9 standard library only. Nothing here writes anywhere but the paths it is given.

Offline guard: with PRACE_DASH_OFFLINE=1 in the environment, importing this module installs an audit
hook that refuses every socket operation (creation, DNS lookup, connect) and every urllib request in
this process. Tests set it; the observe and evidence collectors never need the network at all (their
units also run with PrivateNetwork=yes), the GitLab collector refuses before it would connect.

Scrubbing (contract C4): every string, key or value, of a document served from mgmt-git01 passes
through Scrubber.scrub; Scrubber.residue then re-reads the serialised document and names any
identifier category that survived. A document with residue is never written.
"""
import datetime
import ipaddress
import json
import math
import os
import re
import sys
import tempfile
import time

OFFLINE_ENV = "PRACE_DASH_OFFLINE"
MAX_STRING = 4096          # C1: any longer string in an untrusted document rejects the document
MASK = "████"   # ████


class NetworkRefused(PermissionError):
    """raised for any network use while the offline guard is active"""


_GUARD = {"active": False, "refused": 0}


def _offline_hook(event, args):
    if event.startswith("socket.") or event == "urllib.Request":
        _GUARD["refused"] += 1
        raise NetworkRefused(f"network refused under {OFFLINE_ENV}=1 ({event})")


def install_offline_guard():
    """irreversible for this process (audit hooks cannot be removed)"""
    if not _GUARD["active"]:
        sys.addaudithook(_offline_hook)
        _GUARD["active"] = True


def offline():
    return os.environ.get(OFFLINE_ENV) == "1"


def guard_state():
    return dict(_GUARD)


if offline():
    install_offline_guard()


# --- files ---------------------------------------------------------------------------------------

def read_capped(path, cap):
    """bytes of a file no larger than cap; ValueError if larger, OSError if unreadable"""
    with open(path, "rb") as f:
        raw = f.read(cap + 1)
    if len(raw) > cap:
        raise ValueError(f"{os.path.basename(path)} is larger than {cap} bytes")
    return raw


def _non_finite(token):
    raise ValueError(f"non-finite number {token}")


def loads(text):
    """json.loads that refuses NaN and Infinity (browsers cannot parse them back)"""
    return json.loads(text, parse_constant=_non_finite)


def load_json_capped(path, cap):
    raw = read_capped(path, cap)
    try:
        return loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise ValueError(f"{os.path.basename(path)} is not valid JSON ({type(e).__name__})")


def write_json(path, doc, mode=0o644):
    """atomic: a hidden temporary file in the same directory (same SELinux type, same filesystem),
    flushed, chmod, renamed over the target. Never NaN; an unencodable character becomes '?'."""
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as f:
            json.dump(doc, f, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def clip_strings(doc, cap=MAX_STRING, depth=0):
    """a copy with every string cut to cap (for the monitor's own files, whose reasons are long
    only legitimately); nesting beyond 32 is dropped"""
    if depth > 32:
        return None
    if isinstance(doc, str):
        return doc[:cap]
    if isinstance(doc, dict):
        return {(k[:cap] if isinstance(k, str) else k): clip_strings(v, cap, depth + 1) for k, v in doc.items()}
    if isinstance(doc, list):
        return [clip_strings(v, cap, depth + 1) for v in doc]
    return doc


def check_strings(doc, cap=MAX_STRING, depth=0):
    """ValueError if any string (key or value) is longer than cap, or the nesting is absurd"""
    if depth > 32:
        raise ValueError("document nested too deeply")
    if isinstance(doc, str):
        if len(doc) > cap:
            raise ValueError(f"a string field is longer than {cap} characters")
    elif isinstance(doc, dict):
        for k, v in doc.items():
            check_strings(k, cap, depth + 1)
            check_strings(v, cap, depth + 1)
    elif isinstance(doc, list):
        for v in doc:
            check_strings(v, cap, depth + 1)


# --- time ----------------------------------------------------------------------------------------

_ISO = re.compile(r"(\d{4}-\d{2}-\d{2})(?:[T ](\d{2}:\d{2})(:\d{2})?(\.\d+)?)?\s*(Z|[+-]\d{2}:?\d{2})?")


def parse_iso(text):
    """epoch seconds from an ISO 8601 string as GitLab, git and the window tools write them
    (Python 3.9's fromisoformat accepts neither 'Z' nor 3-digit fractions). No zone = UTC."""
    if not isinstance(text, str) or len(text) > 64:
        raise ValueError("not a timestamp")
    m = _ISO.fullmatch(text.strip())
    if not m:
        raise ValueError(f"not a timestamp: {text[:40]!r}")
    date, hm, sec, frac, tz = m.groups()
    clock = (hm or "00:00") + (sec or ":00")
    if frac:
        clock += "." + frac[1:7].ljust(6, "0")
    if not tz or tz == "Z":
        tz = "+00:00"
    elif ":" not in tz:
        tz = tz[:3] + ":" + tz[3:]
    return datetime.datetime.fromisoformat(f"{date}T{clock}{tz}").timestamp()


def finite_time(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 < value < 4102444800   # before 2100


def now():
    return int(time.time())


# --- scrubbing (C4) ------------------------------------------------------------------------------

_HEX = "0-9a-fA-F"
_K8S = "bcdfghjklmnpqrstvwxz2456789"     # Kubernetes' random-suffix alphabet (no vowels, no 0 1 3)
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_NOT_ID_L = r"(?<![A-Za-z0-9_])"          # names may follow '-' or '.' (slurm-worker-g003-0, node.g003)
_NOT_ID_R = r"(?![A-Za-z0-9_])"
# Every repetition that could backtrack is bounded, and the costly rules run only when a literal
# they need is present: hostile 4 KiB strings stay linear (a test times them).
RX = {
    "recovery_path": re.compile(r"(?i)[^\s\"'<>]{0,256}prace-recovery[^\s\"'<>]{0,1024}"),
    "tailnet_host": re.compile(r"(?i)(?<![a-z0-9-])[a-z0-9-]{1,63}\.tail[0-9a-f]{6}\.ts\.net(?![a-z0-9-])"),
    "tailnet": re.compile(r"(?i)\btail[0-9a-f]{6}(?:\.ts\.net)?\b"),
    "email": re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}\b"),
    "gpu_uuid": re.compile(rf"(?i)\b(?:GPU|MIG)-[{_HEX}]{{8}}-[{_HEX}]{{4}}-[{_HEX}]{{4}}-[{_HEX}]{{4}}-[{_HEX}]{{12}}\b"),   # nvidia-smi -L
    "uuid": re.compile(rf"(?<![{_HEX}-])[{_HEX}]{{8}}-[{_HEX}]{{4}}-[{_HEX}]{{4}}-[{_HEX}]{{4}}-[{_HEX}]{{12}}(?![{_HEX}-])"),
    "mac": re.compile(rf"(?<![{_HEX}:])(?:[{_HEX}]{{2}}[:-]){{5}}[{_HEX}]{{2}}(?![{_HEX}:])"),
    "pci": re.compile(rf"(?<![{_HEX}:])[{_HEX}]{{4}}:[{_HEX}]{{2}}:[{_HEX}]{{2}}\.[0-7](?![0-9])"),
    "ipv4": re.compile(r"(?<!\d)(?<!\d\.)(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?!\d|\.\d)"),
    "ipv6": re.compile(rf"(?<![{_HEX}:])(?:[{_HEX}]{{0,4}}:){{2,7}}[{_HEX}]{{0,4}}(?:/\d{{1,3}})?(?![{_HEX}:]|\.\d)"),
    "lease_id": re.compile(r"(?i)\bid=[0-9a-f]{8,64}\b"),
    "hex32": re.compile(rf"(?<![{_HEX}])[{_HEX}]{{32}}(?![{_HEX}])"),
    "hex16": re.compile(rf"(?<![{_HEX}])[{_HEX}]{{16}}(?![{_HEX}])"),
    "pod_rs": re.compile(rf"(?<![A-Za-z0-9_.-])([a-z0-9]{{1,63}}(?:-[a-z0-9]{{1,63}}){{0,8}}?)-[0-9a-f]{{8,10}}-[{_K8S}]{{5}}(?![A-Za-z0-9_-])"),
    "pod_name": re.compile(rf"(?<![A-Za-z0-9_.-])((?:slurm|prace)(?:-[a-z0-9]{{1,63}}){{1,8}}?)-[{_K8S}]{{5}}(?![A-Za-z0-9_-])"),
    "fleet_host": re.compile(r"(?i)\bhpc-[a-z0-9]{1,63}(?:-[a-z0-9]{1,63}){0,8}\b"),
    "synthetic_user": re.compile(r"(?i)\bsyn-[a-z][a-z0-9]{0,63}\b"),
    "agent_user": re.compile(r"(?i)\bagent-[a-z]{1,63}[0-9]{1,6}\b"),
    "home_path": re.compile(r"/home/(?!<user>)[^/\s\"'<>]{1,255}"),
    "projects_path": re.compile(r"/projects/(?!<project>|:)[^/\s\"'<>]{1,255}"),   # not API paths (/projects/:id/...)
}


def _ip_ok(token, v6=False):
    addr = token.split("/")[0]
    if not v6:   # leading zeros (10.042.001.051) are still an address to hide
        parts = addr.split(".")
        return len(parts) == 4 and all(p.isdigit() and int(p) <= 255 for p in parts)
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.version == 6 and ("::" in addr or addr.count(":") == 7)


def strings(doc, depth=0):
    """every string of a document, keys included"""
    if depth > 64:
        return
    if isinstance(doc, str):
        yield doc
    elif isinstance(doc, dict):
        for k, v in doc.items():
            if isinstance(k, str):
                yield k
            yield from strings(v, depth + 1)
    elif isinstance(doc, list):
        for v in doc:
            yield from strings(v, depth + 1)


class Scrubber:
    """Fixed mapping (scrub-map.json plus the account lists the role renders from the inventory)
    and the pattern rules above. Deterministic: the same input gives the same output. Exact names
    match regardless of case."""

    def __init__(self, hosts, aliases=None, accounts=None, names=None):
        self.exact = {}
        for src in (hosts, aliases or {}, names or {}):
            self.exact.update({k.lower(): v for k, v in src.items() if k})
        for kind, label in (("synthetic", "actor-"), ("agents", "agent-"), ("team", "member-")):
            for i, name in enumerate((accounts or {}).get(kind) or []):
                if name and name.lower() not in self.exact:
                    self.exact[name.lower()] = label + (chr(ord("A") + i) if i < 26 and kind != "team" else str(i + 1))
        keys = sorted(self.exact, key=len, reverse=True)
        self.exact_rx = (re.compile("(?i)" + _NOT_ID_L + "(" + "|".join(re.escape(k) for k in keys) + ")" + _NOT_ID_R)
                         if keys else None)

    @classmethod
    def from_config(cls, cfg):
        sc = cfg.get("scrub") or {}
        with open(sc["map"], encoding="utf-8") as f:
            m = json.load(f)
        names = dict(m.get("names") or {})
        names.update(sc.get("names") or {})
        return cls(m["hosts"], m.get("aliases"), sc.get("accounts"), names)

    def text(self, s):
        if not isinstance(s, str) or not s:
            return s
        s = _CTRL.sub("", s.encode("utf-8", "replace").decode("utf-8"))   # lone surrogates, C0 controls
        low = s.lower()
        if "prace-recovery" in low:
            s = RX["recovery_path"].sub("<private recovery path>", s)
        if "tail" in low:
            if ".ts.net" in low:
                s = RX["tailnet_host"].sub(lambda m: self.exact.get(m.group(0).lower(), self.exact.get(m.group(0).split(".")[0].lower(), "tailnet-host")), s)
            s = RX["tailnet"].sub("tailnet", s)
        if "@" in s:
            s = RX["email"].sub("email-masked", s)
        if "gpu-" in low or "mig-" in low:
            s = RX["gpu_uuid"].sub("GPU-uuid-masked", s)
        s = RX["uuid"].sub("uuid-masked", s)
        s = RX["mac"].sub("mac-masked", s)
        s = RX["pci"].sub("pci-masked", s)
        s = RX["ipv4"].sub(lambda m: "addr-masked" if _ip_ok(m.group(0)) else m.group(0), s)
        if "::" in s or s.count(":") >= 5:
            s = RX["ipv6"].sub(lambda m: "addr-masked" if _ip_ok(m.group(0), v6=True) else m.group(0), s)
        s = RX["lease_id"].sub("id=" + MASK, s)
        s = RX["hex32"].sub("id-" + MASK, s)
        s = RX["hex16"].sub("id-" + MASK, s)
        s = RX["pod_rs"].sub(lambda m: m.group(1) + "-•••••", s)
        s = RX["pod_name"].sub(lambda m: m.group(1) + "-•••••", s)
        if self.exact_rx:
            s = self.exact_rx.sub(lambda m: self.exact[m.group(1).lower()], s)
        s = RX["fleet_host"].sub("host-masked", s)
        s = RX["synthetic_user"].sub("synthetic-user", s)
        s = RX["agent_user"].sub("agent-user", s)
        s = RX["home_path"].sub("/home/<user>", s)
        s = RX["projects_path"].sub("/projects/<project>", s)
        return s

    def scrub(self, doc):
        if isinstance(doc, str):
            return self.text(doc)
        if isinstance(doc, list):
            return [self.scrub(v) for v in doc]
        if isinstance(doc, dict):
            out = {}
            for k, v in doc.items():
                key = self.text(k) if isinstance(k, str) else k
                n, base = 2, key
                while key in out:                 # two originals mapped to one placeholder: keep both
                    key = f"{base}#{n}"; n += 1
                out[key] = self.scrub(v)
            return out
        return doc

    def residue(self, doc):
        """the identifier categories still present in the document's raw strings (empty = clean).
        Besides the scrub rules, every exact name is searched for on its own, ignoring case and word
        boundaries (names of six characters or more), so a rule the scrub got wrong is still caught."""
        text = "\n".join(strings(doc))
        low = text.lower()
        found = set()
        for name in ("recovery_path", "tailnet", "email", "mac", "gpu_uuid", "uuid", "pci", "lease_id", "hex32", "hex16",
                     "pod_rs", "pod_name", "fleet_host", "synthetic_user", "agent_user"):
            if RX[name].search(text):
                found.add(name)
        if "prace-recovery" in low:
            found.add("recovery_path")
        if any(_ip_ok(m.group(0)) for m in RX["ipv4"].finditer(text)):
            found.add("ipv4")
        if any(_ip_ok(m.group(0), v6=True) for m in RX["ipv6"].finditer(text)):
            found.add("ipv6")
        if self.exact_rx and self.exact_rx.search(text):
            found.add("mapped_identifier")
        if any(len(k) >= 6 and k in low for k in self.exact):
            found.add("mapped_identifier")
        if RX["home_path"].search(text) or RX["projects_path"].search(text):
            found.add("private_path")
        return sorted(found)


def publish(path, doc, scrubber):
    """scrub, check for residue, write atomically; the document is never written with residue"""
    clean = scrubber.scrub(doc)
    left = scrubber.residue(clean)
    if left:
        raise ValueError("refusing to write " + os.path.basename(path) + ": residue " + ",".join(left))
    write_json(path, clean)
    return clean


def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    if not isinstance(cfg, dict) or cfg.get("schema") != 1:
        raise ValueError("unreadable dashboard configuration")
    return cfg
