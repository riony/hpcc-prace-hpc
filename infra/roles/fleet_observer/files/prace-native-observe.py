#!/usr/bin/python3
"""Managed by Ansible (roles/fleet_observer, tasks/native.yml). READ-ONLY observation of a native
Slurm worker (T89: slurmd on the host, no pod), served on its private address to the login node's
observer (prace-fleet-observe), which nests it in the fleet observation. It never changes anything.

Reported:
  - the slurmd service as systemd sees it (active, enabled, main PID and that process's command);
  - /home, /projects and /apps as the HOST's mount namespace (PID 1) sees them: per-mount options,
    filesystem type, source and the NFS super-block options (vers, hard). The unit runs in its own
    mount namespace, so its own /proc/self/mountinfo would not be the host's;
  - the native transition marker, the cluster key's owner and mode (never its content);
  - sha256 of the native worker's configuration files (hashes only), for the drift audit;
  - the boot id.

Not containment: root on this host can change what it reports. An unprivileged job cannot answer
in its place: the port is privileged (the unit grants only CAP_NET_BIND_SERVICE) and both the unit
(IPAddressAllow) and this server admit the login node's private address only.

  prace-native-observe serve --address ADDR --allow LOGIN_ADDR     (the unit)
  prace-native-observe check     one observation on stdout; exit 0 only without errors
"""
import argparse
import glob
import hashlib
import http.server
import ipaddress
import json
import os
import pwd
import stat
import subprocess
import sys
import time

PORT = 918
PATH = "/v1/native-worker"
SHARES = ("/home", "/projects", "/apps")
MOUNTINFO = "/proc/1/mountinfo"
KEY = "/etc/slurm/slurm.key"
MARKER = "/var/lib/prace-slinky/native-state"
TRACKED = (   # the native worker's configuration (globs; hashes only)
    "/etc/systemd/system/slurmd.service.d/*.conf",
    "/usr/lib/systemd/system/slurmd.service",
    "/etc/fstab",
    "/etc/systemd/system/prace-*",
    "/usr/local/sbin/prace-*",
)
UNIT_PROPS = ("ActiveState", "SubState", "UnitFileState", "MainPID", "NRestarts")


def unescape(field):
    """mountinfo escapes space, tab, newline and backslash as octal"""
    out, i = [], 0
    while i < len(field):
        if field[i] == "\\" and i + 3 < len(field) and field[i + 1:i + 4].isdigit():
            out.append(chr(int(field[i + 1:i + 4], 8))); i += 4
        else:
            out.append(field[i]); i += 1
    return "".join(out)


def mounts_from(mountinfo, paths=SHARES):
    """{path: {options, fstype, source, super}} for the visible (last) mount on each path"""
    out = {}
    for line in mountinfo.splitlines():
        pre, sep, post = line.partition(" - ")
        f, g = pre.split(), post.split()
        if not sep or len(f) < 6 or len(g) < 3:
            continue
        mp = unescape(f[4])
        if mp in paths:
            out[mp] = {"options": f[5], "fstype": g[0], "source": unescape(g[1]), "super": g[2]}
    return out


def slurmd_from(show, comm):
    """systemctl show's KEY=VALUE lines -> the unit's state; comm(pid) reads the process name"""
    props = dict(l.split("=", 1) for l in show.splitlines() if "=" in l)
    if not all(k in props for k in UNIT_PROPS):
        raise ValueError("incomplete unit state")
    row = {k: props[k] for k in ("ActiveState", "SubState", "UnitFileState")}
    row["MainPID"], row["NRestarts"] = int(props["MainPID"]), int(props["NRestarts"])
    row["comm"] = comm(row["MainPID"]) if row["MainPID"] > 0 else None
    return row


def read(path):
    with open(path) as f:
        return f.read()


def run(argv):
    r = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        raise OSError(f"{argv[0]} failed")
    return r.stdout


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def snapshot(read=read, run=run, now=time.time, host=None):
    out = {"schema": 1, "host": host or os.uname().nodename.split(".")[0], "time": int(now()), "errors": []}
    try:
        out["boot_id"] = read("/proc/sys/kernel/random/boot_id").strip()
    except OSError:
        out["errors"].append("boot_id_unreadable")
    try:
        show = run(["systemctl", "show", "slurmd.service", "--no-pager"] + [f"--property={p}" for p in UNIT_PROPS])
        out["slurmd"] = slurmd_from(show, lambda pid: read(f"/proc/{pid}/comm").strip())
    except (OSError, ValueError, subprocess.TimeoutExpired):
        out["errors"].append("slurmd_unit_unreadable")
    try:
        out["mounts"] = mounts_from(read(MOUNTINFO))
    except OSError:
        out["errors"].append("mountinfo_unreadable")
    try:
        out["marker"] = read(MARKER).strip()
    except FileNotFoundError:
        out["marker"] = None
    except OSError:
        out["errors"].append("marker_unreadable")
    try:
        s = os.stat(KEY)
        out["key"] = {"owner": pwd.getpwuid(s.st_uid).pw_name, "mode": "%04o" % stat.S_IMODE(s.st_mode),
                      "file": stat.S_ISREG(s.st_mode)}
    except FileNotFoundError:
        out["key"] = None
    except (OSError, KeyError):
        out["errors"].append("key_metadata_unreadable")
    out["config"] = {}
    for pattern in TRACKED:
        paths = sorted(glob.glob(pattern))
        if not paths:
            out["config"][pattern] = "missing"
        for p in paths:
            try:
                out["config"][p] = sha256(p)
            except OSError:
                out["config"][p] = "unreadable"
    return out


class Handler(http.server.BaseHTTPRequestHandler):
    allow = None

    def setup(self):
        super().setup()
        self.connection.settimeout(2)

    def do_GET(self):
        if self.client_address[0] != self.allow:
            self.send_error(403)
            return
        if self.path != PATH:
            self.send_error(404)
            return
        raw = (json.dumps(snapshot(), sort_keys=True) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["serve", "check"])
    p.add_argument("--address")
    p.add_argument("--allow")
    a = p.parse_args(argv)
    if a.action == "check":
        s = snapshot()
        print(json.dumps(s, sort_keys=True))
        return 0 if not s["errors"] else 1
    if not a.address or not a.allow:
        p.error("serve needs --address and --allow")
    Handler.allow = str(ipaddress.IPv4Address(a.allow))
    # one request at a time: no unbounded thread or process creation
    http.server.HTTPServer((str(ipaddress.IPv4Address(a.address)), PORT), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
