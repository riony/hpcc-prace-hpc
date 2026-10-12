#!/usr/bin/env python3
"""Offline tests for tools/k3s-login-restore.sh with a temporary target root (PRACE_RESTORE_ROOT):
the restore must refuse a non-empty target, refuse archives whose members leave the backed-up
paths (absolute or ".." names, escaping links, special files) or lack the backup records, refuse
tokens that differ from the recorded hashes, and otherwise extract the state and check the
tokens. The database and K3s steps need a real target (the restore rehearsal). No host is contacted."""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent / "k3s-login-restore.sh"
TOKEN, AGENT = b"K10fake::server:not-a-real-token\n", b"K10fake::node:not-a-real-agent-token\n"


def add(t, name, data=b"x", **kw):
    i = tarfile.TarInfo(name); i.size = len(data); i.mode = kw.get("mode", 0o600)
    for k in ("type", "linkname"):
        if k in kw: setattr(i, k, kw[k])
    t.addfile(i, io.BytesIO(data) if i.type == tarfile.REGTYPE else None)


def archive(path, extra=(), token_record=None, records=True, window=None):
    with tarfile.open(path, "w:gz") as t:
        add(t, "var/lib/rancher/k3s/server/token", TOKEN)
        add(t, "var/lib/rancher/k3s/server/agent-token", AGENT)
        add(t, "var/lib/rancher/k3s/server/node-token", type=tarfile.SYMTYPE, linkname="/var/lib/rancher/k3s/server/token")
        add(t, "var/lib/rancher/k3s/server/db/state.db", b"sqlite")
        add(t, "var/lib/rancher/k3s/storage/pvc-1/statesave/node_state", b"state")
        add(t, "etc/rancher/k3s/config.yaml", b"node-name: lab-dl380\nflannel-iface: eno4\n")
        add(t, "etc/rancher/node/password", b"node-password")
        add(t, "root/slinky-db.pw", b"db-password")
        for e in extra:
            add(t, *e[:2], **(e[2] if len(e) > 2 else {}))
        if records:
            rec = token_record if token_record is not None else (f"{hashlib.sha256(TOKEN).hexdigest()} /var/lib/rancher/k3s/server/token\n"
                                   f"{hashlib.sha256(AGENT).hexdigest()} /var/lib/rancher/k3s/server/agent-token\n")
            add(t, "prace-backup/token-sha256.txt", rec.encode())
            add(t, "prace-backup/slurm_acct_db.sql", b"-- dump")
        if window is not None:
            add(t, "prace-backup/maintenance-window.txt", window.encode())


class Restore(unittest.TestCase):
    def run_restore(self, extra=(), token_record=None, records=True, pre=None, iface=None, services=None, window=None):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d); root = d / "root"; root.mkdir(); art = d / "art"; art.mkdir()
            for f in ("k3s", "install.sh", "k3s-airgap-images-amd64.tar.zst"):
                (art / f).write_text("stub")
            archive(d / "a.tgz", extra, token_record, records, window)
            if pre:
                (root / pre).parent.mkdir(parents=True, exist_ok=True); (root / pre).write_text("existing")
            args = ["bash", str(SCRIPT), "--archive", str(d / "a.tgz"), "--artifacts", str(art)]
            if iface:
                args += ["--flannel-iface", iface]
            env = dict(os.environ, PRACE_RESTORE_ROOT=str(root))
            if services is not None:
                # stub systemctl/mysql: services = {"k3s_active": bool, "mariadb_start_rc": int,
                # "mysql_rc": int, "mysql_out": str}
                stubs = d / "bin"; stubs.mkdir()
                (stubs / "systemctl").write_text(
                    "#!/bin/sh\ncase \"$1\" in is-active) exit %d;; start) exit %d;; esac\nexit 0\n"
                    % (0 if services.get("k3s_active") else 3, services.get("mariadb_start_rc", 0)))
                (stubs / "mysql").write_text("#!/bin/sh\nprintf '%s'\nexit %d\n"
                                             % (services.get("mysql_out", ""), services.get("mysql_rc", 0)))
                for f in stubs.iterdir():
                    f.chmod(0o755)
                env.update(PATH=f"{stubs}:{env['PATH']}", PRACE_RESTORE_CHECK_SERVICES="1")
            r = subprocess.run(args, env=env, capture_output=True, text=True, timeout=30)
            files = sorted(str(p.relative_to(root)) for p in root.rglob("*") if not p.is_dir())
            cfg = (root / "etc/rancher/k3s/config.yaml").read_text() if (root / "etc/rancher/k3s/config.yaml").exists() else ""
            return r, files, cfg

    def test_clean_archive_restores_state_and_matches_tokens(self):
        r, files, cfg = self.run_restore()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for f in ("etc/rancher/node/password", "root/slinky-db.pw", "var/lib/rancher/k3s/server/db/state.db",
                  "var/lib/rancher/k3s/storage/pvc-1/statesave/node_state"):
            self.assertIn(f, files)
        self.assertNotIn("prace-backup/slurm_acct_db.sql", files)   # records are read, not installed
        self.assertEqual(r.stdout.count("matches the backup record"), 2)   # from the archive bytes, before writing
        self.assertEqual(r.stdout.count(": matches\n"), 2)                 # re-checked on disk
        self.assertIn("flannel-iface: eno4", cfg)

    def test_flannel_iface_rewrite(self):
        r, files, cfg = self.run_restore(iface="prace0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("flannel-iface: prace0\n", cfg); self.assertNotIn("eno4", cfg)

    def test_unsafe_archives_refused_before_anything_is_written(self):
        cases = {
            "outside path": [("etc/passwd", b"root::0:0")],
            "dot-dot name": [("var/lib/rancher/k3s/server/../../../../etc/cron.d/x", b"* * * * * root id")],
            "escaping symlink": [("var/lib/rancher/k3s/server/evil", b"", {"type": tarfile.SYMTYPE, "linkname": "/etc/shadow"})],
            "relative escaping symlink": [("etc/rancher/k3s/evil", b"", {"type": tarfile.SYMTYPE, "linkname": "../../passwd"})],
            "device": [("var/lib/rancher/k3s/server/dev", b"", {"type": tarfile.CHRTYPE})],
        }
        for label, extra in cases.items():
            with self.subTest(label):
                r, files, _ = self.run_restore(extra=extra)
                self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
                self.assertEqual(files, [])

    def test_missing_records_refused(self):
        r, files, _ = self.run_restore(records=False)
        self.assertEqual(r.returncode, 4); self.assertIn("backup records missing", r.stdout); self.assertEqual(files, [])

    def test_token_mismatch_refused_before_anything_is_written(self):
        rec = (f"{'0' * 64} /var/lib/rancher/k3s/server/token\n"
               f"{hashlib.sha256(AGENT).hexdigest()} /var/lib/rancher/k3s/server/agent-token\n")
        r, files, _ = self.run_restore(token_record=rec)
        self.assertEqual(r.returncode, 5); self.assertIn("does not match the backup record", r.stdout)
        self.assertEqual(files, [])

    def test_malformed_token_records_refused(self):
        """Review R2: a record missing the agent line, or blank, was accepted."""
        tok = f"{hashlib.sha256(TOKEN).hexdigest()} /var/lib/rancher/k3s/server/token"
        agent = f"{hashlib.sha256(AGENT).hexdigest()} /var/lib/rancher/k3s/server/agent-token"
        cases = {
            "missing agent line": tok + "\n",
            "blank": "\n",
            "empty": "",
            "duplicate line": f"{tok}\n{tok}\n{agent}\n",
            "unexpected path": f"{tok}\n{agent}\n{'a' * 64} /etc/shadow\n",
            "short digest": f"{'a' * 63} /var/lib/rancher/k3s/server/token\n{agent}\n",
            "trailing blank line": f"{tok}\n{agent}\n\n",
        }
        for label, rec in cases.items():
            with self.subTest(label):
                r, files, _ = self.run_restore(token_record=rec)
                self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
                self.assertEqual(files, [])

    def test_link_tricks_refused(self):
        """Review R2: an absolute link with an allowed prefix and '..' components was accepted."""
        cases = {
            "absolute with ..": [("var/lib/rancher/k3s/server/l", b"", {"type": tarfile.SYMTYPE,
                                  "linkname": "/var/lib/rancher/k3s/server/../../../../../../tmp/x"})],
            "relative .. staying inside": [("var/lib/rancher/k3s/server/db/l", b"", {"type": tarfile.SYMTYPE, "linkname": "../token"})],
            "link chain": [("etc/rancher/k3s/a", b"", {"type": tarfile.SYMTYPE, "linkname": "/etc/rancher/k3s/b"}),
                           ("etc/rancher/k3s/b", b"", {"type": tarfile.SYMTYPE, "linkname": "/etc/rancher/k3s/config.yaml"})],
            "written through a link": [("etc/rancher/k3s/d", b"", {"type": tarfile.SYMTYPE, "linkname": "/var/lib/rancher/k3s/server"}),
                                       ("etc/rancher/k3s/d/x", b"payload")],
            "hard link to a non-member": [("var/lib/rancher/k3s/server/h", b"", {"type": tarfile.LNKTYPE, "linkname": "var/lib/rancher/k3s/server/nope"})],
            "hard link outside": [("var/lib/rancher/k3s/server/h", b"", {"type": tarfile.LNKTYPE, "linkname": "etc/shadow"})],
            "duplicate member": [("root/slinky-db.pw", b"other")],
            "non-normal name": [("var/lib/rancher/k3s/server//db2", b"x")],
        }
        for label, extra in cases.items():
            with self.subTest(label):
                r, files, _ = self.run_restore(extra=extra)
                self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
                self.assertEqual(files, [])

    def test_allowed_links_still_restore(self):
        extra = [("var/lib/rancher/k3s/server/rel", b"", {"type": tarfile.SYMTYPE, "linkname": "token"}),
                 ("var/lib/rancher/k3s/server/hard", b"", {"type": tarfile.LNKTYPE, "linkname": "var/lib/rancher/k3s/server/db/state.db"})]
        r, files, _ = self.run_restore(extra=extra)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("var/lib/rancher/k3s/server/hard", files)

    def test_unknown_target_state_refused(self):
        """Review R2: a failed database query with empty output read as 'no database'."""
        cases = {
            "database query fails": ({"mysql_rc": 17}, "database query failed"),
            "mariadb does not start": ({"mariadb_start_rc": 1}, "mariadb did not start"),
            "database exists": ({"mysql_out": "slurm_acct_db\n"}, "already exists"),
            "k3s running": ({"k3s_active": True}, "k3s is running"),
        }
        for label, (svc, msg) in cases.items():
            with self.subTest(label):
                r, files, _ = self.run_restore(services=svc)
                self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
                self.assertIn(msg, r.stdout)
                self.assertEqual(files, [])
        r, files, _ = self.run_restore(services={})         # control: query succeeds, no database
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_non_empty_target_refused(self):
        for pre in ("etc/rancher/k3s/config.yaml", "var/lib/rancher/k3s/server/token", "etc/rancher/node/password"):
            with self.subTest(pre):
                r, files, _ = self.run_restore(pre=pre)
                self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
                self.assertEqual(files, [pre])

    def test_maintenance_window_record(self):
        good = "lease=0a1b2c partitions-before-fence=cpu=UP,gpu=UP loginsets-before-fence=slurm-login-prace=1 home=1 captured=2026-09-28T10:00:00+08:00\n"
        r, files, _ = self.run_restore(window=good)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("var/lib/prace-restore/maintenance-window.txt", files)
        self.assertIn("the fence was captured too", r.stdout)
        for bad in ("", "partitions-before-fence=cpu=UP\n", good.replace("cpu=UP", "cpu=UP;rm -rf /"),
                    good.replace("\n", "\nextra line\n")):
            with self.subTest(bad=bad):
                r, files, _ = self.run_restore(window=bad)
                self.assertEqual(r.returncode, 4, r.stdout + r.stderr); self.assertEqual(files, [])

    def test_usage(self):
        r = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, timeout=10)
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
