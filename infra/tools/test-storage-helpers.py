#!/usr/bin/env python3
"""Unit tests for the storage helpers the roles install on the login node (no host contact):
prace-quota-apply (xfs_quota observations, failures, readback, idempotence; a fake xfs_quota),
prace-storage-check (quota state parsing), prace-tree-listing (copy proof, xattrs) and
prace-project-acl (exact project-root ACL, on a local temporary directory)."""
import contextlib
import errno
from importlib.machinery import SourceFileLoader
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

INFRA = Path(__file__).resolve().parent.parent


def load(name, path):
    loader = SourceFileLoader(name, str(INFRA / path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


QA = load("quota_apply", "roles/storage_policy/files/prace-quota-apply")
SC = load("storage_check", "roles/login_storage/files/prace-storage-check")
TL = INFRA / "roles/login_storage/files/prace-tree-listing"
TLM = load("tree_listing", "roles/login_storage/files/prace-tree-listing")
ACL_SCRIPT = INFRA / "roles/storage_policy/files/prace-project-acl"

REPORT_U = """#0               0     921600    1048576     00 [--------]      3       9000      10000     00 [--------]
#20001           4   18874368   20971520     00 [--------]      4     180000     200000     00 [--------]
#30091      266240     204800     262144     01 [6 days]       10       1500       2000     00 [--------]
"""
STATE_U = """User quota state on /home (/dev/mapper/hpe_vg-home)
  Accounting: ON
  Enforcement: ON
  Inode: #131 (2 blocks, 2 extents)
Blocks grace time: [7 days]
Blocks max warnings: 5
Inodes grace time: [7 days]
Inodes max warnings: 5
Realtime Blocks grace time: [7 days]
"""


NOT_XFS = "xfs_quota: cannot setup path for mount /home: No such device or address\n"   # observed rc 0
HOME_CFG = {"path": "/home", "grace_s": 604800,
            "default": {"bsoft": "900m", "bhard": "1g", "isoft": 9000, "ihard": 10000},
            "users": [{"uid": 20001, "name": "t", "bsoft": "18g", "bhard": "20g", "isoft": 180000, "ihard": 200000},
                      {"uid": 30091, "name": "p", "bsoft": "200m", "bhard": "256m", "isoft": 1500, "ihard": 2000}]}
PROJ_CFG = {"path": "/projects", "grace_s": 604800,
            "projects": [{"id": 31001, "name": "proj-alpha", "dir": "/projects/proj-alpha",
                          "bsoft": "45g", "bhard": "50g", "isoft": 450000, "ihard": 500000},
                         {"id": 31002, "name": "proj-beta", "dir": "/projects/proj-beta",
                          "bsoft": "45g", "bhard": "50g", "isoft": 450000, "ihard": 500000}]}



def _skip_or_fail(self, why):
    """A missing capability skips locally but fails in CI (where the job installs acl and rsync)."""
    if os.environ.get("CI"):
        self.fail(why)
    self.skipTest(why)


unittest.TestCase.skip_or_fail = _skip_or_fail

class FakeXFS:
    """xfs_quota and findmnt as the helper runs them (subprocess.run), for /home (user quota)
    and /projects (project quota). `ignore` = command prefixes accepted with rc 0 and no effect
    (a setter that silently did nothing); `stderr` = {prefix: diagnostic} printed with rc 0."""
    SECTION = {"u": "User", "p": "Project"}

    def __init__(self):
        self.mounts = {"/home": "xfs", "/projects": "xfs"}
        self.on = {"u": True, "p": True}
        self.limits = {"u": {0: (0, 0, 0, 0)}, "p": {0: (0, 0, 0, 0)}}
        self.grace = {("u", "b"): 604800, ("u", "i"): 604800, ("p", "b"): 604800, ("p", "i"): 604800}
        self.tagged = set()
        self.ignore, self.stderr, self.calls, self.walks = set(), {}, [], []

    def untagged(self, top, projid):
        """The helper's own tag walk, answered from the fake's state."""
        self.walks.append(top)
        name = top.rsplit("/", 1)[-1]
        return (0, None) if name in self.tagged else (3, f"{top!r} (project 0, inherit False)")

    def run(self, argv, **kwargs):
        if argv[0] == "findmnt":
            if getattr(self, "findmnt_fails", False):
                # the real findmnt: exit 1 for "nothing mounted" (silent) AND for errors (a message)
                return subprocess.CompletedProcess(argv, 1, "", "findmnt: cannot read /proc/self/mountinfo\n")
            fs = self.mounts.get(argv[-1])
            return subprocess.CompletedProcess(argv, 0 if fs else 1, f"{fs}\n" if fs else "", "")
        command, path = argv[3], argv[4]
        self.calls.append(command)
        out = "" if any(command.startswith(k) for k in self.ignore) else self.handle(path, command)
        err = "".join(v for k, v in self.stderr.items() if command.startswith(k))
        return subprocess.CompletedProcess(argv, 0, out, err)

    @staticmethod
    def days(seconds):
        return "1 day" if seconds == 86400 else f"{seconds // 86400} days"

    def handle(self, path, command):
        f = command.split()
        kind = f[1][1] if len(f) > 1 and f[1].startswith("-") else None
        if f[0] == "state":
            on = "ON" if self.on[kind] else "OFF"
            return (f"{self.SECTION[kind]} quota state on {path} (/dev/mapper/vg-x)\n  Accounting: {on}\n"
                    f"  Enforcement: {on}\n  Inode: #131 (2 blocks, 2 extents)\n"
                    f"Blocks grace time: [{self.days(self.grace[kind, 'b'])}]\nBlocks max warnings: 5\n"
                    f"Inodes grace time: [{self.days(self.grace[kind, 'i'])}]\nInodes max warnings: 5\n"
                    f"Realtime Blocks grace time: [7 days]\n")
        if f[0] == "report":
            return "".join(f"#{i:<8} 4 {bs} {bh} 00 [--------] 1 {is_} {ih} 00 [--------]\n"
                           for i, (bs, bh, is_, ih) in sorted(self.limits[kind].items()))
        if f[0] == "limit":
            v = dict(x.split("=") for x in f[2:6])
            target = 0 if f[6] == "-d" else int(f[6])
            self.limits[kind][target] = (QA.kib(v["bsoft"]), QA.kib(v["bhard"]), int(v["isoft"]), int(v["ihard"]))
            return ""
        if f[0] == "timer":
            self.grace[kind, f[2][1]] = int(f[3])
            return ""
        if f[0] == "project":
            name, op = f[2], f[1]
            head = f"{'Checking' if op == '-c' else 'Setting up'} project {name} (path /projects/{name})...\n"
            tail = f"Processed 1 (/etc/projects and cmdline) paths for project {name} with recursion depth infinite (-1).\n"
            if op == "-s":
                self.tagged.add(name)
                return head + tail
            problem = "" if name in self.tagged else \
                f"/projects/{name} - project identifier is not set (inode=0, tree=31001)\n/projects/{name} - project inheritance flag is not set\n"
            return head + problem + tail
        raise AssertionError(f"unexpected xfs_quota command {command!r}")

    def declared(self, cfg):
        """Make the fake already hold the declaration (a converged host)."""
        home, proj = cfg.get("home"), cfg.get("projects")
        if home:
            self.limits["u"][0] = QA.want(home["default"])
            self.limits["u"].update({u["uid"]: QA.want(u) for u in home["users"]})
        if proj:
            self.limits["p"].update({p["id"]: QA.want(p) for p in proj["projects"]})
            self.tagged |= {p["name"] for p in proj["projects"]}
        return self


def run_helper(fake, cfg, *argv):
    """(exit code, stdout, stderr) of prace-quota-apply main() against the fake."""
    with tempfile.TemporaryDirectory() as d:
        config = Path(d) / "quotas.json"
        if cfg is not None:
            config.write_text(json.dumps(cfg))
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(QA, "CONFIG", str(config)), \
             mock.patch.object(QA.subprocess, "run", side_effect=fake.run), \
             mock.patch.object(QA, "untagged", side_effect=fake.untagged), \
             mock.patch.object(QA, "check_project_dir", return_value=None), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = QA.main(list(argv))
    return rc, out.getvalue(), err.getvalue()


def setters(fake):
    return [c for c in fake.calls if c.startswith(("limit", "timer", "project -s"))]


class QuotaApply(unittest.TestCase):
    def test_report_parses_blocks_and_inodes_including_an_active_grace(self):
        with mock.patch.object(QA, "xq", return_value=REPORT_U):
            rows = QA.report("/home", "u")
        self.assertEqual(rows[0], (921600, 1048576, 9000, 10000))
        self.assertEqual(rows[20001], (18874368, 20971520, 180000, 200000))
        self.assertEqual(rows[30091], (204800, 262144, 1500, 2000))

    def test_sizes(self):
        self.assertEqual(QA.kib("18g"), 18874368)
        self.assertEqual(QA.kib("4608m"), 4718592)
        self.assertEqual(QA.kib("256m"), 262144)
        with self.assertRaises(ValueError):
            QA.kib("5 GB")

    def test_a_matching_declaration_changes_nothing(self):
        cfg = {"home": HOME_CFG, "projects": PROJ_CFG}
        fake = FakeXFS().declared(cfg)
        rc, out, err = run_helper(fake, cfg)
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(setters(fake), [])
        self.assertIn("quotas match the declaration", out)
        # Also with REPORT_U/STATE_U as recorded (an active grace on #30091 is still a match).
        cfg = {"home": dict(HOME_CFG, users=HOME_CFG["users"][:1]), "projects": None}
        with mock.patch.object(QA, "fstype", return_value="xfs"), \
             mock.patch.object(QA, "xq", side_effect=lambda p, c: REPORT_U if c.startswith("report") else STATE_U):
            self.assertEqual(QA.plan(cfg), [])

    def test_a_differing_limit_is_applied_read_back_and_reported(self):
        cfg = {"home": HOME_CFG, "projects": None}
        fake = FakeXFS().declared(cfg)
        cfg = json.loads(json.dumps(cfg))
        cfg["home"]["users"][0]["bhard"] = "25g"
        rc, out, err = run_helper(fake, cfg)
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(setters(fake), ["limit -u bsoft=18g bhard=25g isoft=180000 ihard=200000 20001"])
        self.assertIn("CHANGED user t (20001)", out)
        self.assertEqual(fake.calls.count("report -u -n -N -b -i"), 2)      # observed, then read back

    def test_a_query_that_exits_0_with_a_diagnostic_is_an_error(self):
        # The contract observed on a non-XFS path (review S4): rc 0, empty stdout, stderr diagnostic.
        with mock.patch.object(QA.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 0, "", NOT_XFS)):
            with self.assertRaisesRegex(RuntimeError, "cannot setup path for mount"):
                QA.xq("/home", "state -u")
        fake = FakeXFS()
        fake.stderr["report"] = NOT_XFS
        rc, out, err = run_helper(fake, {"home": HOME_CFG, "projects": None})
        self.assertEqual(rc, 1)
        self.assertIn("No such device or address", err)
        self.assertNotIn("CHANGED", out)
        self.assertEqual(setters(fake), [])

    def test_a_setter_diagnostic_is_an_error(self):
        fake = FakeXFS()
        fake.stderr["limit"] = "xfs_quota: cannot set limits: Operation not permitted\n"
        rc, out, err = run_helper(fake, {"home": HOME_CFG, "projects": None})
        self.assertEqual(rc, 1)
        self.assertIn("cannot set limits", err)

    def test_a_setter_that_changes_nothing_fails_the_readback(self):
        fake = FakeXFS()
        fake.ignore.add("limit -u bsoft=18g")          # rc 0, no diagnostic, no effect
        rc, out, err = run_helper(fake, {"home": HOME_CFG, "projects": None})
        self.assertEqual(rc, 1)
        self.assertIn("STILL DIFFERS user t (20001) on /home: have no record, want bsoft=18874368k", out)
        self.assertIn("1 difference(s) remain", err)
        self.assertNotIn("STILL DIFFERS user p", out)

    def test_grace_that_does_not_change_fails_the_readback(self):
        fake = FakeXFS()
        fake.grace["u", "b"] = fake.grace["u", "i"] = 3 * 86400
        fake.ignore.add("timer -u -b")
        rc, out, err = run_helper(fake, {"home": HOME_CFG, "projects": None})
        self.assertEqual(rc, 1)
        self.assertIn("STILL DIFFERS user block grace on /home: have blocks [3 days] inodes [7 days], want [7 days]", out)
        self.assertIn("timer -u -b 604800", fake.calls)

    def test_project_quota_tags_only_untagged_projects_and_reads_back(self):
        cfg = {"home": None, "projects": PROJ_CFG}
        fake = FakeXFS()
        fake.tagged.add("proj-beta")
        rc, out, err = run_helper(fake, cfg)
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(setters(fake), ["project -s proj-alpha",
                                         "limit -p bsoft=45g bhard=50g isoft=450000 ihard=500000 31001",
                                         "limit -p bsoft=45g bhard=50g isoft=450000 ihard=500000 31002"])
        self.assertEqual(fake.walks.count("/projects/proj-alpha"), 2)       # walked, then read back by the walk
        self.assertEqual(fake.calls.count("report -p -n -N -b -i"), 2)
        self.assertEqual(fake.limits["p"][31001], QA.want(PROJ_CFG["projects"][0]))
        # A second run is a no-op.
        fake.calls.clear()
        rc, out, _ = run_helper(fake, cfg)
        self.assertEqual((rc, setters(fake)), (0, []))

    def test_a_project_tag_or_limit_that_does_not_stick_fails(self):
        fake = FakeXFS()
        fake.ignore.add("project -s proj-alpha")
        rc, out, _ = run_helper(fake, {"home": None, "projects": PROJ_CFG})
        self.assertEqual(rc, 1)
        self.assertIn("STILL DIFFERS project proj-alpha directory tag", out)
        fake = FakeXFS()
        fake.ignore.add("limit -p")
        rc, out, _ = run_helper(fake, {"home": None, "projects": PROJ_CFG})
        self.assertEqual(rc, 1)
        self.assertIn("STILL DIFFERS project proj-beta (31002) on /projects: have no record", out)

    def test_project_setter_output_is_logged_and_the_walk_decides(self):
        # xfs_quota prints raw paths: a name with a newline splits into lines no pattern can
        # classify. Its output is logged; the helper's own NUL-safe walk proves the tag.
        cfg = {"home": None, "projects": PROJ_CFG}
        fake = FakeXFS()
        fake.tagged.add("proj-beta")
        fake.stderr["project -s"] = "xfs_quota: skipping special file /projects/proj-alpha/a\nb\n"
        rc, out, err = run_helper(fake, cfg)
        self.assertEqual((rc, err), (0, ""))
        self.assertIn("skipping special file", out)
        fake = FakeXFS()
        fake.ignore.add("project -s")
        fake.stderr["project -s"] = "anything at all\n"
        rc, out, _ = run_helper(fake, cfg)
        self.assertEqual(rc, 1)
        self.assertIn("STILL DIFFERS project proj-alpha directory tag", out)

    def test_home_and_projects_are_independent(self):
        fake = FakeXFS()
        fake.stderr["report -p"] = "xfs_quota: cannot find mount point\n"
        rc, out, err = run_helper(fake, {"home": HOME_CFG, "projects": PROJ_CFG})
        self.assertEqual(rc, 1)
        self.assertIn("projects:", err)
        self.assertIn("limit -u bsoft=18g bhard=20g isoft=180000 ihard=200000 20001", setters(fake))   # home still applied

    def test_the_walk_skips_symlinks_and_special_files_and_names_with_newlines(self):
        base = Path(tempfile.mkdtemp())
        try:
            (base / "d").mkdir()
            (base / "d" / "f").write_text("x")
            os.mkfifo(base / "a\nb")
            os.symlink("d/f", base / "link")
            seen = {}

            def fsxattr(path, is_dir):
                seen[path] = is_dir
                return (31001, True) if is_dir else ((0, False) if path.endswith("/f") else (31001, False))
            with mock.patch.object(QA, "fsxattr", side_effect=fsxattr):
                bad, first = QA.untagged(str(base), 31001)
            self.assertEqual(bad, 1)
            self.assertIn("/d/f", first)
            self.assertEqual(sorted(seen), sorted([str(base), str(base / "d"), str(base / "d" / "f")]))
        finally:
            shutil.rmtree(base)

    def test_not_xfs_or_quota_off_fails_before_any_query_or_setter(self):
        fake = FakeXFS()
        fake.mounts["/home"] = "ext4"
        rc, _, err = run_helper(fake, {"home": HOME_CFG, "projects": None})
        self.assertEqual((rc, fake.calls), (1, []))
        self.assertIn("/home is not an XFS mountpoint (found ext4)", err)
        del fake.mounts["/home"]
        self.assertIn("found no mount", run_helper(fake, {"home": HOME_CFG, "projects": None})[2])
        fake = FakeXFS()
        fake.on["p"] = False
        rc, _, err = run_helper(fake, {"home": None, "projects": PROJ_CFG})
        self.assertEqual((rc, setters(fake)), (1, []))
        self.assertIn("project quota accounting/enforcement not on", err)

    def test_malformed_observations_are_errors(self):
        for text, why in (("", "no #<id> rows"), ("#20001 4 18874368 20971520 00\n", "malformed row"),
                          (REPORT_U.replace("#0 ", "#x ", 1), "malformed row")):
            with self.subTest(why), mock.patch.object(QA, "xq", return_value=text):
                with self.assertRaisesRegex(RuntimeError, why):
                    QA.report("/home", "u")
        fake = FakeXFS()
        del fake.limits["u"][0]
        fake.limits["u"][20001] = (1, 2, 3, 4)
        rc, _, err = run_helper(fake, {"home": HOME_CFG, "projects": None})
        self.assertEqual((rc, setters(fake)), (1, []))
        self.assertIn("no #0 (default quota) record", err)
        with mock.patch.object(QA, "xq", return_value=STATE_U.replace("Blocks grace time: [7 days]\n", "")):
            with self.assertRaisesRegex(RuntimeError, "no grace times"):
                QA.state("/home", "u")
        # a walk that cannot read an entry is an error, not "tagged"
        fake = FakeXFS().declared({"home": None, "projects": PROJ_CFG})
        fake.untagged = lambda top, projid: (_ for _ in ()).throw(PermissionError(13, "Permission denied", top))
        rc, _, err = run_helper(fake, {"home": None, "projects": PROJ_CFG})
        self.assertEqual(rc, 1)
        self.assertIn("Permission denied", err)

    def test_check_mode_exit_codes(self):
        fake = FakeXFS()
        rc, out, _ = run_helper(fake, None, "--check")
        self.assertEqual((rc, fake.calls), (3, []))
        self.assertIn("no declaration yet", out)
        self.assertEqual(run_helper(FakeXFS(), None)[0], 1)                 # applying without one is an error
        fake = FakeXFS()
        rc, out, _ = run_helper(fake, {"home": HOME_CFG, "projects": PROJ_CFG}, "--check")
        self.assertEqual((rc, setters(fake)), (0, []))
        self.assertIn("WOULD user t (20001): xfs_quota -x -c 'limit -u bsoft=18g", out)
        self.assertIn("WOULD project proj-alpha directory tag", out)
        fake = FakeXFS()
        fake.stderr["state"] = NOT_XFS
        self.assertEqual(run_helper(fake, {"home": HOME_CFG, "projects": None}, "--check")[0], 1)
        rc, _, err = run_helper(FakeXFS(), {"home": dict(HOME_CFG, grace_s=90000), "projects": None}, "--check")
        self.assertEqual(rc, 1)
        self.assertIn("not a whole number of days", err)
        # a preview before the share is mounted (before the preparation window) is not an error
        fake = FakeXFS()
        del fake.mounts["/projects"]
        rc, out, _ = run_helper(fake, {"home": HOME_CFG, "projects": PROJ_CFG}, "--check")
        self.assertEqual(rc, 0)
        self.assertIn("WOULD apply every declared projects quota once /projects is mounted", out)
        # only a verified absent share previews as "would apply" (R4)
        fake = FakeXFS()
        fake.mounts["/projects"] = "ext4"
        rc, out, err = run_helper(fake, {"home": None, "projects": PROJ_CFG}, "--check")
        self.assertEqual(rc, 1)
        self.assertIn("not an XFS mountpoint (found ext4)", err)
        fake = FakeXFS()
        fake.findmnt_fails = True
        rc, out, err = run_helper(fake, {"home": None, "projects": PROJ_CFG}, "--check")
        self.assertEqual(rc, 1)
        self.assertIn("cannot read /proc/self/mountinfo", err)
        self.assertNotIn("WOULD apply every declared", out)

    def test_fstype_tells_absent_from_failed(self):
        # findmnt exits 1 both when nothing is mounted (silently) and on an error (with a message)
        cases = [((1, "", ""), None), ((0, "xfs\n", ""), "xfs"), ((1, "", "findmnt: can't read /proc/self/mountinfo\n"), RuntimeError),
                 ((0, "xfs\n", "findmnt: warning\n"), RuntimeError), ((4, "", ""), RuntimeError), ((0, "", ""), RuntimeError)]
        for (rc, out, err), want in cases:
            with self.subTest(rc=rc, out=out, err=err):
                done = subprocess.CompletedProcess(["findmnt"], rc, out, err)
                with mock.patch.object(QA.subprocess, "run", return_value=done):
                    if want is RuntimeError:
                        self.assertRaises(RuntimeError, QA.fstype, "/projects")
                    else:
                        self.assertEqual(QA.fstype("/projects"), want)
        # --config: the preview reads the declaration it is given
        with tempfile.TemporaryDirectory() as d:
            other = Path(d) / "preview.json"
            other.write_text(json.dumps({"home": HOME_CFG, "projects": None}))
            rc, out, _ = run_helper(FakeXFS(), None, "--check", "--config", str(other))
        self.assertEqual(rc, 0)
        self.assertIn("WOULD user t (20001)", out)


class StorageCheck(unittest.TestCase):
    def run_state(self, text):
        with mock.patch.object(SC, "run", return_value=(0, text)):
            return SC.quota_on("/home", "u")

    def test_on_on(self):
        self.assertTrue(self.run_state(STATE_U))

    def test_enforcement_off_or_missing_header_fails(self):
        self.assertFalse(self.run_state(STATE_U.replace("Enforcement: ON", "Enforcement: OFF")))
        self.assertFalse(self.run_state(STATE_U.replace("User quota state", "Group quota state")))
        with mock.patch.object(SC, "run", return_value=(1, "")):
            self.assertFalse(SC.quota_on("/home", "u"))


class TreeListing(unittest.TestCase):
    def listing(self, path, *flags):
        return subprocess.run(["python3", str(TL), *flags, path], capture_output=True, text=True, check=True).stdout

    def test_copy_matches_and_a_one_byte_change_does_not(self):
        base = Path(tempfile.mkdtemp())
        try:
            src = base / "src"
            (src / "d").mkdir(parents=True)
            (src / "d" / "f").write_text("data\n")
            os.link(src / "d" / "f", src / "hard")
            os.symlink("d/f", src / "link")
            os.mkfifo(src / "fifo")
            with open(src / "sparse", "wb") as f:
                f.truncate(1 << 20)
            if shutil.which("setfacl"):
                subprocess.run(["setfacl", "-m", f"u:{os.getuid()}:r", str(src / "d" / "f")], check=True)
            subprocess.run(["cp", "-a", str(src), str(base / "dst")], check=True)
            a = self.listing(str(src), "--no-label", "--no-root", "--summary")
            b = self.listing(str(base / "dst"), "--no-label", "--no-root", "--summary")
            self.assertEqual(a, b)
            with open(base / "dst" / "d" / "f", "r+") as f:
                f.write("D")
            os.utime(base / "dst" / "d" / "f", ns=(os.stat(src / "d" / "f").st_atime_ns, os.stat(src / "d" / "f").st_mtime_ns))
            self.assertNotEqual(a, self.listing(str(base / "dst"), "--no-label", "--no-root", "--summary"))
        finally:
            shutil.rmtree(base)

    def user_xattrs_or_skip(self, base):
        probe = base / "probe"
        probe.write_text("")
        try:
            os.setxattr(probe, "user.prace-probe", b"1")
        except OSError as err:
            self.skip_or_fail(f"no user xattrs on {base}: {err}")
        finally:
            probe.unlink()

    def test_an_xattr_only_change_or_a_new_attribute_changes_the_listing(self):
        base = Path(tempfile.mkdtemp())
        try:
            self.user_xattrs_or_skip(base)
            home = base / "home"
            home.mkdir()
            f = home / "file"
            f.write_text("same content\n")
            os.setxattr(f, "user.test", b"before")
            before = self.listing(str(home), "--no-label")
            self.assertIn('"user.test": "%s"' % b"before".hex(), before)
            os.setxattr(f, "user.test", b"after")          # content, mode, owner and mtime unchanged
            after = self.listing(str(home), "--no-label")
            self.assertNotEqual(before, after)
            os.setxattr(f, "user.other", b"")
            self.assertNotEqual(after, self.listing(str(home), "--no-label"))
            os.removexattr(f, "user.other")
            self.assertEqual(after, self.listing(str(home), "--no-label"))
            if shutil.which("setfacl"):                     # ACLs are in the same map
                subprocess.run(["setfacl", "-m", f"u:{os.getuid()}:r", str(f)], check=True)
                self.assertIn('"system.posix_acl_access"', self.listing(str(home), "--no-label"))
        finally:
            shutil.rmtree(base)

    def test_copies_that_keep_xattrs_match_and_one_that_drops_them_does_not(self):
        base = Path(tempfile.mkdtemp())
        try:
            self.user_xattrs_or_skip(base)
            src = base / "src"
            (src / "d").mkdir(parents=True)
            (src / "d" / "f").write_text("data\n")
            os.symlink("d/f", src / "link")
            # rsync leaves a symlink's time alone when it is in the same second as the copy
            os.utime(src / "link", ns=(1_600_000_000_123_456_789,) * 2, follow_symlinks=False)
            os.setxattr(src / "d" / "f", "user.test", b"before")
            os.setxattr(src / "d", "user.dir", b"\x00\xff")
            a = self.listing(str(src), "--no-label", "--no-root", "--summary")
            copies = {"cp -a": ["cp", "-a", str(src), str(base / "cp")]}
            if shutil.which("rsync"):                       # what the cutover uses
                copies["rsync -aHAXS"] = ["rsync", "-aHAXS", "--numeric-ids",   # labels: not settable in CI containers;
                                         "--filter=-x security.selinux",     # the comparison is --no-label
                                         f"{src}/", f"{base}/rsync/"]
            for name, argv in copies.items():
                with self.subTest(name):
                    subprocess.run(argv, check=True)
                    self.assertEqual(a, self.listing(str(base / argv[-1].rstrip("/").split("/")[-1]),
                                                     "--no-label", "--no-root", "--summary"))
            subprocess.run(["cp", "-a", "--no-preserve=xattr", str(src), str(base / "noxattr")], check=True)
            self.assertNotEqual(a, self.listing(str(base / "noxattr"), "--no-label", "--no-root", "--summary"))
        finally:
            shutil.rmtree(base)

    def test_no_label_leaves_out_security_selinux_only(self):
        attrs = {"security.selinux": b"system_u:object_r:user_home_t:s0\0", "security.capability": b"\x01",
                 "user.a": b"1"}

        def getxattr(path, name, follow_symlinks=True):
            if name not in attrs:
                raise OSError(errno.ENODATA, "No data available")
            return attrs[name]
        with tempfile.TemporaryDirectory() as d:
            Path(d, "f").write_text("x")
            with mock.patch.object(TLM.os, "listxattr", return_value=list(attrs)), \
                 mock.patch.object(TLM.os, "getxattr", side_effect=getxattr):
                labelled, plain = TLM.entry(d, "f", True), TLM.entry(d, "f", False)
        self.assertEqual(labelled["selinux"], "system_u:object_r:user_home_t:s0")
        self.assertNotIn("selinux", plain)
        for e in (labelled, plain):
            self.assertEqual(e["xattrs"], {"security.capability": "01", "user.a": "31"})

    def test_an_unreadable_attribute_is_exit_2_not_no_attributes(self):
        def main(path):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                return TLM.main(["--no-label", path]), err.getvalue()

        def getxattr(path, name, follow_symlinks=True):
            if name == "user.denied":
                raise OSError(errno.EACCES, "Permission denied")
            if name == "user.gone":
                raise OSError(errno.ENODATA, "No data available")    # removed after listing: skipped
            raise OSError(errno.ENODATA, "No data available")
        with tempfile.TemporaryDirectory() as d:
            Path(d, "f").write_text("x")
            with mock.patch.object(TLM.os, "listxattr", return_value=["user.gone"]), \
                 mock.patch.object(TLM.os, "getxattr", side_effect=getxattr):
                self.assertEqual(main(d)[0], 0)
            with mock.patch.object(TLM.os, "listxattr", return_value=["user.gone", "user.denied"]), \
                 mock.patch.object(TLM.os, "getxattr", side_effect=getxattr):
                rc, err = main(d)
            self.assertEqual(rc, 2)
            self.assertIn("getxattr user.denied: Permission denied", err)
            with mock.patch.object(TLM.os, "listxattr", side_effect=OSError(errno.EIO, "Input/output error")):
                rc, err = main(d)
            self.assertEqual(rc, 2)
            self.assertIn("listxattr: Input/output error", err)


EXPECTED_PROJECT_ACL = """user::rwx
group::rwx
mask::rwx
other::---
default:user::rwx
default:group::rwx
default:mask::rwx
default:other::---
"""


@unittest.skipUnless(os.environ.get("CI") or (shutil.which("setfacl") and shutil.which("getfacl")), "setfacl/getfacl not installed")
class ProjectAcl(unittest.TestCase):
    """The same file roles/storage_policy runs on /projects/<group>, on a local temporary directory."""
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base)

    def project(self, *acl):
        p = self.base / f"proj{len(list(self.base.iterdir()))}"
        p.mkdir()
        os.chmod(p, 0o2770)                                 # what the role's file task sets first
        for spec in acl:
            r = subprocess.run(["setfacl", "-m", spec, str(p)], capture_output=True, text=True)
            if r.returncode:
                self.skip_or_fail(f"no POSIX ACLs on {self.base}: {r.stderr.strip()}")
        return p

    def reconcile(self, p, *flags):
        return subprocess.run(["bash", str(ACL_SCRIPT), *flags, str(p)], capture_output=True, text=True)

    def acl(self, p):
        return subprocess.run(["getfacl", "-cpnE", str(p)], capture_output=True, text=True, check=True).stdout.strip() + "\n"

    def test_an_outsider_grant_and_its_default_are_removed_exactly(self):
        p = self.project("u:54321:rwx,d:u:54321:rwx", "d:u::rwx,d:g::rwx,d:m::rwx,d:o::---")
        before = self.acl(p)
        self.assertIn("user:54321:rwx", before)
        check = self.reconcile(p, "--check")
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertIn("WOULD reconcile", check.stdout)
        self.assertIn("  user:54321:rwx", check.stdout)                  # the old ACL is printed
        self.assertEqual(self.acl(p), before)                            # --check changed nothing
        r = self.reconcile(p)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("CHANGED", r.stdout)
        self.assertIn("  default:user:54321:rwx", r.stdout)
        self.assertEqual(self.acl(p), EXPECTED_PROJECT_ACL)
        self.assertNotIn("54321", self.acl(p))
        self.assertEqual(os.stat(p).st_mode & 0o7777, 0o2770)             # setgid and mode kept
        again = self.reconcile(p)
        self.assertEqual(again.returncode, 0)
        self.assertNotIn("CHANGED", again.stdout)
        self.assertIn("ACL matches", again.stdout)
        self.assertNotIn("WOULD", self.reconcile(p, "--check").stdout)

    def test_a_fresh_directory_and_a_default_only_group_grant_converge(self):
        for p in (self.project(), self.project("d:g:31999:rwx")):
            with self.subTest(p.name):
                r = self.reconcile(p)
                self.assertEqual((r.returncode, "CHANGED" in r.stdout), (0, True), r.stdout + r.stderr)
                self.assertEqual(self.acl(p), EXPECTED_PROJECT_ACL)
                self.assertNotIn("CHANGED", self.reconcile(p).stdout)

    def test_not_a_directory_or_bad_usage_fails(self):
        (self.base / "file").write_text("")
        os.symlink(self.base, self.base / "link")
        self.assertEqual(self.reconcile(self.base / "file").returncode, 1)
        self.assertEqual(self.reconcile(self.base / "link").returncode, 1)
        self.assertEqual(subprocess.run(["bash", str(ACL_SCRIPT)], capture_output=True).returncode, 2)


if __name__ == "__main__":
    unittest.main()
