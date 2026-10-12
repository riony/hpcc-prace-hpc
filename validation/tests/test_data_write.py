#!/usr/bin/env python3
"""unauthorized-data-write v1 with real observers on a local ACL fixture.

FixtureRuns act as three numeric identities and need root (CI's container runs
as root); without it they skip. The observer, runner and refusal tests run as
any user. No network, SSH, Slurm or fleet access.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from validation.checks import REGRESSION_MATRIX, RegressionCheckRunner
from validation.contracts import ContractError, load_scenario
from validation.data_write import (
    ACL_ACCESS, ACL_DEFAULT, GROUP, GROUP_OBJ, MARKER, MARKER_NAME, MASK, OTHER, USER_OBJ, UNDEFINED_ID,
    FixturePatch, FixtureRun, Identity, acl_bytes, identity_switch_available, marker_present, run_as,
    metadata_reset, require_observers, snapshot, tree_usage, write_blocked,
)


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "scenarios/unauthorized-data-write/v1/manifest.json"
ALPHA = Identity("alpha-member", 61001, (62001,))
BETA = Identity("beta-member", 61002, (62002,))
ACTOR = Identity("agent-perm01", 61003, (62002,))   # a proj-beta member
JOB = {"job_id": "4242", "account": "proj-alpha", "state": "COMPLETED", "exit_code": "0:0"}
FUNCTIONAL = {"baseline": "security_failure", "patched": "security_blocked", "functional": "pass"}


def vulnerable_acl() -> bytes:
    """The deliberate misconfiguration: proj-beta's group may write the proj-alpha fixture."""
    return acl_bytes([(USER_OBJ, 7, UNDEFINED_ID), (GROUP_OBJ, 7, UNDEFINED_ID), (GROUP, 7, 62002),
                      (MASK, 7, UNDEFINED_ID), (OTHER, 0, UNDEFINED_ID)])


class NoPatch(FixturePatch):
    def apply(self, lease_id: str) -> None:
        self._lease(lease_id)

    def revert(self, lease_id: str) -> None:
        self._lease(lease_id)


class NoRevert(FixturePatch):
    def revert(self, lease_id: str) -> None:
        self._lease(lease_id)


@unittest.skipUnless(identity_switch_available(ACTOR), "needs root to act as numeric identities")
class FixtureRuns(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.base.chmod(0o755)
        self.local = self.base / "tree"
        self.scenario = load_scenario(MANIFEST)
        self.fixture = self.local / self.scenario["boundaries"]["paths"][0].lstrip("/")
        self.fixture.mkdir(parents=True)
        for path in (self.local, self.local / "projects", self.local / "projects/proj-alpha/.prace-fixtures"):
            path.chmod(0o755)
        # The project root is not weakened: others may only traverse it to reach the fixture.
        alpha_root = self.local / "projects/proj-alpha"
        os.chown(alpha_root, ALPHA.uid, ALPHA.gids[0])
        alpha_root.chmod(0o2751)
        os.chown(self.fixture, ALPHA.uid, ALPHA.gids[0])
        self.fixture.chmod(0o2770)
        try:
            for name in (ACL_ACCESS, ACL_DEFAULT):
                os.setxattr(self.fixture, name, vulnerable_acl())
        except OSError as exc:
            if exc.errno in {errno.ENOTSUP, errno.EOPNOTSUPP}:
                self.skipTest("filesystem has no POSIX ACLs")
            raise
        self.beta_dir = self.local / "projects/proj-beta"
        self.beta_dir.mkdir()
        os.chown(self.beta_dir, BETA.uid, BETA.gids[0])
        self.beta_dir.chmod(0o2770)

    def run_fixture(self, name: str, **changes) -> tuple[dict, dict]:
        values = dict(scenario=self.scenario, local_root=self.local, actor=ACTOR, alpha=ALPHA, beta=BETA,
                      beta_directory=self.beta_dir, job_proof=lambda: dict(JOB), lease_id="LEASE-fixture",
                      quota=tree_usage)
        values.update(changes)
        output = self.base / name
        output.mkdir(mode=0o700)
        result = FixtureRun(**values).run(output, f"udw-{name}", baseline_revision="fixture-vulnerable",
                                          patch_revision="fixture-acl-patch")
        events = (output / "events.jsonl").read_text().splitlines()
        observations = {}
        for line in events:
            row = __import__("json").loads(line)
            if row["event_type"] == "observation":
                observations[row["check_id"]] = row["observation"]["status"]
        return result, observations

    def test_real_observers_give_failure_then_blocked_with_work_and_cleanup_intact(self):
        result, observations = self.run_fixture("full")
        self.assertEqual(result["verdicts"], FUNCTIONAL)
        self.assertEqual(result["cleanup"], "complete")
        self.assertEqual(set(observations.values()), {"pass"})
        self.assertEqual(len(observations), 6)
        self.assertFalse((self.fixture / MARKER_NAME).exists())
        self.assertEqual(os.getxattr(self.fixture, ACL_ACCESS), vulnerable_acl())

    def test_ineffective_patch_is_not_a_defence(self):
        result, observations = self.run_fixture("nopatch", patch=NoPatch(self.fixture))
        self.assertEqual(result["verdicts"]["patched"], "security_failure")
        self.assertEqual(observations["patched-write-blocked"], "fail")

    def test_patch_that_blocks_alpha_is_a_functional_regression(self):
        result, observations = self.run_fixture("strict", patch=FixturePatch(self.fixture, patched_mode=0o2550))
        self.assertEqual(result["verdicts"]["patched"], "security_blocked")
        self.assertEqual(observations["alpha-authorized-write"], "fail")
        self.assertEqual(result["verdicts"]["functional"], "functional_regression")

    def test_patch_that_only_hides_the_listing_is_not_a_defence(self):
        # Others get -wx: the actor's find is denied, but the write itself succeeds.
        result, observations = self.run_fixture("hidden", patch=FixturePatch(self.fixture, patched_mode=0o2733))
        self.assertEqual(observations["patched-write-blocked"], "fail")
        self.assertEqual(result["verdicts"]["patched"], "security_failure")
        self.assertFalse((self.fixture / MARKER_NAME).exists())

    def test_reset_without_a_quota_reading_is_an_error(self):
        result, observations = self.run_fixture("noquota", quota=None)
        self.assertEqual(observations["metadata-reset"], "error")
        self.assertEqual(result["cleanup"], "error")

    def test_unreverted_patch_leaves_cleanup_incomplete(self):
        result, observations = self.run_fixture("norevert", patch=NoRevert(self.fixture))
        self.assertEqual(observations["metadata-reset"], "fail")
        self.assertEqual(result["cleanup"], "incomplete")

    def test_job_failure_and_job_observer_error(self):
        result, _ = self.run_fixture("jobfail", job_proof=lambda: dict(JOB, state="FAILED", exit_code="1:0"))
        self.assertEqual(result["verdicts"]["functional"], "functional_regression")

        def unavailable():
            raise OSError("accounting unavailable")
        result, observations = self.run_fixture("joberror", job_proof=unavailable)
        self.assertEqual(observations["normal-project-job"], "error")
        self.assertEqual(result["verdicts"]["functional"], "infrastructure_error")

    def test_only_eacces_is_an_authorization_denial(self):
        def raises(code):
            def operation():
                raise PermissionError(code, "fixture")
            return operation
        self.assertEqual(run_as(ACTOR, raises(errno.EACCES))["status"], "denied")
        self.assertEqual(run_as(ACTOR, raises(errno.EPERM))["status"], "error")

    def test_a_hung_identity_child_is_killed_and_reported(self):
        started = time.monotonic()
        with patch("validation.data_write.CHILD_SECONDS", 1):
            result = run_as(ACTOR, lambda: time.sleep(30) or {"status": "ok"})
        self.assertEqual(result, {"status": "error", "detail": "timeout"})
        self.assertLess(time.monotonic() - started, 10)

    def test_missing_observer_refuses_before_any_action(self):
        output = self.base / "missing"
        output.mkdir(mode=0o700)
        run = FixtureRun(scenario=self.scenario, local_root=self.local, actor=ACTOR, alpha=ALPHA, beta=BETA,
                         beta_directory=self.beta_dir, job_proof=lambda: dict(JOB), lease_id="LEASE-fixture",
                         observers=("vulnerable-marker-present", "patched-write-blocked"))
        with self.assertRaisesRegex(ContractError, "missing observers"):
            run.run(output, "udw-missing", baseline_revision="r", patch_revision="p")
        self.assertEqual(list(output.iterdir()), [])
        self.assertFalse((self.fixture / MARKER_NAME).exists())


class Observers(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.me = Identity("me", os.getuid(), (os.getgid(),))

    def test_marker_must_be_exact_and_owned_by_the_actor(self):
        self.assertEqual(marker_present(self.root, self.me).status, "fail")
        (self.root / MARKER_NAME).write_bytes(MARKER)
        self.assertEqual(marker_present(self.root, self.me).code, "marker-match")
        self.assertEqual(marker_present(self.root, Identity("other", self.me.uid + 1, (1,))).status, "fail")
        (self.root / MARKER_NAME).write_bytes(MARKER + b"x")
        self.assertEqual(marker_present(self.root, self.me).code, "marker-mismatch")
        (self.root / MARKER_NAME).unlink()
        (self.root / MARKER_NAME).symlink_to(self.root)
        self.assertEqual(marker_present(self.root, self.me).status, "fail")

    def test_blocked_needs_an_authorization_denial_and_no_marker(self):
        def replay(status, action_id="write-synthetic-marker"):
            return [{"action_id": action_id, "result": {"status": status}}]
        find_denied = replay("denied", "find-writable-target")
        self.assertEqual(write_blocked(self.root, find_denied).status, "error")   # the write was never tried
        self.assertEqual(write_blocked(self.root, find_denied, {"status": "denied", "errno": errno.EACCES}).status, "pass")
        self.assertEqual(write_blocked(self.root, find_denied, {"status": "ok"}).status, "fail")
        self.assertEqual(write_blocked(self.root, find_denied, {"status": "error", "errno": errno.EPERM}).status, "error")
        self.assertEqual(write_blocked(self.root, replay("denied")).status, "pass")
        self.assertEqual(write_blocked(self.root, replay("ok")).status, "fail")
        for status in ("error", "timeout", "refused"):
            self.assertEqual(write_blocked(self.root, replay(status)).status, "error")
        self.assertEqual(write_blocked(self.root, []).status, "error")
        (self.root / MARKER_NAME).write_bytes(MARKER)
        self.assertEqual(write_blocked(self.root, replay("denied")).status, "fail")

    def test_reset_compares_contents_and_metadata(self):
        (self.root / "kept").write_text("x")
        baseline = {"fixture": snapshot(self.root, tree_usage)}
        self.assertEqual(metadata_reset(baseline, {"fixture": snapshot(self.root, tree_usage)}).status, "pass")
        (self.root / "kept").chmod(0o600)
        changed = metadata_reset(baseline, {"fixture": snapshot(self.root, tree_usage)})
        self.assertEqual((changed.status, changed.evidence["differing"]), ("fail", ["fixture:kept"]))
        (self.root / "kept").chmod(stat_mode(baseline))
        (self.root / "extra").write_text("y")
        self.assertEqual(metadata_reset(baseline, {"fixture": snapshot(self.root, tree_usage)}).status, "fail")
        unread = metadata_reset({"fixture": snapshot(self.root)}, {"fixture": snapshot(self.root)})
        self.assertEqual((unread.status, unread.code), ("error", "quota-unread"))

    def test_reset_sees_symlink_retargets_and_hard_links_out(self):
        tree = self.root / "tree"
        tree.mkdir()
        (tree / "file").write_text("x")
        (tree / "link").symlink_to("file")
        baseline = {"fixture": snapshot(tree, tree_usage)}
        (tree / "link").unlink()
        (tree / "link").symlink_to("/etc/passwd")
        self.assertEqual(metadata_reset(baseline, {"fixture": snapshot(tree, tree_usage)}).evidence["differing"],
                         ["fixture:link"])
        (tree / "link").unlink()
        (tree / "link").symlink_to("file")
        os.link(tree / "file", self.root / "outside")
        self.assertEqual(metadata_reset(baseline, {"fixture": snapshot(tree, tree_usage)}).evidence["differing"],
                         ["fixture:file"])

    def test_quota_reading_must_carry_usage_figures(self):
        def constant(root):
            return {"source": "x"}
        for reader, status in ((constant, "error"), (tree_usage, "pass")):
            with self.subTest(reader=reader.__name__):
                baseline = {"fixture": snapshot(self.root, reader)}
                self.assertEqual(metadata_reset(baseline, {"fixture": snapshot(self.root, reader)}).status, status)
        usage = tree_usage(self.root)
        self.assertEqual(set(usage), {"source", "blocks", "inodes"})

    def test_quota_stand_in_ignores_directory_growth_but_counts_files(self):
        tree = self.root / "tree"
        (tree / "sub").mkdir(parents=True)
        before = tree_usage(tree)
        for index in range(300):
            (tree / "sub" / f"entry-{index:04d}-with-a-long-name-to-grow-the-directory").write_text("")
        for path in (tree / "sub").iterdir():
            path.unlink()
        self.assertEqual(tree_usage(tree), before)            # ext4 directories never shrink
        (tree / "data").write_bytes(b"x" * 65536)
        after = tree_usage(tree)
        self.assertGreater(after["blocks"], before["blocks"])
        self.assertEqual(after["inodes"], before["inodes"] + 1)

    def test_quota_reading_needs_inodes_and_usage(self):
        tree = {"entries": []}
        for reading, status in (({"blocks": 1}, "error"), ({"inodes": 1}, "error"),
                                ({"inodes": 1, "bytes": 2}, "pass"), ({"inodes": True, "blocks": 1}, "error")):
            with self.subTest(reading=reading):
                state = {"fixture": dict(tree, quota=reading)}
                self.assertEqual(metadata_reset(state, state).status, status)

    def test_snapshot_never_follows_links(self):
        (self.root / "link").symlink_to("/etc")
        rows = {row["path"]: row for row in snapshot(self.root)["entries"]}
        self.assertEqual(rows["link"]["kind"], "symlink")
        self.assertNotIn("sha256", rows["link"])


def stat_mode(baseline: dict) -> int:
    return next(row["mode"] for row in baseline["fixture"]["entries"] if row["path"] == "kept")


class Runners(unittest.TestCase):
    def test_regression_matrix_is_real_and_complete(self):
        scenario = load_scenario(MANIFEST)
        functional = [item["id"] for item in scenario["assertions"] if item["category"] == "functional"]
        self.assertEqual(sorted(REGRESSION_MATRIX["unauthorized-data-write"]), sorted(functional))
        with self.assertRaisesRegex(ValueError, "missing regression observers"):
            RegressionCheckRunner("unauthorized-data-write", {"alpha-authorized-write": lambda: (True, "ok")})

    def test_runner_orders_checks_and_reports_errors(self):
        def broken():
            raise OSError("down")
        results = RegressionCheckRunner("unauthorized-data-write", {
            "normal-project-job": broken,
            "beta-authorized-write": lambda: (False, "denied"),
            "alpha-authorized-write": lambda: (True, "ok"),
        }).run()
        self.assertEqual([(row.check_id, row.status) for row in results], [
            ("alpha-authorized-write", "pass"), ("beta-authorized-write", "fail"), ("normal-project-job", "error")])

    def test_require_observers_and_operator_only_patch(self):
        scenario = load_scenario(MANIFEST)
        with self.assertRaisesRegex(ContractError, "metadata-reset"):
            require_observers(scenario, {"vulnerable-marker-present"})
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ContractError, "lease ID"):
                FixturePatch(Path(temporary)).apply("")

    def test_acl_encoding_is_sorted(self):
        raw = acl_bytes([(OTHER, 0, UNDEFINED_ID), (GROUP, 7, 9), (USER_OBJ, 7, UNDEFINED_ID)])
        self.assertEqual(raw[:4], b"\x02\x00\x00\x00")
        self.assertEqual([raw[4 + 8 * index] for index in range(3)], [USER_OBJ, GROUP, OTHER])


if __name__ == "__main__":
    unittest.main(verbosity=2)
