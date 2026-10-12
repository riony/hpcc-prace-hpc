from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from harness.evidence import ARTIFACTS, checksum_text, package_run, verify_bundle
from harness.runner import run_cycle
from validation.contracts import ContractError


class Evidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hb-")
        cls.root = Path(cls.temporary.name)
        cls.run_dir = cls.root / "run"
        run_cycle(cls.run_dir, "bundle-test-001")
        # Runtime material must never be swept into a bundle.
        (cls.run_dir / "runtime-private.txt").write_text("not evidence")
        cls.bundle_dir = cls.root / "bundle"
        package_run(cls.run_dir, cls.bundle_dir)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.local = tempfile.TemporaryDirectory(prefix="hv-")
        self.addCleanup(self.local.cleanup)
        self.bundle = Path(self.local.name) / "copy"
        shutil.copytree(self.bundle_dir, self.bundle)

    def resign(self):
        """Recompute hashes so semantic checks, rather than checksum failure, run."""
        index_path = self.bundle / "bundle.json"
        index = json.loads(index_path.read_text())
        for entry in index["artifacts"]:
            data = (self.bundle / entry["path"]).read_bytes()
            entry["bytes"] = len(data)
            entry["sha256"] = hashlib.sha256(data).hexdigest()
        index_path.write_text(json.dumps(index))
        (self.bundle / "SHA256SUMS").write_text(checksum_text(index["artifacts"]))

    def test_portable_bundle_verifies_without_runtime_or_workspace(self):
        metadata = verify_bundle(self.bundle)
        self.assertEqual(metadata["run_id"], "bundle-test-001")
        self.assertEqual(len(ARTIFACTS), 22)
        self.assertFalse((self.bundle / "runtime-private.txt").exists())
        self.assertFalse((self.bundle / "before/gateway.json").exists())
        self.assertFalse((self.bundle / "before/workspace").exists())
        self.assertEqual((self.bundle / "run.json").stat().st_mode & 0o777, 0o600)

    def test_one_byte_change_refuses(self):
        path = self.bundle / "after/events.jsonl"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(ContractError, "integrity mismatch"):
            verify_bundle(self.bundle)

    def test_missing_file_refuses(self):
        (self.bundle / "fix-proposal.json").unlink()
        with self.assertRaises(OSError):
            verify_bundle(self.bundle)

    def test_undeclared_file_refuses(self):
        (self.bundle / "unlisted.txt").write_text("extra")
        with self.assertRaisesRegex(ContractError, "undeclared file"):
            verify_bundle(self.bundle)

    def test_symlink_file_and_directory_refuse(self):
        for directory in (False, True):
            with self.subTest(directory=directory):
                temporary = Path(self.local.name) / ("dir-link" if directory else "file-link")
                shutil.copytree(self.bundle, temporary)
                path = temporary / ("before" if directory else "run.json")
                if directory:
                    shutil.rmtree(path)
                    path.symlink_to(self.bundle / "before", target_is_directory=True)
                else:
                    path.unlink()
                    path.symlink_to(self.bundle / "run.json")
                with self.assertRaisesRegex(ContractError, "symlink"):
                    verify_bundle(temporary)

    def test_path_escape_index_refuses_before_reading_outside(self):
        index_path = self.bundle / "bundle.json"
        index = json.loads(index_path.read_text())
        index["artifacts"][0]["path"] = "../outside"
        index_path.write_text(json.dumps(index))
        with self.assertRaisesRegex(ContractError, "artifact paths"):
            verify_bundle(self.bundle)

    def test_rehashed_false_pass_still_refuses(self):
        path = self.bundle / "before/result.json"
        value = json.loads(path.read_text())
        value["verdicts"]["functional"] = "pass"
        path.write_text(json.dumps(value))
        self.resign()
        with self.assertRaisesRegex(ContractError, "contradicts trace"):
            verify_bundle(self.bundle)

    def test_rehashed_unbound_fix_refuses(self):
        path = self.bundle / "fix-proposal.json"
        value = json.loads(path.read_text())
        value["after_template_sha256"] = "0" * 64
        path.write_text(json.dumps(value))
        self.resign()
        with self.assertRaisesRegex(ContractError, "unbound fixture"):
            verify_bundle(self.bundle)

    def test_rehashed_failed_driver_receipt_refuses(self):
        path = self.bundle / "after/driver.json"
        value = json.loads(path.read_text())
        value["returncode"] = 1
        path.write_text(json.dumps(value))
        self.resign()
        with self.assertRaisesRegex(ContractError, "driver receipt"):
            verify_bundle(self.bundle)

    def test_local_run_cannot_claim_slurm_or_recovery(self):
        path = self.bundle / "run.json"
        value = json.loads(path.read_text())
        value["slurm_job_ids"] = [123]
        path.write_text(json.dumps(value))
        self.resign()
        with self.assertRaisesRegex(ContractError, "cannot claim fleet"):
            verify_bundle(self.bundle)

    def test_index_identity_and_checksum_list_refuse_mismatch(self):
        index_path = self.bundle / "bundle.json"
        index = json.loads(index_path.read_text())
        index["run_id"] = "another-run"
        index_path.write_text(json.dumps(index))
        with self.assertRaisesRegex(ContractError, "identity mismatch"):
            verify_bundle(self.bundle)
        index["run_id"] = "bundle-test-001"
        index_path.write_text(json.dumps(index))
        (self.bundle / "SHA256SUMS").write_text("")
        with self.assertRaisesRegex(ContractError, "checksum list"):
            verify_bundle(self.bundle)

    def test_existing_destination_is_not_overwritten(self):
        with self.assertRaisesRegex(ContractError, "new bundle directory"):
            package_run(self.run_dir, self.bundle)


if __name__ == "__main__":
    unittest.main()
