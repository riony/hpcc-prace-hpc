#!/usr/bin/env python3
"""Real local filesystem/tar fixtures; no hosts, services or credentials."""
import importlib.util
import contextlib
import fcntl
import io
import json
import os
import runpy
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("metadata_archive", TOOLS / "prace_metadata_archive.py")
archive = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(archive)
HELPER = TOOLS.parent / "roles/login_storage/files/prace-tree-listing"


def portable_fixture_run(run, args):
    """Test-only adapter: real tar/listing checks every metadata field but SELinux.

    Rootless CI can read inherited labels but cannot restore them. Keep production
    commands and warning/error handling intact; strict qualification never uses
    this adapter. Exclude the label through both GNU tar preservation mechanisms.
    """
    if args[0] == "tar" and ("--create" in args or "--extract" in args):
        args = [args[0], "--no-selinux", "--xattrs-exclude=security.selinux",
                *(arg for arg in args[1:] if arg != "--selinux")]
    elif args[:2] == [sys.executable, str(HELPER)]:
        args = [*args[:2], "--no-label", *args[2:]]
    return run(args)


class MetadataArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="prace-metadata-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o750)
        (self.source / "file").write_bytes(b"metadata and contents\n")
        (self.source / "file").chmod(0o640)
        os.utime(self.source / "file", ns=(1700000000123456789, 1700000000123456789))
        self.output = self.root / "data.tgz"
        self.proof = self.root / "proof"
        if os.environ.get("PRACE_TEST_PORTABLE_METADATA") == "1":
            self.assertNotEqual(os.environ.get("PRACE_REQUIRE_PRIVILEGED"), "1",
                                "portable fixtures cannot provide privileged qualification")
            run = archive._run
            adapter = patch.object(archive, "_run", side_effect=lambda args: portable_fixture_run(run, args))
            adapter.start()
            self.addCleanup(adapter.stop)

    def create(self, **kwargs):
        # Ordinary fixtures use the production core. Explicit portable mode
        # retains real tar/filesystem checks but excludes SELinux preservation.
        return archive._create_verified_archive(self.source, self.output, self.proof, HELPER, **kwargs)

    def missing_tool_refuses(self, missing):
        with patch.object(archive.shutil, "which", side_effect=lambda name: None if name in missing else "/usr/bin/" + name), \
                patch.object(archive, "_run") as command:
            with self.assertRaisesRegex(archive.ArchiveError, "missing archive prerequisite"):
                self.create()
            command.assert_not_called()
            self.assertFalse(self.output.exists())
            self.assertFalse(self.output.with_name(self.output.name + ".partial").exists())
            self.assertFalse(self.proof.exists())
            self.assertEqual((self.source / "file").read_bytes(), b"metadata and contents\n")

    def test_missing_tar_refuses_before_staging(self):
        self.missing_tool_refuses({"tar"})

    def test_missing_gzip_refuses_before_staging(self):
        self.missing_tool_refuses({"gzip"})

    def test_missing_both_archive_tools_refuse_before_staging(self):
        self.missing_tool_refuses({"tar", "gzip"})

    def restored_view(self):
        # Successful create removes its own extract after durable proof. Use a
        # separate fresh verification destination for direct metadata assertions.
        destination = self.root / "verification"
        archive._verify_extract(self.output, destination, HELPER,
                                (self.proof / "source-before.jsonl").read_bytes(),
                                json.loads((self.proof / "source-scope.json").read_text()))
        return destination / "source"

    def prerequisite(self, condition, message, ci_required=False, privileged_required=False):
        if not condition:
            strict = os.environ.get("PRACE_REQUIRE_PRIVILEGED") == "1"
            if (ci_required and (os.environ.get("CI") or strict)) or (privileged_required and strict):
                self.fail(message)
            self.skipTest(message)

    def privileged_environment(self):
        self.prerequisite(os.geteuid() == 0, "privileged fixture requires root", privileged_required=True)
        if os.environ.get("PRACE_REQUIRE_PRIVILEGED") == "1":
            try:
                release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines()
                               if "=" in line and not line.startswith("#"))
                enforcing = Path("/sys/fs/selinux/enforce").read_text().strip()
            except OSError as exc:
                self.fail(f"privileged qualification prerequisites unavailable: {exc}")
            self.assertEqual(release.get("ID", "").strip('"'), "rocky",
                             "privileged qualification requires the isolated Rocky rehearsal VM")
            self.assertEqual(enforcing, "1", "privileged qualification requires enforcing SELinux")

    def test_round_trip_content_mode_nanoseconds_symlink_and_hardlinks(self):
        os.link(self.source / "file", self.source / "hard")
        (self.source / "sym").symlink_to("file")
        (self.source / "empty").mkdir(mode=0o710)
        result = self.create()
        restored = self.restored_view()
        self.assertEqual((restored / "file").read_bytes(), (self.source / "file").read_bytes())
        self.assertEqual((restored / "file").stat().st_mtime_ns, 1700000000123456789)
        self.assertEqual(stat.S_IMODE((restored / "file").stat().st_mode), 0o640)
        self.assertEqual((restored / "file").stat().st_ino, (restored / "hard").stat().st_ino)
        self.assertEqual(os.readlink(restored / "sym"), "file")
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.proof.stat().st_mode), 0o700)
        self.assertFalse((self.proof / "extract").exists())
        self.assertEqual(stat.S_IMODE(restored.parent.stat().st_mode), 0o700)
        self.assertEqual(result["archive_sha256"], archive._sha(self.output))
        self.assertFalse(Path(str(self.output) + ".partial").exists())
        self.assertEqual(json.loads((self.proof / "manifest.json").read_text()), result)

    def test_user_xattr_round_trip(self):
        try:
            os.setxattr(self.source / "file", "user.prace-test", b"binary\x00value")
        except OSError as exc:
            self.prerequisite(False, f"user xattrs unavailable: {exc}", ci_required=True)
        self.create()
        self.assertEqual(os.getxattr(self.restored_view() / "file", "user.prace-test"), b"binary\x00value")

    def test_access_and_default_acl_round_trip(self):
        self.prerequisite(shutil.which("setfacl"), "setfacl is required for ACL proof", ci_required=True)
        # Use a mapped UID even inside a rootless user namespace; arbitrary UID
        # preservation has its own explicitly privileged fixture below.
        result = subprocess.run(["setfacl", "-m", f"u:{os.geteuid()}:r--", str(self.source / "file")], capture_output=True)
        self.prerequisite(result.returncode == 0, f"ACLs unavailable: {result.stderr!r}", ci_required=True)
        subprocess.run(["setfacl", "-m", f"d:u:{os.geteuid()}:rwx", str(self.source)], check=True, capture_output=True)
        self.create()
        restored = self.restored_view()
        self.assertEqual(os.getxattr(self.source / "file", "system.posix_acl_access"),
                         os.getxattr(restored / "file", "system.posix_acl_access"))
        self.assertEqual(os.getxattr(self.source, "system.posix_acl_default"),
                         os.getxattr(restored, "system.posix_acl_default"))

    def test_numeric_ownership_round_trip_when_privileged(self):
        self.privileged_environment()
        os.chown(self.source / "file", 32123, 32124)
        self.create()
        info = (self.restored_view() / "file").stat()
        self.assertEqual((info.st_uid, info.st_gid), (32123, 32124))

    def test_selinux_round_trip_when_supported(self):
        if os.environ.get("PRACE_TEST_PORTABLE_METADATA") == "1":
            self.skipTest("portable metadata mode excludes SELinux; run strict Rocky qualification separately")
        self.privileged_environment()
        self.prerequisite(Path("/sys/fs/selinux/enforce").exists(), "SELinux filesystem is unavailable",
                          privileged_required=True)
        try:
            original = os.getxattr(self.source / "file", "security.selinux")
            parts = original.rstrip(b"\0").split(b":", 3)
            self.assertEqual(len(parts), 4, "expected a complete SELinux context")
            # Both types belong to Rocky's targeted policy. Change the type so a
            # newly created destination's default label cannot satisfy this proof.
            parts[2] = b"user_home_t" if parts[2] != b"user_home_t" else b"usr_t"
            os.setxattr(self.source / "file", "security.selinux", b":".join(parts) + b"\0")
            label = os.getxattr(self.source / "file", "security.selinux")
        except OSError as exc:
            self.prerequisite(False, f"cannot set distinct SELinux fixture label: {exc}",
                              privileged_required=True)
        self.assertNotEqual(label, original)
        self.create()
        # Check the exact captured context before any restorecon/relabel step.
        self.assertEqual(os.getxattr(self.restored_view() / "file", "security.selinux"), label)

    def test_sparse_round_trip_and_logical_size_bound(self):
        with (self.source / "sparse").open("wb") as stream:
            stream.seek(8 * 1024 * 1024)
            stream.write(b"end")
        self.create(max_bytes=10 * 1024 * 1024)
        restored = self.restored_view() / "sparse"
        self.assertEqual(restored.stat().st_size, 8 * 1024 * 1024 + 3)
        self.assertLess(restored.stat().st_blocks * 512, restored.stat().st_size // 2)

    def test_size_refusal_keeps_no_final_archive(self):
        with self.assertRaisesRegex(archive.ArchiveError, "max_bytes"):
            self.create(max_bytes=1)
        self.assertFalse(self.output.exists())

    def test_out_of_root_hardlink_is_refused(self):
        os.link(self.source / "file", self.root / "external")
        with self.assertRaisesRegex(archive.ArchiveError, "outside the selected root"):
            self.create()

    def test_special_object_is_refused(self):
        os.mkfifo(self.source / "fifo")
        with self.assertRaisesRegex(archive.ArchiveError, "special object"):
            self.create()

    def test_nested_same_device_mount_is_refused(self):
        nested = self.source / "nested"
        nested.mkdir()
        with patch.object(archive, "_mountpoints", return_value=[nested]):
            with self.assertRaisesRegex(archive.ArchiveError, "nested mount"):
                self.create()

    def test_absolute_parent_relative_and_dangling_symlinks_round_trip(self):
        sentinel = self.root / "outside"
        sentinel.write_text("outside sentinel")
        targets = {"absolute": str(sentinel), "parent": "../outside",
                   "traversing": "folder/../file", "dangling": "missing/target"}
        for name, target in targets.items():
            (self.source / name).symlink_to(target)
        archive.inspect_source(self.source)
        self.create()
        restored = self.restored_view()
        for name, target in targets.items():
            self.assertEqual(os.readlink(restored / name), target)
        self.assertEqual(sentinel.read_text(), "outside sentinel")
        self.assertFalse((self.source / "missing").exists())

    def test_source_change_is_refused(self):
        original = archive._run
        def mutate(args):
            result = original(args)
            if args[0] == "tar" and "--create" in args:
                (self.source / "file").write_text("changed after capture")
            return result
        with patch.object(archive, "_run", side_effect=mutate):
            with self.assertRaisesRegex(archive.ArchiveError, "source changed"):
                self.create()
        self.assertFalse(self.output.exists())

    def test_extraction_metadata_mismatch_is_refused(self):
        original = archive._run
        def damage(args):
            result = original(args)
            if args[0] == "tar" and "--extract" in args:
                (self.proof / "extract/source/file").chmod(0o600)
            return result
        with patch.object(archive, "_run", side_effect=damage):
            with self.assertRaisesRegex(archive.ArchiveError, "listing differs"):
                self.create()
        self.assertFalse(self.output.exists())
        self.assertTrue((self.proof / "extract/source/file").exists())

    def test_success_cleanup_follows_durable_proof_and_only_removes_own_extract(self):
        other = self.root / "other-proof/extract"
        other.mkdir(parents=True)
        (other / "retained").write_text("another run")
        # Also prove cleanup does not chmod or descend an external linked tree.
        outside = self.root / "outside"
        outside.mkdir(mode=0o500)
        (self.source / "external-dir").symlink_to(outside)
        original = shutil.rmtree
        removed = []
        def remove(path, *args, **kwargs):
            removed.append(Path(path))
            self.assertTrue(self.output.is_file())
            self.assertTrue((self.proof / "manifest.json").is_file())
            self.assertTrue((self.proof / "extracted.jsonl").is_file())
            return original(path, *args, **kwargs)
        with patch.object(archive.shutil, "rmtree", side_effect=remove):
            self.create()
        self.assertEqual(removed, [self.proof / "extract"])
        self.assertEqual((other / "retained").read_text(), "another run")
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o500)
        self.assertFalse((self.proof / "extract").exists())

    def test_proof_publication_failure_retains_extract(self):
        original = archive._private_write
        def fail_manifest(path, data):
            if Path(path).name == "manifest.json":
                raise OSError("proof write failed")
            return original(path, data)
        with patch.object(archive, "_private_write", side_effect=fail_manifest):
            with self.assertRaisesRegex(OSError, "proof write failed"):
                self.create()
        self.assertTrue((self.proof / "extract/source/file").exists())
        self.assertTrue(Path(str(self.output) + ".partial").is_file())
        self.assertFalse(self.output.exists())

    def test_archive_publication_failure_retains_extract(self):
        with patch.object(archive.os, "link", side_effect=OSError("publish failed")):
            with self.assertRaisesRegex(OSError, "publish failed"):
                self.create()
        self.assertTrue((self.proof / "extract/source/file").exists())
        self.assertTrue((self.proof / "manifest.json").exists())
        self.assertFalse(self.output.exists())

    def test_hardlink_group_mismatch_even_when_each_nlink_matches(self):
        for name in ("second",):
            (self.source / name).write_bytes((self.source / "file").read_bytes())
            shutil.copystat(self.source / "file", self.source / name)
        os.link(self.source / "file", self.source / "first-link")
        os.link(self.source / "second", self.source / "second-link")
        original = archive._run
        def regroup(args):
            result = original(args)
            if args[0] == "tar" and "--extract" in args:
                target = self.proof / "extract/source"
                (target / "first-link").unlink()
                (target / "second-link").unlink()
                os.link(target / "file", target / "second-link")
                os.link(target / "second", target / "first-link")
            return result
        with patch.object(archive, "_run", side_effect=regroup):
            with self.assertRaisesRegex(archive.ArchiveError, "hardlink groups"):
                self.create()

    def test_any_tar_warning_fails(self):
        with self.assertRaisesRegex(archive.ArchiveError, "warned"):
            archive._run([sys.executable, "-c", "import sys; sys.stderr.write('warning\\n')"])

    def test_command_timeout_is_a_failure(self):
        with patch.object(archive, "COMMAND_TIMEOUT", 0.05):
            with self.assertRaisesRegex(archive.ArchiveError, "timeout"):
                archive._run([sys.executable, "-c", "import time; time.sleep(10)"])

    def test_source_entry_bound_includes_pending_directory_entries(self):
        for number in range(3):
            (self.source / f"empty-{number}").touch()
        with patch.object(archive, "MAX_ENTRIES", 3):
            with self.assertRaisesRegex(archive.ArchiveError, "source exceeds"):
                self.create()

    def test_public_inspection_is_full_nonmutating_scope_validation(self):
        os.link(self.source / "file", self.source / "hard")
        (self.source / "ordinary-link").symlink_to("../outside")
        before = archive._listing(self.source, HELPER)
        with patch.object(archive, "_run") as command:
            scan = archive.inspect_source(self.source, max_bytes=1024)
        command.assert_not_called()
        self.assertEqual(scan, {"entries": 4, "logical_bytes": len(b"metadata and contents\n"),
                                "hardlink_groups": [["file", "hard"]]})
        self.assertEqual(archive._listing(self.source, HELPER), before)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.proof.exists())

    def test_public_inspection_refuses_external_hardlinks_and_specials_early(self):
        external = self.root / "external"
        os.link(self.source / "file", external)
        with self.assertRaisesRegex(archive.ArchiveError, "outside the selected root"):
            archive.inspect_source(self.source)
        external.unlink()
        os.mkfifo(self.source / "fifo")
        with self.assertRaisesRegex(archive.ArchiveError, "special object"):
            archive.inspect_source(self.source)
        with patch.object(archive, "_run") as command:
            with self.assertRaisesRegex(archive.ArchiveError, "special object"):
                self.create()
        command.assert_not_called()
        self.assertFalse(self.proof.exists())
        self.assertFalse(Path(str(self.output) + ".partial").exists())

    def test_public_inspection_retains_byte_entry_and_depth_bounds(self):
        with self.assertRaisesRegex(archive.ArchiveError, "max_bytes"):
            archive.inspect_source(self.source, max_bytes=0)
        with patch.object(archive, "MAX_ENTRIES", 1):
            with self.assertRaisesRegex(archive.ArchiveError, "entries"):
                archive.inspect_source(self.source)
        (self.source / "a/b/c").mkdir(parents=True)
        with patch.object(archive, "MAX_DEPTH", 2):
            with self.assertRaisesRegex(archive.ArchiveError, "depth"):
                archive.inspect_source(self.source)
        self.assertEqual((archive.MAX_ENTRIES, archive.MAX_DEPTH), (100_000, 128))

    def test_public_inspection_refuses_noncanonical_sources_and_bad_limits(self):
        alias = self.root / "alias"
        alias.symlink_to(self.source)
        for source in (alias, self.source / ".." / "source", Path("relative"), Path("/")):
            with self.subTest(source=source), self.assertRaises(archive.ArchiveError):
                archive.inspect_source(source)
        for limit in (-1, True, 1.5):
            with self.subTest(limit=limit), self.assertRaisesRegex(archive.ArchiveError, "max_bytes"):
                archive.inspect_source(self.source, limit)

    def test_capture_does_not_change_read_only_source(self):
        self.source.chmod(0o555)
        (self.source / "file").chmod(0o444)
        before = archive._listing(self.source, HELPER)
        self.create()
        self.assertEqual(archive._listing(self.source, HELPER), before)
        self.assertEqual(stat.S_IMODE(self.source.stat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE((self.source / "file").stat().st_mode), 0o444)

    def test_helper_error_fails(self):
        bad = self.root / "bad-helper"
        bad.write_text("raise SystemExit(2)\n")
        with self.assertRaises(archive.ArchiveError):
            archive._create_verified_archive(self.source, self.output, self.proof, bad)

    def test_existing_proof_or_archive_cannot_be_overwritten(self):
        self.proof.mkdir()
        with self.assertRaises(FileExistsError):
            self.create()
        self.proof.rmdir()
        self.output.write_text("existing")
        with self.assertRaisesRegex(archive.ArchiveError, "overwrite"):
            self.create()
        self.assertEqual(self.output.read_text(), "existing")

    def test_public_entry_requires_root(self):
        with patch.object(os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(archive.ArchiveError, "requires root"):
                archive.create_verified_archive(self.source, self.output, self.proof, HELPER)

    def test_unprivate_archive_parent_is_refused(self):
        self.root.chmod(0o755)
        with self.assertRaisesRegex(archive.ArchiveError, "private"):
            self.create()

    def test_tar_options_environment_is_not_used(self):
        with patch.dict(os.environ, {"TAR_OPTIONS": "--exclude=*"}):
            self.create()
        self.assertTrue((self.restored_view() / "file").exists())


class PortableMetadataTests(unittest.TestCase):
    def test_adapter_changes_only_fixture_selinux_arguments(self):
        for operation in ("--create", "--extract"):
            args = ["tar", operation, "--acls", "--xattrs", "--xattrs-include=*",
                    "--selinux", "--numeric-owner", "--file", "fixture.tgz"]
            with self.subTest(operation=operation), patch.object(archive, "_run") as run:
                portable_fixture_run(run, args)
                run.assert_called_once_with(["tar", "--no-selinux", "--xattrs-exclude=security.selinux",
                                             *args[1:5], *args[6:]])
                self.assertIn("--selinux", args)  # never mutate the caller's command
        for args, expected in [
                ([sys.executable, str(HELPER), "/fixture"],
                 [sys.executable, str(HELPER), "--no-label", "/fixture"]),
                (["tar", "--version"], ["tar", "--version"]),
                ([sys.executable, "/other-helper", "/fixture"],
                 [sys.executable, "/other-helper", "/fixture"])]:
            with self.subTest(args=args), patch.object(archive, "_run") as run:
                portable_fixture_run(run, args)
                run.assert_called_once_with(expected)

    def test_no_label_listing_excludes_only_selinux_including_listed_xattr(self):
        helper = runpy.run_path(str(HELPER))
        attrs = {"security.selinux": b"system_u:object_r:tmp_t:s0",
                 "user.fixture": b"user data", "system.posix_acl_access": b"access acl",
                 "system.posix_acl_default": b"default acl"}
        with tempfile.TemporaryDirectory(prefix="prace-portable-listing-") as root:
            (Path(root) / "file").write_bytes(b"fixture contents")
            listings = []
            with patch.object(os, "listxattr", return_value=list(attrs)), \
                    patch.object(os, "getxattr", side_effect=lambda path, name, **kwargs: attrs[name]):
                for flags in ([], ["--no-label"]):
                    with contextlib.redirect_stdout(io.StringIO()) as output:
                        self.assertEqual(helper["main"]([*flags, root]), 0)
                    listings.append([json.loads(line) for line in output.getvalue().splitlines()])
            for ordinary, portable in zip(*listings):
                self.assertEqual(ordinary.pop("selinux"), attrs["security.selinux"].decode())
                self.assertEqual(portable, ordinary)
                self.assertEqual(portable["xattrs"], {key: value.hex() for key, value in attrs.items()
                                                    if key != "security.selinux"})

    def test_adapter_is_scoped_to_portable_fixture_and_restored(self):
        original = archive._run
        for portable in ("", "1"):
            case = MetadataArchiveTests("test_round_trip_content_mode_nanoseconds_symlink_and_hardlinks")
            with patch.dict(os.environ, {"PRACE_TEST_PORTABLE_METADATA": portable,
                                         "PRACE_REQUIRE_PRIVILEGED": ""}):
                try:
                    case.setUp()
                    self.assertEqual(archive._run is original, portable != "1")
                finally:
                    case.doCleanups()
            self.assertIs(archive._run, original)

    def test_production_commands_keep_all_selinux_flags_even_with_portable_environment(self):
        class CommandRecorded(Exception):
            pass
        calls = []
        run = archive._run
        def record(args):
            if args[0] == "tar":
                calls.append(args)
                raise CommandRecorded()
            return run(args)
        with tempfile.TemporaryDirectory(prefix="prace-production-command-") as root:
            root = Path(root)
            source, output, proof, destination = (root / name for name in ("source", "data.tgz", "proof", "extract"))
            source.mkdir()
            with patch.dict(os.environ, {"PRACE_TEST_PORTABLE_METADATA": "1"}), \
                    patch.object(archive, "_run", side_effect=record):
                with self.assertRaises(CommandRecorded):
                    archive._create_verified_archive(source, output, proof, HELPER)
                with tarfile.open(output, "w:gz") as stream:
                    info = tarfile.TarInfo("source")
                    info.type = tarfile.DIRTYPE
                    stream.addfile(info)
                with self.assertRaises(CommandRecorded):
                    archive._verify_extract(output, destination, HELPER, b"", {})
            self.assertEqual(calls, [
                ["tar", "--create", "--gzip", "--format=pax", "--acls", "--xattrs",
                 "--xattrs-include=*", "--selinux", "--numeric-owner", "--sparse",
                 "--one-file-system", "--file", str(output) + ".partial", "--directory", str(root), "--", "source"],
                ["tar", "--extract", "--gzip", "--acls", "--xattrs", "--xattrs-include=*",
                 "--selinux", "--numeric-owner", "--same-owner", "--same-permissions",
                 "--file", str(output), "--directory", str(destination)]])

    def test_exit_zero_selinux_warning_remains_fatal_in_portable_mode(self):
        command = [sys.executable, "-c", "import sys; sys.stderr.write("
                   "'tar: Cannot set security.selinux: Operation not supported\\n')"]
        with self.assertRaisesRegex(archive.ArchiveError, r"exit 0.*security[.]selinux"):
            portable_fixture_run(archive._run, command)


def qualification_status(result, require_privileged):
    if not result.wasSuccessful():
        return 1
    if require_privileged:
        if result.skipped:
            print(f"NOT QUALIFIED: {len(result.skipped)} skipped test(s); privileged qualification requires zero skips",
                  file=sys.stderr)
            return 1
        print(f"QUALIFIED: {result.testsRun} tests passed, zero skips", file=sys.stderr)
    return 0


class QualificationResultTests(unittest.TestCase):
    def test_strict_qualification_refuses_portable_mode_before_running(self):
        with patch.dict(os.environ, {"PRACE_REQUIRE_PRIVILEGED": "1", "PRACE_TEST_PORTABLE_METADATA": "1"}), \
                patch.object(unittest, "main") as runner, contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(main(["test-prace-metadata-archive.py"]), 2)
            runner.assert_not_called()
            self.assertIn("cannot qualify SELinux", output.getvalue())

    def test_strict_qualification_refuses_selectors_before_running(self):
        for args in (["MetadataArchiveTests.test_numeric_ownership_round_trip_when_privileged"],
                     ["-k", "round_trip"], ["QualificationResultTests"]):
            with self.subTest(args=args), patch.dict(os.environ, {"PRACE_REQUIRE_PRIVILEGED": "1", "PRACE_TEST_PORTABLE_METADATA": ""}), \
                    patch.object(unittest, "main") as runner, contextlib.redirect_stderr(io.StringIO()) as output:
                self.assertEqual(main(["test-prace-metadata-archive.py", *args]), 2)
                runner.assert_not_called()
                self.assertIn("requires the full suite", output.getvalue())

    def test_intentional_skip_is_successful_normally_but_refuses_qualification(self):
        class IntentionalSkip(unittest.TestCase):
            def runTest(self):
                self.skipTest("intentional unavailable capability")
        result = unittest.TestResult()
        IntentionalSkip().run(result)
        self.assertEqual(result.testsRun, 1)
        self.assertEqual(len(result.skipped), 1)
        self.assertTrue(result.wasSuccessful())
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.assertEqual(qualification_status(result, False), 0)
            self.assertEqual(qualification_status(result, True), 1)
        self.assertIn("NOT QUALIFIED: 1 skipped test(s)", output.getvalue())
        self.assertNotIn("QUALIFIED: 1 tests passed", output.getvalue())

    def test_only_success_without_skips_prints_qualified(self):
        for success in (True, False):
            with self.subTest(success=success):
                class Fixture(unittest.TestCase):
                    def runTest(self):
                        self.assertTrue(success)
                result = unittest.TestResult()
                Fixture().run(result)
                output = io.StringIO()
                with contextlib.redirect_stderr(output):
                    self.assertEqual(qualification_status(result, True), 0 if success else 1)
                    self.assertEqual(qualification_status(result, False), 0 if success else 1)
                self.assertEqual(output.getvalue(), "QUALIFIED: 1 tests passed, zero skips\n" if success else "")


class PrivilegedQualificationTests(unittest.TestCase):
    def result_for(self, name, required, uid, release=None, enforce=None):
        case = MetadataArchiveTests(name)
        with patch.dict(os.environ, {"PRACE_REQUIRE_PRIVILEGED": required, "CI": "",
                                     "PRACE_TEST_PORTABLE_METADATA": ""}), \
                patch.object(os, "geteuid", return_value=uid):
            # Keep real fixtures out of prerequisite-only regressions. Running the
            # test through unittest proves failure/error is never reported as a skip.
            case.setUp = lambda: None
            def read(path, *args, **kwargs):
                if path == Path("/etc/os-release"):
                    return release or 'ID="rocky"\n'
                if path == Path("/sys/fs/selinux/enforce"):
                    if enforce is None:
                        raise FileNotFoundError("SELinux filesystem is unavailable")
                    return enforce
                raise AssertionError(f"unexpected prerequisite read: {path}")
            with patch.object(Path, "read_text", read):
                result = unittest.TestResult()
                case.run(result)
        return result

    def test_ordinary_unprivileged_fixture_remains_a_skip(self):
        result = self.result_for("test_numeric_ownership_round_trip_when_privileged", "", 1000)
        self.assertEqual(len(result.skipped), 1)
        self.assertTrue(result.wasSuccessful())

    def test_required_root_refuses_instead_of_skipping(self):
        result = self.result_for("test_numeric_ownership_round_trip_when_privileged", "1", 1000)
        self.assertFalse(result.wasSuccessful())
        self.assertFalse(result.skipped)
        self.assertIn("requires root", result.failures[0][1])

    def test_required_selinux_and_rocky_refuse_instead_of_skipping(self):
        for release, enforce, reason in [('ID="rocky"\n', None, "prerequisites unavailable"),
                                         ('ID="rocky"\n', "0", "enforcing SELinux"),
                                         ('ID=ubuntu\n', "1", "isolated Rocky")]:
            with self.subTest(release=release, enforce=enforce):
                result = self.result_for("test_selinux_round_trip_when_supported", "1", 0, release, enforce)
                self.assertEqual(len(result.failures), 1)
                self.assertFalse(result.errors)
                self.assertFalse(result.skipped)
                self.assertIn(reason, result.failures[0][1])


class ArchiveValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="prace-tar-validation-")
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "bad.tgz"

    def build(self, entries):
        with tarfile.open(self.path, "w:gz") as stream:
            root = tarfile.TarInfo("source")
            root.type = tarfile.DIRTYPE
            stream.addfile(root)
            for name, kind, target in entries:
                info = tarfile.TarInfo(name)
                info.type = kind
                if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    info.linkname = target
                if kind == tarfile.REGTYPE:
                    info.size = 1
                    stream.addfile(info, io.BytesIO(b"x"))
                else:
                    stream.addfile(info)

    def test_reject_paths_duplicates_specials_and_link_parents(self):
        cases = [
            [("../escape", tarfile.REGTYPE, "")],
            [("/absolute", tarfile.REGTYPE, "")],
            [("source/a/../b", tarfile.REGTYPE, "")],
            [("source/./x", tarfile.REGTYPE, "")],
            [("other", tarfile.DIRTYPE, "")],
            [("source/file", tarfile.REGTYPE, ""), ("source/file", tarfile.REGTYPE, "")],
            [("source/fifo", tarfile.FIFOTYPE, "")],
            [("source/link", tarfile.SYMTYPE, "file"), ("source/link/write", tarfile.REGTYPE, "")],
            [("source/link", tarfile.SYMTYPE, "../escape"), ("source/link/write", tarfile.REGTYPE, "")],
            [("source/link", tarfile.SYMTYPE, "/tmp"), ("source/link/write", tarfile.REGTYPE, "")],
            [("source/link", tarfile.SYMTYPE, "../escape"), ("source/link", tarfile.DIRTYPE, "")],
            [("source/link", tarfile.SYMTYPE, "../escape"), ("source/hard", tarfile.LNKTYPE, "source/link")],
            [("source/link", tarfile.SYMTYPE, "")],
            [("source/link", tarfile.LNKTYPE, "../escape")],
            [("source/link", tarfile.LNKTYPE, "source/future"), ("source/future", tarfile.REGTYPE, "")],
            [("source/missing/file", tarfile.REGTYPE, "")],
        ]
        for entries in cases:
            with self.subTest(entries=entries):
                self.build(entries)
                destination = Path(self.tmp.name) / "extracted"
                with patch.object(archive, "_run") as command:
                    with self.assertRaises(archive.ArchiveError):
                        archive._verify_extract(self.path, destination, HELPER, b"", {})
                command.assert_not_called()
                self.assertFalse(destination.exists())

    def test_archive_accepts_arbitrary_nonempty_symlink_target_data(self):
        for target in ("/absolute", "../outside", "a/../b", "dangling"):
            with self.subTest(target=target):
                self.build([("source/link", tarfile.SYMTYPE, target)])
                self.assertEqual(archive.validate_archive(self.path), "source")

    def test_archive_depth_bound(self):
        self.build([("source/a", tarfile.DIRTYPE, ""),
                    ("source/a/b", tarfile.DIRTYPE, ""),
                    ("source/a/b/c", tarfile.REGTYPE, "")])
        with patch.object(archive, "MAX_DEPTH", 2):
            with self.assertRaisesRegex(archive.ArchiveError, "depth"):
                archive.validate_archive(self.path)

    def test_existing_destination_is_never_merged_or_followed(self):
        self.build([("source/file", tarfile.REGTYPE, "")])
        destination = Path(self.tmp.name) / "extracted"
        outside = Path(self.tmp.name) / "outside"
        outside.mkdir()
        (outside / "sentinel").write_text("unchanged")
        destination.symlink_to(outside)
        with patch.object(archive, "_run") as command:
            with self.assertRaises(FileExistsError):
                archive._verify_extract(self.path, destination, HELPER, b"", {})
        command.assert_not_called()
        self.assertEqual((outside / "sentinel").read_text(), "unchanged")

    def test_archive_size_bound(self):
        self.build([("source/file", tarfile.REGTYPE, "")])
        with self.assertRaisesRegex(archive.ArchiveError, "max_bytes"):
            archive.validate_archive(self.path, 0)

    def test_archive_member_count_bound(self):
        self.build([("source/a", tarfile.REGTYPE, ""), ("source/b", tarfile.REGTYPE, "")])
        with patch.object(archive, "MAX_ENTRIES", 2):
            with self.assertRaisesRegex(archive.ArchiveError, "archive exceeds"):
                archive.validate_archive(self.path)

    def test_corrupt_archive_refused(self):
        self.path.write_bytes(b"not an archive")
        with self.assertRaises(tarfile.TarError):
            archive.validate_archive(self.path)

    def test_pax_path_override_checked_before_any_extraction(self):
        with tarfile.open(self.path, "w:gz", format=tarfile.PAX_FORMAT) as stream:
            root = tarfile.TarInfo("source")
            root.type = tarfile.DIRTYPE
            stream.addfile(root)
            item = tarfile.TarInfo("source/apparently-safe")
            item.pax_headers = {"path": "../escape"}
            stream.addfile(item)
        destination = Path(self.tmp.name) / "extracted"
        with patch.object(archive, "_run") as command:
            with self.assertRaises(archive.ArchiveError):
                archive._verify_extract(self.path, destination, HELPER, b"", {})
        command.assert_not_called()
        self.assertFalse(destination.exists())


class CommandLifetimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="prace-command-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def wait_ready(self, path):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if path.exists() and path.read_text().strip():
                return int(path.read_text())
            time.sleep(0.01)
        self.fail("fixture child did not become ready")

    def assert_stopped(self, pid):
        status = Path(f"/proc/{pid}/stat")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                state = status.read_text().split(")", 1)[1].split()[0]
            except (FileNotFoundError, ProcessLookupError):
                # A reaped process can disappear between observation and read (ENOENT or ESRCH).
                return
            if state == "Z":
                return
            time.sleep(0.01)
        self.fail("command descendant remains live after cancellation")

    def test_stop_probe_accepts_process_reaped_during_read(self):
        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", side_effect=FileNotFoundError):
            self.assert_stopped(1234)

    def test_stop_probe_does_not_accept_other_observation_errors(self):
        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                self.assert_stopped(1234)

    def test_every_base_exception_kills_and_reaps_command_group(self):
        class Cancelled(BaseException):
            pass
        real_popen = subprocess.Popen
        for exception in (KeyboardInterrupt, SystemExit, Cancelled):
            with self.subTest(exception=exception):
                ready = self.root / exception.__name__
                launched = []
                child_code = (
                    "import pathlib,subprocess,sys,time; "
                    "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
                    "pathlib.Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(30)"
                )
                def launch(*args, **kwargs):
                    process = real_popen(*args, **kwargs)
                    launched.append(process)
                    communicate = process.communicate
                    first = True
                    def cancel(*positional, **named):
                        nonlocal first
                        if first:
                            first = False
                            self.wait_ready(ready)
                            raise exception("cancel fixture")
                        return communicate(*positional, **named)
                    process.communicate = cancel
                    return process
                try:
                    with patch.object(archive.subprocess, "Popen", side_effect=launch):
                        with self.assertRaises(exception):
                            archive._run([sys.executable, "-c", child_code, str(ready)])
                    self.assertEqual(launched[0].returncode, -signal.SIGKILL)
                    self.assert_stopped(int(ready.read_text()))
                finally:
                    for process in launched:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait()

    def test_inherited_operation_lock_survives_handler_death(self):
        lock = self.root / "operation.lock"
        ready = self.root / "child.pid"
        script = (
            "import fcntl,importlib.util,os,sys; "
            "spec=importlib.util.spec_from_file_location('archive',sys.argv[1]); "
            "m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); "
            "fd=os.open(sys.argv[2],os.O_RDWR|os.O_CREAT,0o600); "
            "fcntl.flock(fd,fcntl.LOCK_EX); m.OPERATION_LOCK_FD=fd; "
            "m._run([sys.executable,'-c',"
            "'import os,pathlib,sys,time; os.fstat(int(sys.argv[1])); "
            "pathlib.Path(sys.argv[2]).write_text(str(os.getpid())); time.sleep(30)',"
            "str(fd),sys.argv[3]])"
        )
        handler = subprocess.Popen([sys.executable, "-c", script, str(TOOLS / "prace_metadata_archive.py"),
                                    str(lock), str(ready)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        child_pid = None
        try:
            child_pid = self.wait_ready(ready)
            handler.kill()
            handler.communicate(timeout=5)
            with lock.open("rb") as contender:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.killpg(child_pid, signal.SIGKILL)
                self.assert_stopped(child_pid)
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            handler.kill()
            if child_pid is not None:
                try:
                    os.killpg(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            handler.communicate(timeout=5)


def main(argv=None):
    argv = list(sys.argv if argv is None else argv)
    strict = os.environ.get("PRACE_REQUIRE_PRIVILEGED") == "1"
    portable = os.environ.get("PRACE_TEST_PORTABLE_METADATA") == "1"
    if strict and portable:
        print("NOT QUALIFIED: portable metadata tests cannot qualify SELinux; unset PRACE_TEST_PORTABLE_METADATA",
              file=sys.stderr)
        return 2
    # A selected unrelated test could otherwise print QUALIFIED without running
    # the numeric-owner and SELinux fixtures. Qualification always runs all tests.
    if strict and len(argv) != 1:
        print("NOT QUALIFIED: strict qualification requires the full suite; omit unittest selectors/options",
              file=sys.stderr)
        return 2
    program = unittest.main(argv=argv, verbosity=2, exit=False)
    status = qualification_status(program.result, strict)
    if portable and status == 0:
        print("PORTABLE CHECKS PASSED: SELinux preservation excluded; privileged qualification has not run",
              file=sys.stderr)
    return status


if __name__ == "__main__":
    sys.exit(main())
