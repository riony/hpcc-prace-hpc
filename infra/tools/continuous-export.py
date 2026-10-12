#!/usr/bin/env python3
"""Export a published physical permission recording for the dashboard; never execute it."""
import argparse
import ctypes
import datetime
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
DASH = ROOT / "infra/roles/fleet_dashboard/files"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(DASH))
import prace_dash_evidence as evidence  # noqa: E402
import prace_dash_physical as physical  # noqa: E402
from validation.contracts import canonical_json  # noqa: E402


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def checksums(folder):
    files = sorted(p for p in folder.rglob("*") if p.is_file() and p != folder / "SHA256SUMS")
    text = "".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.relative_to(folder).as_posix() + "\n" for p in files)
    (folder / "SHA256SUMS").write_text(text, encoding="utf-8")


def check_with_dashboard(folder, rel):
    verified = evidence.verify(str(folder))
    physical.require(verified["state"] == "ok", "dashboard checksum verification failed")
    run = evidence.scenario(str(folder), rel, verified["files"], evidence.load_trust())
    physical.require(run.get("physical", {}).get("verified") is True and not run["capture_late"]
                     and run["events"], "dashboard refused verified recording")
    return run


def rename_new(stage, output):
    # Linux RENAME_NOREPLACE: no check/rename race can replace even an empty output.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    physical.require(rename is not None, "atomic append-only publication unavailable")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(stage), -100, os.fsencode(output), 1) != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise ValueError("physical recording: output already exists")
        raise OSError(error, "atomic append-only publication failed")


def fsync_tree(root):
    for path in root.rglob("*"):
        if path.is_file():
            with path.open("rb") as handle:
                os.fsync(handle.fileno())
    for path in sorted([root] + [p for p in root.rglob("*") if p.is_dir()], key=lambda p: len(p.parts), reverse=True):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def export(campaign, output, exported_at=None):
    campaign, output = Path(campaign), Path(output)
    physical.require(not output.exists() and not output.is_symlink(), "output already exists")
    source = physical.read_checked(campaign)
    summary, events, bindings = physical.derive(source)
    # Explicitly use the harness canonical-json contract when checking its journal.
    for row in physical.lines(source["journal.jsonl"]):
        payload = {k: v for k, v in row.items() if k != "sha256"}
        physical.require(hashlib.sha256(canonical_json(payload)).hexdigest() == row["sha256"],
                         "harness canonical journal verification failed")
    raw_sums = (campaign / "SHA256SUMS").read_bytes()
    stamp = time.time() if exported_at is None else exported_at
    physical.require(physical.finite(stamp) and stamp >= bindings["stop"], "invalid export time")
    date = datetime.datetime.fromtimestamp(bindings["stop"], datetime.timezone.utc).date().isoformat()
    rel = date + "/" + bindings["run_id"]
    # All source bindings pass before even the output parent is created.
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".physical-export-", dir=output.parent))
    try:
        (stage / "source").mkdir()
        for name, raw in dict(source, SHA256SUMS=raw_sums).items():
            path = stage / "source" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        write_json(stage / "physical.json", summary)
        (stage / "events.jsonl").write_bytes(b"".join(physical.canonical(row) + b"\n" for row in events))
        cap = dict(bindings, schema=1, kind="scenario-run", exported_at=stamp)
        write_json(stage / "capture.json", cap)
        (stage / "README.md").write_text(
            "# Physical permission recording derivative\n\n"
            "Exported from the published campaign, with its checksum-listed source bytes unchanged in source/. "
            "The collector recomputes the journal, action and objective bindings. "
            "This proves internal consistency of co-located T2 records, not T1 independence. "
            "Model-call counts retain T3 trust. Config is the original published redacted copy; "
            "its private-input digest is provenance, not a claimed byte match.\n\n"
            "Repair, replay and legitimate use were not run in this recording. Reset was pending at STOP. "
            "This historical capture does not report current lease or fixture state. "
            "No full-cluster restore is claimed. Browser playback executes nothing. "
            "captured_at is STOP; exported_at is retrospective publication time.\n", encoding="utf-8")
        checksums(stage)
        check_with_dashboard(stage, rel)
        fsync_tree(stage)
        stage.chmod(0o755)
        rename_new(stage, output)
        fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return output
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-dir", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        out = export(args.campaign_dir, args.out)
    except (ValueError, OSError) as exc:
        parser.exit(2, "Refused: " + str(exc) + "\n")
    print(out)


if __name__ == "__main__":
    main()
