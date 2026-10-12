#!/usr/bin/env python3
"""Change scope of a branch pipeline, for the four ansible test jobs (.gitlab-ci.yml, 6 Oct).

Prints exactly one word on stdout:
  full          run everything (the default, and the answer to anything unexpected);
  docs          the WHOLE branch, compared with main from their merge base, changes only
                documentation, evidence or agent notes;
  audit-record  the same plus the audit records (fleet-baseline.json, deployed.json).
The reason goes to stderr.

Main, tags, schedules and web/API runs are always "full". The branch is compared with main,
never with its previous commit: a documentation commit after a code commit is still "full".
A changed file that any infra code or test names (docs/..., evidence/..., agents/...), and any
runbook (docs/runbooks/, whose shell blocks the tests parse), is "full" too.

The jobs that always run whatever the scope (secret scan, evidence checksums, export gate,
audit-check, python-tests, role-tests, nri-mount-guard) are not affected.
"""
import os
import re
import subprocess
import sys
from pathlib import Path

DOC_PREFIXES = ("docs/", "evidence/", "agents/")
ALWAYS_FULL_PREFIXES = ("docs/runbooks/",)
AUDIT_RECORDS = ("infra/audit/fleet-baseline.json", "infra/audit/deployed.json")
SCANNED_SUFFIXES = (".py", ".sh", ".yml", ".yaml", ".j2", ".json", ".cfg", ".lua")
REFERENCE = re.compile(r"(?:docs|evidence|agents)/[A-Za-z0-9_.\-/]+")
SELF = ("ci-change-scope.py", "test-ci-change-scope.py")    # their own fixtures and docstrings
FETCH_REF = "refs/ci-scope/main"
BRANCH_REF = "refs/ci-scope/branch"


def say(msg):
    print(msg, file=sys.stderr)


def git(*args, timeout=300):
    return subprocess.run(["git", *args], capture_output=True, text=True, timeout=timeout)


def referenced_paths(root):
    """Paths under docs/, evidence/ or agents/ that infra code or tests name literally."""
    refs = set()
    for path in (root / "infra").rglob("*"):
        if path.is_file() and path.suffix in SCANNED_SUFFIXES and path.name not in SELF:
            try:
                text = path.read_text(errors="ignore")
            except OSError as exc:
                raise RuntimeError(f"cannot inspect {path.relative_to(root)}") from exc
            refs.update(m.rstrip("/.") for m in REFERENCE.findall(text))
    # a bare top-level name ("docs/..." in a comment) names no particular file
    return {r for r in refs if "/" in r}


def is_referenced(name, refs):
    return any(name == r or name.startswith(r + "/") for r in refs)


def doc_like(name):
    return name.startswith(DOC_PREFIXES) or ("/" not in name and name.endswith(".md"))


def classify(files, refs):
    if not files:
        return "full", "no changed file found: run everything"
    for name in files:
        if name.startswith(ALWAYS_FULL_PREFIXES):
            return "full", f"{name}: runbooks are parsed by the tests"
        if is_referenced(name, refs):
            return "full", f"{name}: named by infra code or a test"
    other = [n for n in files if not doc_like(n) and n not in AUDIT_RECORDS]
    if other:
        return "full", f"{len(other)} file(s) outside documentation and audit records, e.g. {other[0]}"
    if any(n in AUDIT_RECORDS for n in files):
        return "audit-record", f"{len(files)} file(s): documentation, evidence and audit records only"
    return "docs", f"{len(files)} file(s): documentation, evidence and notes only"


def changed_files():
    """Files the branch changes against main since their merge base, or None when unsure."""
    env = os.environ
    branch, default = env.get("CI_COMMIT_BRANCH", ""), env.get("CI_DEFAULT_BRANCH", "main")
    if env.get("CI_PIPELINE_SOURCE") != "push":
        say(f"pipeline source {env.get('CI_PIPELINE_SOURCE')!r} is not a push")
        return None
    if not branch or branch == default:
        say(f"branch {branch!r}: the default branch and tags always run everything")
        return None
    remote = env.get("CI_REPOSITORY_URL") or "origin"
    if git("fetch", "--quiet", "--no-tags", "--depth=1000", remote,
           f"+refs/heads/{default}:{FETCH_REF}").returncode:
        say(f"cannot fetch {default}")
        return None
    base = git("merge-base", FETCH_REF, "HEAD")
    if base.returncode:      # a shallow branch clone: deepen it once and retry
        git("fetch", "--quiet", "--no-tags", "--deepen=1000", remote, f"+refs/heads/{branch}:{BRANCH_REF}")
        base = git("merge-base", FETCH_REF, "HEAD")
    if base.returncode or not base.stdout.strip():
        say(f"no merge base with {default}")
        return None
    diff = git("diff", "--name-only", "--no-renames", base.stdout.strip(), "HEAD")
    if diff.returncode:
        say("git diff failed")
        return None
    return [line for line in diff.stdout.splitlines() if line.strip()]


def main():
    try:
        top = git("rev-parse", "--show-toplevel")
        root = Path(top.stdout.strip()) if top.returncode == 0 else Path.cwd()
        files = changed_files()
        if files is None:
            scope, why = "full", "run everything"
        else:
            scope, why = classify(files, referenced_paths(root))
            for name in files[:40]:
                say(f"  changed: {name}")
            if len(files) > 40:
                say(f"  ... and {len(files) - 40} more")
    except Exception as exc:  # anything unexpected runs everything
        scope, why = "full", f"error: {exc}"
    say(f"change scope: {scope} ({why})")
    print(scope)


if __name__ == "__main__":
    main()
