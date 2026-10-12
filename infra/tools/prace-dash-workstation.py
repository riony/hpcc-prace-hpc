#!/usr/bin/env python3
"""Build the PRIVATE fleet-dashboard bundle on the operator workstation (docs/design/dashboard, C4).

The same evidence builder as roles/fleet_dashboard, without the scrub step: real hostnames, actor
accounts, addresses and lease/point ids, for the operator's own review of acceptance runs, recovery
points and scenario runs. The output stays on this workstation (directory 0700, files 0600). It is
never copied to mgmt-git01, which serves only the scrubbed build; this tool is not installed there
and refuses to run on a GitLab host. The live Cluster and CI/CD data exist only in the mgmt-git01
build; this bundle shows them as "not part of the workstation build".

  prace-dash-workstation.py --out ~/prace-dash-private [--repo .]
  python3 -m http.server --bind 127.0.0.1 --directory ~/prace-dash-private 8000    (then open it locally)
"""
import argparse
import os
import shutil
import subprocess
import sys

ROLE_FILES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "roles", "fleet_dashboard", "files")
sys.path.insert(0, ROLE_FILES)
import prace_dash_common as common  # noqa: E402
import prace_dash_evidence as evidence  # noqa: E402


def refuse_here(out):
    if os.path.exists("/etc/gitlab/gitlab.rb") or os.uname().nodename.split(".")[0].endswith("git01"):
        return "this looks like the GitLab VM; the private bundle is built on the operator workstation only"
    real = os.path.realpath(out)
    if real.startswith("/var/lib/prace-dash") or real.startswith("/srv") or real == "/":
        return f"refusing to write the private bundle to {real}"
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, help="output directory (created 0700)")
    ap.add_argument("--repo", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    a = ap.parse_args(argv)
    why = refuse_here(a.out)
    if why:
        print(f"prace-dash-workstation: {why}", file=sys.stderr)
        return 2
    repo = os.path.abspath(a.repo)
    try:
        commit = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        commit = None
    out = os.path.abspath(os.path.expanduser(a.out))
    os.makedirs(os.path.join(out, "data"), mode=0o700, exist_ok=True)
    os.chmod(out, 0o700)
    os.chmod(os.path.join(out, "data"), 0o700)
    for name in ("index.html", "app.css", "app.js"):
        shutil.copyfile(os.path.join(ROLE_FILES, "www", name), os.path.join(out, name))
        os.chmod(os.path.join(out, name), 0o600)
    doc = evidence.build(repo, commit, common.now())
    doc["build"] = "workstation"
    common.write_json(os.path.join(out, "data", "evidence.json"), doc, mode=0o600)
    print(f"private bundle in {out} (from {str(commit)[:12]}): {len(doc['acceptance'])} acceptance row(s), "
          f"{len(doc['recovery_points'])} recovery point(s), {len(doc['scenarios']['runs'])} scenario run(s).")
    print(f"View it locally: python3 -m http.server --bind 127.0.0.1 --directory {out} 8000")
    return 0


if __name__ == "__main__":
    sys.exit(main())
