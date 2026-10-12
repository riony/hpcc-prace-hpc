#!/usr/bin/env python3
"""Offline tests for the recovery stanzas of tools/slinky-acceptance.sh (review F3): each stanza is
executed as written, with mocked L/wait_all_usable. A recovery check may only PASS when the restart
command succeeded AND the component really restarted (new PID / pod UIDs) AND every worker ran a
job afterwards. With a native worker declared, the worker and combined restarts must also restart
its slurmd and see a new main PID (Session B re-review R8: the combined stanza never restarted it).
No host is contacted."""
from pathlib import Path
import subprocess
import tempfile
import unittest

RUNNER = (Path(__file__).resolve().parent / "slinky-acceptance.sh").read_text()
STEPS = ["Recovery: K3s server restart", "Recovery: controller restart alone",
         "Recovery: worker restart alone", "Recovery: controller and workers together"]
MOCK = r'''set -uo pipefail
K="kubectl -n slurm"; S="$K exec slurm-controller-0 -c slurmctld --"; COMBINED_DEADLINE=300
EXPECTED=(g3 g4 $NATIVE_NODE); declare -A IP=([g3]=10.90.10.23 [g4]=10.90.10.24 [lenovo]=10.90.10.21)
STATE=$STATE_DIR
step() { :; }
result() { printf 'RESULT %s: %s\n' "$1" "$2"; }
ident() {   # identity before the restart command ran; after it, a new one only if it "worked"
  if [ -f "$STATE/restarted" ] && [ "$CHANGE" = yes ]; then printf '%s\n' "$1-new"; else printf '%s\n' "$1-old"; fi
}
L() {
  case "$*" in
    *"systemctl show -p MainPID"*) ident 4242 ;;
    *"systemctl restart k3s"*) [ "$CMD_RC" = 0 ] && : > "$STATE/restarted"; return "$CMD_RC" ;;
    *"delete pod"*) [ "$CMD_RC" = 0 ] && : > "$STATE/restarted"; return "$CMD_RC" ;;
    *readyz*) echo ok ;;
    *journalctl*"newer than datastore"*) echo 0 ;;
    *journalctl*) echo "" ;;
    *"date "*) echo "2026-09-28 10:00:00" ;;
    *sacct*) printf '100\n' ;;
    *"get pod slurm-controller-0"*) ident ctl ;;
    *"get pods -l app.kubernetes.io/name=slurmd"*) ident w1; ident w2 ;;
    *native-workers*) if [ -n "$NATIVE_NODE" ]; then printf '# Managed by Ansible\n%s %s\n' "$NATIVE_NODE" "${IP[$NATIVE_NODE]}"; fi ;;
    *) return 0 ;;
  esac
}
N() {   # a native worker's host
  echo "$*" >> "$STATE/native-calls"
  case "$2" in
    *"systemctl show -p MainPID"*)
      if [ -f "$STATE/native-restarted" ] && [ "$NATIVE_CHANGE" = yes ]; then echo 778; else echo 777; fi ;;
    *"systemctl restart slurmd"*) [ "$NATIVE_RC" = 0 ] && : > "$STATE/native-restarted"; return "$NATIVE_RC" ;;
    *) return 0 ;;
  esac
}
wait_all_usable() { printf '5 g3=101:COMPLETED g4=102:COMPLETED\n'; return 0; }
'''


HELPERS = RUNNER.split("# --- recovery helpers", 1)[1].split("# --- end recovery helpers", 1)[0].split("\n", 1)[1]


def stanza(name):
    start = RUNNER.index(f'step "{name}')
    ends = [RUNNER.find('\nstep "', start + 10), RUNNER.find('\nfi\n\nstep "Summary"', start)]
    end = min(e for e in ends if e != -1)
    return RUNNER[start:end]


class RecoveryVerdicts(unittest.TestCase):
    def run_stanza(self, name, cmd_rc, change, native="", native_rc=0, native_change="yes"):
        with tempfile.TemporaryDirectory() as d:
            env = {"PATH": "/usr/bin:/bin", "STATE_DIR": d, "CMD_RC": str(cmd_rc), "CHANGE": change,
                   "NATIVE_NODE": native, "NATIVE_RC": str(native_rc), "NATIVE_CHANGE": native_change}
            r = subprocess.run(["bash", "-c", MOCK + HELPERS + stanza(name)], env=env, capture_output=True, text=True, timeout=30)
            verdicts = [l.rsplit(": ", 1)[1] for l in r.stdout.splitlines() if l.startswith("RESULT ")]
            self.assertEqual(len(verdicts), 1, r.stdout + r.stderr)
            calls = Path(d, "native-calls").read_text() if Path(d, "native-calls").exists() else ""
            self.last_native_restarts = calls.count("systemctl restart slurmd")
            return verdicts[0], r.stdout

    def test_failed_restart_command_is_never_recovery(self):
        """The review's replay: the restart/delete fails, later jobs succeed -> must be FAIL."""
        for name in STEPS:
            with self.subTest(name):
                self.assertEqual(self.run_stanza(name, 9, "no")[0], "FAIL")

    def test_restart_that_changed_nothing_is_not_recovery(self):
        for name in STEPS:
            with self.subTest(name):
                self.assertEqual(self.run_stanza(name, 0, "no")[0], "FAIL")

    def test_real_restart_with_jobs_on_every_worker_passes(self):
        for name in STEPS:
            with self.subTest(name):
                verdict, out = self.run_stanza(name, 0, "yes")
                self.assertEqual(verdict, "PASS", out)


    def test_worker_and_combined_restarts_restart_the_native_slurmd(self):
        """review R8: with a native Lenovo declared, the combined stanza printed PASS after zero
        native restart commands"""
        for name in STEPS[2:]:
            with self.subTest(name):
                verdict, out = self.run_stanza(name, 0, "yes", native="lenovo")
                self.assertEqual(verdict, "PASS", out)
                self.assertEqual(self.last_native_restarts, 1, "one restart of the native slurmd")
                self.assertIn("native slurmd PIDs: lenovo=777 -> lenovo=778", out)
                self.assertEqual(self.run_stanza(name, 0, "yes", native="lenovo", native_rc=5)[0], "FAIL")
                self.assertEqual(self.run_stanza(name, 0, "yes", native="lenovo", native_change="no")[0], "FAIL")

    def test_an_unreadable_native_list_stops_the_run(self):
        helpers = HELPERS.split("\nis_native()", 1)[0]
        mock = MOCK.replace('*native-workers*) if', '*native-workers*) return 1; if')
        r = subprocess.run(["bash", "-c", mock + helpers + "\necho still running"], capture_output=True, text=True, timeout=30,
                           env={"PATH": "/usr/bin:/bin", "STATE_DIR": "/nonexistent", "NATIVE_NODE": ""})
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertNotIn("still running", r.stdout)


if __name__ == "__main__":
    unittest.main()
