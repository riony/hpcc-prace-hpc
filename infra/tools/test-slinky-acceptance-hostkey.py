#!/usr/bin/env python3
"""The login pod's SSH host keys in tools/slinky-acceptance.sh (3 Oct, Session A's review of the
handback): pinned at the start from the operator's Secret over the verified root connection,
checked strictly on every login, and required unchanged across every rollout and restart. The run
used to drop the pinned key around each rollout and accept whatever came next.

The script's own pinning functions run with a mocked L (the login node); the rest is checked as
written. No host is contacted."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

RUNNER = (Path(__file__).resolve().parent / "slinky-acceptance.sh").read_text()
UID, UID2 = "14126072-841a-4177-a3bd-eca04101890a", "99999999-841a-4177-a3bd-eca04101890a"
KEYS = ["ecdsa-sha2-nistp256 AAAAE2VjZHNh", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5", "ssh-rsa AAAAB3NzaC1yc2EAAAA"]


def functions():
    start = RUNNER.index('PIN="$MUX/login-pod-known-hosts"')
    end = RUNNER.index("\n", RUNNER.index("host_keys_unchanged() {"))
    return RUNNER[start:end + 1]


def run(answers, body):
    """answers: what L prints for each successive host_keys call (None: L fails)"""
    with tempfile.TemporaryDirectory() as d:
        for i, a in enumerate(answers):
            if a is not None:
                Path(d, f"answer{i}").write_text(a)
        script = f'''set -uo pipefail
MUX={d} PRIV=10.90.10.1 PORT=32222
L() {{   # host_keys runs in a command substitution (a subshell): the call count lives in a file
  cat >/dev/null; n=$(cat {d}/n 2>/dev/null || echo 0); echo $((n + 1)) > {d}/n
  [ -f {d}/answer$n ] || return 1; cat {d}/answer$n
}}
''' + functions() + body
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
        pin = Path(d, "login-pod-known-hosts")
        return r, (pin.read_text() if pin.exists() else None)


def answer(uid=UID, keys=KEYS):
    return f"uid {uid}\n" + "".join(k + "\n" for k in keys)


class Pinning(unittest.TestCase):
    def test_the_secrets_public_keys_are_pinned_for_the_login_pods_address(self):
        r, pin = run([answer()], 'pin_login_host_keys && echo "pinned: $HOSTKEYS" | head -1')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(pin, "".join(f"[10.90.10.1]:32222 {k}\n" for k in KEYS))

    def test_no_secret_no_keys_or_no_answer_refuses(self):
        for label, a in {"no answer": None, "no Secret (no uid)": "uid \n", "no keys": answer(keys=[]),
                         "a malformed uid": answer(uid="x")}.items():
            with self.subTest(label):
                r, pin = run([a], "pin_login_host_keys")
                self.assertEqual(r.returncode, 1, label)
                self.assertIsNone(pin, "nothing is pinned")

    def test_the_keys_must_stay_the_same(self):
        for label, later, want in (("unchanged", answer(), 0), ("a new Secret (UID)", answer(uid=UID2), 1),
                                   ("another key", answer(keys=[KEYS[0], "ssh-ed25519 AAAAC3OTHER", KEYS[2]]), 1),
                                   ("a key gone", answer(keys=KEYS[:2]), 1), ("no answer", None, 1)):
            with self.subTest(label):
                r, _ = run([answer(), later], "pin_login_host_keys && host_keys_unchanged")
                self.assertEqual(r.returncode, want, label)

    def test_only_public_keys_are_read_on_the_login_node(self):
        remote = RUNNER[RUNNER.index("<<'EOS'"):RUNNER.index("\nEOS\n")]
        self.assertIn(r"_key\.pub}", remote)
        self.assertEqual(re.findall(r'\.data\.(.+?)\}"', remote), [r"ssh_host_${t}_key\.pub"], "no other field of the Secret")


class AsWritten(unittest.TestCase):
    def test_no_trust_on_first_use_anywhere(self):
        for bad in ("accept-new", "ssh-keygen -R", "StrictHostKeyChecking=no", "$KH"):
            self.assertNotIn(bad, RUNNER)

    def test_every_login_pod_connection_checks_the_pin_strictly(self):
        pod = RUNNER[RUNNER.index("POD() {"):RUNNER.index("\n}\n", RUNNER.index("POD() {"))]
        for opt in ('UserKnownHostsFile="$PIN"', "GlobalKnownHostsFile=/dev/null", "StrictHostKeyChecking=yes", "UpdateHostKeys=no"):
            self.assertIn(opt, pod)

    def test_pinned_before_the_first_login_and_checked_after_every_rollout_and_the_restarts(self):
        pin = RUNNER.index('pin_login_host_keys || { echo "refusing')
        self.assertLess(RUNNER.index("LEASED=1\n"), pin)
        self.assertLess(pin, RUNNER.index('step "R3 identity: running login pod"'))
        checks = [m.start() for m in re.finditer(r"pass_if \"[^\"]*host keys unchanged[^\"]*\" host_keys_unchanged", RUNNER)]
        self.assertEqual(len(checks), 4)
        fresh, conv1, conv2, last = checks
        self.assertLess(RUNNER.index('step "R3 identity: fresh login pod"'), fresh)
        self.assertLess(fresh, RUNNER.index('identity_checks "fresh login pod"'))
        self.assertLess(RUNNER.index("converge -e \"@$present\""), conv1)
        self.assertLess(RUNNER.index("if converge; then"), conv2)
        self.assertLess(RUNNER.index('step "Recovery: controller and workers together'), last)
        self.assertLess(last, RUNNER.index('step "Summary"'))


if __name__ == "__main__":
    unittest.main()
