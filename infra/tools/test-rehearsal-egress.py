#!/usr/bin/env python3
"""Renders roles/rehearsal_host's nftables template (plain Jinja2, no host contacted) and checks
that the table confines only the rehearsal user's sockets: the base output chain may hold nothing
but the positive 'meta skuid <user> jump confine'. On 28 September the selector was written as
'meta skuid != <user> accept'; packets without a socket (the kernel's flannel VXLAN encapsulation
of forwarded pod traffic) do not match that rule, fell through to the private-range drop and cut
all cross-node pod traffic. When unprivileged user namespaces and nft are available, the rendered
file is also syntax-checked with 'nft -c' inside a throwaway network namespace."""
import getpass
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

import jinja2
import yaml

ROLE = Path(__file__).resolve().parent.parent / "roles/rehearsal_host"
DEFAULTS = yaml.safe_load((ROLE / "defaults/main.yml").read_text())


def render(**override):
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
    return env.from_string((ROLE / "templates/prace-rehearsal.nft.j2").read_text()).render({**DEFAULTS, **override})


def chain(text, name):
    m = re.search(r"chain %s \{\n(.*?)\n  \}" % name, text, re.S)
    assert m, f"chain {name} not found"
    return [l.strip() for l in m.group(1).splitlines() if l.strip() and not l.strip().startswith("#")]


class RehearsalEgress(unittest.TestCase):
    def test_base_chain_selects_only_the_rehearsal_users_sockets(self):
        out = chain(render(), "output")
        self.assertEqual(out, ["type filter hook output priority filter; policy accept;",
                               f'meta skuid "{DEFAULTS["rehearsal_user"]}" jump confine'])

    def test_no_negated_owner_match_anywhere(self):
        # A negated owner match silently includes every socketless packet (tunnels, forwarding).
        rules = "\n".join(l for l in render().splitlines() if not l.strip().startswith("#"))
        self.assertNotRegex(rules, r"sk(uid|gid)\s*!=")

    def test_confine_chain_drops_every_blocked_range_and_ipv6(self):
        body = "\n".join(chain(render(), "confine"))
        for net in DEFAULTS["rehearsal_blocked_v4"]:
            self.assertIn(net, body)
        self.assertIn("meta nfproto ipv6 counter drop", body)
        self.assertIn("ip daddr 127.0.0.0/8 counter drop", body)

    @unittest.skipUnless(shutil.which("nft") and shutil.which("unshare"), "nft/unshare not available")
    def test_rendered_file_is_valid_nftables(self):
        with tempfile.NamedTemporaryFile("w", suffix=".nft") as f:
            # The user must exist where nft resolves it; the check runs as whoever runs the tests.
            f.write(render(rehearsal_user=getpass.getuser())); f.flush()
            r = subprocess.run(["unshare", "-rn", "nft", "-c", "-f", f.name], capture_output=True, text=True)
            if "Operation not permitted" in r.stderr or "unshare failed" in r.stderr:
                self.skipTest("unprivileged network namespaces are not permitted here")
            self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
