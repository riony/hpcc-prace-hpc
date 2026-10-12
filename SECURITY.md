# Security and release handling

Keep suspected credentials out of public issues and attachments. Report
vulnerabilities or leaked credentials privately through GitHub's private
vulnerability reporting (the repository's Security tab, "Report a vulnerability").

`tools/public-check.py` checks sensitive filenames, common credential formats,
Vault payloads and Tailscale names. Add your own host names, domains and project
codes, one regular expression per line, to the untracked `tools/public-check.local`. Gitleaks runs independently
with its standard rules. Ignore rules are not protection for already tracked
files: inspect the staged file list and scan the full history before publishing.

No model, Slurm, Kubernetes or SSH credential is required for the local CPU demo.
Charts create fresh local authentication material at install. The demo directory
is private and must never be copied into the repository. The advanced templates
read operator-supplied secrets at runtime, not from committed values files.

The kind demo is a development convenience, not containment for hostile code.
It is not the environment for sudo/SUID exploits or physical restoration tests.
