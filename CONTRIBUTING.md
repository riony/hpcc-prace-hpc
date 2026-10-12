# Contributing

Use synthetic data and example identities. Never commit a kubeconfig, rendered
Secret, private key, model credential, production inventory or run directory.
Keep runtime state outside the repository and follow `SECURITY.md`.

Enable the pre-commit hook with `git config core.hooksPath .githooks`; it runs
the public content check and Gitleaks on staged files. Run `bash tools/check.sh`; changes to the demo also require `up`, `test`, `down`
and a repeat from clean owned state. Changes to the advanced fleet roles need
focused offline tests and a separately owned operational qualification window.
Do not describe mocked transports, skipped tests or schema checks as live proof.

Use a branch and reviewable change. Preserve dependency notices and actual
contributor attribution. No deployment or access to shared systems is implied
by a contribution or a successful CI run.
