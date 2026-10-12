# Infrastructure reference

Start with the [CPU-only demo](../README.md#try-a-cpu-only-cluster). It is the
supported public quickstart and contacts only its dedicated local kind cluster.

The advanced roles/playbooks cover accounts, storage, native Slurm workers,
Kubernetes/Slinky, GPUs, observability, maintenance leases and recovery checks.
`inventories/` contains synthetic examples retaining the shape expected by the
roles and their tests. Addresses, hardware identifiers, account names, public
keys and host fingerprints are examples, not installation defaults for a fleet.
Never run these playbooks against physical hosts without your own inventory,
reviewed configuration and operational ownership.

Reference tests under `tools/test-*.py` cover individual infrastructure contracts.
Some historical acceptance tests require private evidence that is intentionally
not distributed; they are not part of the public portable CI promise.
The public check workflow tests the core harness/validation and demo, and applies minimum correctness lint to the retained playbooks, plus full lint
to the new Ansible entry point and the shell check driver. It does not claim every
legacy fleet role meets modern ansible-lint/ShellCheck style rules.

The original physical build used offline repository staging, metadata-aware
recovery, scoped helper delivery and node-specific qualification. This public
copy preserves code for adaptation, not the original runtime state or results.
See [results and limitations](../RESULTS.md) and [dependencies](../THIRD_PARTY.md).

Chart archives are fetched using `tools/fetch-charts.py`. The optional NRI guard
must be built from `nri-mount-guard/`, and its new hash explicitly pinned in role
configuration. The old compiled binary is not included.
