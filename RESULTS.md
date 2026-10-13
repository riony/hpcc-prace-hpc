# Public-edition validation

Local checks completed on 12 October 2026 on Linux x86-64, and re-run on
13 October 2026 after the pre-release review. These are results of
this sanitized edition, not republished private-cluster evidence.

| Check | Result |
| --- | --- |
| Real CPU scheduling | PASS: Slinky 1.2.2 on kind/Kubernetes 1.34.0; one CPU NodeSet; `srun` returned `PRACE_CPU_JOB_OK` and exit zero |
| Clean setup through Ansible | PASS: dedicated local cluster created from the public inputs |
| Repeat Ansible apply | PASS: `changed=0`, `failed=0` |
| Scoped teardown | PASS: owned kind node deleted, no kind clusters remained; private receipts archived outside this tree |
| Validation suite | 79 tests: 69 passed, 10 expected privileged-test skips |
| Harness suite | 249 tests: 187 passed, 62 expected optional-runtime/privileged-test skips |
| Demo ownership/admission/result tests | 13 passed |
| Offline infrastructure tests | 39 `infra/tools/test-*.py` scripts passed locally; now included in the separate `infra-tests` hosted job |
| Ansible lint | Full profile on demo entry point passed; minimum correctness profile across retained playbooks passed (135 files examined) |
| ShellCheck | Public check driver and pre-commit hook passed |
| Helm lint | Four pinned dependency charts and the public Slurm values passed |
| Public filename/content guard | Zero findings |
| Gitleaks 8.30.1 | Zero findings in the final public tree and disposable sanitized test history |

The harness requires a Git revision for attributable evidence, so run the
portable checks from a Git checkout. Gitleaks was run over the published commit
history before upload, with zero findings.

Testing found and corrected a webhook startup race: Helm's operator readiness
can precede its admission listener. The demo now requires a successful
server-side dry run before installing Slurm; failed readiness retains owned
state instead of retrying mutations. Sanitization tests also caught and fixed
two overly broad substitutions. The original failed local reports were retained
privately rather than presented as passes.

The Ansible lint profile for the retained advanced roles checks correctness;
this does not claim all legacy role style rules or all physical acceptance tests
were run. Scripts from the original project that depended on excluded private inventories,
evidence or recordings were removed from this edition rather than shipped failing. The portable CI scope is explicit in
`tools/check.sh`. NeMo/model and dedicated root/container suites remain optional;
a skip does not mean those capabilities were qualified in this release.

Hosted GitHub CI subsequently passed both `checks` and `cpu-integration` at
[`81f6ce0`](https://github.com/riony/hpcc-prace-hpc/actions/runs/38320865272),
including a fresh kind cluster and real Slurm CPU job. The new `infra-tests` job
extends coverage to the retained infrastructure scripts; its result is tracked
separately in subsequent runs.

No physical deployment, GPU qualification, hostile scenario, full-cluster reset
or production acceptance is established by these public checks.
Accounting persistence, multi-user isolation and hardware-dependent recovery are
outside the small CPU demo. Checksum-pinned tools and charts are provided;
upstream container image version tags are still a supply-chain limitation to
address before production, alongside threat modelling and operational review.
