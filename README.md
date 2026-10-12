# HPCC PRACE HPC

[![Public validation](https://github.com/riony/hpcc-prace-hpc/actions/workflows/ci.yml/badge.svg)](https://github.com/riony/hpcc-prace-hpc/actions/workflows/ci.yml)

A reproducible HPC infrastructure and security-validation project: Slurm on
Kubernetes with Slinky, Ansible roles for physical Linux fleets, and a bounded
action harness that records, verifies and replays scenario activity.

This public edition uses example identities and networks. It includes reusable
code and tests; private fleet configuration, original operational evidence,
team credentials, presentation material and internal Git history are excluded.

## Try a CPU-only cluster

Requirements: Linux x86-64, Docker access, Python 3.12, at least 8 GiB available
RAM and 15 GiB free disk, plus internet access for public images/charts. The demo
uses kind in a privileged Docker container, as required by kind; run it only on
a development machine. It mounts no physical cluster credentials or disks.

Install kind 0.30.0, kubectl 1.34.0 and Helm 3.19.0 using their official release
instructions, then put them on PATH. Or use the checksum-verifying installer:

```bash
python3 tools/bootstrap-tools.py
export PATH="$HOME/.local/state/hpcc-prace-hpc-public/tools:$PATH"
python3 demo/cluster.py up
python3 demo/cluster.py test
python3 demo/cluster.py status
python3 demo/cluster.py down
```

`test` runs a real `srun` CPU job and requires `PRACE_CPU_JOB_OK` with exit zero.
It requires no GPU, institutional account, API key, SSH connection or model.
The dedicated cluster is named `prace-public-demo`; the API binds to loopback.
Every Kubernetes command uses the demo's own kubeconfig and context. Ownership
receipts bind teardown to that exact container and cluster. Existing names or
uncertain ownership are refused. Failed runs preserve state for inspection.
Private runtime state is outside this repository, under
`~/.local/state/hpcc-prace-hpc-public/demo/` (0700). Do not publish that directory.

Alternatively use the local Ansible entry point after installing the tools:

```bash
ansible-playbook -i demo/inventory.example.yaml demo/provision.yaml --check
ansible-playbook -i demo/inventory.example.yaml demo/provision.yaml
ansible-playbook -i demo/inventory.example.yaml demo/provision.yaml
python3 demo/cluster.py test
python3 demo/cluster.py down
```

The second successful apply should report `changed=0`. The example disables
accounting persistence and uses ephemeral authentication generated at install.
It demonstrates scheduling, not the full physical deployment or restoration.

## Architecture

```text
Local demonstration: Ansible/Python -> kind -> cert-manager + Slinky operator
                                             -> Slurm controller + CPU NodeSet
                                                -> real srun job

Validation path: bounded action gateway -> recorded events + tracer observations
                                        -> independent objective checks
                                        -> deterministic, model-free replay

Advanced physical deployment: example inventories -> Ansible fleet roles
                              -> Linux/storage/accounts + Kubernetes/Slurm
```

| Directory | Purpose |
| --- | --- |
| `demo/` | Tested CPU-only Kubernetes setup, example values and ownership checks |
| `infra/roles`, `infra/playbooks` | Advanced provisioning, accounts, storage, scheduler, observation and recovery components |
| `infra/inventories/` | Synthetic example topology; never an actual deployment inventory |
| `infra/nri-mount-guard/` | Source and build recipe for the optional runtime mount guard |
| `harness/` | Bounded campaign orchestration, provenance, model integration and follow-up control |
| `validation/` | Action contracts, trace/replay and independent verdicts |
| `scenarios/`, `schemas/` | Declarative scenario definitions and event contracts |
| `tools/` | Public dependency setup and release checks |

## Validation and results

See [RESULTS.md](RESULTS.md) for the checks performed on this public edition and
their limits. The original team's physical measurements are not republished here.
A local scheduling pass does not demonstrate GPU readiness, storage isolation,
full-cluster restoration, production acceptance or independent off-node observation.
Repair/replay interfaces are retained; do not equate interfaces or unit tests
with a completed physical repair-and-replay qualification.

Run the portable checks with Python 3.12 from a Git checkout (the harness
deliberately refuses to run without source provenance):

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
bash tools/check.sh
```

GitHub Actions runs these checks and a separate local-kind integration job.
Optional NeMo dependencies and their additional tests are documented in
`harness/README.md`. Tests requiring NeMo or root explicitly skip without them.

## Advanced roles

The copied roles are reference infrastructure, not a default action of the demo.
All site names, network bindings, people and key data are synthetic. Public SSH
keys in example fixtures are deterministic dummy bytes with no corresponding
private keys; supply your own keys in a private inventory. Do not deploy the
example fleets to real machines. Adapt hardware, policies and recovery gates,
review the resulting configuration, and qualify it in your own environment.
Renamed service/module prefixes in this public fork are not a drop-in update
for an existing private deployment.

The private project used admission/lease checks, scoped privileges, attributable
journals and conservative retention on uncertain outcomes. Those controls are
retained in source, but neither this demo nor a lint pass is a production claim.
Full restore qualification and broader feature completion remain future work.

## Contributors and licence

Developed collaboratively by the HPCC PRACE HPC team. Individual public display
names will be added after contributors approve them; private usernames and
emails are intentionally absent. The public import must not be interpreted as
sole authorship of the original team work.

First-party code: [Apache-2.0](LICENSE), released with team permission.
See [NOTICE](NOTICE) and [THIRD_PARTY.md](THIRD_PARTY.md) for dependency attribution.
