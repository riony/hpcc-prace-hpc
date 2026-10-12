# Harness integration

Component 2 orchestration uses Component 4's existing gateway, action contracts,
cluster-tracer feed, replay engine and independent verdicts. It is separate from
`agents/`, which holds repository reviews and handoffs.

NeMo Agent Toolkit **1.9.0** is the primary driver. Install its pinned runtime
in a separate Python 3.12 environment, then run from the repository:

```bash
python3.12 -m venv "$HOME/.venvs/prace-nat"
"$HOME/.venvs/prace-nat/bin/pip" install -r harness/requirements-nemo.txt
"$HOME/.venvs/prace-nat/bin/python" -m harness \
  --run-id team-smoke-001 --output-dir /tmp/team-smoke-001
```

For manifest-driven goals, bounded discovery tools and the optional SSH
file/Slurm smoke, see [configurable scenarios](SCENARIOS.md). These are additional
`--plan` modes; the original two-attempt fixture correction below stays available.

With no `--model`, the default driver runs a **real NeMo workflow and registered
tool**, using four fixed actions and local file telemetry. It calls no model,
SSH, Slurm, Kubernetes or fleet node. Each run gets new private workspaces; an existing output directory
is refused, and the shared `/tmp/prace-file-ops-smoke-v1` workspace is not reset.

The rehearsal runs two attempts under one run ID:

1. Record four file actions with an intentionally wrong short fixture string.
   Reset, replay and independently observe the layout. Both observations must
   reproduce the functional regression, with cleanup complete.
2. Save a hash-bound proposal correcting that one literal string. Record and
   replay again from a fresh workspace. The independent verdict must now pass,
   and cleanup must complete.

The correction is a deterministic **fixture correction**, not an agent-discovered
vulnerability or an infrastructure patch. Security verdicts are `not_applicable`.
The local `cluster_tracer` snapshots prove the gateway feed and correlations;
they do not prove live cluster telemetry. Original failed-attempt artifacts stay
alongside the passing rerun.

To have NeMo's ReAct agent drive the sequence, select an endpoint and model:

```bash
"$HOME/.venvs/prace-nat/bin/python" -m harness \
  --run-id team-agent-001 --output-dir /tmp/team-agent-001 \
  --provider nim --model selected-model-name
```

The generated workflow uses only `prace_action`, with an action-ID input schema
and a fixed gateway socket. NeMo handles the model/tool workflow and telemetry;
Component 4 independently handles replay and verdicts. For configurable `--plan`
runs, NeMo also drives and records the replay through a model-free workflow;
the gateway still chooses every replayed action
([NeMo-driven replay](SCENARIOS.md#nemo-driven-replay)). The model does not reset,
finalize or choose an arbitrary shell command. The fixture correction remains an
explicit deterministic operator step, so this smoke run does not claim autonomous
repair. The ReAct wiring is tested with a local fake model; a real model/provider
run is pending endpoint selection.

Credentials come from `NVIDIA_API_KEY` for `nim`, or `OPENAI_API_KEY` with
`--provider openai`. An optional `PRACE_MODEL_BASE_URL` selects a hosted/local
endpoint. Set these privately in your environment. Generated config contains
variable references only. Neither credentials nor provider calls are needed for
the integration rehearsal.

Every attempt retains the private `nemo-trace.jsonl` with workflow/model/tool
events. The portable `agent-trace.json` contains span IDs, timestamps, data
digests and gateway-correlated actions, without raw model text. It is a bounded
projection, not the full conversation. NeMo's asynchronous exporter is given a
bounded completion wait; missing telemetry fails the attempt.

The stdlib-only `--driver scripted` remains useful for quick contract tests and
invokes the same Python bridge as the existing OpenCode tool. The optional
`--driver opencode --opencode /absolute/path --model provider/model` driver pins
the existing `prace-smoke` agent without enabling automatic approval. A zero
process exit is insufficient for any driver: complete successful actions and
matching evidence are required.

Any process failure, timeout, omitted action, missing snapshot, contradictory
result or incomplete cleanup exits nonzero. `run.json` stays `failed`; no correction
is applied after an unsuccessful first gate. Temporary processes stop, the failed
layout is recorded, and only the newly created local workspace is emptied.

```bash
python3 -m unittest discover -s harness/tests -v
"$HOME/.venvs/prace-nat/bin/python" -m unittest harness.tests.test_nemo harness.tests.test_nemo_session -v
```

## Evidence follow-up

Package a completed run and verify it anywhere with this repository's Python
validator; this does not execute actions again:

```bash
python3 -m harness.evidence pack --run-dir /tmp/team-smoke-001 \
  --output-dir /tmp/team-smoke-001-bundle
python3 -m harness.evidence verify --bundle-dir /tmp/team-smoke-001-bundle
```

The original fixture bundle has one run ID, source revision and dirty-tree flag, both manifests,
the hash-bound proposal, traces, agent trace projections, layout proofs, driver
receipts and independent results/reports. `bundle.json` indexes 22 artifacts by
size and SHA-256; `SHA256SUMS` provides a conventional checksum list. Runtime
config, raw model traces, sockets, logs and workspaces are excluded. No Slurm job
or recovery-point ID is invented for a local run; those fields are empty/null.

Verification checks all files and then rederives both verdicts, checks the
one-field fix and correlates agent actions with gateway actions. A contradictory
PASS is refused even if its file checksum has been recomputed. Keep the
`bundle.json` digest separately if provenance matters: checksums detect alteration
relative to that reference; they do not authenticate a producer that can rewrite
all artifacts. A successful local cleanup is not a cluster restore proof.

Configurable runs use the same pack/verify commands with a separate scenario
bundle schema; the bound plan, manifest, selected-action replay and independent
observer proofs replace the two-attempt fixture correction. Both formats export
to the dashboard. See [scenario delivery and evidence](SCENARIOS.md).

Framework references: [NeMo workflow configuration](https://docs.nvidia.com/nemo/agent-toolkit/latest/build-workflows/workflow-configuration.html)
and [observability](https://docs.nvidia.com/nemo/agent-toolkit/latest/run-workflows/observe/observe.html).

For a single NeMo CLI/HTTP entry point that records, replays, verifies and packages
an agent session without terminal-driving scripts, see [NeMo-native sessions](NAT-SESSIONS.md).
