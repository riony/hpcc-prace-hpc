# Component 4 validation package

Dependency-free Python package for independent security and functionality
validation. Owner: `team-user03`. The original project's full guide and
realtime trace runbook are not part of this public edition.

## What this package does

- Enforce scenario, action, observation, cluster, and run-result contracts.
- Append private JSONL traces with flock serialization and writer-owned stamps.
- Replay only scenario-declared structured actions (fail closed).
- Run a single local tracer/gateway over a Unix-domain socket.
- Support local and bounded SSH file adapters for smoke file-ops.
- Auto-ingest **cluster tracer** events (`source=cluster_tracer`) after actions.
- Optional interim `cluster_watcher` corroboration; trusted observations drive verdicts.
- Produce independent verdicts and sanitized `result.json` / `report.md`.

## Quick checks

```bash
python3 -m unittest validation.tests.test_component4 validation.tests.test_tracer_realtime validation.tests.test_review_regressions -v
python3 -m validation.examples.file_ops_tracer_smoke --output-dir /tmp/prace-c4-demo
python3 -m validation.examples.offline_data_write_demo --output-dir /tmp/prace-c4-udw
```

CI and unit tests use no network credentials. Live OpenCode/SSH runs require an
operator-owned config outside git (`config/examples/`).
# Harness handoff

The reusable local orchestration and optional OpenCode driver are in
[`harness/`](../harness/README.md). Component 4 continues to own trace contracts,
replay and verdicts; the harness coordinates the fixture correction and rerun.

The [configurable scenario runner](../harness/SCENARIOS.md) adds benign discovery
and SSH file/job smoke plans. Its explicit smoke-only `execution` manifest
extension permits choosing declared actions and replays the actual sequence.
Existing manifests retain their ordered completion rules. The remote helper now
ships with `file_discovery.py` and `slurm_smoke.py`; install all three from one
reviewed revision before the operator's remote smoke.
