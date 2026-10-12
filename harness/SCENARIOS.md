# Configurable NeMo scenarios and SSH integration

For the ordered CPU/GPU test as `syn-alice`, with the user's selected home setup
and scripted driver, see [CPU/GPU tracing without sudo](USER-RESEARCHER.md).

The original `python -m harness` fixture correction remains unchanged. With
`--plan`, the harness loads a Component 4 manifest plus an operator-owned plan.
This first extension supports **benign smoke scenarios**. It does not report a
security finding or apply a configuration repair.

For the separate, disposable Linux ACL write and read-canary CTF path, with
NeMo recording/replay and portable proofs, see
[Security simulations](SECURITY-SIMULATIONS.md). This does not extend the benign
plan runner's live permissions.

## Offline use

Run the configurable discovery example through the real NeMo runtime without
a model endpoint:

```bash
python -m harness --plan harness/examples/file-discovery.plan.json \
  --run-id discovery-001 --output-dir /tmp/discovery-001
python -m harness.scenario_run --run-dir /tmp/discovery-001
```

Use the pinned Python 3.12 environment described in the harness README. For a
stdlib-only check, add `--driver scripted`. Neither command contacts the fleet
or a model provider. A new private output directory is required.

A plan supplies the manifest path, goal, execution mode, required completion
actions, synthetic seed files and independent checks. The examples show layout
checks using file digests, successful job accounting and empty-workspace
cleanup. Every manifest assertion must have a supported observer check.
Arbitrary programs, unsupported action kinds and security manifests are refused
before execution. More scenario-specific observers belong in later changes.

`ordered` runs retain the manifest sequence. `discovery` runs use the explicit,
smoke-only `execution` extension in the bound manifest: the agent can choose a
subset/order of declared actions within the budget. It must perform the required
completion actions. Component 4 replays the **actual** chosen sequence and
independently derives the verdict. Existing manifests without the extension
keep their strict ordered completeness checks.

With a selected model, add `--provider openai --model selected-model-name` (or
`nim`). `prace_catalog` exposes only the manifest actions. `prace_action` has a
schema generated from their IDs, returning captured facts alongside a correlated
action receipt. The goal in discovery mode contains no prescribed action order.
The fake-model test chooses stat before list, contrary to manifest order, and
proves that replay follows it. This proves orchestration, not model discovery
quality. Endpoint selection and a real provider run remain pending.

`file.list` returns bounded names/types; `file.stat` returns numeric owner,
group and permission facts. Both use declared paths, no shell, no file contents,
and at most 32 entries. Discovery captures permit up to 4096 bytes and remain
subject to the scenario output budget and redaction rules. Other capture kinds
retain their 256-byte limit. Reset, replay, observation and finalization remain
operator functions, unavailable to the model.

### NeMo-driven replay

With `--driver nemo`, the replay is also a NeMo workflow
(`harness.nemo_driver --operation replay`), so record and replay share one
telemetry pipeline. The [session entry point](NAT-SESSIONS.md) uses the same
path. The model-free `prace_replay` workflow calls one tool, `prace_replay_step`,
which takes no choice: each call asks the gateway's `replay_next` for exactly one
action. The gateway selects the next recorded
action, resolves its new bindings (a replayed job ID, for example) from the
replay so far, and writes the same trace as a whole `replay`. A denied action
ends the replay; any other failure stops it for good. The replay config has no
`llms` section, and the driver refuses one that does. The model is never
consulted during replay.

`agent-replay-trace.json` (`prace.agent-replay-trace.v1`) binds that telemetry
to the gateway. Each completed step is one gateway replay action, with the same
sequence, action, status, captured facts and the SHA-256 of the whole event. The
last step is the gateway's "done", and the workflow result must equal its steps.
Any `LLM_*` event or malformed telemetry is refused. The bundle carries it and verification
rederives it. The dashboard export shows the replay workflow and each step. The
raw `nemo-replay-trace.jsonl` stays private, like `nemo-trace.jsonl`.
`run.json` records `replay_driver` (`nemo` or `gateway`). Runs from before this
change have no such field: the gateway replayed them, and they verify unchanged.
The scripted driver keeps the gateway's whole `replay`.

A **draft** researcher-workflow scenario (CPU and GPU site examples, output read and kept) is in
[drafts/researcher-workflow](drafts/researcher-workflow/README.md). It is not runnable yet: it needs four new
action kinds, listed there.

## Remote preparation and execution

Remote execution is a later owned operation. CI and this MR's tests replace SSH
and Slurm with local stand-ins. They prove neither live SSH identities nor live
job submission. The cluster operator must use a reviewed, merged revision with
passing main CI, and coordinate the live slot before running this command.

1. In the cluster operator's owned window, deploy the explicit `harness_helper`
   tag from a clean merged execution pin after main CI passes:

   ```bash
   tools/run-ansible.sh -i inventories/fleet playbooks/fleet.yml \
     --limit lab-dl380 --tags harness_helper -e fleet_armed=true \
     -e fleet_lease_id="$LEASE_ID" \
     -e harness_helper_revision="$(git rev-parse HEAD)" --check
   ```

   Review the preview, apply without `--check`, then repeat for `changed=0`.
   The role checks the exact clean source pin and mounted apps/projects devices.
   It delivers the helper and both companions under `/apps/prace/<full-SHA>/`,
   root-owned, readable by all; the entrypoint is executable. The shared `/apps`
   mount persists across login-pod recreation. Set all three `remote_helper`
   paths to this release. No helper runs as root. The entrypoint uses
   `/usr/bin/python3 -I`, imports only its delivered companion directory and
   ignores actor Python startup overrides. Slurm commands use absolute,
   root-owned executables in the declared system/OpenHPC locations with a clean
   environment, rather than the actor's PATH or Slurm overrides. The capabilities
   handshake compares all three code digests with the local execution source;
   this self-reported digest is drift detection, not off-node attestation.
2. The role creates the shared `proj-ops` parent
   `/projects/proj-ops/.prace-smoke/runs`, owned by root and group `proj-ops`,
   mode `3770` (sticky and setgid), with inherited access/default ACLs removed only
   on those two synthetic parents. The project ACL and existing runs stay unchanged.
   The helper never changes shared parent permissions or an existing run.
   It creates only a new `<run-id>/workspace`, mode `0750`; new action directories
   use `0750` and files `0640`, retaining observer read access without group write;
   a reused directory is refused and never reset. Preparation restores the actor umask after setting the mode of the new
   directories. The shared group allows the
   independent tracer and observer to inspect synthetic files. Existing run and
   workspace directories must have matching numeric owners and mode `0750`
   (inherited setgid is allowed). Symlink parents and action paths resolving
   outside the owned workspace are refused; actions cannot edit the job ticket.
3. Copy `examples/ssh.json.example` **outside git**, mode `0600`, and fill in
   three distinct identities, SSH aliases and private-key paths. Use pinned
   known-hosts files and the existing login route. Keys are neither read nor
   copied into the run. Preflight confirms all three remote usernames and
   distinct UIDs before preparing a workspace. For a Slurm plan, the observer
   also queries retained accounting and the active queue before preparation;
   an existing run-specific job name refuses reuse of that run ID. The observer
   records the run start using the login host's UTC clock.
4. The manifest actor must match the actor SSH user. The example uses
   `syn-smoke`, `syn-tracer`, `syn-observer` and `proj-ops`. Choose a new run ID.

```bash
python -m harness --plan harness/examples/cluster-smoke.plan.json \
  --ssh-config /absolute/private/ssh.json --allow-remote \
  --run-id cluster-smoke-001 --output-dir /tmp/cluster-smoke-001
python -m harness.scenario_run --run-dir /tmp/cluster-smoke-001
```

Omitting `--allow-remote` refuses the run before any SSH call. No routing,
firewall, scheduler configuration or fleet installation happens automatically.

The fixed `slurm.submit` action submits `/bin/true`: one node, one task, one CPU,
32 MiB, one-minute walltime, output to `/dev/null`, the actor's project and a
manifest-declared partition. The job name is `prace-smoke-<run-id>`;
the comment remains a convenience tag, with no dependence on `job_comment`
accounting storage. The operator binds both tags;
the agent cannot supply a program or another run ID. The job ID is captured in
the gateway trace and used by `slurm.wait`. The observer separately queries
accounting, requiring the exact job/user/project/partition/name, one node,
one requested CPU, 32 MiB, one-minute limit and the full fixed submission command (including
`--wrap=/bin/true`), plus `COMPLETED|0:0`. Truncated or missing fields refuse
the proof. UTC Submit must be at or after the recorded run start.
[Slurm documents these accounting fields](https://slurm.schedmd.com/sacct.html),
including `SubmitLine`, `NNodes` and `Submit`; no scheduler setting is changed.
The first fixed-job proof must pass before reset/replay, establishing that the
real cluster retains the required tag and fields. Replay submits a new job and
records its new ID. Observer access to the actor's queue/accounting is a live
prerequisite; a PrivateData policy that hides them needs operator resolution.

Job tickets live beside, outside, the action workspace. Reset cancels only this
actor's tagged pending job and requires its disappearance and terminal
accounting before deleting a known ticket. If submission has an unknown outcome,
accounting is unavailable or cleanup fails, the run remains failed and the
ticket stays for operator reconciliation. It never cancels unrelated jobs.
An sbatch diagnostic still fails the action; a valid receipt accompanying it is
saved for verified cleanup. Missing or malformed receipts remain unknown.
If preparation creates a directory but its SSH reply is lost, cleanup is also
recorded as unknown: the harness does not adopt or delete an unconfirmed run.
The operator inspects those retained paths/jobs before deciding how to reconcile
them. Local output paths with symlink parents are refused before writes.
Successful cleanup uses the observer identity to query the actor's queue and
verify terminal accounting for every captured job ID. A still-active job is
refused even if renamed, and a missing/malformed query never means absent.
It also independently observes an empty workspace and no ticket;
only then are the owned remote directories removed.

Actor actions, per-action tracer inventories and observer checks share one run
ID. An inventory `match` means the tracer collected the snapshot; final layout
and job PASS come from the separate observer. A tracer timeout or malformed
reply retains both the action event and a correlated unavailable-inventory
snapshot, then fails the action through the gateway without killing the service.
The verifier recomputes results
from trace/proof artifacts, checks resolved replay bindings, job IDs and agent
telemetry. SSH configuration, key paths and raw model traces remain private.
`harness.evidence pack` accepts the original two-attempt fixture cycle and
configurable runs. Configurable bundles use `prace.scenario-bundle.v1`, retaining
the bound plan/manifest, selected-action and replay traces, agent projection,
each observer proof, result/report and run provenance. SSH configuration, raw
model traces, logs, sockets and workspaces are excluded. Verification rederives
the result and cleanup before and after packing. The dashboard exporter accepts
both formats and preserves the unchanged bundle in its verified private copy.
It labels configurable runs as smoke runs with no repair claim. Separate SSH
identities do not establish off-node T1 evidence; trust remains T2/T3.

```bash
python -m harness.evidence pack --run-dir /tmp/cluster-smoke-001 \
  --output-dir /tmp/cluster-smoke-001-bundle
python infra/tools/scenario-export.py --bundle-dir /tmp/cluster-smoke-001-bundle
```

No recovery-point ID or full restore proof is invented for a smoke run.

For a single command that runs, verifies, packs and exports a smoke, use
`python -m harness.smoke --run-id smoke-unique --output-dir /absolute/private/new-directory`.
It defaults to the model-free NeMo driver; `--driver scripted` permits a local
stdlib check. Supplying both `--ssh-config` and `--allow-remote` selects the
cluster smoke. The output directory must be new and outside the source checkout.
The original project's ordered rollout runbook (helper deployment, dashboard
refresh, Apptainer and directed-route IB mapping) is not part of this edition.

Environment provenance is distinct from transport. New SSH runs retain the reviewed capabilities for actor, tracer and observer in `environment.json`, included in their bundle. All three may explicitly declare `ssh-stand-in`; otherwise the environment is `ssh-unqualified`. Mixed or unsupported declarations stop before preparation. SSH alone does not establish real fleet contact. Exports place stand-in job receipts in `simulated_job_ids`; historical SSH bundles stay verifiable but export fleet contact as unknown. These declarations remain co-located evidence, not independent controller qualification.

If the trace is torn, finalization retains `run.json` with failed status and attempts bounded cleanup using the last fully validated receipts. It records cleanup as unknown when a missing receipt cannot be ruled out, keeps the ownership record for reconciliation, and never packages the failed run as verified evidence.
