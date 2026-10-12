# NeMo-native recorded sessions

This entry point replaces the terminal-typing driver for **agent workflows**.
NeMo runs the declared action tools, records its tool/model telemetry, starts a
model-free replay workflow, then verifies and packages the Component 4 evidence.
It supports `nat run` and `nat serve` on the harness host. The operator can use the local client without `pov-drive.py` or a keystroke
recorder. A future remote HTTP client can avoid a local Python installation;
remote service access and authentication are not qualified by this change.

Status: implemented and tested offline with pinned NeMo 1.9.0. This does not
deploy a service or install a helper on the cluster. A real model endpoint is
still an operator choice; the default is explicitly a model-free rehearsal.

## Run the local rehearsal

Use Python 3.12 and an editable install from the pinned source checkout. The
repository contains scenario data, source provenance and helper hashes, so a
standalone wheel without the checkout is not a supported deployment.

```bash
python3.12 -m venv /tmp/prace-session-env
/tmp/prace-session-env/bin/pip install -r harness/requirements-nemo.txt
/tmp/prace-session-env/bin/pip install --no-deps -e .
/tmp/prace-session-env/bin/nat run \
  --config_file harness/examples/nat-session.yml \
  --input '{"run_id":"researcher-session-001"}'
```

This default uses a local file fixture, with no SSH, GPU or provider call. It
executes through the real NeMo runtime; it is not evidence of an AI choosing
actions. Completion requires the original and replayed actions, independent
checks, cleanup, both NeMo traces and the portable bundle to verify.

## Serve from the harness host

The same workflow can stay running on a designated harness host:

```bash
/tmp/prace-session-env/bin/nat serve \
  --config_file harness/examples/nat-session.yml \
  --host 127.0.0.1 --port 8000 --workers 1
```

An HTTP client submits only a run ID:

```bash
curl --fail-with-body http://127.0.0.1:8000/generate \
  -H 'Content-Type: application/json' \
  -d '{"input_message":"{\"run_id\":\"researcher-session-002\"}"}'
```

Use an existing authenticated tunnel to that host for remote clients. This
change does not publish an unauthenticated cluster execution endpoint. `/generate`
waits for the session to finish. NeMo's background-job endpoints need Dask, which
is not in the pinned environment, plus job-state configuration. Inbound API
authentication has not been qualified. Keep `--host 127.0.0.1` until both are. Keep one
service instance and one configured run root; the local lock is not a distributed
cluster lease. A disconnected request keeps ownership until its bounded run and
cleanup finish. An interrupted process requires inspection of retained artifacts.

Run IDs are never reused: a retry with the same ID is refused, including after a
failure. Another request is refused while the root is locked. Caller input cannot
change the plan, SSH identities, model, output root or allowed actions.

A session is **unresolved** if it was interrupted (the service stopped
mid-session), or if it failed after running without verified complete cleanup.
Either way a submitted job or a workspace may have been left behind. While any
session is unresolved, every new session is refused, whatever its run ID. The
operator inspects the retained `run/` directory, reconciles its jobs and
workspace, and records that locally, as the service user, with the client's
`resolve` command. Resolution is not an HTTP operation.

## Use the local client

`harness.session_client` is the operator's client for this service. It uses the
standard library only, talks only to a loopback URL, never chooses actions and
never retries a start by itself. The example configuration serves two evidence/status
companions next to `/generate` (neither executes cluster actions):
- `/prace/status`: the state, stage and progress of a session, or a list of sessions;
- `/prace/export`: exports a complete session's verified bundle.

```bash
python3 -m harness.session_client start researcher-session-003
python3 -m harness.session_client export researcher-session-003 --preview ~/prace-dash-session
python3 -m harness.session_client status            # all sessions; add a run ID for one
python3 -m harness.session_client watch researcher-session-003   # follow it after a disconnect
python3 -m harness.session_client resolve crashed-001 --run-root /private/sessions \
  --note "inspected run/: no ticket, no queued job, workspace removed"
```

`start` prints each stage, each gateway action with its job IDs, each observer
check and the NeMo tool-call and replay-step counts. Captured outputs are not
shown. A dropped request does not stop the session; the client keeps following
it. A standalone `watch` stops with a visible diagnostic and exit 3 if no session
record is visible for that run ID. Check the run ID and service with `status`, then
watch again. The initial `start` still waits for its pending request to settle so
an early status response cannot be mistaken for a missing session. Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | complete |
| 1 | failed and cleaned up |
| 2 | refused before starting (lock, reused run ID, unresolved session) |
| 3 | uncertain: interrupted, or failed without verified cleanup; inspect, then `resolve` |

`export` writes the dashboard evidence folder once, inside the private session
directory and revalidates its bundle, receipt binding and cached dashboard files
on every request. `--preview` builds the private workstation dashboard from it, with
`infra/tools/prace-dash-workstation.py`, so the run can be opened locally under
Scenarios. Publishing it is still a reviewed evidence MR, passing main CI and the
dashboard refresh. Serve the preview on a different port, such as 8001, while
NeMo occupies port 8000.

## Switch to the researcher workflow

In operator-owned configuration, set `plan` to
`harness/drafts/researcher-workflow/plan.json`, `ssh_config` to the private role
configuration, and `allow_remote: true`. Prefer absolute paths for service
configuration. The actor, tracer and observer stay separate SSH identities.

Select `model` and `provider` only when ready for a real agent run. Provider
credentials come from the host environment and are not request parameters.
Without `model`, NeMo executes the manifest sequence without an LLM; with it,
the existing ReAct workflow chooses among declared actions. The replay never
calls that model.

Before live use, qualify the matching `/apps` helper, real job accounting fields
and observer access in the assigned operator's window, as documented in
[the researcher plan](drafts/researcher-workflow/README.md). Main CI and the
existing operating rules still apply. This configuration is a benign workflow;
the permission CTF has not been migrated or authorized by these defaults.

## Who owns each step

| Step | Implementation |
| --- | --- |
| Entry point and orchestration | NeMo `prace_session`, callable by CLI or HTTP |
| Agent decisions and tool calls | Existing NeMo ReAct workflow, or labelled model-free rehearsal |
| Execution and structured action records | Component 4 gateway and bounded SSH helper |
| Original workflow telemetry | NeMo file exporter, `nemo-trace.jsonl` |
| Reset and observation | Operator orchestration and separate observer; never agent tools |
| Replay orchestration and telemetry | NeMo `prace_replay`, one `prace_replay_step` per recorded action; no LLM or agent tool catalog |
| Exact action sequence and fresh job-ID bindings | Component 4 gateway `replay_next`: it chooses each step and resolves fresh bindings |
| Verification and packaging | Existing Component 4 proofs and bundle verifier |
| Controller accounting | Separate operator evidence; attaching accounting remains future work |
| Dashboard playback | Read-only visualization; does not execute the workflow |

NVIDIA's observability system records workflow/model/tool events. Its
[`push_intermediate_steps` replay](https://docs.nvidia.com/nemo/agent-toolkit/latest/run-workflows/observe/observe.html)
re-injects telemetry into a trace; that alone does not re-execute Slurm jobs.
The registered PRACE replay workflow deliberately calls our existing execution
engine rather than interpreting observability spans as commands.

## Artifacts and trust

The configured root holds `<run-id>/session.json`, `run/` and `bundle/`, with
private directory/file permissions. The receipt includes the bundle index hash
and both raw NeMo trace hashes. It reports whether an LLM was used, the transport,
job IDs and verified cleanup. Failed sessions retain a failure receipt and their
available evidence; they cannot return a completed receipt.

Recording and replay are two NeMo workflows linked by the same run ID. This first
version does not combine their subprocess spans into one live streaming trace.
Each replay step is one gateway action, and its telemetry carries the SHA-256 of
that replay action event, including its new bindings and result. The workflow's
result must equal its steps. Any of the following refuses completion:

- a missing end event;
- a step bound to another event;
- a contradictory result;
- an LLM event.

Replay repeats the recorded **actions** with fresh bindings. It does not promise
the same **outcome**: job IDs, scheduler timing and file state can differ. The
replay-phase observer checks are the outcome comparison.

`bundle/` keeps the existing dashboard-compatible schema. It contains both action
sequences and the sanitized original-agent projection, and now also
`agent-replay-trace.json`, the replay projection (spans, timestamps and digests).
Verification rederives that projection. The session checks that it equals what
the private replay telemetry yields, and the dashboard export shows each replay
step. Raw model text, SSH configuration and raw replay telemetry remain private
in `run/`. The session receipt also stays outside the portable bundle. The replay's executed events and
observer proofs are already in that bundle. Dashboard deployment remains its own
operation.

NeMo telemetry is actor-side evidence, not independent controller evidence. Local
fixtures do not acquire T1 trust merely because NeMo logged them. Ordinary manual
SSH commands outside these tools are not recorded by this workflow; terminal or
host audit collection remains appropriate for human sessions.

## Next increments

1. Qualify one model-free CPU/GPU session through this entry point on the cluster.
2. Select an endpoint and run the same plan with real agent decisions.
3. Attach the independent controller accounting and export the verified bundle.
4. Add an authenticated service UI without sharing actor keys with clients. The
   local client and its status view are in place. A separately requested replay of
   an older run needs an explicit reset/baseline contract; this version replays
   within one verified session.
5. Migrate the reviewed permission CTF into its own manifest and observer contract,
   keeping owner seeding/repair outside model tools.
