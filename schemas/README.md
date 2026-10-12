# Component 2–4 contract

**Status (5 Oct 2026):** schema v1 plus `prace.cluster-event.v1` are implemented
and hermetically tested under `validation/`. Action phases include `record`
(ordinary smoke) as well as `attack` / `replay` (security). Scenario status may
be `smoke` for trace/replay/report rehearsals that must not claim a security
result. The cp2 tracer owns action-event writes; OpenCode talks only through
`prace_action`.

These schemas define the portable boundary between the agent harness, replay
runner, independent validator, and report generator.

- Component 2 / the tracer emits `prace.action-event.v1` only after its bounded
  gateway attempts an action. It records digests and status, not raw output.
- The cluster tracer emits `prace.cluster-event.v1` with
  `source=cluster_tracer` (pinned observe helper). Interim cp2 corroboration
  may use `source=cluster_watcher`. Only final `prace.observation-event.v1`
  checks drive verdicts.
- Component 4 emits `prace.observation-event.v1` from a separate trusted
  observer. Agent claims are never observations.
- Component 3 supplies the patch revision recorded in `prace.run-result.v1`;
  patch apply and rollback are outside the scenario agent's authority.
- Component 1 supplies the baseline/recovery revision and the owned live window.

The JSON Schema documents are the language-neutral interface. The
dependency-free enforcement used by this repository is in
`validation/contracts.py`. Both use schema version 1 and reject unknown fields.

The optional smoke-only `execution` object (`mode=discovery`,
`required_actions`) allows a model to choose declared actions. Its source phase
is `attack` as a gateway ordering mode, while security verdicts remain
`not_applicable`. Completion requires the declared required actions and replay
of the actual chosen sequence. Ordinary manifests without this object keep the
original exact record/replay ordering rules. `file.list` / `file.stat` bindings
can hold bounded structured facts up to 4096 characters; all other kinds retain
256. The scenario output byte budget and redaction rules apply to both.

An action trace, a fresh agent rerun, and a recorded playback are different:

1. Action replay re-executes only scenario-declared structured actions.
2. A fresh rerun lets the model choose a new path.
3. Playback renders existing events and performs no action.

Raw prompts, model responses, command output, credentials, and private keys do
not belong in these records. Keep raw restricted traces off-fleet and outside
Git; commit only sanitized events, reports, and hashes.
