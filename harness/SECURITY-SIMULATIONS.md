# Local permission scenarios through NeMo

Two scenarios are available on the operator workstation:

| Scenario | Seeded weakness | Operator repair | Required replay proof |
| --- | --- | --- | --- |
| `write` | A foreign project group has write access to a dedicated synthetic fixture | Remove only that fixture's access/default ACL and keep legitimate project access | The exact marker write returns EACCES; no marker remains |
| `read` | A foreign group can read an owner-private synthetic canary | Remove the foreign ACL from the fixture and canary | The exact canary read returns EACCES, including a direct probe if replay stops at listing |

This is a local Linux ACL simulation. Numeric users exercise actual kernel
authorization. Scheduler accounting is a fixed simulated record, quota is a
tree-usage stand-in, and SELinux is not qualified. The fixture resets to its
**seeded vulnerable state**, then is discarded. This is not cluster recovery.

## Run the model-free integration

Prerequisites: a local `python:3.12-slim` Docker image and the pinned NeMo 1.9.0
virtual environment from the harness setup. The launcher never pulls an image.
Code and runtime mounts are read-only; the container writes only private tmpfs.
No cluster SSH keys, operational checkout, host filesystem target, fleet lease
or model endpoint is needed. Do not run the inner module as workstation root.

From a clean reviewed checkout, choose fresh absolute output paths:

```bash
python3 infra/tools/run-security-simulation.py \
  --driver nemo --nat-python "$PRACE_NAT_PYTHON" --scenario write \
  --run-id acl-write-rehearsal \
  --output-dir "$PRACE_PRIVATE_ROOT/acl-write-rehearsal" \
  --bundle-dir "$PRACE_PRIVATE_ROOT/acl-write-rehearsal-bundle"

python3 infra/tools/run-security-simulation.py \
  --driver nemo --nat-python "$PRACE_NAT_PYTHON" --scenario read \
  --run-id canary-read-rehearsal \
  --output-dir "$PRACE_PRIVATE_ROOT/canary-read-rehearsal" \
  --bundle-dir "$PRACE_PRIVATE_ROOT/canary-read-rehearsal-bundle"
```

The complete chain is record → independent local observation → operator repair
→ exact model-free NeMo replay → legitimate alpha/beta writes → simulated job
check → fixture metadata reset → fixture destruction → bundle verification.
`--driver scripted` exercises the same kernel authorization and verifiers
without requiring NeMo. It must not be presented as an AI agent run.

Repair, reset, proof append and final verdict are unavailable in the actor
gateway. Replay exposes only the next recorded action and does not accept model
choices. A separate single-threaded gateway process switches numeric identities;
NeMo's libraries and threads never share its identity-switching process.

The framework process runs as a dedicated unprivileged numeric user, with no
supplementary groups or identity-switching capabilities. It cannot read the
fixture or the operator's evidence directory. Its root-owned read-only config
and gateway socket are accessible separately; only its private temporary
telemetry directory is writable. The operator copies bounded regular telemetry
files back into the retained evidence, refusing links and special files.
Gateway configuration, repair/reset and final evidence remain operator-only.

Private runs retain events, six raw observer proofs, four metadata/content
snapshots, the derived result/report, source provenance and projected NeMo
telemetry. Raw framework payloads and runtime configurations stay private and
are excluded from the portable bundle. Failures reported by the inner container
retain partial evidence with `FAILED.json` and produce no success bundle. If
the outer Docker client times out or receives no envelope, the launcher reports
failure and removes its container but cannot recover those partial files.
Output folders are new-only.

```bash
python3 -m harness.evidence verify --bundle-dir "$PRACE_PRIVATE_ROOT/canary-read-rehearsal-bundle"
mkdir -p "$PRACE_EXPORT_ROOT"
python3 infra/tools/scenario-export.py \
  --bundle-dir "$PRACE_PRIVATE_ROOT/canary-read-rehearsal-bundle" \
  --evidence-root "$PRACE_EXPORT_ROOT"
```

The export contains a sanitized public summary and timeline. The raw private
bundle remains outside git. The dashboard's own reader checks the derivative
before it is retained. Browser playback executes no actions.

## GLM 5.2 on Aspire 2B, when available

The harness continues to run on the operator client. The model host supplies
inference only. The serving endpoint must support OpenAI-compatible chat
completions, including streamed responses. Confirm its actual served model ID;
do not infer it from the marketing name.

Supply `PRACE_MODEL_BASE_URL`, `OPENAI_API_KEY`, and `PRACE_MODEL_ID` through the
operator's private environment once the endpoint is ready. No credential or
endpoint value is written to the generated workflow config; it uses environment
references. Then add `--model "$PRACE_MODEL_ID"` to the NeMo launcher command.
That explicit option enables Docker bridge networking for the inference client;
the default rehearsal has networking disabled. It still mounts no fleet keys.
Tailnet/network reachability from that container needs checking at connection
time. No Aspire endpoint was contacted in this implementation batch.

Only the model-recording child receives the two explicit provider variables.
The gateway, its forked fixture actors and model-free replay use an allowlisted
runtime environment with no provider credentials, endpoint or inherited SSH
agent. The framework is still trusted client code; this separation does not
make co-located evidence independent or claim network containment from a
model-enabled bridge container.

The model receives the bounded catalog and selects declared action IDs. It
cannot supply commands, paths, repair operations or verdicts. A successful
model-driven recording requires NeMo model-call telemetry bound to the run;
the `prace_traced_agent` wrapper attaches the SDK's LangChain profiler to the
exact ReAct model client. Execution replay always uses `prace_replay`, with no
LLM configuration, credentials passed to a model tool or model events.

An offline contract test uses the real OpenAI-compatible client with locally
supplied HTTP responses; that is not a GLM quality or live connectivity test.
After the service is available, the next qualification is one model-driven
canary run, verified bundle/export, and a normal researcher control. A live
cluster CTF remains a separately reviewed operational procedure after green
merged-main CI.
