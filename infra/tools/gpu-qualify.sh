#!/bin/bash
# V100 node qualification (D39), run ON a GPU node as root after roles/nvidia_gpu:
#   gpu-qualify.sh [--quick] --nccl-tests /path/nccl-tests-2.20.0.tar.gz
# Read-mostly and bounded: it starts the DCGM host engine if it is not running, builds
# nccl-tests under /var/tmp, and loads the GPUs with DCGM diagnostics and NCCL. It changes no
# configuration. Throughout it samples every GPU's power, temperature, SM clock and hardware
# slowdown flags (hw_slowdown / hw_power_brake point at the power feed or cooling).
#
# Every observation must be present and readable: a failed query, unreadable output, a missing
# GPU/test/sample, a skipped test or a skipped NCCL run is never a pass. Lines are PASS, FAIL or
# UNRESOLVED (a diagnostic that did not produce a result, with its raw logs kept for follow-up);
# the verdict "QUALIFY: PASS" (exit 0) needs zero FAIL and zero UNRESOLVED, otherwise
# "QUALIFY: FAIL" (exit 1). Raw outputs and DCGM's own logs are kept in /var/tmp/gpu-qualify-<time>/.
set -u
QUICK=0 NCCL_TGZ="" EXPECT=${NVIDIA_EXPECTED_GPUS:-8}
LINKS_EXPECTED=${NVIDIA_EXPECTED_NVLINKS:-$((EXPECT * 6))}      # V100 SXM2: 6 NVLinks per GPU
NCCL_SHA=6087c4cbf91018866d2a5ba75bc0dcee83f473ce4a6899db020cb402a877ed9f   # nccl-tests v2.20.0
while [ $# -gt 0 ]; do
  case $1 in --quick) QUICK=1; shift ;; --nccl-tests) NCCL_TGZ=$2; shift 2 ;; *) echo "unknown argument: $1"; exit 2 ;; esac
done
CUDA=/usr/local/cuda-12.9
RUN=/var/tmp/gpu-qualify-$(date +%Y%m%dT%H%M%S); mkdir -p "$RUN"
FAILS=0 UNRESOLVED=0
ok()    { echo "PASS  $*"; }
bad()   { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }
unres() { echo "UNRESOLVED  $*"; UNRESOLVED=$((UNRESOLVED + 1)); }
step()  { echo; echo "== $(date '+%T') $*"; }
count_lines() { grep -c . <<<"$1"; }
echo "raw outputs: $RUN"

step "inventory"
nvidia-smi --query-gpu=index,name,serial,vbios_version,driver_version,pstate,ecc.mode.current,power.limit,persistence_mode --format=csv
if list=$(nvidia-smi -L) && n=$(grep -c '^GPU ' <<<"$list") && [ "$n" = "$EXPECT" ]; then ok "$n GPUs visible"
else bad "GPUs visible: ${n:-query failed} (expected $EXPECT)"; fi
if ecc=$(nvidia-smi --query-gpu=ecc.mode.current --format=csv,noheader) && [ "$(count_lines "$ecc")" = "$EXPECT" ] \
   && ! grep -qv '^Enabled$' <<<"$ecc"; then ok "ECC enabled on every GPU"
else bad "ECC mode: not Enabled on every one of $EXPECT GPUs, or the query failed: $(tr '\n' ' ' <<<"${ecc:-}")"; fi
if unc=$(nvidia-smi --query-gpu=ecc.errors.uncorrected.volatile.total --format=csv,noheader) \
   && [ "$(count_lines "$unc")" = "$EXPECT" ] && ! grep -qv '^0$' <<<"$unc"; then ok "no uncorrected ECC errors"
else bad "uncorrected ECC errors, unreadable counters or a failed query: $(tr '\n' ' ' <<<"${unc:-}")"; fi
if pr=$(nvidia-smi -q -d PAGE_RETIREMENT) && [ "$(grep -c 'Pending Page Blacklist' <<<"$pr")" = "$EXPECT" ] \
   && ! grep -qE 'Pending Page Blacklist *: Yes|Pending *: Yes' <<<"$pr"; then ok "no pending page retirements"
else bad "pending page retirements, or the page-retirement query failed / did not cover $EXPECT GPUs"; fi

step "topology and NVLink"
nvidia-smi topo -m
if nv=$(nvidia-smi nvlink -s); then
  links=$(grep -cE 'Link [0-9]+: [0-9.]+ GB/s' <<<"$nv"); inactive=$(grep -ciE 'inactive' <<<"$nv")
  echo "active NVLinks: $links (expected $LINKS_EXPECTED), inactive: $inactive"
  [ "$links" = "$LINKS_EXPECTED" ] && [ "$inactive" = 0 ] && ok "all $links NVLinks active" || bad "NVLinks: $links active (expected $LINKS_EXPECTED), $inactive inactive"
else bad "nvidia-smi nvlink -s failed"; fi

# power/thermal sampler for the load phases
SAMPLES=$RUN/samples.csv
nvidia-smi --query-gpu=timestamp,index,power.draw,temperature.gpu,clocks.sm,clocks_event_reasons.hw_slowdown,clocks_event_reasons.hw_power_brake_slowdown,clocks_event_reasons.hw_thermal_slowdown \
  --format=csv,noheader -l 5 > "$SAMPLES" 2>"$RUN/samples.err" &
SAMPLER=$!
trap 'kill $SAMPLER 2>/dev/null' EXIT

step "DCGM"
systemctl is-active -q nvidia-dcgm || systemctl start nvidia-dcgm
dcgmi discovery -l | head -20
level=3; [ $QUICK = 1 ] && level=1
dcgmi diag -r $level -j > "$RUN/dcgm.json" 2>&1; drc=$?
cp -p /var/log/nvidia-dcgm/nvvs.log /var/log/nvidia-dcgm/stats_*.json "$RUN/" 2>/dev/null
echo "dcgmi diag -r $level exit status: $drc (raw: $RUN/dcgm.json, nvvs.log, stats_*.json)"
# Each test must report Pass for all $EXPECT GPUs. A skipped test is a missing observation. The
# pcie test's child-process internal error (28 Sep, all three nodes: nvvs.log shows the pcie
# plugin exec'ing plugins/cuda13/BwChecker_13, which is not installed) is an UNRESOLVED
# diagnostic failure, not a pass: the PCIe bandwidth measurement never ran. Question for the
# NVIDIA mentor; raw logs kept.
python3 - "$RUN/dcgm.json" "$EXPECT" "$level" "$drc" > "$RUN/dcgm-verdicts.txt" <<'PY'
import json, sys
path, expect, level, drc = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
try:
    cats = json.load(open(path))["DCGM Diagnostic"]["test_categories"]
    tests = [t for c in cats for t in c["tests"]]
except (ValueError, KeyError, TypeError, OSError) as e:
    print(f"FAIL  dcgmi diag produced no readable result ({type(e).__name__}); rc {drc}"); sys.exit(0)
required = {"software"} | ({"memory", "diagnostic", "pcie", "targeted_stress", "targeted_power"} if level >= 3 else set())
missing = required - {t.get("name") for t in tests}
if missing:
    print(f"FAIL  dcgm tests missing from the result: {sorted(missing)}")
for t in tests:
    name = t.get("name"); status = t.get("test_summary", {}).get("status")
    results = t.get("results", [])
    per = [r.get("status") for r in results]
    warns = [w.get("warning", "") if isinstance(w, dict) else str(w)
             for w in (t.get("test_summary", {}).get("warnings") or [])]
    warns += [w.get("warning", "") if isinstance(w, dict) else str(w) for r in results for w in (r.get("warnings") or [])]
    if status == "Pass" and len(per) == expect and all(v == "Pass" for v in per):
        print(f"PASS  dcgm {name} ({expect} GPUs)")
    elif status == "Skip" or (per and all(v == "Skip" for v in per)):
        print(f"UNRESOLVED  dcgm {name}: skipped, no result (see nvvs.log)")
    elif (status == "Fail" and len(per) == expect and all(v == "Pass" for v in per) and warns
          and all("internal error" in w and "child process" in w for w in warns)):
        print(f"UNRESOLVED  dcgm {name}: diagnostic failure, {len(warns)} internal child-process error(s); "
              f"per-GPU results Pass but the measurement did not run (see nvvs.log)")
    else:
        print(f"FAIL  dcgm {name}: summary {status}, {len(per)}/{expect} per-GPU results {sorted(set(map(str, per)))}; "
              + " | ".join(w[:160] for w in warns[:3]))
PY
prc=$?
cat "$RUN/dcgm-verdicts.txt"
nf=$(grep -c '^FAIL' "$RUN/dcgm-verdicts.txt"); nu=$(grep -c '^UNRESOLVED' "$RUN/dcgm-verdicts.txt")
FAILS=$((FAILS + nf)) UNRESOLVED=$((UNRESOLVED + nu))
[ $prc = 0 ] || bad "DCGM result parser exited $prc"
[ "$(grep -c '^PASS' "$RUN/dcgm-verdicts.txt")" -ge 1 ] || bad "no DCGM test passed"
# dcgmi exits nonzero when any test does not pass; that must already be reflected above.
[ $drc = 0 ] || [ $((nf + nu)) -gt 0 ] || bad "dcgmi diag exited $drc but no test was reported as not passing"

step "CUDA demo suite"
D=$CUDA/extras/demo_suite
if $D/deviceQuery > "$RUN/devicequery.txt" 2>&1 && tail -2 "$RUN/devicequery.txt" | grep -q 'Result = PASS'; then ok "deviceQuery"; else bad "deviceQuery"; fi
if $D/bandwidthTest --device=all --memory=pinned > "$RUN/bandwidth.txt" 2>&1 && grep -q 'Result = PASS' "$RUN/bandwidth.txt"; then
  ok "bandwidthTest (all devices, pinned)"; grep -E 'Bandwidth|^ +[0-9]+ +[0-9.]+' "$RUN/bandwidth.txt" | head -8
else bad "bandwidthTest"; fi
if [ -x $D/busGrind ]; then
  $D/busGrind -a > "$RUN/busgrind.txt" 2>&1 && ok "busGrind (peer-to-peer)" || bad "busGrind"
  grep -iE 'result|bandwidth' "$RUN/busgrind.txt" | tail -4
else bad "busGrind missing from $D"; fi

step "NCCL all-reduce across all $EXPECT GPUs"
if [ -z "$NCCL_TGZ" ]; then bad "NCCL not run (no --nccl-tests archive)"
elif [ "$(sha256sum "$NCCL_TGZ" | cut -d' ' -f1)" != "$NCCL_SHA" ]; then bad "nccl-tests archive hash mismatch"
else
  W=/var/tmp/gpu-qualify-nccl; rm -rf "$W"; mkdir -p "$W"; tar -xzf "$NCCL_TGZ" -C "$W" --strip-components=1
  if make -C "$W" -j"$(nproc)" MPI=0 CUDA_HOME=$CUDA NCCL_HOME=/usr NVCC_GENCODE="-gencode=arch=compute_70,code=sm_70" > "$RUN/nccl-build.log" 2>&1; then
    e=4G; [ $QUICK = 1 ] && e=256M
    O=$RUN/nccl.txt
    "$W/build/all_reduce_perf" -b 8M -e $e -f 2 -g "$EXPECT" > "$O" 2>&1; nrc=$?
    grep -E '^#|^ +[0-9]+' "$O" | tail -8
    ranks=$(grep -cE '^# +Rank +[0-9]+ ' "$O")
    rows=$(grep -cE '^ +[0-9]+ +[0-9]+ +(float|half|double)' "$O")
    # both "#wrong" columns (out-of-place and in-place) must be 0 on every row
    wrong=$(awk '/^ +[0-9]+ +[0-9]+ +(float|half|double)/ && ($9 != 0 || $13 != 0)' "$O" | wc -l)
    errs=$(grep -ciE 'NCCL WARN|failure|error' "$O")
    busbw=$(awk '/Avg bus bandwidth/{print $NF}' "$O")
    echo "exit $nrc; ranks $ranks; rows $rows; rows with wrong results $wrong; warning/error lines $errs; avg busbw ${busbw:-none}"
    if [ $nrc = 0 ] && [ "$ranks" = "$EXPECT" ] && [ "$rows" -ge 5 ] && [ "$wrong" = 0 ] && [ "$errs" = 0 ] \
       && grep -qE '^# Out of bounds values : 0 OK' "$O" && awk -v b="${busbw:-0}" 'BEGIN{exit !(b + 0 > 0)}'; then
      ok "NCCL all_reduce_perf: $EXPECT ranks, results correct, average bus bandwidth $busbw GB/s"
    else bad "NCCL all_reduce_perf (exit $nrc, $ranks ranks, $rows rows, $wrong wrong, $errs warnings/errors; see $O)"; fi
  else bad "nccl-tests build (see $RUN/nccl-build.log)"; fi
fi

if kill -0 $SAMPLER 2>/dev/null; then kill $SAMPLER; else bad "telemetry sampler stopped early (see $RUN/samples.err)"; fi
trap - EXIT; sleep 1
step "power and thermals during the load phases (5 s samples)"
python3 - "$SAMPLES" "$EXPECT" "$RUN/telemetry-verdict" <<'PY'
import collections, sys
path, expect, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
lines = [l.rstrip("\n") for l in open(path) if l.strip()]
by = collections.defaultdict(list); rounds = [0.0]; last = None; bad = []
for l in lines:
    r = l.split(", ")
    try:
        g, w, c, flags = int(r[1]), float(r[2].split()[0]), int(r[3]), [x.strip() for x in r[5:8]]
        if len(flags) != 3 or any(f not in ("Active", "Not Active") for f in flags): raise ValueError
    except (ValueError, IndexError):
        bad.append(l); continue
    # one sample round = one line per GPU in index order (each line has its own timestamp)
    if last is not None and g <= last: rounds.append(0.0)
    last = g; by[g].append((w, c, *flags)); rounds[-1] += w
verdict = []
if bad: verdict.append(f"{len(bad)} unreadable sample line(s), e.g. {bad[0][:120]!r}")
missing = [g for g in range(expect) if len(by.get(g, [])) < 3]
if missing: verdict.append(f"GPUs with fewer than 3 samples: {missing}")
flags = 0
print("gpu  maxW  maxC  samples  hw_slowdown  power_brake  thermal")
for g in sorted(by):
    s = by[g]
    hs, pb, th = (sum(1 for x in s if x[i] == "Active") for i in (2, 3, 4))
    flags += hs + pb + th
    print(f"{g:>3} {max(x[0] for x in s):6.0f} {max(x[1] for x in s):5d} {len(s):8d} {hs:12d} {pb:12d} {th:8d}")
if flags: verdict.append(f"{flags} hardware/power-brake/thermal slowdown sample(s)")
print(f"peak total GPU power (one sample round): {max(rounds):.0f} W")
open(out, "w").write("\n".join(verdict) if verdict else "OK")
PY
tv=$(cat "$RUN/telemetry-verdict" 2>/dev/null || echo "telemetry summary missing")
[ "$tv" = OK ] && ok "telemetry complete for $EXPECT GPUs; no hardware/power-brake/thermal slowdown during load" || bad "telemetry: $tv"

echo
if [ $FAILS = 0 ] && [ $UNRESOLVED = 0 ]; then echo "QUALIFY: PASS ($(hostname -s); raw outputs $RUN)"; exit 0; fi
echo "QUALIFY: FAIL ($FAILS failed, $UNRESOLVED unresolved check(s); $(hostname -s); raw outputs $RUN)"; exit 1
