#!/bin/sh
# Retry the single-process certification.  Good boots (runs 046/048/049/052/054)
# complete every channel in a few minutes; bad boots either never reach
# sample_start or start then crawl mid-run (guest freezes inside
# local_self_modify, ~1 root block/min while system code idle-spins).
#
# CRITICAL: each attempt runs in its OWN process group (setsid) so a fast-fail
# kills run_trace.py AND its qemu child.  Leaking qemus piles up host load and
# starves later boots into a death spiral (observed: 2 orphans -> load 9 -> all
# subsequent boots miss sample_start).  kill_group + a hard qemu sweep between
# attempts guarantee a clean slate.  Stops on the first VALIDATED: true.
set -u
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo"
FB=empirical_results/qemu_runtime/windows10-qemu-fixture.qcow2
QEMU=empirical_results/qemu_runtime/qemu-build/qemu-system-x86_64
PLUGIN=ops/qemu/paper_trace.so

execs() { grep -c '"event":"exec"' "$1" 2>/dev/null | head -1; }
has()   { grep -q "\"event\":\"$2\"" "$1" 2>/dev/null; }
kill_group() {  # kill the runner's whole process group (runner + qemu child)
  kill -TERM "-$1" 2>/dev/null; sleep 4; kill -KILL "-$1" 2>/dev/null; sleep 1
}
sweep() {  # belt-and-suspenders: no qemu/runner may survive between attempts
  ps ax -o pid,command | grep -E 'qemu-system-x86_64 -name paper|run_trace\.py' \
    | grep -v grep | awk '{print $1}' | xargs -r kill -KILL 2>/dev/null
  sleep 2
}

for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  sweep
  D=empirical_results/qemu_runtime/cert_attempt_$attempt
  rm -rf "$D"; mkdir -p "$D"
  echo "=== attempt $attempt: launching (load $(cut -d' ' -f1 /proc/loadavg)) ==="
  # host-idle DISABLED for the fixture: its completion is the guest stop marker
  # (ExitProcess -> launcher action-3), event-driven and clock-immune; the 2-min
  # idle boundary would otherwise race and kill a slow-to-exit good boot.
  setsid uv run python ops/qemu/run_trace.py "$FB" "$D/work.qcow2" "$D/trace.jsonl" \
    --meta "$D/meta.json" --log "$D/qemu.log" --monitor "$D/monitor.sock" \
    --host-timeout 1200 --host-idle-seconds 0 --guest-memory 4G \
    --qemu "$QEMU" --plugin "$PLUGIN" > "$D/runner.out" 2>&1 &
  RP=$!

  started=0
  for i in $(seq 1 20); do
    sleep 30
    kill -0 $RP 2>/dev/null || break
    if has "$D/trace.jsonl" sample_start; then started=1; break; fi
  done
  if [ "$started" != 1 ]; then
    echo "attempt $attempt: no sample_start, killing group"
    kill_group $RP; continue
  fi

  prev=$(execs "$D/trace.jsonl"); stalls=0; done_ok=0
  for i in $(seq 1 24); do
    sleep 45
    if ! kill -0 $RP 2>/dev/null; then done_ok=1; break; fi
    if has "$D/trace.jsonl" free && has "$D/trace.jsonl" unmap \
       && has "$D/trace.jsonl" exception_dispatch; then
      echo "attempt $attempt: all channels present, waiting for exit"
      done_ok=1; break
    fi
    cur=$(execs "$D/trace.jsonl"); grow=$((cur - prev)); prev=$cur
    # A boot that has already recorded real root progress (exec > 500) and then
    # stalls is almost always grinding through the local_self_modify W->X SMC
    # crawl (QEMU precise-SMC 1-insn-TB storm), which recovers and completes if
    # given time.  A boot still at exec ~1 is a hard root stall that never
    # recovers.  Kill the hard stall fast (2 intervals); give a progressing boot
    # much longer (10 intervals ~= 7.5 min) to grind through the W->X crawl.
    if [ "$grow" -lt 40 ]; then
      stalls=$((stalls + 1))
      limit=2; [ "$cur" -gt 500 ] && limit=10
      echo "attempt $attempt: stall $stalls/$limit (grow=$grow exec=$cur)"
      [ "$stalls" -ge "$limit" ] && { echo "attempt $attempt: CRAWLER, killing group"; kill_group $RP; break; }
    else
      stalls=0; echo "attempt $attempt: advancing (grow=$grow exec=$cur)"
    fi
  done
  [ "$done_ok" = 1 ] || continue

  echo "attempt $attempt: waiting for completion..."
  while kill -0 $RP 2>/dev/null; do sleep 15; done

  out=$(uv run python ops/qemu/validate_fixture_trace.py --single-process \
    "$D/trace.jsonl" ops/qemu/backend_validation.json \
    --qemu "$QEMU" --plugin "$PLUGIN" \
    --launcher ops/panda/build/guest_launcher.exe \
    --fixture ops/qemu/build/validation_fixture.exe \
    --ntdll empirical_results/qemu_runtime/ntdll.dll \
    --profile-header ops/qemu/win10_profile.h 2>&1)
  if echo "$out" | grep -q '"validated": true'; then
    echo "===== CERTIFIED on attempt $attempt (dir $D) ====="
    sweep; exit 0
  fi
  echo "attempt $attempt: completed but NOT validated:"
  echo "$out" | python3 -c "import sys,json; d=json.load(sys.stdin); [print('  ERR:',e) for e in d.get('errors',[])]" 2>/dev/null | head
done
sweep
echo "===== all attempts exhausted without certification ====="
exit 1
