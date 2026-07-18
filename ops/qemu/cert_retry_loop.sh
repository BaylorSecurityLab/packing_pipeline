#!/bin/sh
# Retry the single-process certification, fast-failing "slow boots" (the guest
# occasionally crawls at ~1% speed after sample_start) and letting a good boot
# run to completion + validate.  Stops on the first VALIDATED: true.
set -u
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo"
FB=empirical_results/qemu_runtime/windows10-qemu-fixture.qcow2
QEMU=empirical_results/qemu_runtime/qemu-build/qemu-system-x86_64
PLUGIN=ops/qemu/paper_trace.so

for attempt in 1 2 3 4 5 6 7 8 9 10; do
  D=empirical_results/qemu_runtime/cert_attempt_$attempt
  rm -rf "$D"; mkdir -p "$D"
  echo "=== attempt $attempt: launching ==="
  uv run python ops/qemu/run_trace.py "$FB" "$D/work.qcow2" "$D/trace.jsonl" \
    --meta "$D/meta.json" --log "$D/qemu.log" --monitor "$D/monitor.sock" \
    --host-timeout 1800 --guest-memory 4G --qemu "$QEMU" --plugin "$PLUGIN" \
    > "$D/runner.out" 2>&1 &
  RP=$!

  # wait for sample_start (max ~9 min of boot)
  started=0
  for i in $(seq 1 18); do
    sleep 30
    kill -0 $RP 2>/dev/null || break
    if grep -q '"event":"sample_start"' "$D/trace.jsonl" 2>/dev/null; then started=1; break; fi
  done
  if [ "$started" != 1 ]; then
    echo "attempt $attempt: no sample_start (bad boot), killing"
    kill -TERM $RP 2>/dev/null; sleep 5
    pgrep -f "fixture_validation\|cert_attempt_$attempt" >/dev/null 2>&1
    continue
  fi

  # measure exec growth over ~3 min to distinguish a good boot from a ~1% crawl
  e1=$(grep -c '"event":"exec"' "$D/trace.jsonl" 2>/dev/null || echo 0)
  sleep 180
  e2=$(grep -c '"event":"exec"' "$D/trace.jsonl" 2>/dev/null || echo 0)
  growth=$((e2 - e1))
  echo "attempt $attempt: exec growth over 3min = $growth"
  if [ "$growth" -lt 300 ]; then
    echo "attempt $attempt: SLOW/STALLED boot ($growth), killing to retry"
    kill -TERM $RP 2>/dev/null; sleep 5
    continue
  fi

  echo "attempt $attempt: GOOD boot, waiting for completion..."
  while kill -0 $RP 2>/dev/null; do sleep 20; done

  out=$(uv run python ops/qemu/validate_fixture_trace.py --single-process \
    "$D/trace.jsonl" ops/qemu/backend_validation.json \
    --qemu "$QEMU" --plugin "$PLUGIN" \
    --launcher ops/panda/build/guest_launcher.exe \
    --fixture ops/qemu/build/validation_fixture.exe \
    --ntdll empirical_results/qemu_runtime/ntdll.dll \
    --profile-header ops/qemu/win10_profile.h 2>&1)
  if echo "$out" | grep -q '"validated": true'; then
    echo "===== CERTIFIED on attempt $attempt (dir $D) ====="
    echo "$out" | grep -E '"validated"|"certification_mode"'
    exit 0
  fi
  echo "attempt $attempt: good boot but NOT validated:"
  echo "$out" | python3 -c "import sys,json; d=json.load(sys.stdin); [print('  ERR:',e) for e in d.get('errors',[])]" 2>/dev/null | head
done
echo "===== all attempts exhausted without certification ====="
exit 1
