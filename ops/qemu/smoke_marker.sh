#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
runtime="$root/empirical_results/qemu_runtime"
build="$runtime/marker-smoke"
qemu="$runtime/qemu-build/qemu-system-x86_64"
plugin="$root/ops/qemu/paper_trace.so"
trace="$build/trace.jsonl"

mkdir -p "$build"
as --32 "$root/ops/qemu/marker_smoke.S" -o "$build/marker_smoke.o"
ld -m elf_i386 -Ttext 0x7c00 --oformat binary \
  "$build/marker_smoke.o" -o "$build/marker_smoke.img"
test "$(stat -c %s "$build/marker_smoke.img")" -eq 512

set +e
"$qemu" \
  -machine pc-i440fx-5.2 \
  -accel tcg,thread=single \
  -cpu qemu64 \
  -m 64M \
  -smp 2 \
  -display none \
  -monitor none \
  -serial none \
  -parallel none \
  -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -drive "file=$build/marker_smoke.img,format=raw,if=floppy,readonly=on" \
  -plugin "$plugin,out=$trace"
status=$?
set -e

# isa-debug-exit returns (value << 1) | 1; the guest writes 0x10.
test "$status" -eq 33
python3 - "$trace" <<'PY'
import json
import sys

events = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
markers = [event for event in events if event.get("event") == "marker"]
assert [event["action"] for event in markers] == [1, 2, 3], markers
assert all(event["pid"] == 1234 for event in markers), markers
summary = next(event for event in events if event.get("event") == "summary")
assert summary["root_pid"] == 1234, summary
assert summary["saw_stop"] is True, summary
print("marker_smoke=ok")
PY
