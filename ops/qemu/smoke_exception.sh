#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
runtime="$root/empirical_results/qemu_runtime"
build="$runtime/exception-smoke"
qemu="$runtime/qemu-build/qemu-system-x86_64"
plugin="$build/exception_smoke.so"
result="$build/exception_result.json"

mkdir -p "$build"
as --32 "$root/ops/qemu/exception_smoke.S" -o "$build/exception_smoke.o"
ld -m elf_i386 -Ttext 0x7c00 --oformat binary \
  "$build/exception_smoke.o" -o "$build/exception_smoke.img"
test "$(stat -c %s "$build/exception_smoke.img")" -eq 512

cc -std=gnu11 -O2 -g -Wall -Wextra -Werror -fPIC -shared \
  $(pkg-config --cflags glib-2.0) \
  -I"$runtime/qemu-build" -I"$runtime/qemu-build/include" \
  -I"$runtime/qemu-src/include/plugins" \
  "$root/ops/qemu/exception_smoke.c" -o "$plugin" \
  $(pkg-config --libs glib-2.0)

set +e
timeout --signal=INT 5s "$qemu" \
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
  -boot a \
  -drive "file=$build/exception_smoke.img,format=raw,if=floppy,readonly=on" \
  -plugin "$plugin,out=$result"
status=$?
set -e
test "$status" -eq 124

python3 - "$result" <<'PY'
import json
import sys

result = json.load(open(sys.argv[1], encoding="utf-8"))
assert result["count"] >= 1, result
assert result["exception_index"] == 6, result
assert result["from_pc"] == 0x7C01, result
print("exception_smoke=ok")
PY
