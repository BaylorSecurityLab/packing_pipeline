#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
runtime="$root/empirical_results/qemu_runtime"
build="$runtime/marker-smoke"
qemu="$runtime/qemu-build/qemu-system-x86_64"
plugin="$build/buffer_smoke.so"
result="$build/buffer_result.json"
qemu_log="$build/buffer_qemu.log"

mkdir -p "$build"
as --32 "$root/ops/qemu/marker_smoke.S" -o "$build/marker_smoke.o"
ld -m elf_i386 -Ttext 0x7c00 --oformat binary \
  "$build/marker_smoke.o" -o "$build/marker_smoke.img"
test "$(stat -c %s "$build/marker_smoke.img")" -eq 512

cc -std=gnu11 -O2 -g -Wall -Wextra -Werror -fPIC -shared \
  $(pkg-config --cflags glib-2.0) \
  -I"$runtime/qemu-build" -I"$runtime/qemu-build/include" \
  -I"$runtime/qemu-src/include/plugins" \
  "$root/ops/qemu/buffer_smoke.c" -o "$plugin" \
  $(pkg-config --libs glib-2.0)

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
  -plugin "$plugin,out=$result" 2>"$qemu_log"
status=$?
set -e
test "$status" -eq 33
! grep -q "invalid use of qemu_plugin_get_hwaddr" "$qemu_log"

python3 - "$result" <<'PY'
import json
import sys

result = json.load(open(sys.argv[1], encoding="utf-8"))
assert result["retained"] == 2, result
assert result["overflows"] == 0, result
assert result["addresses"] == [0x7000, 0x7002], result
assert result["physical_addresses"] == [0x7000, 0x7002], result
assert result["ram_addresses"] == [0x7000, 0x7002], result
assert result["pcs"] == [0x7C04, 0x7C08], result
assert result["mapping_failures"] == 0, result
print("buffer_smoke=ok")
PY
