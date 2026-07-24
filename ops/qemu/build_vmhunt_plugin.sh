#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build=${QEMU_BUILD:-"$repo/empirical_results/qemu_runtime/qemu-build"}

cc -std=gnu11 -O2 -g -Wall -Wextra -Werror -fPIC -shared \
    $(pkg-config --cflags glib-2.0) \
    $(pkg-config --cflags capstone) \
    -I"$build" -I"$build/include" \
    -I"$repo/empirical_results/qemu_runtime/qemu-src/include/plugins" \
    -I"$repo/ops/qemu" \
    "$repo/ops/qemu/vmhunt_trace.c" \
    -o "$repo/ops/qemu/vmhunt_trace.so" \
    $(pkg-config --libs glib-2.0) \
    $(pkg-config --libs capstone)
