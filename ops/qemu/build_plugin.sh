#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build=${QEMU_BUILD:-"$repo/empirical_results/qemu_runtime/qemu-build"}
profile=${KERNEL_PROFILE:-/var/lib/drakrun/profiles/kernel.json}

python3 "$repo/ops/qemu/build_profile_header.py" \
    "$profile" "$repo/ops/qemu/win10_profile.h"
cc -std=gnu11 -O2 -g -Wall -Wextra -Werror -fPIC -shared \
    $(pkg-config --cflags glib-2.0) \
    -I"$build" -I"$build/include" \
    -I"$repo/empirical_results/qemu_runtime/qemu-src/include/plugins" \
    -I"$repo/ops/qemu" \
    "$repo/ops/qemu/paper_trace.c" \
    -o "$repo/ops/qemu/paper_trace.so" \
    $(pkg-config --libs glib-2.0)
