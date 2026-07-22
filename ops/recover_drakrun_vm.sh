#!/bin/sh
set -u

DRAKRUN=/opt/pydrakvuf/.venv/bin/drakrun
QEMU_PATTERN='^/usr/local/lib/xen/bin/qemu-system-i386 .* -name vm-1( |$)'

timeout 30 "$DRAKRUN" vm-stop --vm-id 1 >/dev/null 2>&1 || true
pkill -TERM -f "$QEMU_PATTERN" >/dev/null 2>&1 || true

attempt=0
while pgrep -f "$QEMU_PATTERN" >/dev/null 2>&1 && [ "$attempt" -lt 5 ]; do
    sleep 1
    attempt=$((attempt + 1))
done

pkill -KILL -f "$QEMU_PATTERN" >/dev/null 2>&1 || true
exit 0
