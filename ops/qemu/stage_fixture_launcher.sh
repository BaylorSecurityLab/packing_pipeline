#!/bin/sh
# Stage the validation launcher + idle override into a COPY of the Windows base
# image, so the pristine base is never mutated.  Run as root (needs qemu-nbd +
# mount).  Defensive: refuses a hibernated/dirty NTFS, verifies SHA-256 in the
# mounted image, and always disconnects NBD.
#
#   sudo ops/qemu/stage_fixture_launcher.sh
#
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
runtime="$repo/empirical_results/qemu_runtime"
base="$runtime/windows10-qemu-repair.qcow2"
fixture_base="$runtime/windows10-qemu-fixture.qcow2"
launcher="$repo/ops/panda/build/guest_launcher.exe"
idle_src="$repo/ops/qemu/fixture_idle_ms.txt"
nbd=/dev/nbd0
mnt=$(mktemp -d)

if [ "$(id -u)" -ne 0 ]; then echo "must run as root" >&2; exit 1; fi
for f in "$base" "$launcher" "$idle_src"; do
    [ -f "$f" ] || { echo "missing: $f" >&2; exit 1; }
done

cleanup() {
    mountpoint -q "$mnt" && umount "$mnt" || true
    qemu-nbd --disconnect "$nbd" >/dev/null 2>&1 || true
    rmdir "$mnt" 2>/dev/null || true
}
trap cleanup EXIT

echo "== base integrity =="
qemu-img check "$base"

echo "== make working copy (original stays pristine) =="
cp --reflink=auto "$base" "$fixture_base"
qemu-img check "$fixture_base"

echo "== connect $fixture_base via $nbd =="
qemu-nbd --disconnect "$nbd" >/dev/null 2>&1 || true
qemu-nbd --connect="$nbd" "$fixture_base"
sleep 1
partprobe "$nbd" 2>/dev/null || true
sleep 1

# Find the NTFS partition that contains the Panda directory.
target=""
for part in "$nbd"p1 "$nbd"p2 "$nbd"p3 "$nbd"p4 "$nbd"; do
    [ -b "$part" ] || continue
    umount "$mnt" 2>/dev/null || true
    if mount -t ntfs-3g -o ro "$part" "$mnt" 2>/dev/null; then
        if [ -d "$mnt/Panda" ] || [ -d "$mnt/Windows" ]; then
            target="$part"; umount "$mnt"; break
        fi
        umount "$mnt"
    fi
done
[ -n "$target" ] || { echo "could not locate Windows/Panda partition" >&2; exit 1; }
echo "Windows partition: $target"

echo "== refuse hibernated/dirty NTFS (paper-safe: no force/ntfsfix) =="
mount -t ntfs-3g -o rw "$target" "$mnt"

if [ ! -d "$mnt/Panda" ]; then
    echo "C:\\Panda not found on $target" >&2; exit 1
fi

echo "== stage launcher + idle override =="
[ -f "$mnt/Panda/guest_launcher.exe" ] && \
    cp -f "$mnt/Panda/guest_launcher.exe" "$mnt/Panda/guest_launcher.exe.bak"
cp -f "$launcher" "$mnt/Panda/guest_launcher.exe"
cp -f "$idle_src" "$mnt/Panda/idle_ms.txt"
sync

echo "== verify SHA-256 in the mounted image =="
want_launcher=$(sha256sum "$launcher" | awk '{print $1}')
got_launcher=$(sha256sum "$mnt/Panda/guest_launcher.exe" | awk '{print $1}')
echo "launcher want=$want_launcher"
echo "launcher got =$got_launcher"
[ "$want_launcher" = "$got_launcher" ] || { echo "launcher hash MISMATCH" >&2; exit 1; }
echo "idle_ms.txt = $(cat "$mnt/Panda/idle_ms.txt")"

umount "$mnt"
qemu-nbd --disconnect "$nbd"
trap - EXIT
rmdir "$mnt" 2>/dev/null || true

echo "== final integrity =="
qemu-img check "$fixture_base"
echo "OK: staged into $fixture_base (original base untouched)"
