#!/usr/bin/env python3
"""Set the PandaPilot service ImagePath in an offline Windows SYSTEM hive.

Switches the analysis VM between the certification fixture and a real packed
sample without touching anything else.  REG_EXPAND_SZ (type 2), UTF-16LE with a
NUL terminator, exactly as the guest expects.  Idempotent; prints before/after.
"""
from __future__ import annotations

import argparse
import struct
import sys

import hivex


PILOT = 'ControlSet001', 'Services', 'PandaPilot'


def find_node(h: "hivex.Hivex") -> int:
    node = h.root()
    for part in PILOT:
        node = h.node_get_child(node, part)
        if not node:
            sys.exit(f"missing hive path component: {part}")
    return node


def read_imagepath(h: "hivex.Hivex", node: int) -> str | None:
    for v in h.node_values(node):
        if h.value_key(v).lower() == "imagepath":
            t, data = h.value_value(v)
            return data.decode("utf-16-le").rstrip("\x00")
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("hive")
    ap.add_argument("--launcher", default=r"C:\Panda\guest_launcher.exe")
    ap.add_argument("--image", required=True, help=r"e.g. C:\Panda\sample.exe")
    ap.add_argument("--timeout", type=int, required=True)
    ap.add_argument("--status", default=r"C:\Panda\status.txt")
    ap.add_argument("--record", default="-", help='record dir, or "-" for live mode')
    args = ap.parse_args()

    image = f'"{args.launcher}" --service {args.image} {args.timeout} {args.record} {args.status}'
    h = hivex.Hivex(args.hive, write=True)
    node = find_node(h)
    print("before ImagePath:", read_imagepath(h, node))
    h.node_set_value(node, {
        "key": "ImagePath",
        "t": 2,  # REG_EXPAND_SZ
        "value": image.encode("utf-16-le") + b"\x00\x00",
    })
    # Ensure the service still auto-starts.
    h.node_set_value(node, {"key": "Start", "t": 4, "value": struct.pack("<I", 2)})
    h.commit(None)
    # Re-open read-only to confirm the write landed.
    h2 = hivex.Hivex(args.hive)
    got = read_imagepath(h2, find_node(h2))
    print("after  ImagePath:", got)
    if got != image:
        sys.exit("ImagePath write did not persist")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
