#!/usr/bin/env python3
"""Diagnostic: verify that a replay reaches a specific virtual address."""

import argparse

from pandare import Panda


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("recording")
    parser.add_argument("address", type=lambda value: int(value, 0))
    args = parser.parse_args()
    panda = Panda(
        arch="x86_64",
        mem="2G",
        os="windows",
        extra_args=["-display", "none", "-net", "none"],
    )
    hits: list[int] = []

    @panda.hook(args.address, kernel=False)
    def address_hook(cpu, tb, hook):
        del tb
        hits.append(int(panda.current_asid(cpu)))
        print(f"HOOK_HIT address=0x{args.address:x} asid=0x{hits[-1]:x}", flush=True)
        hook.enabled = False
        panda.end_analysis()

    panda.run_replay(args.recording)
    print(f"hook_hits={len(hits)}")
    return 0 if hits else 1


if __name__ == "__main__":
    raise SystemExit(main())
