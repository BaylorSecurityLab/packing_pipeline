#!/usr/bin/env python3
"""Queue retryable UNRESOLVED conditions for another pass.

`investigate_unresolved.py` classifies each unresolved condition.  The
INFRASTRUCTURE ones (trace truncated by the host timeout, crash, backend hiccup)
say nothing about the packer -- they just need another run, typically with a
larger LABEL_HOST_TIMEOUT.  UNKNOWN ones lost their evidence and also need a
fresh run to be diagnosable.

This clears only those conditions' .done markers so the resumable orchestrator
picks them up again; everything already typed is left untouched.

Usage:
    python3 ops/qemu/retry_unresolved.py [--also-unknown] [--dry-run]
    LABEL_HOST_TIMEOUT=3600 LABEL_CONDITIONS=2 LABEL_JOBS=6 \
        python3 ops/qemu/label_all.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DONE = REPO / "empirical_results/full_matrix"
RETRYABLE = {"INFRASTRUCTURE"}


def main() -> int:
    args = sys.argv[1:]
    dry = "--dry-run" in args
    if "--also-unknown" in args:
        RETRYABLE.add("UNKNOWN")

    rc_path = DONE / "unresolved_rootcause.json"
    if not rc_path.exists():
        print("no unresolved_rootcause.json -- run investigate_unresolved.py first")
        return 1
    rows = json.loads(rc_path.read_text())

    queued, skipped = [], []
    for r in rows:
        tag, verdict = r["tag"], r.get("verdict")
        if verdict in RETRYABLE:
            marker = DONE / f"{tag}.done"
            queued.append((tag, verdict))
            if not dry and marker.exists():
                marker.unlink()
        else:
            skipped.append((tag, verdict))

    print(f"[retry] queued {len(queued)} condition(s) for another pass"
          f"{' (dry-run, nothing changed)' if dry else ''}:")
    for tag, v in queued:
        print(f"    {tag}  [{v}]")
    if skipped:
        print(f"[retry] left {len(skipped)} unresolved condition(s) alone "
              f"(not retryable -- a re-run would not change the verdict):")
        for tag, v in skipped:
            print(f"    {tag}  [{v}]")
    if not dry and queued:
        print("\n[retry] now re-run with a larger per-trace budget, e.g.:")
        print("    LABEL_HOST_TIMEOUT=3600 LABEL_CONDITIONS=2 LABEL_JOBS=6 \\")
        print("        setsid .venv/bin/python ops/qemu/label_all.py > "
              "empirical_results/qemu_runtime/label_retry.out 2>&1 &")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
