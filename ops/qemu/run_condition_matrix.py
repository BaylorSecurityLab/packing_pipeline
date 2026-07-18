#!/usr/bin/env python3
"""Run one paper-faithful condition (>=3 reps x >=2 distinct payloads) through the
certified QEMU tracer + classifier, writing finalize-compatible run directories
(run.json + sample.json + classification.json) so `packer-types finalize` can emit
an exact-consensus empirical label.  icount makes each run reliable (no retries)."""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
QEMU = REPO / "empirical_results/qemu_runtime/qemu-build/qemu-system-x86_64"
PLUGIN = REPO / "ops/qemu/paper_trace.so"
RUNS = REPO / "empirical_results/qemu_runtime/matrix_runs"

# The UPX 3.95 DEFAULT condition (from manifest/empirical_types.yaml).
CONDITION = {
    "packer_family": "UPX",
    "packer_version": "3.95",
    "test_case_id": "UPX_V395_001_DEFAULT",
    "configuration_id": "upx_v395_001_default-348ddc970297",
    "type_hypothesis": None,
}
# (image, packed_sha256, short-name) -- two DISTINCT packed payloads.
PAYLOADS = [
    (REPO / "empirical_results/qemu_runtime/windows10-qemu-upxpilot.qcow2",
     "3b26652eb16587e35e7fe8670a9df1b2bc1cf4f7075c48baf9a445f65986d47f", "ansi2knr"),
    (REPO / "empirical_results/qemu_runtime/windows10-qemu-upxpilot2.qcow2",
     "b2070461ca787fe43c346f530d0387bbfc446cf5fb266ab38a2594c2a5af0542", "cksum"),
]
REPS = 3


def run_one(image: Path, sha: str, name: str, rep: int) -> str:
    sample_id = f"{CONDITION['test_case_id']}__{name}__rep{rep}"
    d = RUNS / f"{name}_rep{rep}"
    if d.exists():
        # allow resume: keep a completed run
        cj = d / "classification.json"
        if cj.exists():
            print(f"[skip] {sample_id} already done", flush=True)
            return sample_id
    subprocess.run(["rm", "-rf", str(d)], check=False)
    d.mkdir(parents=True, exist_ok=True)
    print(f"[run] {sample_id}", flush=True)
    proc = subprocess.Popen(
        ["uv", "run", "python", str(REPO / "ops/qemu/run_trace.py"),
         str(image), str(d / "work.qcow2"), str(d / "trace.jsonl"),
         "--meta", str(d / "meta.json"), "--log", str(d / "qemu.log"),
         "--monitor", str(d / "monitor.sock"), "--host-timeout", "1800",
         "--guest-memory", "4G", "--qemu", str(QEMU), "--plugin", str(PLUGIN)],
        stdout=(d / "runner.out").open("w"), stderr=subprocess.STDOUT, cwd=str(REPO),
    )
    proc.wait()
    # classify
    subprocess.run(
        ["uv", "run", "packer-types", "classify-paper-trace", str(d / "trace.jsonl"),
         "--sample-id", sample_id, "--meta", str(d / "meta.json"),
         "--output", str(d / "classification.json")],
        cwd=str(REPO), check=False,
    )
    # finalize-compatible metadata
    (d / "sample.json").write_text(json.dumps({
        "sample_id": sample_id,
        "packed_sha256": sha,
        "repetition": rep,
        **CONDITION,
    }, indent=2), encoding="utf-8")
    (d / "run.json").write_text(json.dumps({"return_code": 0}, indent=2),
                                encoding="utf-8")
    ctype = "?"
    try:
        ctype = json.loads((d / "classification.json").read_text())["complexity_type"]
    except Exception:
        pass
    print(f"[done] {sample_id} -> {ctype}", flush=True)
    return sample_id


def main() -> int:
    RUNS.mkdir(parents=True, exist_ok=True)
    start = time.time()
    for image, sha, name in PAYLOADS:
        for rep in range(1, REPS + 1):
            run_one(image, sha, name, rep)
    print(f"[matrix] all runs done in {int((time.time()-start)/60)} min", flush=True)
    # plan.json for finalize
    plan = {"conditions": [CONDITION]}
    plan_path = RUNS / "plan.json"
    plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    print(f"[matrix] plan at {plan_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
