#!/usr/bin/env python3
"""Run one paper-faithful condition (>=3 reps x >=2 distinct payloads) through the
certified QEMU tracer + classifier, writing finalize-compatible run directories
(run.json + sample.json + classification.json) so `packer-types finalize` can emit
an exact-consensus empirical label.  icount makes each run reliable (no retries)."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
QEMU = REPO / "empirical_results/qemu_runtime/qemu-build/qemu-system-x86_64"
PLUGIN = REPO / "ops/qemu/paper_trace.so"

# Default: UPX 3.95 DEFAULT.  Override via a --config JSON with keys
# {condition:{...}, payloads:[[image, packed_sha256, name], ...], reps, runs_dir}.
_DEFAULT = {
    "condition": {
        "packer_family": "UPX", "packer_version": "3.95",
        "test_case_id": "UPX_V395_001_DEFAULT",
        "configuration_id": "upx_v395_001_default-348ddc970297",
        "type_hypothesis": None,
    },
    "payloads": [
        ["empirical_results/qemu_runtime/windows10-qemu-upxpilot.qcow2",
         "3b26652eb16587e35e7fe8670a9df1b2bc1cf4f7075c48baf9a445f65986d47f", "ansi2knr"],
        ["empirical_results/qemu_runtime/windows10-qemu-upxpilot2.qcow2",
         "b2070461ca787fe43c346f530d0387bbfc446cf5fb266ab38a2594c2a5af0542", "cksum"],
    ],
    "reps": 3,
    "runs_dir": "empirical_results/qemu_runtime/matrix_runs",
}

_cfg = _DEFAULT
if len(sys.argv) > 1:
    _cfg = json.loads(Path(sys.argv[1]).read_text())
CONDITION = _cfg["condition"]
PAYLOADS = [(REPO / p[0], p[1], p[2]) for p in _cfg["payloads"]]
REPS = int(_cfg.get("reps", 3))
RUNS = REPO / _cfg.get("runs_dir", "empirical_results/qemu_runtime/matrix_runs")
# Parallelism: the REPS x len(PAYLOADS) runs are independent -- each has its own
# run dir, its own qcow2 overlay (base is read-only backing), and a unique monitor
# socket (hashed on sample_id), so they run concurrently safely.  Sized by the
# LABEL_JOBS env var (or cfg "jobs"); default 1 keeps the old sequential behavior.
JOBS = max(1, int(_cfg.get("jobs") or os.environ.get("LABEL_JOBS", "1")))
# Per-trace host timeout.  1200s suits compressive packers; protectors emit multi-GB
# traces and get truncated (TRACE_LOSS) at that cap, so the retry pass raises it via
# LABEL_HOST_TIMEOUT rather than mislabeling a slow packer as unresolvable.
HOST_TIMEOUT = str(int(_cfg.get("host_timeout") or
                       os.environ.get("LABEL_HOST_TIMEOUT", "1200")))
# Concurrent classifications are capped independently of concurrent traces: the
# classifier is the memory hog (~10GB per multi-GB trace), tracing is not.
CLASSIFY_SEM = threading.Semaphore(
    max(1, int(os.environ.get("LABEL_CLASSIFY_JOBS", "4"))))


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
    # AF_UNIX socket paths must be < 108 bytes.  The deep all_runs/<tag>/<name>_repN
    # run dir overflows that, so qemu refuses to start.  Put the ephemeral monitor
    # socket under a short /tmp path (unique per run) instead of inside the run dir.
    mon = Path("/tmp/qm") / (hashlib.md5(f"{sample_id}".encode()).hexdigest()[:12] + ".sock")
    mon.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["rm", "-f", str(mon)], check=False)
    proc = subprocess.Popen(
        ["uv", "run", "python", str(REPO / "ops/qemu/run_trace.py"),
         str(image), str(d / "work.qcow2"), str(d / "trace.jsonl"),
         "--meta", str(d / "meta.json"), "--log", str(d / "qemu.log"),
         "--monitor", str(mon), "--host-timeout", HOST_TIMEOUT,
         "--guest-memory", "4G", "--qemu", str(QEMU), "--plugin", str(PLUGIN)],
        stdout=(d / "runner.out").open("w"), stderr=subprocess.STDOUT, cwd=str(REPO),
    )
    proc.wait()
    # Classify under a SEPARATE concurrency cap.  Tracing is cheap on RAM (~3.6GB per
    # qemu) but classification loads the whole trace analysis (~10GB on a multi-GB
    # protector trace), so tying the two together forced the trace concurrency down to
    # whatever the classifier could afford and left most of the CPU idle.  Gating only
    # the classify step lets many more traces run in parallel with bounded peak memory.
    with CLASSIFY_SEM:
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
    tasks = [(image, sha, name, rep)
             for image, sha, name in PAYLOADS
             for rep in range(1, REPS + 1)]
    if JOBS <= 1:
        for t in tasks:
            run_one(*t)
    else:
        print(f"[matrix] running {len(tasks)} traces with {JOBS} parallel workers",
              flush=True)
        with ThreadPoolExecutor(max_workers=JOBS) as ex:
            futs = {ex.submit(run_one, *t): t for t in tasks}
            for f in as_completed(futs):
                try:
                    f.result()
                except Exception as e:            # a dead run must not sink the batch
                    print(f"[run-error] {futs[f][2]} rep{futs[f][3]}: {e}", flush=True)
    print(f"[matrix] all runs done in {int((time.time()-start)/60)} min", flush=True)
    # plan.json for finalize
    plan = {"conditions": [CONDITION]}
    plan_path = RUNS / "plan.json"
    plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    print(f"[matrix] plan at {plan_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
