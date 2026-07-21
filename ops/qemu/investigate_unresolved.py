#!/usr/bin/env python3
"""Root-cause every UNRESOLVED condition: is it a SAMPLE defect, a METHODOLOGY /
backend limitation, or an INFRASTRUCTURE failure?

Reads the per-run evidence that survives trace cleanup
(classification.json + meta.json + sample.json under all_runs/<tag>/<run>/) and
assigns each UNRESOLVED condition a root-cause verdict with the numbers behind it.

Verdict taxonomy
----------------
SAMPLE_NOT_PACKED   The payload is not actually packed (pass-through pack, or an
                    unpacked original mixed into the packer dir).  Signature:
                    the run completed cleanly, executed a healthy number of
                    blocks, but every executed block came from a mapped file
                    (mapped_file_exec_events == exec_events) and no written byte
                    was ever executed (layers == 1).  Fix belongs in the corpus,
                    not the classifier.
METHODOLOGY_LIMIT   The sample really did run, but its unpacking is invisible to a
                    write->execute model: section//view-mapped loading, nanomite /
                    debugger-driven patching, or decryption before the traced
                    entry.  Signature: layers == 1 with substantial execution AND
                    (cross-process activity, or heavy mapped-file execution with a
                    large write volume that never becomes code).
INFRASTRUCTURE      The trace never reached a usable end state: host timeout,
                    truncated/lost trace, backend failure, crash.  Signature:
                    host_timed_out, trace_complete false, or TRACE_LOSS/CRASH.
                    Retryable -- not a statement about the packer.
NO_CONSENSUS        Individual runs produced Types but they disagreed across
                    reps/payloads, so no exact consensus could be formed.
UNKNOWN             Evidence is insufficient to classify; needs a manual re-run.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RUNS = REPO / "empirical_results/qemu_runtime/all_runs"
DONE = REPO / "empirical_results/full_matrix"


def _load(p: Path):
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def evidence_for(tag: str) -> list[dict]:
    """Collect the surviving per-run evidence for one condition."""
    out = []
    d = RUNS / tag
    if not d.is_dir():
        return out
    for run in sorted(x for x in d.iterdir() if x.is_dir()):
        c = _load(run / "classification.json")
        m = _load(run / "meta.json")
        s = _load(run / "sample.json")
        if not c and not m:
            continue
        summ = m.get("summary") or {}
        out.append({
            "run": run.name,
            "type": c.get("complexity_type"),
            "layers": c.get("layers"),
            "rule": c.get("rule"),
            "trace_complete": c.get("trace_complete"),
            "cross_process": c.get("cross_process_activity"),
            "termination": c.get("termination"),
            "host_timed_out": m.get("host_timed_out"),
            "paper_termination": m.get("paper_termination_reason"),
            "eligible": m.get("paper_label_eligible"),
            "elapsed": m.get("elapsed_seconds"),
            "exec_events": summ.get("exec_events"),
            "write_events": summ.get("write_events"),
            "mapped_exec": summ.get("mapped_file_exec_events"),
            "writes_wo_phys": summ.get("writes_without_physical"),
            "phys_fail": summ.get("physical_mapping_failures"),
            "packed_sha256": s.get("packed_sha256"),
            "trace_kept": (run / "trace.jsonl").exists(),
        })
    return out


def classify(tag: str, ev: list[dict]) -> dict:
    if not ev:
        return {"verdict": "UNKNOWN", "why": "no surviving per-run evidence",
                "evidence": {}}
    types = Counter(e["type"] for e in ev if e["type"])
    n = len(ev)
    timed_out = sum(1 for e in ev if e.get("host_timed_out"))
    incomplete = sum(1 for e in ev if e.get("trace_complete") is False)
    loss = sum(1 for e in ev if str(e.get("type", "")).endswith(("TRACE_LOSS", "CRASH")))
    no_unpack = sum(1 for e in ev if e.get("type") == "UNRESOLVED_NO_UNPACKING_OBSERVED")
    concrete = {t: c for t, c in types.items() if str(t).startswith("TYPE_")}

    # averages over runs that reported counters
    def avg(key):
        vals = [e[key] for e in ev if isinstance(e.get(key), (int, float))]
        return sum(vals) / len(vals) if vals else 0

    ex, wr, mp = avg("exec_events"), avg("write_events"), avg("mapped_exec")
    mapped_ratio = (mp / ex) if ex else 0
    shas = {e.get("packed_sha256") for e in ev if e.get("packed_sha256")}

    base = {
        "runs": n, "types": dict(types), "avg_exec": int(ex), "avg_writes": int(wr),
        "mapped_exec_ratio": round(mapped_ratio, 3), "timed_out": timed_out,
        "incomplete": incomplete, "distinct_payloads": len(shas),
        "trace_kept": any(e.get("trace_kept") for e in ev),
    }

    # 1) infrastructure first -- a truncated/timed-out trace says nothing about the packer
    if timed_out or incomplete or loss:
        return {"verdict": "INFRASTRUCTURE",
                "why": (f"{timed_out}/{n} runs hit the host timeout, {incomplete} had an "
                        f"incomplete trace, {loss} were TRACE_LOSS/CRASH -- the recording "
                        f"never reached a usable end state (retryable)"),
                "evidence": base}

    # 2) disagreement between otherwise-valid runs
    if len(concrete) > 1:
        return {"verdict": "NO_CONSENSUS",
                "why": (f"runs disagreed ({concrete}); exact consensus requires the same "
                        f"Type across all reps x >=2 payloads"),
                "evidence": base}

    # 3) no unpacking observed -- sample defect vs methodology limit
    if no_unpack:
        cross = any(e.get("cross_process") for e in ev)
        if cross:
            return {"verdict": "METHODOLOGY_LIMIT",
                    "why": ("no write->execute in-process, but the sample did cross-process "
                            "work -- unpacking likely happened in a child/injected process "
                            "outside the single-process certification"),
                    "evidence": base}
        if ex and mapped_ratio > 0.99:
            # every executed block came from a mapped file: the code was never written
            if wr > 100000:
                return {"verdict": "METHODOLOGY_LIMIT",
                        "why": (f"all execution came from mapped sections "
                                f"(mapped/exec={mapped_ratio:.3f}) despite {int(wr)} writes -- "
                                f"consistent with view/section-mapped loading or pre-entry "
                                f"decryption, which a write->execute model cannot observe"),
                        "evidence": base}
            return {"verdict": "SAMPLE_NOT_PACKED",
                    "why": (f"ran cleanly ({int(ex)} blocks) yet every block came from a "
                            f"mapped file (mapped/exec={mapped_ratio:.3f}) and nothing written "
                            f"was executed -- the payload behaves like an unpacked binary "
                            f"(pass-through pack or original mixed into the packer dir)"),
                    "evidence": base}
        return {"verdict": "METHODOLOGY_LIMIT",
                "why": (f"executed {int(ex)} blocks with {int(wr)} writes but produced no "
                        f"write->execute layer -- unpacking mechanism not captured by the "
                        f"layer model"),
                "evidence": base}

    return {"verdict": "UNKNOWN",
            "why": f"unresolved with types {dict(types)}; needs a manual re-run",
            "evidence": base}


def main() -> int:
    rows = []
    for f in sorted(DONE.glob("*.done")):
        tag = f.stem
        label = (_load(f) or {}).get("label", "?")
        if str(label).startswith("TYPE_"):
            continue
        ev = evidence_for(tag)
        v = classify(tag, ev)
        v.update({"tag": tag, "label": label})
        rows.append(v)

    out = REPO / "empirical_results/full_matrix/unresolved_rootcause.json"
    out.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    by = Counter(r["verdict"] for r in rows)
    print(f"[investigate] {len(rows)} UNRESOLVED conditions")
    for k, c in by.most_common():
        print(f"  {k}: {c}")
    print()
    for r in rows:
        print(f"- {r['tag']}  [{r['verdict']}]")
        print(f"    {r['why']}")
        e = r.get("evidence") or {}
        if e:
            print(f"    runs={e.get('runs')} types={e.get('types')} "
                  f"avg_exec={e.get('avg_exec')} avg_writes={e.get('avg_writes')} "
                  f"mapped/exec={e.get('mapped_exec_ratio')} "
                  f"payloads={e.get('distinct_payloads')} trace_kept={e.get('trace_kept')}")
    print(f"\n[investigate] wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
