#!/usr/bin/env python3
"""Empirically label EVERY packer family+version in the NAS (one representative
testcase per family_version -- the Type is invariant across a family+version's
testcases).  Resumable; commits+pushes each label.  Sample-fallback: if the chosen
payloads do not yield a consensus Type (a sample that evades/crashes/doesn't
unpack), it retries with DIFFERENT samples before recording an UNRESOLVED reason.

Reads empirical_results/qemu_runtime/worklist.json (built by the enumerator).
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RT = REPO / "empirical_results/qemu_runtime"
SUDO_PW = "resbears"
MAX_SAMPLE_ATTEMPTS = 3        # distinct payload-pairs to try before giving up
REPS = 3


def sh(cmd, **kw):
    return subprocess.run(cmd, cwd=str(REPO), **kw)


def _session():
    import smbclient
    for line in (REPO / ".env").read_text().splitlines():
        if line.startswith("PACKER_NAS_"):
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())
    smbclient.register_session("10.100.99.29",
                               username=os.environ["PACKER_NAS_USERNAME"],
                               password=os.environ["PACKER_NAS_PASSWORD"])
    return smbclient


def candidate_samples(nas_dir: str, testcase: str, limit: int = 8):
    smb = _session()
    base = f"//10.100.99.29/samples/benign_packed/{nas_dir}/{testcase}"
    cand = []
    for e in smb.scandir(base):
        if e.name.lower().endswith(".exe"):
            try:
                cand.append((smb.stat(base + "/" + e.name).st_size, e.name))
            except Exception:
                pass
    cand.sort()  # smallest first (fastest to trace)
    return [(base + "/" + nm, nm) for _, nm in cand[:limit]]


def fetch(remote: str, dest: Path) -> str:
    smb = _session()
    with smb.open_file(remote, mode="rb") as sf:
        data = sf.read()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def stage(sample: Path, image: Path) -> bool:
    p = subprocess.run(["sudo", "-S", "ops/qemu/stage_sample.sh", str(sample),
                        str(image), "300"], cwd=str(REPO), input=SUDO_PW + "\n",
                       text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return p.returncode == 0


def run_pair(tag: str, cond: dict, pair) -> tuple[str, dict]:
    """Run n=REPS x 2 payloads for one pair; return (label, per-run types)."""
    images = []
    for i, (remote, nm) in enumerate(pair, 1):
        sample = RT / f"{tag}_s{i}" / "sample.exe"
        sha = fetch(remote, sample)
        img = RT / f"windows10-qemu-{tag}{i}.qcow2"
        if not stage(sample, img):
            return "STAGE_FAILED", {}
        images.append([f"empirical_results/qemu_runtime/windows10-qemu-{tag}{i}.qcow2",
                       sha, f"{tag}{chr(64+i)}"])
    runs_dir = f"empirical_results/qemu_runtime/all_runs/{tag}"
    cfg = {"condition": cond, "payloads": images, "reps": REPS, "runs_dir": runs_dir}
    cfg_path = RT / "configs" / f"{tag}.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(cfg, indent=2))
    sh(["rm", "-rf", str(REPO / runs_dir)])
    sh(["python3", "ops/qemu/run_condition_matrix.py", str(cfg_path)])
    # collect per-run types
    types = {}
    d = REPO / runs_dir
    for rd in sorted(d.glob("*/")):
        cj = rd / "classification.json"
        if cj.exists():
            try:
                types[rd.name] = json.loads(cj.read_text())["complexity_type"]
            except Exception:
                types[rd.name] = "?"
    # finalize
    plan = REPO / runs_dir / "plan.json"
    if plan.exists():
        pd = json.loads(plan.read_text())
        for c in pd["conditions"]:
            c.setdefault("source", "yaml_test_case")
            c.setdefault("status", "planned")
            c.setdefault("available_samples", 2)
        plan.write_text(json.dumps(pd, indent=2))
        sh(["uv", "run", "packer-types", "finalize", str(plan), str(REPO / runs_dir),
            "--yaml-output", f"manifest/empirical_types_{tag}.yaml",
            "--output", f"empirical_results/full_matrix/{tag}_labels.json"])
        import yaml
        m = yaml.safe_load((REPO / f"manifest/empirical_types_{tag}.yaml").read_text())
        for c in m.get("conditions", []):
            if c.get("label_status") == "empirical_exact_trace_consensus" and c.get("label"):
                return c["label"], types
    return "UNRESOLVED", types


def already_labeled(tag: str) -> bool:
    # A .done marker (written after processing, incl. UNRESOLVED-after-exhaustion)
    # is authoritative.
    if (REPO / f"empirical_results/full_matrix/{tag}.done").exists():
        return True
    f = REPO / f"manifest/empirical_types_{tag}.yaml"
    if not f.exists():
        return False
    import yaml
    m = yaml.safe_load(f.read_text()) or {}
    for c in m.get("conditions", []):
        if c.get("label_status") == "empirical_exact_trace_consensus":
            return True
    return False


def label_condition(w: dict) -> None:
    tag = w["nas_dir"]
    if already_labeled(tag):
        print(f"[skip] {tag} already labeled", flush=True)
        return
    cond = {
        "packer_family": w.get("family") or w["nas_dir"].split("_v")[0],
        "packer_version": w.get("version") or "?",
        "test_case_id": w["testcase"],
        "configuration_id": w.get("cid") or f"{tag}-auto",
        "type_hypothesis": None, "source": "yaml_test_case",
        "status": "planned", "available_samples": 2,
    }
    cands = candidate_samples(w["nas_dir"], w["testcase"], limit=2 * MAX_SAMPLE_ATTEMPTS)
    print(f"[cond] {tag}: {len(cands)} candidate samples", flush=True)
    label, all_types = "UNRESOLVED", {}
    for attempt in range(MAX_SAMPLE_ATTEMPTS):
        pair = cands[2 * attempt: 2 * attempt + 2]
        if len(pair) < 2:
            break
        print(f"[try] {tag} attempt {attempt+1}: {[p[1] for p in pair]}", flush=True)
        label, types = run_pair(tag, cond, pair)
        all_types = types
        print(f"[try] {tag} attempt {attempt+1} -> {label} (runs: {types})", flush=True)
        if label.startswith("TYPE_"):
            break
    # commit
    sh(["python3", "ops/qemu/build_label_document.py"])
    (REPO / f"empirical_results/full_matrix/{tag}.done").write_text(
        json.dumps({"label": label, "runs": all_types}), encoding="utf-8")
    sh(["git", "add", "-f", f"manifest/empirical_types_{tag}.yaml",
        "doc/EMPIRICAL_TYPE_LABELS.md"])
    sh(["git", "add", f"empirical_results/qemu_runtime/configs/{tag}.json"])
    sh(["git", "commit", "-q", "-m",
        f"Empirical label: {tag} -> {label} ({w['testcase']})"])
    sh(["git", "push", "origin", "feature/empirical-type-backend"],
       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[LABEL] {tag} -> {label}", flush=True)


def main() -> int:
    work = json.loads((RT / "worklist.json").read_text())
    # order: non-UPX first (diversity), then UPX versions
    work.sort(key=lambda w: (str(w.get("family", "")).lower() == "upx", w["nas_dir"]))
    print(f"[all] {len(work)} conditions to label", flush=True)
    for i, w in enumerate(work, 1):
        subprocess.run(["pkill", "-f", "qemu-system-x86_64 -name paper"], check=False)
        time.sleep(2)
        print(f"===== [{i}/{len(work)}] {w['nas_dir']} =====", flush=True)
        try:
            label_condition(w)
        except Exception as e:
            print(f"[error] {w['nas_dir']}: {e}", flush=True)
    print("[all] DONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
