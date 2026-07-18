# Automatic Empirical Packer-Type Labeling

This subsystem assigns each packed sample an **exact Ugarte et al. Type I–VI label**
("SoK: Deep Packer Inspection") **empirically, from a real dynamic trace** — not
from static heuristics or hypotheses. It runs the packed sample inside an
instrumented Windows guest, records every executed basic block and every memory
store, reconstructs the paper's write→execute **layer-production topology**, and
classifies the Type from that topology. No approximations: a label is emitted only
when the exact channels are present and, per condition, only on **exact consensus**
across the paper's `n = 3 executions × ≥2 distinct payloads`.

- **Backend**: an upstream **QEMU 11 TCG plugin** (`ops/qemu/paper_trace.c`) traces
  the guest; it is gated by a purpose-built certification fixture and refuses to
  emit labels until the exact backend identity passes (`ops/qemu/backend_validation.json`).
- **Classifier**: `empirical_types/paper.py` + `classifier.py` implement Section
  III-E of the paper on the recorded trace.
- **Aggregation**: `empirical_types/finalize.py` turns per-run classifications into
  per-condition empirical labels and writes the manifest.

The **final packer→Type document** is [`EMPIRICAL_TYPE_LABELS.md`](EMPIRICAL_TYPE_LABELS.md),
regenerated from the empirical labels by `ops/qemu/build_label_document.py`.

---

## Architecture / data flow

```
NAS corpus sample (packed .exe)
   │  ops/qemu/stage_sample.sh  (copy pristine base image, place sample.exe +
   │                             guest_launcher.exe, flip PandaPilot ImagePath
   │                             to live sample mode via python-hivex)
   ▼
windows10-qemu-<sample>.qcow2 (disposable staged image, base never mutated)
   │  ops/qemu/run_trace.py  (upstream QEMU + paper_trace.so plugin,
   │                          -accel tcg,thread=single -smp 2 -icount shift=2)
   ▼
trace.jsonl  (exec / write / free / unmap / exception / marker events, one
   │          globally-ordered stream) + meta.json (eligibility, cert identity)
   │  packer-types classify-paper-trace   (empirical_types/paper.py + classifier.py)
   ▼
classification.json  (complexity_type = TYPE_I..VI, layers, tail, linear, ...)
   │  packer-types finalize   (exact consensus across reps × payloads)
   ▼
manifest/empirical_types_*.yaml  +  docs/EMPIRICAL_TYPE_LABELS.md
```

Why the specific QEMU flags:
- `-accel tcg,thread=single -smp 2` — both vCPUs form one ordered event stream, as
  the paper's transition model requires (MTTCG would break the ordering).
- `-icount shift=2` — a fixed instruction-counted virtual clock. Without it, heavy
  instrumentation dilates guest time so the Windows scheduler drowns in timer
  interrupts and starves the freshly-started sample thread (the "boot lottery").
  A fixed low shift makes runs reliable **and** near-deterministic. (Do **not** use
  `shift=auto` — it reconverges to real time and reproduces the starvation.)

---

## Installation guide

Target host: **Linux** (developed on Debian 12 / Xen dom0). The analysis guest is
Windows 10 x64; you do not install anything *into* it — a prepared guest image is
provided as a repo artifact.

### 1. System packages (Debian/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential pkg-config ninja-build meson \
    libglib2.0-dev libpixman-1-dev libslirp-dev flex bison \  # QEMU build deps
    gcc-mingw-w64-x86-64 \                                    # guest fixture/launcher
    qemu-utils ntfs-3g \                                      # qemu-nbd, qemu-img, staging
    python3-hivex                                             # offline SYSTEM-hive edit
sudo modprobe nbd max_part=8                                  # qemu-nbd needs the nbd module
```

`stage_sample.sh` mounts the guest image via `qemu-nbd` + `ntfs-3g` and edits the
registry hive, so it needs **root** (`sudo`).

### 2. Python environment (uv)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh   # if uv is not installed
cd <repo>
uv sync                # installs the package (console script: packer-types)
# tests: PYTHONPATH=$PWD uv run --with pytest pytest -q
```

Key Python deps (in `pyproject.toml`): `pyyaml`, `smbprotocol` (NAS), `pefile`.

### 3. Build the QEMU backend (once)

```bash
ops/qemu/build_qemu.sh          # clones qemu-project, checks out the pinned rev
                                #   eca2c16212ef9dcb0871de39bb9d1c2efebe76be, builds
                                #   qemu-system-x86_64 into empirical_results/qemu_runtime/qemu-build
ops/qemu/build_plugin.sh        # builds ops/qemu/paper_trace.so (needs glib-2.0)
ops/qemu/build_validation_fixture.sh   # builds the cert fixture (mingw-w64)
# guest_launcher: ops/panda/build/guest_launcher.exe (mingw-w64)
```

### 4. Guest + profile artifacts (repo-provided, in `empirical_results/qemu_runtime/`)

- `windows10-qemu-repair.qcow2` — the pristine prepared Windows 10 x64 guest
  (PandaPilot service installed). **Never mutated**; staging copies it.
- `ntdll.dll` — the guest's exact ntdll (identity-checked into every trace).
- `ops/qemu/win10_profile.h` — the exact kernel PDB offset profile the plugin is
  built against (it refuses generic offsets). Regenerate with
  `ops/qemu/build_profile_header.py` if the guest kernel changes.

### 5. NAS credentials (packed-sample source)

Create `.env` (git-ignored) with the SMB corpus credentials:

```
PACKER_NAS_USERNAME=...
PACKER_NAS_PASSWORD=...
# NAS_SERVER / NAS_SHARE default to the corpus host/share
```

---

## Running the pipeline

### A. Certify the backend (required before any label is trusted)

```bash
ops/qemu/cert_retry_loop.sh      # runs the fixture under icount until it certifies;
                                 # writes ops/qemu/backend_validation.json (validated:true)
```
Any change to the plugin/QEMU/ntdll/profile changes the backend identity and
**requires re-certification** — an uncertified trace is classified `UNRESOLVED`.

### B. Label one condition end-to-end (n=3 × 2 payloads → exact consensus)

```bash
# 1) fetch 2 distinct packed payloads for the condition from the NAS, then stage:
sudo ops/qemu/stage_sample.sh <payload1.exe> windows10-qemu-cond1.qcow2 300
sudo ops/qemu/stage_sample.sh <payload2.exe> windows10-qemu-cond2.qcow2 300

# 2) write a condition config (see empirical_results/qemu_runtime/configs/*.json)
#    {condition:{...configuration_id...}, payloads:[[image,sha256,name],...], reps:3, runs_dir:...}
python3 ops/qemu/run_condition_matrix.py <config.json>   # 6 traces + classify -> run dirs

# 3) aggregate into an empirical manifest:
uv run packer-types finalize <runs_dir>/plan.json <runs_dir> \
    --yaml-output manifest/empirical_types_<cond>.yaml
```

`ops/qemu/cert_matrix_finalize.sh` chains cert → matrix → finalize for one condition.

### C. Regenerate the final packer→Type document

```bash
python3 ops/qemu/build_label_document.py    # scans manifest/empirical_types_*.yaml
                                            # -> docs/EMPIRICAL_TYPE_LABELS.md
```

---

## Faithfulness guarantees

- The label uses only the recorded trace's write→execute topology (Section III-E) —
  **no original binary** is consulted (the paper is runtime-only for Type I/II/III/
  V/VI; using ground truth to label would be unfaithful).
- Certification gates every channel; a trace missing a channel is `UNRESOLVED`.
- A trace exhibiting **cross-process** behavior under the single-process
  certification is `UNRESOLVED_UNCERTIFIED_CROSS_PROCESS` (never guessed).
- A condition gets an exact label only on **consensus** across ≥2 distinct payloads
  × ≥3 consistent repetitions; otherwise it stays provisional/hypothesis.
