# Packer Corpus Orchestrator

**Automated Framework for Generating Packed Executable Datasets**

This repository serves as the "Orchestrator" for the **Leal Security Lab** automated packing research project. It manages the acquisition of benign executable sources, the configuration of packer tools, and the automated generation of packed artifacts for malware analysis and evasion research.

## 📂 Repository Structure

This project uses **Git Submodules** to keep heavy binary data (`inputs`, `tools`, `outputs`) separate from the logic.

```text
packer-corpus/
├── benign_sources/       # [Submodule] Input datasets (Linked to 'inputs' repo)
│   └── manifest/         # JSON tracking files (processed_ids.json, x64.json)
├── packers/              # [Submodule] Packer binaries (Linked to 'tools' repo)
│   └── exe32pack/
├── packed_sources/       # [Submodule] Output artifacts (Linked to 'outputs' repo)
├── manifest/             # Configuration
│   └── packer_corpus.yaml # Main definition file for packers and test cases
├── utils/                # Python Automation Scripts
│   ├── beningn_source_downloader.py
│   ├── packer_runner.py
│   └── update_manifest.py
├── pyproject.toml        # Dependency definitions
└── uv.lock               # Lockfile for reproducible builds
```

# 🚀 Prerequisites & Installation

This framework is designed for Windows environments (required for winget and PE-specific packers).

## 1. Install winget (Windows Package Manager)

Most modern Windows 10/11 builds have this pre-installed.

- **Check if you have it:** Open PowerShell and type `winget`.
- **If missing:** Install the "App Installer" from the Microsoft Store.

## 2. Install uv (Fast Python Package Manager)

We use `uv` for extremely fast dependency management and script execution. Run the following command in PowerShell:
```powershell
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

## 3. Clone the Repository

Because this repo uses submodules, you must use the `--recurse-submodules` flag to pull the linked projects immediately.
```powershell
git clone --recurse-submodules git@gitlab.ecs.baylor.edu:leal-security-lab/automated-packing/corpus.git
cd corpus
```

**Already cloned without submodules?** Run this to fix it:
```powershell
git submodule update --init --recursive
```

## 4. Install Dependencies

Initialize the environment and install dependencies defined in `pyproject.toml`.
```powershell
uv sync
```

---

# 🛠️ Usage Guide

All scripts are located in the `utils/` folder. You should execute them from the project root using `uv run`.

## Phase 1: Acquire Data (Benign Sources)

This script queries the Winget API, downloads distinct executables, extracts them from installers/zips, and categorizes them into `benign_sources/x64` and `benign_sources/x86`.
```powershell
uv run utils/benign_source_downloader.py
```

- **Configuration:** Adjust the `LIMIT` variable inside the script to change how many samples are fetched per run.
- **Manifests:** It automatically tracks downloaded IDs in `benign_sources/manifest/processed_ids.json` to avoid duplicates.

## Phase 2: Run Packing Experiments

This script reads `manifest/packer_corpus.yaml` and executes defined test cases against your benign sources.

### Basic Usage:
```powershell
# Syntax: uv run utils/packer_runner.py <packer_name> [options]

# Example: Run 'exe32pack' test cases
uv run utils/packer_runner.py exe32pack
```

### Advanced Usage (Size Filtering):

Some shareware packers (like evaluation versions) have strict file size limits. You can filter inputs automatically:
```powershell
# Only pack files smaller than 80KB
uv run utils/packer_runner.py exe32pack --max-size-kb 80
```

## Phase 3: Manifest Maintenance

Updates the `last_updated`, `version`, and `maintainer` fields in `packer_corpus.yaml` based on git history.
```powershell
uv run utils/update_manifest.py
```

## Phase 4: Empirical Type I–VI collection

The manifest's complexity labels are hypotheses, not measured truth. DRAKVUF
results remain useful behavioral diagnostics but are not accepted as Type I–VI
evidence. Paper-faithful labels require the two-vCPU upstream-QEMU tracer,
complete ordered basic-block/write/IPC evidence, and a passing eligibility
gate. Backend details and validation status are in
[`ops/qemu/README.md`](ops/qemu/README.md); the collection workflow is in
[`docs/empirical_type_collection.md`](docs/empirical_type_collection.md).

---

# ⚙️ Configuration (packer_corpus.yaml)

The `manifest/packer_corpus.yaml` file is the source of truth for the experiment. It defines:

- **Packer Definitions:** Paths to binaries (in `packers/`), checksums, and metadata.
- **Test Cases:** Specific command-line arguments to run (e.g., "Maximum Compression", "Re-alignment").

### Example Entry:
```yaml
  - id: "EXE32PACK_001_DEFAULT"
    <<: *exe32pack_v142
    command_label: "Default Auto-Compression"
    cli_template: "{bin} /M:0 {in} {out}"
```

---

# ⚠️ Important Notes

## Antivirus Interference:

The `packed_sources/` directory will contain obfuscated binaries that will trigger Windows Defender or other AV solutions.

**Action:** Add a folder exclusion in Windows Security for your entire `packer-corpus` directory.

## Git Submodules:

If you need to update the tools or inputs, go into their respective folders (`packers/` or `benign_sources/`), pull changes, and then commit the new reference in the main repo.

---

# 🏷️ Automatic Empirical Type Labeling (Deep Packer Inspection)

Beyond *generating* the packed corpus, this repository now includes a subsystem
that assigns each packed sample its exact **Ugarte et al. Type I–VI** label
("SoK: Deep Packer Inspection") **empirically, from a real dynamic trace** — not
from static heuristics. A packed sample is executed inside an instrumented
Windows 10 guest under an upstream **QEMU 11 TCG plugin** that records every
executed basic block and memory store; the write→execute **layer-production
topology** is reconstructed and the Type is read off it. A label is emitted only
when a purpose-built certification fixture passes and, per condition, only on
**exact consensus** across `n = 3 executions × ≥2 distinct payloads`.

- **How to install & run it (all prerequisites, step by step):**
  [`docs/AUTOMATIC_LABELING.md`](docs/AUTOMATIC_LABELING.md)
- **The final packer → empirical Type document (generated):**
  [`docs/EMPIRICAL_TYPE_LABELS.md`](docs/EMPIRICAL_TYPE_LABELS.md)

Key components: `ops/qemu/` (QEMU build, `paper_trace.c` plugin, staging,
`run_trace.py`, `run_condition_matrix.py`, `cert_retry_loop.sh`),
`empirical_types/` (the paper's Section III-E classifier + `finalize`), and
`ops/qemu/backend_validation.json` (the certification stamp). Regenerate the
label document with `python3 ops/qemu/build_label_document.py`.

---

# 👥 Maintainers

**Leal Security Lab** (Baylor University)

**Current Maintainer:** Abanisenioluwa Kolawole Orojo
