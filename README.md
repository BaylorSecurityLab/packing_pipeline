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
├── manifest/             # Configuration
│   └── packer_corpus.yaml # Main definition file for packers and test cases
├── utils/                # Python Automation Scripts
│   ├── beningn_source_downloader.py
│   ├── packer_runner.py
│   └── update_manifest.py
├── pyproject.toml        # Dependency definitions
└── uv.lock               # Lockfile for reproducible builds
```

Note: `packed_sources/` (the generated output artifacts) is **not committed to this repo** — it's produced by GitHub Actions runs and published to a separate `outputs` repo.

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

## 3. Install Go (required for amber v2.0)

amber v2.0 shells out to `go build` to compile its runtime stub. The prebuilt amber.exe predates Go modules (no `go.mod` in its tree), so Go 1.21+ must be told to use the legacy GOPATH build mode.

- **Recommended:** Install Go via Scoop (`scoop install go`) — the runner auto-detects `C:\Users\<you>\scoop\shims\go.exe`.
- **Manual:** Install Go from <https://go.dev/dl/> and ensure `go.exe` is on `PATH`.

The runner also sets `GO111MODULE=off` automatically for `amber_v2.0`, so you don't need to change your global Go config.

## 4. Clone the Repository

Because this repo uses submodules, you must use the `--recurse-submodules` flag to pull the linked projects immediately.
```powershell
git clone --recurse-submodules https://github.com/BaylorSecurityLab/packing_pipeline.git
cd packing_pipeline
```

**Already cloned without submodules?** Run this to fix it:
```powershell
git submodule update --init --recursive
```

## 5. Install Dependencies

Initialize the environment and install dependencies defined in `pyproject.toml`.
```powershell
uv sync
```

## 6. Install WSL2 (required for PEzor)

PEzor shells into WSL2 to compile its C++ stub. Other packers are pure Windows binaries and don't need WSL.

```powershell
wsl --install
# Reboot if prompted, then set the default distro:
wsl --set-default-version 2
```

Inside WSL, install the build toolchain PEzor needs (clang, make, git):
```bash
wsl -d Ubuntu-26.04 -u root -- bash -c 'apt-get update && apt-get install -y build-essential clang git'
```

Verify with `wsl --status` — you should see `Default Version: 2`.

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

### PEzor WSL worker count:

PEzor shells into WSL2 and compiles C++ per job. By default it runs **4 concurrent `wsl.exe` invocations**; bump it with `--wsl-workers N` (the runner caps N at the per-packer ceiling of 8 and logs the effective value at start-up):
```powershell
# Default 4 — fine for most boxes
uv run utils/packer_runner.py pezor

# Custom worker count (capped at 8 by the runner's per-packer ceiling)
uv run utils/packer_runner.py pezor --wsl-workers 6
```
The memory-budget scheduler (see `memory/pezor-memory-gate.md`) is the real throttle for PEzor — the worker count is just an upper bound on simultaneous `wsl.exe` launches. If you raise `--wsl-workers` and the WSL VM OOMs, lower it.

## Phase 3: Manifest Maintenance

Updates the `last_updated`, `version`, and `maintainer` fields in `packer_corpus.yaml` based on git history.
```powershell
uv run utils/update_manifest.py
```

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

# 👥 Maintainers

**Leal Security Lab** (Baylor University)

**Current Maintainer:** Abanisenioluwa Kolawole Orojo