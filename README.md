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

## 3. Install Go (required for amber v2.0)

amber v2.0 shells out to `go build` to compile its runtime stub. The prebuilt amber.exe predates Go modules (no `go.mod` in its tree), so Go 1.21+ must be told to use the legacy GOPATH build mode.

- **Recommended:** Install Go via Scoop (`scoop install go`) — the runner auto-detects `C:\Users\<you>\scoop\shims\go.exe`.
- **Manual:** Install Go from <https://go.dev/dl/> and ensure `go.exe` is on `PATH`.

The runner also sets `GO111MODULE=off` automatically for `amber_v2.0`, so you don't need to change your global Go config.

## 4. Clone the Repository

Because this repo uses submodules, you must use the `--recurse-submodules` flag to pull the linked projects immediately.
```powershell
git clone --recurse-submodules git@gitlab.ecs.baylor.edu:leal-security-lab/automated-packing/corpus.git
cd corpus
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

## 6. Pack the SimpleDpack shell DLLs (required)

SimpleDpack loads `simpledpackshell.dll` (and the 64-bit variant) from its own directory via `LoadLibrary`. The prebuilt `SimpleDpack.exe` ships without the DLL, so every invocation segfaults on `GetModuleInformation(NULL, ...)`.

Download both DLLs from the upstream release and drop them next to the binary:
```powershell
$dest = "packers/SimpleDpack"
Invoke-WebRequest -OutFile "$dest/simpledpackshell.dll" `
  "https://github.com/YuriSizuku/win-SimpleDpack/releases/download/v0.5.3/simpledpackshell.dll"
Invoke-WebRequest -OutFile "$dest/simpledpackshell64.dll" `
  "https://github.com/YuriSizuku/win-SimpleDpack/releases/download/v0.5.3/simpledpackshell64.dll"
```
Without these the packer exits with Windows error code `0xC0000005` (ACCESS_VIOLATION) on every input.

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

# 🩺 Per-Packer Gotchas

These are real failures I hit and the fixes — keep them in mind when a packer reports `0 packed / N failed` with no obvious error.

### amber v2.0 — needs Go on PATH

- amber v2.0 shells `go build` to compile its runtime stub. Without `go.exe` discoverable the build fails immediately.
- The prebuilt amber.exe is GOPATH-era, so Go 1.21+ (default module mode) rejects it. The runner sets `GO111MODULE=off` automatically.
- amber v2.0 also **modifies the input file in place** (no `*_packed.exe` sidecar like v3.x). The manifest is set to `output_behavior: in_place` — don't "fix" it back to `input_dir_suffix`.

### hyperion (v1.2 and v2.3.1) — must run from its own directory

- hyperion spawns `Fasm\FASM.EXE` with relative paths (`Src\FasmContainer32\main.asm`). If the CWD is anywhere else, it fails with `Could not open output file Src\FasmContainer32\infile.asm`.
- The runner already sets `cwd = os.path.dirname(packer_bin)`, so this works automatically — but don't refactor that path logic without re-testing.

### hxor_packer — needs `unpackerLoadEXE.exe` sibling

- The packer prompts "Press any key" interactively; you must pass `<S> <D>` on the command line.
- It also looks for `unpackerLoadEXE.exe` in the current directory. The runner's CWD = packer dir handles this; verify both files are present in `packers/hxor_packer/`.

### SimpleDpack — needs the shell DLL

- See **Install step 6** above. Without `simpledpackshell.dll` next to `SimpleDpack.exe`, every pack exits with `0xC0000005` (ACCESS_VIOLATION).

### FSG — GUI only, must run on an interactive desktop

- Use `python wrapper/gui_runner.py --packer fsg_v1.0` (or `python wrapper/fsg.py --file-path …`) on a real desktop session — the wrapper drives pyautogui.
- FSG refuses files that have a TLS directory (`.tls` section). The GUI runner auto-detects the TLS error dialog and skips them; the CLI runner cannot help here.

### kkrunchy 0.23a `--new` frontend — broken upstream

- The experimental frontend hangs forever at "preprocessing, filtering & reslicing". This testcase was removed from `manifest/packer_corpus.yaml` — use only `--good` (default) and `--best`.

### PEzor — memory-budget scheduler

- See `memory/pezor-memory-gate.md` for the WSL memory-gate implementation that prevents VM crashes on large inputs.

---

# 👥 Maintainers

**Leal Security Lab** (Baylor University)

**Current Maintainer:** Abanisenioluwa Kolawole Orojo