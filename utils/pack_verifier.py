"""
Pack Verifier - Multi-tool packing detection for packed samples.

Uses multiple detection engines in an "any positive = packed" strategy:
  1. DIE (Detect It Easy) - Signature-based packer detection
  2. Capa - Behavioral capability analysis
  3. Manalyze - PE analysis with packer plugin
  4. YARA - Rule-based signature matching (packer rules)
  5. pefile entropy - Section entropy heuristic + suspicious section names

Outputs a CSV with per-sample rows labelled with the actual packer name
(e.g. "upx_5.1.0"), not just a packed/not-packed flag.

Capa is slow: it runs in a separate limited pool so fast detectors cycle
through files without waiting on capa.

Usage:
    python pack_verifier.py <packer_dir>                        # verify one packer's output
    python pack_verifier.py all                                  # verify everything in packed_sources
    python pack_verifier.py all --csv results.csv               # save labelled CSV
    python pack_verifier.py all --workers 8 --capa-workers 2   # parallel fast + limited capa
    python pack_verifier.py all --dry-run                        # report only, no deletes
    python pack_verifier.py all --report out.json               # JSON report (legacy)
"""

import argparse
import csv
import json
import math
import os
import re
import subprocess
import sys
import threading
import concurrent.futures
from multiprocessing import cpu_count
from tqdm import tqdm

# Optional imports — gracefully degrade if not installed
try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# --- CONFIGURATION ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
PACKED_OUTPUT_DIR = os.path.join(PROJECT_ROOT, "packed_sources")
DETECTORS_DIR = os.path.join(PROJECT_ROOT, "detectors")
YAML_CONFIG_FILE = os.path.join(PROJECT_ROOT, "manifest", "packer_corpus.yaml")

DIE_BIN = os.path.join(DETECTORS_DIR, "die_win64_portable_3.10_x64", "diec.exe")
CAPA_BIN = os.path.join(DETECTORS_DIR, "capa-v9.3.1-windows", "capa.exe")
MANALYZE_BIN = os.path.join(DETECTORS_DIR, "manalyze", "manalyze.exe")
YARA_RULES_DIR = os.path.join(
    DETECTORS_DIR, "die_win64_portable_3.10_x64", "yara_rules"
)

ENTROPY_THRESHOLD = 6.85

SUSPICIOUS_SECTIONS = {
    "upx0", "upx1", "upx2", "upx!",
    ".aspack", ".adata",
    ".themida", ".winlice",
    ".vmprotect", ".vmp0", ".vmp1", ".vmp2",
    ".mpress1", ".mpress2",
    ".petite",
    ".spack", ".svkp",
    ".shrink",
    ".enigma1", ".enigma2",
    ".perplex",
    ".nsp0", ".nsp1", ".nsp2",
    ".packed", ".pec1", ".pec2",
    ".rlpack",
    ".yp", ".y0da",
    ".bero",
    ".kkrunchy",
    "pec2", "pecloak",
}

ENTROPY_DEPENDENT_SECTIONS = {".rsrc", ".text", ".rdata"}


# ============================================================
# DETECTOR 1: DIE (Detect It Easy)
# ============================================================
def detect_die(filepath):
    """Run diec.exe and check for packer/protector detections."""
    if not os.path.exists(DIE_BIN):
        return None, "DIE binary not found"

    try:
        result = subprocess.run(
            [DIE_BIN, "--json", "--heuristicscan", "--deepscan", filepath],
            capture_output=True,
            text=True,
            timeout=60,
            encoding="utf-8",
            errors="replace",
        )

        if result.returncode != 0 and not result.stdout.strip():
            return False, f"DIE exited with code {result.returncode}"

        output = result.stdout.strip()
        if not output:
            return False, "No output"

        json_start = output.find("{")
        if json_start == -1:
            return False, "No JSON in output"
        output = output[json_start:]

        data = json.loads(output)

        packer_types = {
            "packer", "protector", "cryptor", "scrambler",
            "(heur)packer", "(heur)protector", "(heur)cryptor",
        }
        detections = []
        for detect_block in data.get("detects", []):
            for value in detect_block.get("values", []):
                det_type = value.get("type", "").lower()
                det_name = value.get("name", "")
                if det_type in packer_types:
                    detections.append(f"{det_type}:{det_name}")

        if detections:
            return True, f"Detected: {', '.join(detections)}"
        return False, "No packer signatures found"

    except subprocess.TimeoutExpired:
        return None, "Timeout"
    except json.JSONDecodeError as e:
        return None, f"JSON parse error: {e}"
    except Exception as e:
        return None, f"Error: {e}"


# ============================================================
# DETECTOR 2: Capa
# ============================================================
_CAPA_TIMEOUT = 45   # seconds — lower than default; state lets us skip on resume

def detect_capa(filepath):
    """
    Run capa.exe and check for packing-related capabilities.

    Uses Popen + communicate(timeout) + explicit kill so orphaned capa child
    processes are reliably terminated on Windows (subprocess.run timeout is
    not always sufficient when capa spawns workers).

    --format pe  tells capa to skip format-detection overhead and go straight
    to PE analysis, which is noticeably faster on most samples.
    """
    if not os.path.exists(CAPA_BIN):
        return None, "Capa binary not found"

    cmd = [CAPA_BIN, "--json",
           "--backend", "pefile",
           "--format",  "pe",
           "--os",      "windows",
           filepath]
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        try:
            stdout, _ = proc.communicate(timeout=_CAPA_TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()   # drain pipes so the process fully exits
            return None, f"Timeout (>{_CAPA_TIMEOUT}s)"

        output = stdout.strip()
        if not output:
            return False, f"No output (exit code {proc.returncode})"

        data = json.loads(output)

        packing_keywords = [
            "packed with", "packed binary", "packer",
            "obfuscated", "anti-analysis", "anti-disassembly",
            "upx", "themida", "vmprotect", "aspack", "mpress",
            "petite", "pecompact", "rlpack", "fsg",
        ]

        detections = []
        for rule_name in data.get("rules", {}):
            if any(kw in rule_name.lower() for kw in packing_keywords):
                detections.append(rule_name)

        if detections:
            return True, f"Capabilities: {', '.join(detections[:5])}"
        return False, "No packing capabilities detected"

    except json.JSONDecodeError:
        return False, "Non-JSON output (likely unsupported file)"
    except Exception as e:
        return None, f"Error: {e}"
    finally:
        if proc and proc.poll() is None:
            proc.kill()


# ============================================================
# DETECTOR 3: Manalyze
# ============================================================
def detect_manalyze(filepath):
    """Run manalyze.exe with packer plugin and check results."""
    if not os.path.exists(MANALYZE_BIN):
        return None, "Manalyze binary not found"

    try:
        result = subprocess.run(
            [MANALYZE_BIN, "--output=json", "--plugins=packer", filepath],
            capture_output=True,
            text=True,
            timeout=60,
            encoding="utf-8",
            errors="replace",
            cwd=os.path.dirname(MANALYZE_BIN),
        )

        output = result.stdout.strip()
        if not output:
            return False, f"No output (exit code {result.returncode})"

        data = json.loads(output)

        detections = []

        if isinstance(data, dict):
            entries = []
            for key, value in data.items():
                if isinstance(value, dict) and ("Plugins" in value or "Summary" in value):
                    entries.append(value)
            if not entries:
                entries = [data]
        elif isinstance(data, list):
            entries = data
        else:
            entries = []

        for file_entry in entries:
            plugins = file_entry.get("Plugins", file_entry.get("plugins", {}))

            packer_keys = ["Packer Detection", "packer", "Packer"]
            packer_info = None
            for pk in packer_keys:
                if pk in plugins:
                    packer_info = plugins[pk]
                    break

            if packer_info is None:
                continue

            if isinstance(packer_info, dict):
                plugin_output = packer_info.get("plugin_output", {})
                packer_list = packer_info.get("packers", [])

                if isinstance(plugin_output, dict):
                    for key, value in plugin_output.items():
                        if value and str(value).strip():
                            detections.append(str(value))
                elif isinstance(plugin_output, str) and plugin_output.strip():
                    detections.append(plugin_output.strip())

                if packer_list:
                    detections.extend(
                        [str(p) for p in packer_list if str(p).strip()]
                    )

                level = packer_info.get("level", 0)
                summary = packer_info.get("summary", "")
                if level >= 2 or "packed" in summary.lower():
                    detections.append(summary or f"level={level}")

            elif isinstance(packer_info, str) and packer_info.strip():
                detections.append(packer_info.strip())

        if detections:
            return True, f"Detected: {', '.join(detections[:5])}"
        return False, "No packer detected"

    except subprocess.TimeoutExpired:
        return None, "Timeout"
    except json.JSONDecodeError:
        if result.stdout and "packer" in result.stdout.lower():
            return True, "Packer mentioned in text output"
        return False, "Non-JSON output"
    except Exception as e:
        return None, f"Error: {e}"


# ============================================================
# DETECTOR 4: YARA rules
# ============================================================
def _compile_yara_rules():
    if not HAS_YARA:
        return None

    if not os.path.exists(YARA_RULES_DIR):
        return None

    rule_files = {}
    for f in os.listdir(YARA_RULES_DIR):
        if f.endswith((".yar", ".yara")):
            rule_path = os.path.join(YARA_RULES_DIR, f)
            namespace = os.path.splitext(f)[0]
            rule_files[namespace] = rule_path

    if not rule_files:
        return None

    try:
        return yara.compile(filepaths=rule_files)
    except yara.Error:
        compiled = None
        for ns, path in rule_files.items():
            try:
                rules = yara.compile(filepath=path)
                if compiled is None:
                    compiled = rules
            except yara.Error:
                continue
        return compiled


_YARA_RULES = None


def _get_yara_rules():
    global _YARA_RULES
    if _YARA_RULES is None:
        _YARA_RULES = _compile_yara_rules()
    return _YARA_RULES


def detect_yara(filepath):
    """Match file against YARA packer rules."""
    if not HAS_YARA:
        return None, "yara-python not installed"

    rules = _get_yara_rules()
    if rules is None:
        return None, "No YARA rules compiled"

    try:
        matches = rules.match(filepath, timeout=30)

        packer_keywords = [
            "pack", "upx", "aspack", "themida", "vmprotect", "mpress",
            "petite", "fsg", "pecompact", "rlpack", "upack", "cryptor",
            "protector", "obfuscat", "encrypt", "compress",
        ]

        detections = []
        for match in matches:
            rule_name = match.rule.lower()
            if any(kw in rule_name for kw in packer_keywords):
                detections.append(match.rule)

        if not detections and matches:
            all_names = [m.rule for m in matches]
            return False, f"YARA matches (non-packer): {', '.join(all_names[:3])}"

        if detections:
            return True, f"Rules matched: {', '.join(detections[:5])}"
        return False, "No packer rules matched"

    except yara.TimeoutError:
        return None, "Timeout"
    except Exception as e:
        return None, f"Error: {e}"


# ============================================================
# DETECTOR 5: pefile entropy + section analysis
# ============================================================
def _shannon_entropy(data):
    if not data:
        return 0.0

    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1

    length = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            freq = count / length
            entropy -= freq * math.log2(freq)

    return entropy


def detect_entropy(filepath):
    """Analyze PE sections for high entropy and suspicious names."""
    if not HAS_PEFILE:
        return None, "pefile not installed"

    try:
        pe = pefile.PE(filepath, fast_load=False)
    except pefile.PEFormatError:
        return None, "Not a valid PE file"
    except Exception as e:
        return None, f"PE parse error: {e}"

    try:
        findings = []
        high_entropy_count = 0
        total_sections = len(pe.sections)

        for section in pe.sections:
            try:
                name = section.Name.decode("utf-8", errors="replace").strip("\x00").strip()
            except Exception:
                name = str(section.Name)

            name_lower = name.lower()
            data = section.get_data()
            entropy = _shannon_entropy(data)

            is_suspicious_name = name_lower in SUSPICIOUS_SECTIONS
            is_entropy_dependent = name_lower in ENTROPY_DEPENDENT_SECTIONS

            if entropy > ENTROPY_THRESHOLD:
                high_entropy_count += 1
                if is_suspicious_name and not is_entropy_dependent:
                    findings.append(f"{name}(entropy={entropy:.2f},suspicious_name)")
                else:
                    findings.append(f"{name}(entropy={entropy:.2f})")
            elif is_suspicious_name and not is_entropy_dependent:
                findings.append(f"{name}(suspicious_name)")

        has_packer_section = any(
            name_lower in SUSPICIOUS_SECTIONS and name_lower not in ENTROPY_DEPENDENT_SECTIONS
            for section in pe.sections
            for name_lower in [section.Name.decode("utf-8", errors="replace").strip("\x00").strip().lower()]
        )

        if has_packer_section:
            pe.close()
            return True, f"Packer sections: {', '.join(findings)}"

        if total_sections > 0 and high_entropy_count >= 2 and high_entropy_count / total_sections >= 0.5:
            pe.close()
            return True, f"High entropy ratio ({high_entropy_count}/{total_sections}): {', '.join(findings)}"

        pe.close()

        if findings:
            return False, f"Some findings but below threshold: {', '.join(findings)}"
        return False, "Normal entropy profile"

    except Exception as e:
        try:
            pe.close()
        except Exception:
            pass
        return None, f"Analysis error: {e}"


# ============================================================
# PACKER METADATA — load from YAML once
# ============================================================
def _load_packer_meta(yaml_path=None):
    """
    Build a mapping of packer_dir_name -> metadata dict from packer_corpus.yaml.
    packer_dir_name matches what packer_runner.py produces: f"{packer_name}_{safe_version}".
    Returns {} if yaml is unavailable or the file doesn't exist.
    """
    if not HAS_YAML:
        return {}

    path = yaml_path or YAML_CONFIG_FILE
    if not os.path.exists(path):
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except Exception:
        return {}

    meta = {}
    for defn in config.get("definitions", []):
        name = defn.get("packer_name", "")
        version = defn.get("version", "")
        safe_ver = re.sub(r"[^\w\.\-]", "_", version).strip("_")
        dir_key = f"{name}_{safe_ver}"
        meta[dir_key] = {
            "packer_family": defn.get("packer_family", ""),
            "version": version,
            "packer_type": defn.get("type", ""),
            "type_ex": defn.get("type_ex", ""),
            "arch_origin": defn.get("arch_origin", ""),
            "license": defn.get("license", ""),
        }
    return meta


# ============================================================
# PATH HELPERS
# ============================================================
def _extract_label_parts(filepath, packed_base_dir):
    """
    Given an absolute filepath under packed_base_dir, extract:
      packer_label — the first sub-directory under packed_base_dir (e.g. "upx_5.1.0")
      test_id      — the second sub-directory (e.g. "TEST_DEFAULT")

    Returns ("", "") when the file isn't under packed_base_dir.
    """
    try:
        rel = os.path.relpath(filepath, packed_base_dir)
    except ValueError:
        return "", ""

    parts = rel.replace("\\", "/").split("/")
    packer_label = parts[0] if len(parts) > 0 else ""
    test_id = parts[1] if len(parts) > 1 else ""
    return packer_label, test_id


# ============================================================
# VERIFY STATE — per-file, per-detector checkpoint for resume
# ============================================================
class VerifyState:
    """
    Persists which detectors have already run on which files so a resumed
    run only executes the missing detectors.

    Schema (verify_state.json):
        {
          "/abs/path/to/sample.exe": {
              "die":      {"verdict": true,  "detail": "Detected: packer:UPX"},
              "manalyze": {"verdict": false, "detail": "No packer detected"},
              "yara":     {"verdict": null,  "detail": "Timeout"},
              "entropy":  {"verdict": true,  "detail": "High entropy ratio"},
              "capa":     {"verdict": false, "detail": "No packing capabilities"}
          },
          ...
        }
    verdict is true/false/null (Python bool or None), stored as JSON true/false/null.
    """

    ALL_DETECTORS = ["die", "manalyze", "yara", "entropy", "capa"]

    def __init__(self, path=None):
        self._path = path
        self._lock = threading.Lock()
        self._data = {}          # abs_path -> {detector -> {verdict, detail}}
        self._dirty = 0          # unsaved result count
        self._save_every = 20    # flush to disk every N new results

        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    self._data = json.load(f)
                total = len(self._data)
                full  = sum(1 for v in self._data.values()
                            if len(v) == len(self.ALL_DETECTORS))
                print(f"[*] Verify state loaded: {total} file(s) seen, "
                      f"{full} fully complete — skipping those")
            except Exception as e:
                print(f"[!] Could not load verify state ({e}) — starting fresh")

    def get(self, filepath, detector):
        """Return (verdict, detail) if already recorded, else None."""
        rec = self._data.get(os.path.abspath(filepath), {}).get(detector)
        if rec is None:
            return None
        return rec["verdict"], rec["detail"]

    def set(self, filepath, detector, verdict, detail):
        """Record a result and periodically flush to disk."""
        key = os.path.abspath(filepath)
        with self._lock:
            if key not in self._data:
                self._data[key] = {}
            self._data[key][detector] = {"verdict": verdict, "detail": detail}
            self._dirty += 1
            if self._dirty >= self._save_every:
                self._save_locked()
                self._dirty = 0

    def flush(self):
        """Force a save — call this at the end of a run."""
        with self._lock:
            self._save_locked()
            self._dirty = 0

    def is_fully_done(self, filepath):
        rec = self._data.get(os.path.abspath(filepath), {})
        return all(d in rec for d in self.ALL_DETECTORS)

    def missing(self, filepath):
        rec = self._data.get(os.path.abspath(filepath), {})
        return [d for d in self.ALL_DETECTORS if d not in rec]

    def _save_locked(self):
        if not self._path:
            return
        tmp = self._path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._data, f)
            os.replace(tmp, self._path)
        except Exception as e:
            print(f"[!] Could not save verify state: {e}")


# ============================================================
# FAST DETECTOR BUNDLE (all non-capa detectors in one call)
# ============================================================
_FAST_DETECTORS = [
    ("die", detect_die),
    ("manalyze", detect_manalyze),
    ("yara", detect_yara),
    ("entropy", detect_entropy),
]


def _run_fast_detectors(filepath, state):
    """
    Run DIE, Manalyze, YARA, Entropy — skipping any already in state.
    Returns (filepath, {det: (verdict, detail)}).
    """
    results = {}
    for name, fn in _FAST_DETECTORS:
        cached = state.get(filepath, name)
        if cached is not None:
            results[name] = cached
        else:
            verdict, detail = fn(filepath)
            state.set(filepath, name, verdict, detail)
            results[name] = (verdict, detail)
    return filepath, results


def _run_capa(filepath, state):
    """Run Capa — skip if already in state. Returns (filepath, verdict, detail)."""
    cached = state.get(filepath, "capa")
    if cached is not None:
        return filepath, cached[0], cached[1]
    verdict, detail = detect_capa(filepath)
    state.set(filepath, "capa", verdict, detail)
    return filepath, verdict, detail


# ============================================================
# ORCHESTRATOR
# ============================================================

_KNOWN_PACKERS = [
    "upx", "vmprotect", "themida", "aspack", "mpress", "petite",
    "pecompact", "rlpack", "fsg", "obsidium", "enigma", "armadillo",
    "execryptor", "molebox", "telock", "npack", "nspack", "upack",
    "expressor", "peshield", "mew", "wwpack", "confuser", "dotbundle",
    "netz", "ilprotector", "dnguard", "reactor", "babel", "eazfuscator",
    "deepsea", "smartassembly", "dotfuscator", "crypto", "packman",
    "yodas", "andpakk", "bangcle", "jiagu", "kiro", "ali",
]


def _extract_packer_name(*detail_pairs):
    """
    Best-effort packer name from detector detail strings.

    Accepts (detector_name, detail_str) pairs in priority order.
    Returns a cleaned lowercase name, or '' if nothing specific found.
    """
    for det, detail in detail_pairs:
        if not detail:
            continue
        detail_l = detail.lower()

        if det == "die":
            # "packer:UPX(3.96)[NRV,LZMA,...]" or "protector:VMProtect"
            m = re.search(r'(?:packer|protector):([A-Za-z0-9][\w.\-+]*)', detail, re.IGNORECASE)
            if m:
                name = m.group(1).split("(")[0].strip()
                if name.lower() not in ("compressed", "data", "packed", "or", "heur"):
                    return name.lower()

        elif det == "yara":
            # "Packed__With__UPX", "UPXv20...", "UPXV200..."
            m = re.search(r'Packed__With__(\w+)', detail, re.IGNORECASE)
            if m:
                return m.group(1).lower()
            for rule in re.findall(r'\w+', detail):
                rule_l = rule.lower()
                if rule_l in ("packed", "highentropy", "entrypoint", "obfuscated"):
                    continue
                for packer in _KNOWN_PACKERS:
                    if rule_l.startswith(packer):
                        return packer

        elif det in ("manalyze", "entropy", "capa"):
            # "packed with VMProtect", or section name ".vmp0", "UPX0"
            m = re.search(r'packed with ([A-Za-z0-9][\w.\-+]*)', detail, re.IGNORECASE)
            if m:
                return m.group(1).lower()
            for packer in _KNOWN_PACKERS:
                if packer in detail_l:
                    return packer

    return ""


CSV_COLUMNS = [
    "file",
    "packer_label",
    "test_id",
    "packer_family",
    "version",
    "packer_type",
    "detected_packer_name",
    "die_verdict",
    "die_detail",
    "capa_verdict",
    "capa_detail",
    "manalyze_verdict",
    "manalyze_detail",
    "yara_verdict",
    "yara_detail",
    "entropy_verdict",
    "entropy_detail",
    "overall_packed",
]


def verify_all_files(
    target_dir,
    packed_base_dir=None,
    workers=4,
    capa_workers=1,
    dry_run=False,
    packer_meta=None,
    state=None,
):
    """
    Verify all PE files under target_dir.

    Fast detectors (DIE, Manalyze, YARA, Entropy) run in a pool of `workers`
    threads.  Capa runs concurrently in a separate smaller pool of `capa_workers`
    threads so it never blocks the fast cycle.

    state (VerifyState): if provided, already-run detectors are skipped and
    results are checkpointed after each completion so the run can be resumed.

    Returns a list of row dicts with CSV_COLUMNS as keys.
    """
    packed_base_dir = packed_base_dir or target_dir
    packer_meta     = packer_meta or {}
    state           = state or VerifyState()   # no-op state if none provided

    _MZ = b"\x4D\x5A"  # PE magic

    def _is_pe(path):
        try:
            with open(path, "rb") as f:
                return f.read(2) == _MZ
        except OSError:
            return False

    # Collect PE files by extension (.exe / .dll) OR by MZ magic for
    # extensionless/hash-named samples (MalwareBazaar / VT Intelligence format).
    _PE_EXTS = {".exe", ".dll", ".scr", ".sys"}
    _SKIP_EXTS = {".json", ".txt", ".log", ".csv", ".7z", ".zip", ".rar",
                  ".gz", ".bz2", ".js", ".pdf", ".doc", ".docx", ".xls"}

    exe_files = []
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d != "_temp_build"]
        for f in files:
            path = os.path.abspath(os.path.join(root, f))
            ext  = os.path.splitext(f)[1].lower()
            if ext in _PE_EXTS:
                exe_files.append(path)
            elif ext not in _SKIP_EXTS:
                if _is_pe(path):
                    exe_files.append(path)

    if not exe_files:
        print(f"[!] No PE files found in {target_dir}")
        return []

    # Split into fully done (all 5 detectors in state) vs still pending
    done_files    = [f for f in exe_files if state.is_fully_done(f)]
    pending_files = [f for f in exe_files if not state.is_fully_done(f)]

    print(f"\n[*] PE files found:  {len(exe_files)}")
    if done_files:
        print(f"[*] Already verified: {len(done_files)} (resume — skipping)")
    print(f"[*] To verify:       {len(pending_files)}")
    print(f"[*] Fast workers: {workers}  |  Capa workers: {capa_workers}")
    print(f"[*] Mode: {'DRY RUN' if dry_run else 'DELETE unverified'}\n")

    if HAS_YARA:
        _get_yara_rules()

    fast_results = {}   # filepath -> {det_name: (verdict, detail)}
    capa_results = {}   # filepath -> (verdict, detail)

    # Within pending_files, further split by which detectors are still needed
    needs_fast = [f for f in pending_files
                  if any(d in state.missing(f) for d in ["die", "manalyze", "yara", "entropy"])]
    needs_capa = [f for f in pending_files if "capa" in state.missing(f)]

    # Pre-populate results from state for files that only need some detectors
    for fp in pending_files:
        fast_results[fp] = {}
        for det in ["die", "manalyze", "yara", "entropy"]:
            cached = state.get(fp, det)
            if cached is not None:
                fast_results[fp][det] = cached
        cached = state.get(fp, "capa")
        if cached is not None:
            capa_results[fp] = cached

    # --- Phase 1: fast detectors ---
    fast_total = len(needs_fast)
    capa_total = len(needs_capa)

    try:
        if needs_fast:
            with tqdm(total=fast_total, unit="file", desc="Fast detectors", position=0) as fast_pbar, \
                 concurrent.futures.ThreadPoolExecutor(max_workers=workers) as fast_exec:
                fast_futs = {fast_exec.submit(_run_fast_detectors, fp, state): fp
                             for fp in needs_fast}
                for fut in concurrent.futures.as_completed(fast_futs):
                    try:
                        fp, det_map = fut.result()
                        fast_results[fp] = det_map
                    except Exception as exc:
                        fp = fast_futs[fut]
                        fast_results.setdefault(fp, {}).update(
                            {d: (None, f"Exception: {exc}") for d, _ in _FAST_DETECTORS
                             if d not in fast_results.get(fp, {})}
                        )
                    fast_pbar.update(1)

        # --- Phase 2: capa — all workers now free, use full budget ---
        if needs_capa:
            # workers + capa_workers = total budget; use all of it now
            all_workers = workers + capa_workers
            print(f"[*] Capa phase: {capa_total} files, {all_workers} workers")
            with tqdm(total=capa_total, unit="file", desc="Capa          ", position=0) as capa_pbar, \
                 concurrent.futures.ThreadPoolExecutor(max_workers=all_workers) as capa_exec:
                capa_futs = {capa_exec.submit(_run_capa, fp, state): fp
                             for fp in needs_capa}
                for fut in concurrent.futures.as_completed(capa_futs):
                    try:
                        fp, verdict, detail = fut.result()
                        capa_results[fp] = (verdict, detail)
                    except Exception as exc:
                        fp = capa_futs[fut]
                        capa_results.setdefault(fp, (None, f"Exception: {exc}"))
                    capa_pbar.update(1)

    except KeyboardInterrupt:
        tqdm.write("\n[!] Interrupted — flushing state...")
        state.flush()
        tqdm.write("[*] State saved. Re-run the same command to resume.")
        raise

    state.flush()

    # --- Assemble rows (all files — done + freshly verified) ---
    # Pull fully-done files' results from state
    for fp in done_files:
        fast_results[fp] = {}
        for det in ["die", "manalyze", "yara", "entropy"]:
            cached = state.get(fp, det)
            fast_results[fp][det] = cached if cached is not None else (None, "not run")
        cached = state.get(fp, "capa")
        capa_results[fp] = cached if cached is not None else (None, "not run")

    all_rows = []
    packed_count = not_packed_count = error_count = 0

    for filepath in exe_files:
        packer_label, test_id = _extract_label_parts(filepath, packed_base_dir)
        meta = packer_meta.get(packer_label, {})

        det = fast_results.get(filepath, {d: (None, "not run") for d, _ in _FAST_DETECTORS})
        capa_v, capa_d = capa_results.get(filepath, (None, "not run"))

        all_verdicts = [
            det.get("die", (None,))[0],
            capa_v,
            det.get("manalyze", (None,))[0],
            det.get("yara", (None,))[0],
            det.get("entropy", (None,))[0],
        ]
        is_packed = any(v is True for v in all_verdicts)
        all_errors = all(v is None for v in all_verdicts)

        if is_packed:
            packed_count += 1
        elif all_errors:
            error_count += 1
            tqdm.write(f"[?] {os.path.relpath(filepath, packed_base_dir)}: All detectors errored — keeping")
        else:
            not_packed_count += 1
            tqdm.write(f"[X] {os.path.relpath(filepath, packed_base_dir)}: NOT PACKED")
            if not dry_run:
                try:
                    os.remove(filepath)
                    tqdm.write(f"    -> Deleted")
                except OSError as e:
                    tqdm.write(f"    -> Delete failed: {e}")

        def _v(verdict):
            if verdict is True:
                return "positive"
            if verdict is False:
                return "negative"
            return "error"

        die_detail      = det.get("die",      (None, ""))[1]
        manalyze_detail = det.get("manalyze", (None, ""))[1]
        yara_detail     = det.get("yara",     (None, ""))[1]
        entropy_detail  = det.get("entropy",  (None, ""))[1]

        detected_name = _extract_packer_name(
            ("die",      die_detail),
            ("yara",     yara_detail),
            ("manalyze", manalyze_detail),
            ("entropy",  entropy_detail),
            ("capa",     capa_d),
        )

        row = {
            "file": os.path.relpath(filepath, packed_base_dir),
            "packer_label": packer_label,
            "test_id": test_id,
            "packer_family": meta.get("packer_family", ""),
            "version": meta.get("version", ""),
            "packer_type": meta.get("packer_type", ""),
            "detected_packer_name": detected_name,
            "die_verdict": _v(det.get("die", (None,))[0]),
            "die_detail": die_detail,
            "capa_verdict": _v(capa_v),
            "capa_detail": capa_d,
            "manalyze_verdict": _v(det.get("manalyze", (None,))[0]),
            "manalyze_detail": manalyze_detail,
            "yara_verdict": _v(det.get("yara", (None,))[0]),
            "yara_detail": yara_detail,
            "entropy_verdict": _v(det.get("entropy", (None,))[0]),
            "entropy_detail": entropy_detail,
            "overall_packed": "yes" if is_packed else ("error" if all_errors else "no"),
        }
        all_rows.append(row)

    print(f"\n{'='*50}")
    print(f"VERIFICATION SUMMARY")
    print(f"{'='*50}")
    print(f"  Total files:     {len(exe_files)}")
    print(f"  Packed (kept):   {packed_count}")
    print(f"  Not packed:      {not_packed_count} {'(deleted)' if not dry_run else '(dry run)'}")
    print(f"  Errors (kept):   {error_count}")
    print(f"{'='*50}")

    return all_rows


def write_csv(rows, csv_path):
    """Write verification rows to a CSV file."""
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"\n[*] CSV written to: {os.path.abspath(csv_path)}")


# ============================================================
# LEGACY COMPAT — called by packer_runner.py --verify
# ============================================================
def verify_directory(target_dir, dry_run=False, workers=4):
    """Thin wrapper kept for backward compatibility with packer_runner.py."""
    packer_meta = _load_packer_meta()
    packed_base = PACKED_OUTPUT_DIR if target_dir.startswith(PACKED_OUTPUT_DIR) else target_dir
    return verify_all_files(
        target_dir,
        packed_base_dir=packed_base,
        workers=workers,
        capa_workers=1,
        dry_run=dry_run,
        packer_meta=packer_meta,
    )


# ============================================================
# CLI
# ============================================================
def main():
    # 75 % of cores total; capa gets ~25 % of that slice, fast detectors the rest.
    total_workers = max(int(cpu_count() * 0.75), 1)
    default_capa  = max(1, total_workers // 4)
    default_fast  = max(1, total_workers - default_capa)

    parser = argparse.ArgumentParser(
        description="Verify packed samples using multiple detection engines."
    )
    parser.add_argument(
        "target",
        type=str,
        help=(
            "Path to a directory of samples, a packer sub-directory name "
            "(e.g. 'upx_5.1.0'), or 'all' to scan everything under --packed-dir."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report only — do not delete unverified files.",
    )
    parser.add_argument(
        "--report",
        type=str,
        default=None,
        help="Save detailed JSON report to this path.",
    )
    parser.add_argument(
        "--csv",
        type=str,
        default=None,
        help="Save labelled CSV (packer name + per-detector columns) to this path.",
    )
    parser.add_argument(
        "--packed-dir",
        type=str,
        default=PACKED_OUTPUT_DIR,
        help=f"Base packed output directory (default: {PACKED_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--state",
        type=str,
        default=None,
        help="Path to verify_state.json for resume (default: <csv>.state.json when --csv is set).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=total_workers,
        help=(
            f"Total worker budget (default: {total_workers} = 75 %% of {cpu_count()} cores). "
            f"Auto-split: ~{default_fast} fast, ~{default_capa} capa."
        ),
    )

    args = parser.parse_args()

    # Auto-split the worker budget: capa gets 25 %, fast gets 75 %.
    capa_workers = max(1, args.workers // 4)
    fast_workers = max(1, args.workers - capa_workers)

    packed_dir = os.path.abspath(args.packed_dir)

    print("[*] Detector status:")
    print(f"    DIE:      {'OK' if os.path.exists(DIE_BIN) else 'MISSING'}")
    print(f"    Capa:     {'OK' if os.path.exists(CAPA_BIN) else 'MISSING'}")
    print(f"    Manalyze: {'OK' if os.path.exists(MANALYZE_BIN) else 'MISSING'}")
    print(f"    YARA:     {'OK' if HAS_YARA else 'NOT INSTALLED'}")
    print(f"    pefile:   {'OK' if HAS_PEFILE else 'NOT INSTALLED'}")
    print(f"    YAML meta: {'OK' if HAS_YAML else 'NOT INSTALLED (pip install pyyaml)'}")
    print(f"[*] Workers: {args.workers} total  ({fast_workers} fast / {capa_workers} capa)")

    packer_meta = _load_packer_meta()
    if packer_meta:
        print(f"[*] Loaded metadata for {len(packer_meta)} packer(s) from YAML")

    # Resolve target: direct path > packed_dir sub-folder > 'all'
    target_arg = args.target
    if os.path.isdir(target_arg):
        # Caller passed an explicit path — use it directly.
        target_dir    = os.path.abspath(target_arg)
        packed_base   = os.path.dirname(target_dir)
    elif target_arg.lower() == "all":
        if not os.path.exists(packed_dir):
            print(f"[!] Packed output directory not found: {packed_dir}")
            print(f"    Run packer_runner.py first to generate packed samples.")
            sys.exit(1)
        target_dir  = packed_dir
        packed_base = packed_dir
    else:
        target_dir = os.path.join(packed_dir, target_arg)
        if not os.path.exists(target_dir):
            print(f"[!] Target not found as a path or sub-folder of packed_dir: {target_arg}")
            sys.exit(1)
        packed_base = packed_dir

    # Resolve state file — next to the CSV by default so resume just works
    state_path = args.state
    if not state_path and args.csv:
        state_path = args.csv + ".state.json"
    elif not state_path:
        state_path = os.path.join(target_dir, "verify_state.json")
    state = VerifyState(state_path)
    print(f"[*] Verify state:  {state_path}")

    rows = verify_all_files(
        target_dir,
        packed_base_dir=packed_base,
        workers=fast_workers,
        capa_workers=capa_workers,
        dry_run=args.dry_run,
        packer_meta=packer_meta,
        state=state,
    )

    if args.csv and rows:
        write_csv(rows, args.csv)

    if args.report and rows:
        report_path = os.path.abspath(args.report)
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)
        print(f"[*] JSON report saved to: {report_path}")


if __name__ == "__main__":
    main()
