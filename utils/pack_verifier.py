"""
Pack Verifier - Multi-tool packing detection for packed samples.

Uses multiple detection engines in an "any positive = packed" strategy:
  1. DIE (Detect It Easy) - Signature-based packer detection
  2. Capa - Behavioral capability analysis
  3. Manalyze - PE analysis with packer plugin
  4. YARA - Rule-based signature matching (packer rules)
  5. pefile entropy - Section entropy heuristic + suspicious section names

Usage:
    python pack_verifier.py <packer_dir>           # verify one packer's output
    python pack_verifier.py all                     # verify everything in packed_sources
    python pack_verifier.py all --dry-run           # report only, don't delete
    python pack_verifier.py all --report out.json   # save detailed results
"""

import argparse
import json
import math
import os
import subprocess
import sys
import concurrent.futures
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


# --- CONFIGURATION ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
PACKED_OUTPUT_DIR = os.path.join(PROJECT_ROOT, "packed_sources")
DETECTORS_DIR = os.path.join(PROJECT_ROOT, "detectors")

DIE_BIN = os.path.join(DETECTORS_DIR, "die_win64_portable_3.10_x64", "diec.exe")
CAPA_BIN = os.path.join(DETECTORS_DIR, "capa-v9.3.1-windows", "capa.exe")
MANALYZE_BIN = os.path.join(DETECTORS_DIR, "manalyze", "manalyze.exe")
YARA_RULES_DIR = os.path.join(
    DETECTORS_DIR, "die_win64_portable_3.10_x64", "yara_rules"
)

# Entropy threshold for packed section detection
ENTROPY_THRESHOLD = 6.85

# Suspicious section names commonly used by packers
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

# Section names that are suspicious ONLY when combined with high entropy
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

        # DIE prefixes heuristic scan text before JSON — extract the JSON portion
        json_start = output.find("{")
        if json_start == -1:
            return False, "No JSON in output"
        output = output[json_start:]

        data = json.loads(output)

        # DIE JSON structure: {"detects": [{"values": [{"type": "Packer", ...}]}]}
        # Types include: Packer, Protector, Cryptor, (Heur)Cryptor, Scrambler, etc.
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
def detect_capa(filepath):
    """Run capa.exe and check for packing-related capabilities."""
    if not os.path.exists(CAPA_BIN):
        return None, "Capa binary not found"

    try:
        result = subprocess.run(
            [CAPA_BIN, "--json", filepath],
            capture_output=True,
            text=True,
            timeout=120,
            encoding="utf-8",
            errors="replace",
        )

        output = result.stdout.strip()
        if not output:
            return False, f"No output (exit code {result.returncode})"

        data = json.loads(output)

        # Capa JSON: {"rules": {"rule_name": {...}, ...}}
        # Use specific packing-related keywords, avoid generic ones like "protect"
        packing_keywords = [
            "packed with", "packed binary", "packer",
            "obfuscated", "anti-analysis", "anti-disassembly",
            "upx", "themida", "vmprotect", "aspack", "mpress",
            "petite", "pecompact", "rlpack", "fsg",
        ]

        detections = []
        rules = data.get("rules", {})
        for rule_name in rules:
            rule_lower = rule_name.lower()
            if any(kw in rule_lower for kw in packing_keywords):
                detections.append(rule_name)

        if detections:
            return True, f"Capabilities: {', '.join(detections[:5])}"
        return False, "No packing capabilities detected"

    except subprocess.TimeoutExpired:
        return None, "Timeout"
    except json.JSONDecodeError:
        # Capa may output non-JSON on error
        return False, "Non-JSON output (likely unsupported file)"
    except Exception as e:
        return None, f"Error: {e}"


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

        # Manalyze JSON: {"filepath": {"Summary": {...}, "Plugins": {...}}}
        detections = []

        # Handle both dict-with-filepath-key and direct structures
        if isinstance(data, dict):
            # Check if top-level keys look like file paths
            entries = []
            for key, value in data.items():
                if isinstance(value, dict) and ("Plugins" in value or "Summary" in value):
                    entries.append(value)
            if not entries:
                # Direct structure
                entries = [data]
        elif isinstance(data, list):
            entries = data
        else:
            entries = []

        for file_entry in entries:
            plugins = file_entry.get("Plugins", file_entry.get("plugins", {}))

            # Manalyze uses various plugin name keys
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

                # Check plugin_output for packer names
                if isinstance(plugin_output, dict):
                    for key, value in plugin_output.items():
                        if value and str(value).strip():
                            detections.append(str(value))
                elif isinstance(plugin_output, str) and plugin_output.strip():
                    detections.append(plugin_output.strip())

                # Direct packer list
                if packer_list:
                    detections.extend(
                        [str(p) for p in packer_list if str(p).strip()]
                    )

                # Check summary/level
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
        # Manalyze might not output valid JSON for all files
        # Check stderr/stdout for plain-text packer mentions
        if result.stdout and "packer" in result.stdout.lower():
            return True, "Packer mentioned in text output"
        return False, "Non-JSON output"
    except Exception as e:
        return None, f"Error: {e}"


# ============================================================
# DETECTOR 4: YARA rules
# ============================================================
def _compile_yara_rules():
    """Compile all .yar files in the yara_rules directory."""
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
        # Try compiling rules one by one, skip broken ones
        compiled = None
        for ns, path in rule_files.items():
            try:
                rules = yara.compile(filepath=path)
                if compiled is None:
                    compiled = rules
            except yara.Error:
                continue
        return compiled


# Global compiled rules (compiled once, reused)
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

        # If no keyword match but there ARE matches, still report
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
    """Calculate Shannon entropy of a byte sequence."""
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
            # Decode section name, strip null bytes
            try:
                name = section.Name.decode("utf-8", errors="replace").strip("\x00").strip()
            except Exception:
                name = str(section.Name)

            name_lower = name.lower()
            data = section.get_data()
            entropy = _shannon_entropy(data)

            # Check for suspicious section names (packer-specific)
            is_suspicious_name = name_lower in SUSPICIOUS_SECTIONS
            is_entropy_dependent = name_lower in ENTROPY_DEPENDENT_SECTIONS

            if entropy > ENTROPY_THRESHOLD:
                high_entropy_count += 1
                if is_suspicious_name and not is_entropy_dependent:
                    findings.append(f"{name}(entropy={entropy:.2f},suspicious_name)")
                elif is_entropy_dependent:
                    findings.append(f"{name}(entropy={entropy:.2f})")
                else:
                    findings.append(f"{name}(entropy={entropy:.2f})")

            elif is_suspicious_name and not is_entropy_dependent:
                findings.append(f"{name}(suspicious_name)")

        # Decision logic:
        # - Any packer-specific section name (UPX0, .aspack, etc.) → packed
        # - Multiple high-entropy sections → packed
        # - Single high-entropy .text section alone is normal for some compilers

        has_packer_section = any(
            name_lower in SUSPICIOUS_SECTIONS and name_lower not in ENTROPY_DEPENDENT_SECTIONS
            for section in pe.sections
            for name_lower in [section.Name.decode("utf-8", errors="replace").strip("\x00").strip().lower()]
        )

        if has_packer_section:
            pe.close()
            return True, f"Packer sections: {', '.join(findings)}"

        # If half or more sections are high entropy, likely packed
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
# ORCHESTRATOR
# ============================================================
DETECTORS = [
    ("DIE", detect_die),
    ("Capa", detect_capa),
    ("Manalyze", detect_manalyze),
    ("YARA", detect_yara),
    ("Entropy", detect_entropy),
]


def verify_single_file(filepath):
    """
    Run all detectors on a single file.
    Returns (is_packed: bool, results: dict)
    """
    # All detectors need absolute paths
    filepath = os.path.abspath(filepath)

    results = {}
    is_packed = False

    for name, detector_fn in DETECTORS:
        verdict, detail = detector_fn(filepath)
        results[name] = {"verdict": verdict, "detail": detail}
        if verdict is True:
            is_packed = True

    return is_packed, results


def verify_directory(target_dir, dry_run=False, workers=4):
    """
    Verify all .exe files in a directory tree.
    Returns list of result dicts.
    """
    # Collect all exe files
    exe_files = []
    for root, dirs, files in os.walk(target_dir):
        for f in files:
            if f.lower().endswith(".exe"):
                exe_files.append(os.path.join(root, f))

    if not exe_files:
        print(f"[!] No .exe files found in {target_dir}")
        return []

    print(f"\n[*] Verifying {len(exe_files)} files in {target_dir}")
    print(f"[*] Detectors: {', '.join(name for name, _ in DETECTORS)}")
    print(f"[*] Mode: {'DRY RUN' if dry_run else 'DELETE unverified'}\n")

    all_results = []
    packed_count = 0
    not_packed_count = 0
    error_count = 0

    # Pre-compile YARA rules before parallel execution
    if HAS_YARA:
        _get_yara_rules()

    with tqdm(total=len(exe_files), unit="file", desc="Verifying") as pbar:
        # Use sequential for now since some detectors spawn subprocesses
        for filepath in exe_files:
            filename = os.path.basename(filepath)
            rel_path = os.path.relpath(filepath, target_dir)

            is_packed, results = verify_single_file(filepath)

            entry = {
                "file": rel_path,
                "is_packed": is_packed,
                "detectors": results,
            }
            all_results.append(entry)

            if is_packed:
                packed_count += 1
            else:
                # Check if all detectors errored vs genuinely not packed
                all_errors = all(
                    r["verdict"] is None for r in results.values()
                )
                if all_errors:
                    error_count += 1
                    tqdm.write(f"[?] {rel_path}: All detectors errored — keeping file")
                else:
                    not_packed_count += 1
                    positive_names = [
                        name for name, r in results.items() if r["verdict"] is False
                    ]
                    tqdm.write(
                        f"[X] {rel_path}: NOT PACKED (checked by: {', '.join(positive_names)})"
                    )

                    if not dry_run:
                        try:
                            os.remove(filepath)
                            tqdm.write(f"    -> Deleted")
                        except OSError as e:
                            tqdm.write(f"    -> Delete failed: {e}")

            pbar.update(1)

    # Summary
    print(f"\n{'='*50}")
    print(f"VERIFICATION SUMMARY")
    print(f"{'='*50}")
    print(f"  Total files:     {len(exe_files)}")
    print(f"  Packed (kept):   {packed_count}")
    print(f"  Not packed:      {not_packed_count} {'(deleted)' if not dry_run else '(dry run — not deleted)'}")
    print(f"  Errors (kept):   {error_count}")
    print(f"{'='*50}")

    return all_results


# ============================================================
# CLI
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="Verify packed samples using multiple detection engines."
    )
    parser.add_argument(
        "target",
        type=str,
        help="Packer directory name (e.g., 'upx_5.1.0') or 'all' for everything in packed_sources.",
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
        "--packed-dir",
        type=str,
        default=PACKED_OUTPUT_DIR,
        help=f"Base packed output directory (default: {PACKED_OUTPUT_DIR})",
    )

    args = parser.parse_args()

    packed_dir = os.path.abspath(args.packed_dir)
    if not os.path.exists(packed_dir):
        print(f"[!] Packed output directory not found: {packed_dir}")
        print(f"    Run packer_runner.py first to generate packed samples.")
        sys.exit(1)

    # Check detector availability
    print("[*] Detector status:")
    print(f"    DIE:      {'OK' if os.path.exists(DIE_BIN) else 'MISSING'} ({DIE_BIN})")
    print(f"    Capa:     {'OK' if os.path.exists(CAPA_BIN) else 'MISSING'} ({CAPA_BIN})")
    print(f"    Manalyze: {'OK' if os.path.exists(MANALYZE_BIN) else 'MISSING'} ({MANALYZE_BIN})")
    print(f"    YARA:     {'OK' if HAS_YARA else 'NOT INSTALLED'}")
    print(f"    pefile:   {'OK' if HAS_PEFILE else 'NOT INSTALLED'}")

    if args.target.lower() == "all":
        target_dir = packed_dir
    else:
        target_dir = os.path.join(packed_dir, args.target)
        if not os.path.exists(target_dir):
            print(f"[!] Target directory not found: {target_dir}")
            sys.exit(1)

    results = verify_directory(target_dir, dry_run=args.dry_run)

    if args.report and results:
        report_path = os.path.abspath(args.report)
        with open(report_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[*] Report saved to: {report_path}")


if __name__ == "__main__":
    main()
