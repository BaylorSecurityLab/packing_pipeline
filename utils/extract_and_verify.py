"""
extract_and_verify.py

1. Scans input_dir for README/text files that might contain passwords.
2. Recursively extracts all archives (zip/7z/rar/...) — including archives
   found inside archives — until no new ones surface.
3. Logs every attempt to extraction.log and tracks completed archives in
   processed.json so the run can be resumed after an interruption.
4. Runs pack_verifier against every .exe found and writes a CSV.

Resume: just re-run the same command. Already-extracted archives are skipped.
If an archive previously failed all passwords, it is retried only when new
passwords are available (from README discovery or --password).

Usage:
    uv run python utils/extract_and_verify.py <input_dir> <output_dir> [options]

Options:
    --csv PATH        Final CSV path (default: <output_dir>/results.csv)
    --dry-run         Verify without deleting files that fail detection
    --workers N       Worker budget (default: 75% of CPU cores, auto-split)
    --skip-verify     Extract only, skip verification
    --password PW     Extra password to try (repeatable: --password pw1 --password pw2)
    --retry-failed    Re-attempt archives that previously failed all passwords

Example:
    uv run python utils/extract_and_verify.py "C:\\Downloads\\samples" "C:\\extracted" --csv results.csv
"""

import argparse
import datetime
import json
import logging
import os
import re
import subprocess
import sys
from multiprocessing import cpu_count

# -----------------------------------------------------------------------
# 7-Zip
# -----------------------------------------------------------------------
_7Z_CANDIDATES = [
    r"C:\Users\resbears\scoop\shims\7z.exe",
    r"C:\Program Files\7-Zip\7z.exe",
    r"C:\Program Files (x86)\7-Zip\7z.exe",
    "7z",
]


def _find_7z():
    for c in _7Z_CANDIDATES:
        try:
            r = subprocess.run([c, "i"], capture_output=True, timeout=5)
            if r.returncode == 0:
                return c
        except Exception:
            continue
    return None


# -----------------------------------------------------------------------
# Logger — console (INFO) + persistent append log (DEBUG)
# -----------------------------------------------------------------------
_log = logging.getLogger("extract_and_verify")


def _setup_logging(log_path):
    _log.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s  %(levelname)-7s  %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    _log.addHandler(ch)

    # Append mode — accumulates across resumed runs
    fh = logging.FileHandler(log_path, mode="a", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    _log.addHandler(fh)

    _log.info("=" * 60)
    _log.info(f"Session start  {datetime.datetime.now().isoformat(timespec='seconds')}")
    _log.info(f"Log: {log_path}")


# -----------------------------------------------------------------------
# Processed-file tracker  (processed.json)
# -----------------------------------------------------------------------
class ProcessedTracker:
    """
    Persists which archives have been attempted so a resumed run skips them.

    Schema (processed.json):
        {
          "abs/path/to/archive.zip": {
              "status":   "ok" | "failed" | "error",
              "password": "infected" | null,
              "tried":    ["infected", "virus", ...],
              "ts":       "2026-06-27T21:00:00"
          },
          ...
        }
    """

    def __init__(self, path):
        self._path = path
        self._data: dict = {}
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    self._data = json.load(f)
                _log.info(f"Loaded processed tracker: {len(self._data)} archive(s) already recorded")
            except Exception as e:
                _log.warning(f"Could not read processed.json ({e}) — starting fresh")

    def is_done(self, archive_path: str, new_passwords: list) -> bool:
        """
        Returns True if this archive should be skipped:
          - status == 'ok'  (already extracted successfully)
          - status == 'failed' AND no new passwords have appeared since last attempt
        """
        rec = self._data.get(os.path.abspath(archive_path))
        if rec is None:
            return False
        if rec["status"] == "ok":
            return True
        if rec["status"] in ("failed", "error"):
            previously_tried = set(rec.get("tried", []))
            new_ones = [p for p in new_passwords if p not in previously_tried]
            if new_ones:
                _log.info(f"Retrying previously-failed archive with new password(s) {new_ones}: "
                          f"{os.path.basename(archive_path)}")
                return False
            return True
        return False

    def mark(self, archive_path: str, status: str, password=None, tried=None):
        key = os.path.abspath(archive_path)
        self._data[key] = {
            "status":   status,
            "password": password,
            "tried":    tried or [],
            "ts":       datetime.datetime.now().isoformat(timespec="seconds"),
        }
        self._save()

    def _save(self):
        tmp = self._path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2)
            os.replace(tmp, self._path)
        except Exception as e:
            _log.warning(f"Could not save processed.json: {e}")

    @property
    def counts(self):
        ok = sum(1 for r in self._data.values() if r["status"] == "ok")
        failed = sum(1 for r in self._data.values() if r["status"] != "ok")
        return ok, failed


# -----------------------------------------------------------------------
# Password discovery
# -----------------------------------------------------------------------
_README_NAMES = {
    "readme.txt", "readme.md", "readme", "password.txt", "passwords.txt",
    "pass.txt", "info.txt", "note.txt", "notes.txt", "instructions.txt",
    "how_to.txt", "howto.txt", "key.txt",
}

_PW_PATTERNS = [
    re.compile(r'(?:password|pass|pwd|key)\s*[=:]\s*["\']?([^\s"\']{1,64})', re.I),
    re.compile(r'(?:the\s+)?password\s+is\s+["\']?([^\s"\']{1,64})', re.I),
]

_DEFAULT_PASSWORDS = [
    "infected", "virus", "malware", "1234", "password",
    "abuse.ch", "bazaar", "infected!", "MalwareBazaar",
    "vt", "VirusTotal", "virustotal",
    "",
]


def _scan_for_passwords(root):
    found, seen = [], set()
    for dirpath, _, files in os.walk(root):
        for fname in files:
            if fname.lower() in _README_NAMES or fname.lower().endswith(".txt"):
                fpath = os.path.join(dirpath, fname)
                try:
                    text = open(fpath, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                _log.info(f"README/text: {os.path.relpath(fpath, root)}")
                for pat in _PW_PATTERNS:
                    for m in pat.finditer(text):
                        pw = m.group(1).strip().strip("'\".,;")
                        if pw and pw not in seen:
                            seen.add(pw)
                            found.append(pw)
                            _log.info(f"  Password candidate: {repr(pw)}")
                _log.debug(f"  --- {fname} content (first 2000 chars) ---\n"
                           f"{text[:2000]}\n  ---")
    if not found:
        _log.info("No password candidates found in README/text files.")
    return found


# -----------------------------------------------------------------------
# Extraction
# -----------------------------------------------------------------------
_ARCHIVE_EXTS = {".zip", ".7z", ".rar", ".gz", ".tar", ".bz2", ".xz",
                 ".cab", ".lzh", ".ace"}

# Magic-byte signatures for archives that appear without an extension
# (e.g. hash-named per-sample archives from MalwareBazaar / VT Intelligence)
_ARCHIVE_MAGIC = [
    (b"\x37\x7A\xBC\xAF", ".7z"),
    (b"\x50\x4B\x03\x04", ".zip"),
    (b"\x52\x61\x72\x21", ".rar"),
    (b"\x1F\x8B",         ".gz"),
    (b"\x42\x5A\x68",     ".bz2"),
]
_SKIP_EXTS = {".exe", ".json", ".txt", ".log", ".csv", ".js", ".dll",
              ".pdf", ".doc", ".docx", ".xls", ".xlsx"}


def _is_archive_by_magic(path):
    try:
        with open(path, "rb") as f:
            header = f.read(8)
        return any(header.startswith(sig) for sig, _ in _ARCHIVE_MAGIC)
    except OSError:
        return False


def extract_archive(seven_z, archive_path, output_dir, passwords, tracker):
    """Try each password; update tracker; return True on success."""
    os.makedirs(output_dir, exist_ok=True)
    name = os.path.basename(archive_path)
    tried = []

    for pw in passwords:
        label = repr(pw) if pw else "(empty)"
        tried.append(pw)
        _log.debug(f"  Trying {label}  →  {name}")

        cmd = [seven_z, "e", archive_path, f"-o{output_dir}",
               "-y", "-aoa", f"-p{pw}"]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=600,
                               text=True, encoding="utf-8", errors="replace")
            combined = (r.stdout + r.stderr).lower()

            if r.returncode == 0:
                _log.info(f"  OK   password={label}  {name}")
                tracker.mark(archive_path, "ok", password=pw, tried=tried)
                return True

            if "wrong password" in combined or "cannot open encrypted" in combined:
                _log.debug(f"  WRONG password {label}  {name}")
                continue

            # Non-password failure
            _log.warning(
                f"  FAIL (exit {r.returncode})  {name}\n"
                f"    stdout: {r.stdout.strip()[:300]}\n"
                f"    stderr: {r.stderr.strip()[:300]}"
            )
            tracker.mark(archive_path, "error", tried=tried)
            return False

        except subprocess.TimeoutExpired:
            _log.warning(f"  TIMEOUT  {name}")
            tracker.mark(archive_path, "error", tried=tried)
            return False
        except Exception as e:
            _log.warning(f"  ERROR  {name}: {e}")
            tracker.mark(archive_path, "error", tried=tried)
            return False

    _log.warning(
        f"  ALL PASSWORDS FAILED  {name}\n"
        f"  Tried: {[repr(p) if p else '(empty)' for p in tried]}\n"
        f"  Tip: add --password <pw> or put the password in a README in the input dir."
    )
    tracker.mark(archive_path, "failed", tried=tried)
    return False


def collect_archives(root):
    """
    Return all archive files under root.
    Files with a recognised archive extension are included directly.
    Files with no extension (or an unrecognised one not in _SKIP_EXTS) are
    sniffed by magic bytes — this catches hash-named per-sample archives.
    """
    found = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != "_temp_build"]
        for f in files:
            path = os.path.join(dirpath, f)
            ext  = os.path.splitext(f)[1].lower()
            if ext in _ARCHIVE_EXTS:
                found.append(path)
            elif ext not in _SKIP_EXTS:
                # Sniff unknown/extensionless files — cheap (reads 8 bytes)
                if _is_archive_by_magic(path):
                    found.append(path)
    return found


def _dest_for(arc, base_override=None):
    """
    Choose the extraction destination for an archive.

    Named archives (.zip, .7z, etc.)  → <parent>/<stem>/
    Extensionless archives             → <parent>/   (flat; stem==name, can't mkdir over itself)

    If the computed sub-folder path already exists as a FILE (e.g. stem of
    "CAU THANG 3.db1.bak" is "CAU THANG 3.db1" which is itself a file),
    fall back to extracting flat into the parent directory.
    """
    name = os.path.basename(arc)
    stem, ext = os.path.splitext(name)
    parent = base_override if base_override else os.path.dirname(arc)
    if ext:
        candidate = os.path.join(parent, stem)
        if os.path.isfile(candidate):
            # Stem collides with an existing file — extract flat instead
            return parent
        return candidate
    else:
        return parent


def extract_all(seven_z, input_dir, output_dir, passwords, tracker, max_passes=3):
    """
    Pass 0       : seed archives from input_dir → output_dir sub-folders.
    Pass 1..N    : newly found nested archives inside output_dir, in-place.
    Stops after max_passes nested passes so we never recurse into actual
    malware files (.jar, .zip, .bak) that happen to look like archives.
    """
    _log.info(f"Scanning input: {input_dir}")
    seed = collect_archives(input_dir)
    _log.info(f"Found {len(seed)} archive(s) in input dir")

    pending = [a for a in seed if not tracker.is_done(a, passwords)]
    skipped = len(seed) - len(pending)
    if skipped:
        _log.info(f"Skipping {skipped} already-extracted archive(s) (resume)")

    for i, arc in enumerate(pending, 1):
        _log.info(f"[{i}/{len(pending)}] {os.path.basename(arc)}")
        dest = _dest_for(arc, base_override=output_dir)
        extract_archive(seven_z, arc, dest, passwords, tracker)

    pass_num = 1
    while pass_num <= max_passes:
        all_in_output = collect_archives(output_dir)
        pending = [a for a in all_in_output if not tracker.is_done(a, passwords)]
        if not pending:
            _log.info("No new nested archives — extraction complete.")
            break

        _log.info(f"Pass {pass_num}/{max_passes}: {len(pending)} nested archive(s)")
        for i, arc in enumerate(pending, 1):
            rel = os.path.relpath(arc, output_dir)
            _log.info(f"  [{i}/{len(pending)}] {rel}")
            dest = _dest_for(arc)
            extract_archive(seven_z, arc, dest, passwords, tracker)

        pass_num += 1
    else:
        remaining = [a for a in collect_archives(output_dir)
                     if not tracker.is_done(a, passwords)]
        if remaining:
            _log.info(f"Reached max passes ({max_passes}) — "
                      f"{len(remaining)} archive(s) not recursed into "
                      f"(likely extracted malware, not containers). "
                      f"Use --max-passes N to go deeper.")

    ok, failed = tracker.counts
    _log.info(f"Tracker summary: {ok} succeeded, {failed} failed/errored")


def count_exes(directory):
    n = 0
    for _, _, files in os.walk(directory):
        for f in files:
            if f.lower().endswith(".exe"):
                n += 1
    return n


# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------
def main():
    default_workers = max(int(cpu_count() * 0.75), 1)

    parser = argparse.ArgumentParser(
        description="Extract archives and run pack_verifier on the result."
    )
    parser.add_argument("input_dir",  help="Directory containing sample archives")
    parser.add_argument("output_dir", help="Where extracted files will land")
    parser.add_argument("--csv",          default=None,
                        help="CSV output path (default: <output_dir>/results.csv)")
    parser.add_argument("--dry-run",      action="store_true",
                        help="Verify without deleting unverified files")
    parser.add_argument("--workers",      type=int, default=default_workers,
                        help=f"Total worker budget (default: {default_workers})")
    parser.add_argument("--skip-verify",     action="store_true",
                        help="Extract only, skip verification")
    parser.add_argument("--skip-extraction", action="store_true",
                        help="Skip extraction, go straight to verification")
    parser.add_argument("--password",     action="append", default=[],
                        dest="extra_passwords",
                        help="Extra password to try (repeatable)")
    parser.add_argument("--retry-failed", action="store_true",
                        help="Re-attempt archives that previously failed all passwords")
    parser.add_argument("--max-passes",   type=int, default=3,
                        help="Max nested extraction passes (default 3). Stops recursing "
                             "into extracted malware that looks like an archive.")
    args = parser.parse_args()

    input_dir  = os.path.abspath(args.input_dir)
    output_dir = os.path.abspath(args.output_dir)
    csv_path   = args.csv or os.path.join(output_dir, "results.csv")

    os.makedirs(output_dir, exist_ok=True)

    log_path       = os.path.join(output_dir, "extraction.log")
    processed_path = os.path.join(output_dir, "processed.json")

    _setup_logging(log_path)

    if not os.path.isdir(input_dir):
        _log.error(f"Input directory not found: {input_dir}")
        sys.exit(1)

    seven_z = _find_7z()
    if not seven_z:
        _log.error("7-Zip not found.")
        sys.exit(1)
    _log.info(f"7-Zip: {seven_z}")

    # Load resume tracker
    tracker = ProcessedTracker(processed_path)
    _log.info(f"Processed file: {processed_path}")

    if args.retry_failed:
        # Clear failed/error entries so they get retried this run
        before = len(tracker._data)
        tracker._data = {k: v for k, v in tracker._data.items() if v["status"] == "ok"}
        cleared = before - len(tracker._data)
        tracker._save()
        _log.info(f"--retry-failed: cleared {cleared} failed record(s)")

    # Build password list: README-discovered > user-supplied > defaults
    discovered = _scan_for_passwords(input_dir)
    passwords = list(dict.fromkeys(
        discovered + args.extra_passwords + _DEFAULT_PASSWORDS
    ))
    _log.info(f"Password list ({len(passwords)}): "
              f"{[repr(p) if p else '(empty)' for p in passwords]}")

    # --- Step 1: Extract ---
    if args.skip_extraction:
        _log.info("--skip-extraction set, skipping to verification.")
    else:
        extract_all(seven_z, input_dir, output_dir, passwords, tracker,
                    max_passes=args.max_passes)

    exe_count = count_exes(output_dir)
    _log.info(f"Extraction done — {exe_count} .exe file(s) in {output_dir}")

    if args.skip_verify:
        _log.info("--skip-verify set, stopping here.")
        _log.info(f"Log: {log_path}   Processed: {processed_path}")
        return

    if exe_count == 0:
        _log.warning("No .exe files found — nothing to verify.")
        return

    # --- Step 2: Verify ---
    _log.info(f"Running pack_verifier  →  {csv_path}")
    _log.info(f"Workers: {args.workers} (auto-split 75% fast / 25% capa)")

    script_dir    = os.path.dirname(os.path.abspath(__file__))
    verifier_path = os.path.join(script_dir, "pack_verifier.py")

    state_path = csv_path + ".state.json"
    subprocess.run(
        [sys.executable, verifier_path,
         output_dir,
         "--csv",     csv_path,
         "--state",   state_path,
         "--workers", str(args.workers),
         "--dry-run"],
        check=False,
    )

    _log.info(f"Done.  CSV: {csv_path}")
    _log.info(f"Log:   {log_path}")
    _log.info(f"Processed: {processed_path}")


if __name__ == "__main__":
    main()
