"""
zip_samples.py

Wraps each PE sample from a verification CSV into its own password-protected
zip (password: "infected" by default) for easy single-sample testing.

  • One zip per sample — single file stored flat (no subdirectory inside zip).
  • Zip name = the sample's original filename (e.g. notepad.exe → notepad.exe.zip).
  • Collisions resolved by appending a counter: notepad_1.exe.zip, notepad_2.exe.zip …
  • Skip zips that already exist (cheap resume).

Usage:
    uv run python utils/zip_samples.py results_final.csv [output_dir] [options]

Arguments:
    results_final.csv   — The slim CSV from make_final_csv.py (sample_file, packer_label, packed)
                          Any CSV with a 'sample_file' column also works.
    output_dir          — Where zips land (default: <csv_dir>/zipped)

Options:
    --base-dir DIR      Root that sample_file paths are relative to
                        (default: directory containing the input CSV)
    --password PW       Zip password (default: infected)
    --workers N         Parallel workers (default: 75% of CPU cores)
    --only-packed       Only zip samples where packed=True
"""

import argparse
import collections
import concurrent.futures
import csv
import os
import subprocess
import sys
from multiprocessing import cpu_count

# Force UTF-8 output so filenames with non-ASCII chars don't crash on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

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


def _resolve_zip_names(sample_files):
    """
    Build a list of (sample_file, zip_basename) pairs.
    Collisions: first occurrence keeps bare name; subsequent get _1, _2, …
    """
    seen = collections.Counter()
    results = []
    for sf in sample_files:
        fname = os.path.basename(sf)           # e.g. "malware.exe"
        stem, ext = os.path.splitext(fname)   # "malware", ".exe"
        count = seen[fname]
        seen[fname] += 1
        if count == 0:
            zip_name = fname + ".zip"          # malware.exe.zip
        else:
            zip_name = f"{stem}_{count}{ext}.zip"  # malware_1.exe.zip
        results.append((sf, zip_name))
    return results


def _zip_one(seven_z, sample_path, zip_path, password):
    """
    Create a password-protected zip holding a single file, stored flat.
    Returns (zip_path, True, '') on success or (zip_path, False, reason).
    """
    if not os.path.exists(sample_path):
        return zip_path, False, "source file not found"

    file_dir  = os.path.dirname(sample_path)
    file_name = os.path.basename(sample_path)

    try:
        # 7-Zip treats filenames starting with '@' as list-file references.
        # Use -i!<name> include syntax to pass those as literal filenames.
        if file_name.startswith("@"):
            file_arg = [f"-i!{file_name}"]
        else:
            file_arg = [file_name]

        r = subprocess.run(
            [
                seven_z, "a",
                "-tzip",            # zip format
                f"-p{password}",    # password
                "-mem=AES256",      # AES-256 encryption
                "-mx=0",            # store only — fastest; packed files don't compress further
                zip_path,
            ] + file_arg,
            capture_output=True,
            timeout=120,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=file_dir,           # run from the file's own directory
        )
        if r.returncode == 0:
            return zip_path, True, ""
        return zip_path, False, f"7z exit {r.returncode}: {r.stderr.strip()[:200]}"
    except subprocess.TimeoutExpired:
        return zip_path, False, "timeout"
    except Exception as e:
        return zip_path, False, str(e)


def main():
    default_workers = max(int(cpu_count() * 0.75), 1)

    parser = argparse.ArgumentParser(
        description="Zip each malware sample individually, password-protected."
    )
    parser.add_argument("csv",        help="Path to results_final.csv (needs 'sample_file' column)")
    parser.add_argument("output_dir", nargs="?", default=None,
                        help="Directory for output zips (default: <csv_dir>/zipped)")
    parser.add_argument("--base-dir",   default=None,
                        help="Root that sample_file paths are relative to "
                             "(default: directory of the input CSV)")
    parser.add_argument("--password",   default="infected",
                        help="Zip password (default: infected)")
    parser.add_argument("--workers",    type=int, default=default_workers,
                        help=f"Parallel workers (default: {default_workers})")
    parser.add_argument("--only-packed", action="store_true",
                        help="Only zip samples where packed=True")
    args = parser.parse_args()

    csv_path   = os.path.abspath(args.csv)
    csv_dir    = os.path.dirname(csv_path)
    base_dir   = os.path.abspath(args.base_dir) if args.base_dir else csv_dir
    output_dir = os.path.abspath(args.output_dir) if args.output_dir else os.path.join(csv_dir, "zipped")

    if not os.path.exists(csv_path):
        print(f"[!] CSV not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    seven_z = _find_7z()
    if not seven_z:
        print("[!] 7-Zip not found — install it or add to PATH.", file=sys.stderr)
        sys.exit(1)
    print(f"[*] 7-Zip:      {seven_z}")
    print(f"[*] Base dir:   {base_dir}")
    print(f"[*] Output dir: {output_dir}")
    print(f"[*] Password:   {args.password}")
    print(f"[*] Workers:    {args.workers}")

    os.makedirs(output_dir, exist_ok=True)

    # Read CSV
    with open(csv_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    if args.only_packed:
        rows = [r for r in rows if r.get("packed", "").strip().lower() in ("true", "yes", "1")]
        print(f"[*] --only-packed: {len(rows)} packed samples selected")

    # Resolve output zip names (collision-safe)
    sample_files = [r["sample_file"] for r in rows]
    name_pairs   = _resolve_zip_names(sample_files)   # [(sample_file, zip_basename), ...]

    # Build work list — resolve full paths, skip already-done zips
    work = []
    skipped = 0
    missing_src = 0
    for sf, zip_name in name_pairs:
        full_sample = os.path.join(base_dir, sf)
        zip_path    = os.path.join(output_dir, zip_name)

        if os.path.exists(zip_path):
            skipped += 1
            continue
        if not os.path.exists(full_sample):
            missing_src += 1
            continue
        work.append((full_sample, zip_path))

    total = len(rows)
    print(f"\n[*] Total samples:   {total:,}")
    if skipped:
        print(f"[*] Already zipped:  {skipped:,}  (skipping)")
    if missing_src:
        print(f"[!] Source missing:  {missing_src:,}  (skipping)")
    print(f"[*] To zip:          {len(work):,}")
    print()

    if not work:
        print("[*] Nothing to do.")
        return

    ok_count  = 0
    err_count = 0
    errors    = []

    try:
        from tqdm import tqdm
        progress = tqdm(total=len(work), unit="zip", desc="Zipping")
    except ImportError:
        progress = None
        print(f"  0 / {len(work)}")

    def _update(n, total_n):
        if progress:
            progress.update(1)
        elif n % 500 == 0 or n == total_n:
            print(f"  {n} / {total_n}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = {
            pool.submit(_zip_one, seven_z, sp, zp, args.password): (sp, zp)
            for sp, zp in work
        }
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            zp, ok, reason = fut.result()
            if ok:
                ok_count += 1
            else:
                err_count += 1
                sp = futs[fut][0]
                errors.append((sp, reason))
            _update(done, len(work))

    if progress:
        progress.close()

    print(f"\n{'='*50}")
    print(f"  Zipped OK : {ok_count:,}")
    print(f"  Errors    : {err_count:,}")
    print(f"  Output dir: {output_dir}")
    print(f"{'='*50}")

    if errors:
        print(f"\nFirst 10 errors:")
        for sp, reason in errors[:10]:
            print(f"  {os.path.basename(sp)}: {reason}")


if __name__ == "__main__":
    main()
