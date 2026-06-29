"""
make_final_csv.py

Reads the full verification results CSV produced by pack_verifier.py /
extract_and_verify.py and writes a slim three-column CSV:

    sample_file   — relative path to the PE sample
    packer_label  — named packer (e.g. "upx", "vmprotect") or
                    "unknown" when packed but unidentified, or
                    "" when not packed
    packed        — True / False

Rules
-----
* packed  = overall_packed == 'yes'   → True
            otherwise                 → False
  (overall_packed uses an "any positive = packed" strategy across 5 detectors)

* packer_label:
    - packed=True  + detected_packer_name non-empty → use the name
    - packed=True  + no detected name              → "unknown"
    - packed=False                                 → "" (empty)

  The name is ONLY used when packed=True.  The source CSV sometimes carries
  a detected_packer_name on packed=False rows (name-extractor ran on raw
  detector strings regardless of verdict — e.g. a non-packer YARA rule
  "Armadillov1xxv2xx" can leave an "armadillo" artefact when the overall
  verdict is still negative).  Those artefacts are silently dropped here.

Usage
-----
    python utils/make_final_csv.py results.csv final.csv
    python utils/make_final_csv.py results.csv         # writes results_final.csv next to input
"""

import argparse
import csv
import os
import sys


def make_final_csv(input_path: str, output_path: str) -> None:
    input_path  = os.path.abspath(input_path)
    output_path = os.path.abspath(output_path)

    if not os.path.exists(input_path):
        print(f"[!] Input not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    packed_count   = 0
    unpacked_count = 0
    unknown_count  = 0  # packed but no name
    named_count    = 0  # packed and named

    with open(input_path, newline="", encoding="utf-8") as fin, \
         open(output_path, "w", newline="", encoding="utf-8") as fout:

        reader = csv.DictReader(fin)
        writer = csv.DictWriter(fout, fieldnames=["sample_file", "packer_label", "packed"])
        writer.writeheader()

        for row in reader:
            is_packed = row.get("overall_packed", "no") == "yes"

            if is_packed:
                packed_count += 1
                raw_name = row.get("detected_packer_name", "").strip()
                if raw_name:
                    packer_label = raw_name
                    named_count += 1
                else:
                    packer_label = "unknown"
                    unknown_count += 1
            else:
                unpacked_count += 1
                packer_label = ""   # no packer — label is meaningless

            writer.writerow({
                "sample_file":  row.get("file", ""),
                "packer_label": packer_label,
                "packed":       is_packed,
            })

    total = packed_count + unpacked_count
    print(f"[*] Read   {total:,} rows from {input_path}")
    print(f"[*] Wrote  {total:,} rows to   {output_path}")
    print(f"")
    print(f"    packed=True  : {packed_count:,}")
    print(f"      named      : {named_count:,}")
    print(f"      unknown    : {unknown_count:,}")
    print(f"    packed=False : {unpacked_count:,}")


def main():
    parser = argparse.ArgumentParser(
        description="Produce slim sample_file / packer_label / packed CSV from verification results."
    )
    parser.add_argument("input",  help="Path to results.csv from pack_verifier / extract_and_verify")
    parser.add_argument("output", nargs="?", default=None,
                        help="Output path (default: <input_stem>_final.csv beside the input)")
    args = parser.parse_args()

    if args.output:
        output_path = args.output
    else:
        stem, _ = os.path.splitext(os.path.abspath(args.input))
        output_path = stem + "_final.csv"

    make_final_csv(args.input, output_path)


if __name__ == "__main__":
    main()
