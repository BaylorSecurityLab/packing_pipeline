import argparse
import os
import subprocess

import yaml

# --- CONFIGURATION ---
BENIGN_SOURCE_DIR = "../benign_sources"  # Same base dir as your downloader
PACKED_OUTPUT_DIR = "../packed_sources"
YAML_CONFIG_FILE = "../manifest/packer_corpus.yaml"

# Architecture Mapping
ARCH_MAP = {
    "PE32": ["x86"],
    "PE64": ["x64"],
    "BOTH": ["x86", "x64"]
}


def load_yaml(path):
    if not os.path.exists(path):
        print(f"[!] Error: Configuration file '{path}' not found.")
        exit(1)
    with open(path, "r") as f:
        return yaml.safe_load(f)


def get_targets(supported_arch):
    """
    Scans for executables based on arch.
    Explicitly filters for .exe only to avoid .msi crashes.
    """
    target_folders = ARCH_MAP.get(supported_arch, [])
    if not target_folders:
        print(f"[!] Warning: Unknown architecture '{supported_arch}'. Defaulting to x86 only.")
        target_folders = ["x86"]

    targets = []
    for folder in target_folders:
        search_path = os.path.join(BENIGN_SOURCE_DIR, folder)
        if os.path.exists(search_path):
            for f in os.listdir(search_path):
                full_path = os.path.join(search_path, f)
                # FIX: Added check for .exe extension
                if os.path.isfile(full_path) and f.lower().endswith(".exe"):
                    targets.append(full_path)
    return targets


def run_packing(packer_name_input):
    config = load_yaml(YAML_CONFIG_FILE)
    selected_tests = []

    # Filter for the requested packer
    for case in config.get('test_cases', []):
        if case.get('packer_name', '').lower() == packer_name_input.lower():
            selected_tests.append(case)

    if not selected_tests:
        print(f"[!] No test cases found for packer: '{packer_name_input}'")
        return

    print(f"[*] Found {len(selected_tests)} test cases for '{packer_name_input}'")

    for test_case in selected_tests:
        test_id = test_case['id']
        packer_bin = os.path.abspath(test_case['binary_path'])
        cmd_template = test_case['cli_template']
        supp_arch = test_case.get('supported_input_arch', 'PE32')
        output_dir = os.path.join(PACKED_OUTPUT_DIR, packer_name_input, test_id)
        os.makedirs(output_dir, exist_ok=True)

        print(f"\n--- Running Case: {test_id} ---")
        targets = get_targets(supp_arch)

        if not targets:
            print(f"    [!] No .exe files found in benign sources for {supp_arch}")
            continue

        success_count = 0
        for src_path in targets:
            filename = os.path.basename(src_path)
            dst_path = os.path.join(output_dir, filename)

            if os.path.exists(dst_path):
                print(f"    [.] Skipping {filename} (exists)")
                continue

            # FIX: Use dictionary unpacking for arguments
            cmd_args = {
                "bin": f'"{packer_bin}"',
                "in": f'"{os.path.abspath(src_path)}"',
                "out": f'"{os.path.abspath(dst_path)}"'
            }
            cmd_str = cmd_template.format(**cmd_args)

            try:
                # FIX: Removed DEVNULL so we can capture output on error
                # We use capture_output=True to handle it manually
                result = subprocess.run(
                    cmd_str,
                    shell=True,
                    check=True,
                    capture_output=True,
                    text=True
                )

                if os.path.exists(dst_path):
                    print(f"    [+] Packed: {filename}")
                    success_count += 1
                else:
                    print(f"    [-] Failed (No Output File): {filename}")
                    # Print stdout/stderr if file wasn't created, even if exit code was 0
                    if result.stdout: print(f"        Output: {result.stdout.strip()}")
                    if result.stderr: print(f"        Error: {result.stderr.strip()}")

            except subprocess.CalledProcessError as e:
                print(f"    [x] Error packing {filename}")
                # FIX: Print the actual error from the packer
                if e.stdout: print(f"        STDOUT: {e.stdout.strip()}")
                if e.stderr: print(f"        STDERR: {e.stderr.strip()}")

        print(f"    Result: {success_count}/{len(targets)} packed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pack benign sources using defined test cases.")
    parser.add_argument("packer_name", type=str, help="The name of the packer to run (e.g., exe32pack)")

    args = parser.parse_args()

    run_packing(args.packer_name)