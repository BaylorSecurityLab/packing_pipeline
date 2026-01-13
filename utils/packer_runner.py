import argparse
import os
import subprocess
import sys
import yaml
import concurrent.futures
import threading
import time
from multiprocessing import cpu_count
from tqdm import tqdm
import hashlib
import re


# --- DIALOG KILLER (Windows only) ---
if os.name == 'nt':
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32

    _EnumWindows = user32.EnumWindows
    _GetWindowTextW = user32.GetWindowTextW
    _GetClassNameW = user32.GetClassNameW
    _PostMessageW = user32.PostMessageW
    _IsWindowVisible = user32.IsWindowVisible

    _WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    _WM_CLOSE = 0x0010

# Packer-specific settings
PACKER_SETTINGS = {
    'exe32pack': {
        'use_dialog_killer': True,
        'timeout': 30,
    },
    'upx': {
        'use_dialog_killer': False,
        'timeout': 1000,
    },
    # Default for unknown packers
    '_default': {
        'use_dialog_killer': False,
        'timeout': 60,
    }
}

def get_packer_settings(packer_name):
    return PACKER_SETTINGS.get(packer_name.lower(), PACKER_SETTINGS['_default'])

def sanitize_filename(filename):
    """
    Convert filename to ASCII-safe version.
    Preserves ASCII chars, replaces Unicode with a short hash.
    """
    try:
        filename.encode('ascii')
        return filename  # Already ASCII-safe
    except UnicodeEncodeError:
        pass

    name, ext = os.path.splitext(filename)

    # Extract ASCII portions and create hash for non-ASCII
    ascii_parts = re.findall(r'[\x00-\x7F]+', name)
    ascii_portion = ''.join(ascii_parts).strip('_- ')

    # Create short hash of original name for uniqueness
    name_hash = hashlib.md5(name.encode('utf-8')).hexdigest()[:8]

    if ascii_portion:
        # Keep ASCII part + hash: "AcFun_1.32.0.1772_Machine_X64_inno_en-US" -> "AcFun_1.32.0.1772_a1b2c3d4"
        safe_name = f"{ascii_portion}_{name_hash}"
    else:
        # Pure non-ASCII: just use hash
        safe_name = f"packed_{name_hash}"

    return safe_name + ext

def dialog_killer(stop_event, target_keywords=None):
    """Background thread that auto-closes error dialog boxes."""
    if os.name != 'nt':
        return

    # Keywords to match in dialog titles (case-insensitive)
    target_keywords = target_keywords or [
        "error", "exe32pack", "evaluation", "trial",
        "limit", "warning", "notice"
    ]

    closed_count = [0]  # Use list to allow modification in nested function

    def enum_callback(hwnd, _):
        if not _IsWindowVisible(hwnd):
            return True

        class_name = ctypes.create_unicode_buffer(256)
        _GetClassNameW(hwnd, class_name, 256)

        # #32770 is the Windows dialog box class
        if class_name.value == "#32770":
            title = ctypes.create_unicode_buffer(256)
            _GetWindowTextW(hwnd, title, 256)
            title_lower = title.value.lower()

            if any(kw in title_lower for kw in target_keywords):
                _PostMessageW(hwnd, _WM_CLOSE, 0, 0)
                closed_count[0] += 1
        return True

    callback = _WNDENUMPROC(enum_callback)

    while not stop_event.is_set():
        _EnumWindows(callback, 0)
        time.sleep(0.05)  # Check every 50ms

    if closed_count[0] > 0:
        tqdm.write(f"[*] Dialog killer closed {closed_count[0]} popup(s)")


# --- CONFIGURATION ---
BENIGN_SOURCE_DIR = "../benign_sources"
PACKED_OUTPUT_DIR = "../packed_sources"
YAML_CONFIG_FILE = "../manifest/packer_corpus.yaml"

ARCH_MAP = {
    "PE32": ["x86"],
    "PE32+": ["x64"],
    "PE64": ["x64"],
    "BOTH": ["x86", "x64"]
}


def load_yaml(path):
    if not os.path.exists(path):
        print(f"[!] Error: Configuration file '{path}' not found.")
        sys.exit(1)
    with open(path, "r") as f:
        return yaml.safe_load(f)


def get_targets(supported_arch):
    if isinstance(supported_arch, list):
        requested_archs = supported_arch
    else:
        requested_archs = [supported_arch]

    target_folders = set()
    for arch in requested_archs:
        folders = ARCH_MAP.get(arch, [])
        if folders:
            target_folders.update(folders)

    targets = []
    for folder in target_folders:
        search_path = os.path.join(BENIGN_SOURCE_DIR, folder)
        if os.path.exists(search_path):
            for f in os.listdir(search_path):
                full_path = os.path.join(search_path, f)
                if os.path.isfile(full_path) and f.lower().endswith(".exe"):
                    targets.append(full_path)
    return targets


# --- SHORT PATH FOR UNICODE FILENAMES ---
if os.name == 'nt':
    _GetShortPathNameW = ctypes.windll.kernel32.GetShortPathNameW
    _GetShortPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    _GetShortPathNameW.restype = wintypes.DWORD


def get_short_path(path):
    """Convert a path to its Windows 8.3 short form (ASCII-safe)."""
    if os.name != 'nt':
        return path

    try:
        path.encode('ascii')
        return path
    except UnicodeEncodeError:
        pass

    buf_size = _GetShortPathNameW(path, None, 0)
    if buf_size == 0:
        return path

    buf = ctypes.create_unicode_buffer(buf_size)
    _GetShortPathNameW(path, buf, buf_size)
    return buf.value


def pack_single_file(args):
    """Worker function to pack a single file."""
    src_path, output_dir, packer_bin, cmd_template, max_size_kb, timeout = args

    filename = os.path.basename(src_path)
    safe_filename = sanitize_filename(filename)
    dst_path = os.path.join(output_dir, safe_filename)

    if max_size_kb > 0:
        file_size_kb = os.path.getsize(src_path) / 1024
        if file_size_kb > max_size_kb:
            return False, f"Skipped (Too large: {file_size_kb:.1f} KB)"

    if os.path.exists(dst_path):
        return False, "Skipped (Exists)"

    raw_parts = cmd_template.split()
    command_list = []

    for part in raw_parts:
        if "{bin}" in part:
            command_list.append(packer_bin)
        elif "{in}" in part:
            command_list.append(get_short_path(os.path.abspath(src_path)))
        elif "{out}" in part:
            command_list.append(get_short_path(os.path.abspath(dst_path)))
        else:
            command_list.append(part)

    try:
        result = subprocess.run(
            command_list,
            shell=False,
            check=True,
            capture_output=True,
            text=True,
            encoding='mbcs' if os.name == 'nt' else 'utf-8',
            errors='replace',
            timeout=timeout
        )

        if os.path.exists(dst_path):
            return True, "Packed"
        else:
            combined_output = f"STDOUT: {result.stdout.strip()} | STDERR: {result.stderr.strip()}"
            return False, f"Failed (No Output) - {combined_output}"

    except subprocess.TimeoutExpired:
        return False, "Timeout (possible stuck dialog)"
    except subprocess.CalledProcessError as e:
        combined_output = f"STDOUT: {e.stdout.strip()} | STDERR: {e.stderr.strip()}"
        return False, f"Exit Code {e.returncode} - {combined_output}"
    except Exception as e:
        return False, f"Exception: {str(e)}"


def run_packing(packer_name_input, max_size_kb=0, config=None, workers=1):
    if config is None:
        config = load_yaml(YAML_CONFIG_FILE)

    selected_tests = []
    for case in config.get('test_cases', []):
        if case.get('packer_name', '').lower() == packer_name_input.lower():
            selected_tests.append(case)

    if not selected_tests:
        print(f"[!] No test cases found for packer: '{packer_name_input}'")
        return

    print(f"[*] Found {len(selected_tests)} test cases for '{packer_name_input}'")

    # Get packer-specific settings
    settings = get_packer_settings(packer_name_input)

    # Only start dialog killer if needed
    stop_event = None
    killer_thread = None
    if settings['use_dialog_killer']:
        stop_event = threading.Event()
        killer_thread = threading.Thread(
            target=dialog_killer,
            args=(stop_event,),
            daemon=True
        )
        killer_thread.start()

    try:
        for test_case in selected_tests:
            test_id = test_case['id']

            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.abspath(os.path.join(script_dir, ".."))
            raw_bin_path = test_case['binary_path']
            if raw_bin_path.startswith("./"):
                raw_bin_path = raw_bin_path[2:]
            packer_bin = os.path.join(project_root, raw_bin_path)

            if not os.path.exists(packer_bin):
                print(f"    [!] Error: Packer binary not found at: {packer_bin}")
                continue

            output_dir = os.path.join(PACKED_OUTPUT_DIR, packer_name_input, test_id)
            os.makedirs(output_dir, exist_ok=True)

            targets = get_targets(test_case.get('supported_input_arch', 'PE32'))
            if not targets:
                print(f"    [!] No targets found for case {test_id}")
                continue

            print(f"\n--- Case: {test_id} (Workers: {workers}) ---")

            jobs = []
            for src in targets:
                jobs.append((
                    src, output_dir, packer_bin, test_case['cli_template'],
                    max_size_kb, settings['timeout']
                ))

            success_count = 0

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                future_to_file = {executor.submit(pack_single_file, job): job[0] for job in jobs}

                with tqdm(total=len(jobs), unit="file", desc="Packing") as pbar:
                    for future in concurrent.futures.as_completed(future_to_file):
                        fname = os.path.basename(future_to_file[future])
                        try:
                            success, msg = future.result()
                            if success:
                                success_count += 1
                            else:
                                tqdm.write(f"[-] {fname}: {msg}")
                        except Exception as exc:
                            tqdm.write(f"[x] Exception processing {fname}: {exc}")

                        pbar.update(1)

            print(f"    Result: {success_count}/{len(targets)} packed.")


    finally:

        if stop_event:
            stop_event.set()

        if killer_thread:
            killer_thread.join(timeout=1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-threaded packer runner.")
    parser.add_argument("packer_name", type=str, help="Packer name (e.g., 'upx', 'exe32pack', or 'all')")
    parser.add_argument("--max-size-kb", type=int, default=0, help="Skip files larger than KB.")
    default_workers = cpu_count()
    parser.add_argument("--workers", type=int, default=default_workers,
                        help=f"Number of parallel threads (default: {default_workers})")

    args = parser.parse_args()
    main_config = load_yaml(YAML_CONFIG_FILE)

    if args.packer_name.lower() == "all":
        packers = list(set([d['packer_name'] for d in main_config.get('definitions', [])]))
        print(f"=== RUNNING ALL PACKERS: {', '.join(packers)} ===")
        for p in packers:
            run_packing(p, args.max_size_kb, main_config, args.workers)
            print("=" * 40)
    else:
        run_packing(args.packer_name, args.max_size_kb, main_config, args.workers)