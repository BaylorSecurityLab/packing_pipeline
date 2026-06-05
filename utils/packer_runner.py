import argparse
import os
import shutil
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
if os.name == "nt":
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
    "exe32pack": {
        "use_dialog_killer": True,
        "timeout": 30,
    },
    "upx": {
        "use_dialog_killer": False,
        "timeout": 1000,
    },
    "eronona": {
        "use_dialog_killer": False,
        "timeout": 60,
    },
    "pezor": {
        "use_dialog_killer": False,
        "timeout": 300,
    },
    # Default for unknown packers
    "_default": {
        "use_dialog_killer": False,
        "timeout": 60,
    },
}


# Global verbosity flag. When False (default) we only show progress bars,
# failures, the active packer, and its test cases. When True we print everything.
VERBOSE = False


def vlog(msg):
    """Print only when --verbose is set (uses tqdm.write so bars stay intact)."""
    if VERBOSE:
        tqdm.write(msg)


def get_packer_settings(packer_name):
    return PACKER_SETTINGS.get(packer_name.lower(), PACKER_SETTINGS["_default"])


def sanitize_filename(filename):
    """
    Convert filename to ASCII-safe version, replacing spaces with underscores.
    """
    # 1. Replace spaces with underscores immediately
    filename = filename.replace(" ", "_")

    try:
        filename.encode("ascii")
        return filename  # Already ASCII-safe
    except UnicodeEncodeError:
        pass

    name, ext = os.path.splitext(filename)

    # Extract ASCII portions
    ascii_parts = re.findall(r"[\x00-\x7F]+", name)
    # Join and strip bad chars
    ascii_portion = "".join(ascii_parts).strip("_-")

    # Create short hash of original name for uniqueness
    name_hash = hashlib.md5(name.encode("utf-8")).hexdigest()[:8]

    if ascii_portion:
        safe_name = f"{ascii_portion}_{name_hash}"
    else:
        safe_name = f"packed_{name_hash}"

    return safe_name + ext


def dialog_killer(stop_event, target_keywords=None):
    """Background thread that auto-closes error dialog boxes."""
    if os.name != "nt":
        return

    # Keywords to match in dialog titles (case-insensitive)
    target_keywords = target_keywords or [
        "error",
        "exe32pack",
        "evaluation",
        "trial",
        "limit",
        "warning",
        "notice",
    ]

    closed_count = [0]

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
        vlog(f"[*] Dialog killer closed {closed_count[0]} popup(s)")


# --- CONFIGURATION ---
BENIGN_SOURCE_DIR = "../benign_sources"
PACKED_OUTPUT_DIR = "../packed_sources"
YAML_CONFIG_FILE = "../manifest/packer_corpus.yaml"

# UPDATED: Enforce strict x86 mapping
ARCH_MAP = {
    "PE32": ["x86"],
    "PE32+": [],  # Disabled x64
    "PE64": [],  # Disabled x64
    "BOTH": ["x86"],  # Only take the x86 portion
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
                # Skip already-packed files
                if ".packed" in f.lower():
                    continue
                if os.path.isfile(full_path) and f.lower().endswith(".exe"):
                    targets.append(full_path)
    return targets


# --- SHORT PATH FOR UNICODE FILENAMES ---
if os.name == "nt":
    _GetShortPathNameW = ctypes.windll.kernel32.GetShortPathNameW
    _GetShortPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    _GetShortPathNameW.restype = wintypes.DWORD


def get_short_path(path):
    """Convert a path to its Windows 8.3 short form (ASCII-safe)."""
    if os.name != "nt":
        return path

    try:
        path.encode("ascii")
        return path
    except UnicodeEncodeError:
        pass

    # Must exist for GetShortPathName to work
    if not os.path.exists(path):
        return path

    buf_size = _GetShortPathNameW(path, None, 0)
    if buf_size == 0:
        return path

    buf = ctypes.create_unicode_buffer(buf_size)
    _GetShortPathNameW(path, buf, buf_size)
    return buf.value


def to_wsl_path(win_path):
    """Convert a Windows path to WSL path format."""
    # Normalize to absolute path
    abs_path = os.path.abspath(win_path)
    # Convert C:\Users\... to /mnt/c/Users/...
    if len(abs_path) >= 2 and abs_path[1] == ":":
        drive = abs_path[0].lower()
        rest = abs_path[2:].replace("\\", "/")
        return f"/mnt/{drive}{rest}"
    return abs_path.replace("\\", "/")


def pack_single_file(args):
    """Worker function to pack a single file."""
    (
        src_path,
        output_dir,
        packer_bin,
        cmd_template,
        max_size_kb,
        timeout,
        output_behavior,
        dependencies,
        config,
        project_file,
    ) = args

    filename = os.path.basename(src_path)
    safe_filename = sanitize_filename(filename)
    dst_path = os.path.join(output_dir, safe_filename)

    if max_size_kb > 0:
        file_size_kb = os.path.getsize(src_path) / 1024
        if file_size_kb > max_size_kb:
            return False, f"Skipped (Too large: {file_size_kb:.1f} KB)"

    if os.path.exists(dst_path):
        return False, "Skipped (Exists)"

    current_input = src_path
    temp_files_to_clean = []

    if dependencies:
        for dep_name in dependencies:
            dep_def = next(
                (
                    p
                    for p in config.get("definitions", [])
                    if p["packer_name"].lower() == dep_name.lower()
                ),
                None,
            )
            dep_test_cases = [
                t
                for t in config.get("test_cases", [])
                if t["packer_name"].lower() == dep_name.lower()
            ]

            if not dep_def or not dep_test_cases:
                return False, f"Dependency or test case not found for: {dep_name}"

            dep_case = next(
                (t for t in dep_test_cases if "DEFAULT" in t["id"]), dep_test_cases[0]
            )

            # --- FIX: Use a safe local path for the dependency stage ---
            # This prevents the "FileNotFound" error by avoiding long absolute paths with spaces
            dep_stage_path = os.path.abspath(
                os.path.join(output_dir, f"stage_{dep_name}_{safe_filename}")
            )

            # Create a local temporary copy of the current_input to the output_dir
            # so the packer is working on a local file, not a deep-pathed source file.
            temp_local_input = os.path.abspath(
                os.path.join(output_dir, f"tmp_input_{dep_name}.exe")
            )
            shutil.copy2(current_input, temp_local_input)
            temp_files_to_clean.append(temp_local_input)

            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.abspath(os.path.join(script_dir, ".."))
            raw_dep_bin = dep_case["binary_path"]
            if raw_dep_bin.startswith("./"):
                raw_dep_bin = raw_dep_bin[2:]
            dep_bin = os.path.abspath(os.path.join(project_root, raw_dep_bin))

            # Build command using the local temp input
            dep_raw_template = dep_case["cli_template"]
            dep_cmd_parts = dep_raw_template.split()
            dep_command = []

            for part in dep_cmd_parts:
                # We use get_short_path to further protect against path issues
                new_part = (
                    part.replace("{bin}", get_short_path(dep_bin))
                    .replace("{in}", get_short_path(temp_local_input))
                    .replace("{out}", get_short_path(dep_stage_path))
                    .replace("{python}", sys.executable)
                )
                dep_command.append(new_part)

            try:
                # Handle in_place for dependencies
                if dep_def.get("output_behavior") == "in_place":
                    shutil.copy2(temp_local_input, dep_stage_path)
                    dep_command = [
                        p.replace(
                            get_short_path(temp_local_input),
                            get_short_path(dep_stage_path),
                        )
                        for p in dep_command
                    ]

                subprocess.run(
                    dep_command,
                    check=True,
                    capture_output=True,
                    timeout=timeout,
                    cwd=os.path.dirname(dep_bin),
                )

                current_input = dep_stage_path
                temp_files_to_clean.append(dep_stage_path)
            except subprocess.CalledProcessError as e:
                return False, f"Dependency {dep_name} failed: {e.stderr.decode()}"
            except Exception as e:
                return False, f"Stage failed ({dep_name}): {str(e)}"

    # --- Create local temp for intermediate files and Safe Input Copy ---
    local_temp = os.path.join(output_dir, "_temp_build")
    os.makedirs(local_temp, exist_ok=True)

    # --- NEW: Create a safe, simple copy of the input file ---
    # This solves issues with spaces, Unicode, and long paths in legacy packers.
    # The packer will work on 'in.exe' inside the temp folder.
    safe_input_name = "in.exe"
    safe_input_path = os.path.join(local_temp, safe_input_name)

    # Clean up previous temp files to ensure no collision
    if os.path.exists(safe_input_path):
        try:
            os.remove(safe_input_path)
        except:
            pass

    try:
        shutil.copyfile(src_path, safe_input_path)
    except Exception as e:
        return False, f"Failed to create temp input copy: {e}"

    # Calculate EXPECTED output locations based on the SAFE INPUT name (in.exe)
    # Because the packer runs on 'in.exe' in 'local_temp', the output will be there.
    safe_name_no_ext = os.path.splitext(safe_input_name)[0]  # "in"

    # Amber style: local_temp/in_packed.exe
    temp_amber_output = os.path.join(local_temp, f"{safe_name_no_ext}_packed.exe")

    # Eronona style: local_temp/in.packed.exe
    temp_suffix_output = os.path.join(local_temp, f"{safe_name_no_ext}.packed.exe")

    pack_env = os.environ.copy()
    pack_env["TEMP"] = os.path.abspath(local_temp)
    pack_env["TMP"] = os.path.abspath(local_temp)

    # In-place behavior: copy input to destination first, then pack destination
    if output_behavior == "in_place":
        try:
            shutil.copy2(safe_input_path, dst_path)
        except Exception as e:
            return False, f"Failed to setup in-place file: {e}"

    # --- Robust Command Construction ---
    raw_parts = cmd_template.split()
    command_list = []
    is_wsl_command = raw_parts[0].lower() == "wsl" if raw_parts else False

    # Prepare values for substitution
    # Use short paths for Windows binaries to avoid space issues
    val_bin = packer_bin
    if is_wsl_command:
        val_bin = to_wsl_path(packer_bin)

    val_in = get_short_path(os.path.abspath(safe_input_path))
    if is_wsl_command:
        val_in = to_wsl_path(val_in)

    val_out = os.path.abspath(dst_path)
    if output_behavior != "explicit_absolute":
        val_out = get_short_path(val_out)
    if is_wsl_command:
        val_out = to_wsl_path(val_out)

    val_python = sys.executable
    val_project = get_short_path(os.path.abspath(project_file)) if project_file else ""

    for part in raw_parts:
        # Use simple substitution to preserve flags attached to placeholders
        # e.g., "-f{in}" -> "-fC:\path\to\in.exe"
        new_part = part
        if "{python}" in new_part:
            new_part = new_part.replace("{python}", val_python)

        if "{bin}" in new_part:
            new_part = new_part.replace("{bin}", val_bin)

        if "{project}" in new_part:
            new_part = new_part.replace("{project}", val_project)

        if "{in}" in new_part:
            new_part = new_part.replace("{in}", val_in)

        if "{out}" in new_part:
            new_part = new_part.replace("{out}", val_out)

        command_list.append(new_part)

    try:
        cwd = os.path.dirname(packer_bin)

        # DEBUG: Uncomment the next line to see exactly what runs
        # print(f"DEBUG EXECUTING: {command_list}")

        result = subprocess.run(
            command_list,
            shell=False,
            check=True,
            capture_output=True,
            text=True,
            encoding="mbcs" if os.name == "nt" else "utf-8",
            errors="replace",
            timeout=timeout,
            env=pack_env,
            cwd=cwd,
            input="\n\n",
        )

        # Cleanup temp
        try:
            # We delay strict cleanup slightly to allow file handles to close
            pass
        except:
            pass

        # --- POST-PROCESSING ---

        # 1. Handle "input_dir_suffix" (Amber style)
        if output_behavior == "input_dir_suffix":
            if os.path.exists(temp_amber_output):
                if os.path.exists(dst_path):
                    os.remove(dst_path)
                shutil.move(temp_amber_output, dst_path)

        # 2. Handle "suffix_packed" (Eronona style)
        elif output_behavior == "suffix_packed":
            if os.path.exists(temp_suffix_output):
                if os.path.exists(dst_path):
                    os.remove(dst_path)
                shutil.move(temp_suffix_output, dst_path)

            # Fallback: sometimes it might drop in the CWD (unlikely with Safe Copy but possible)
            cwd_suffix_output = os.path.join(cwd, "in.packed.exe")
            if os.path.exists(cwd_suffix_output):
                if os.path.exists(dst_path):
                    os.remove(dst_path)
                shutil.move(cwd_suffix_output, dst_path)

        # 3. Final Verification
        if os.path.exists(dst_path):
            # Clean up input copy if successful
            try:
                os.remove(safe_input_path)
            except:
                pass
            return True, "Packed"
        else:
            combined_output = (
                f"STDOUT: {result.stdout.strip()} | STDERR: {result.stderr.strip()}"
            )
            return (
                False,
                f"Failed (No Output) - Behavior: {output_behavior} | {combined_output}",
            )

    except subprocess.TimeoutExpired:
        if os.path.exists(temp_amber_output):
            os.remove(temp_amber_output)
        if output_behavior == "in_place" and os.path.exists(dst_path):
            os.remove(dst_path)
        return False, "Timeout (possible stuck dialog)"

    except subprocess.CalledProcessError as e:
        if os.path.exists(temp_amber_output):
            os.remove(temp_amber_output)
        if output_behavior == "in_place" and os.path.exists(dst_path):
            os.remove(dst_path)
        combined_output = f"STDOUT: {e.stdout.strip()} | STDERR: {e.stderr.strip()}"
        return False, f"Exit Code {e.returncode} - {combined_output}"

    except Exception as e:
        if os.path.exists(temp_amber_output):
            os.remove(temp_amber_output)
        if output_behavior == "in_place" and os.path.exists(dst_path):
            os.remove(dst_path)
        return False, f"Exception: {str(e)}"


def run_packing(packer_name_input, max_size_kb=0, config=None, workers=1):
    if config is None:
        config = load_yaml(YAML_CONFIG_FILE)

    definitions = config.get("definitions", [])
    packer_def = next(
        (
            p
            for p in definitions
            if p["packer_name"].lower() == packer_name_input.lower()
        ),
        None,
    )

    if not packer_def:
        print(f"[!] Packer definition not found for: {packer_name_input}")
        return

    # Check if 'CLI' is in the tags
    tags = packer_def.get("tags", [])
    if "CLI" not in tags:
        print(f"[*] Skipping '{packer_name_input}' - Not a CLI tool (Tags: {tags})")
        return
    # ----------------------------------

    selected_tests = []
    for case in config.get("test_cases", []):
        if case.get("packer_name", "").lower() == packer_name_input.lower():
            selected_tests.append(case)

    if not selected_tests:
        print(f"[!] No test cases found for packer: '{packer_name_input}'")
        return

    tqdm.write(f"[*] Found {len(selected_tests)} test cases for '{packer_name_input}'")

    # Get packer-specific settings
    settings = get_packer_settings(packer_name_input)

    # Only start dialog killer if needed
    stop_event = None
    killer_thread = None
    if settings["use_dialog_killer"]:
        stop_event = threading.Event()
        killer_thread = threading.Thread(
            target=dialog_killer, args=(stop_event,), daemon=True
        )
        killer_thread.start()

    try:
        case_bar = tqdm(
            selected_tests,
            total=len(selected_tests),
            unit="case",
            desc=f"[{packer_name_input}] Test cases",
            position=1,
            leave=False,
        )
        for test_case in case_bar:
            test_id = test_case["id"]
            case_bar.set_postfix_str(test_id)

            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.abspath(os.path.join(script_dir, ".."))
            raw_bin_path = test_case["binary_path"]
            if raw_bin_path.startswith("./"):
                raw_bin_path = raw_bin_path[2:]
            packer_bin = os.path.join(project_root, raw_bin_path)

            if not os.path.exists(packer_bin):
                tqdm.write(f"    [!] Error: Packer binary not found at: {packer_bin}")
                continue

            # Include version in directory name (e.g., upx_5.1.0/TEST_ID)
            version = packer_def.get("version", "unknown")
            # Sanitize version for filesystem (replace spaces, parens, etc.)
            safe_version = re.sub(r'[^\w\.\-]', '_', version).strip('_')
            packer_dir_name = f"{packer_name_input}_{safe_version}"
            output_dir = os.path.join(PACKED_OUTPUT_DIR, packer_dir_name, test_id)
            os.makedirs(output_dir, exist_ok=True)

            targets = get_targets(test_case.get("supported_input_arch", "PE32"))
            if not targets:
                tqdm.write(
                    f"    [!] No targets found for case {test_id} (Checking x86 only)"
                )
                continue

            # Get the behavior from the definition (defaults to explicit)
            output_behavior = packer_def.get("output_behavior", "explicit")
            dependencies = packer_def.get("dependencies", [])

            # Resolve project_file if present
            raw_project = packer_def.get("project_file", "")
            if raw_project:
                if raw_project.startswith("./"):
                    raw_project = raw_project[2:]
                project_file_path = os.path.join(project_root, raw_project)
            else:
                project_file_path = ""

            vlog(f"\n--- Case: {test_id} (Workers: {workers}) ---")

            jobs = []
            for src in targets:
                jobs.append(
                    (
                        src,
                        output_dir,
                        packer_bin,
                        test_case["cli_template"],
                        max_size_kb,
                        settings["timeout"],
                        output_behavior,
                        dependencies,
                        config,
                        project_file_path,
                    )
                )

            success_count = 0

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                future_to_file = {
                    executor.submit(pack_single_file, job): job[0] for job in jobs
                }

                with tqdm(
                    total=len(jobs),
                    unit="file",
                    desc=f"  └─ Packing [{test_id}]",
                    position=2,
                    leave=False,
                ) as pbar:
                    for future in concurrent.futures.as_completed(future_to_file):
                        fname = os.path.basename(future_to_file[future])
                        try:
                            success, msg = future.result()
                            if success:
                                success_count += 1
                            elif msg.startswith("Skipped"):
                                # Skips are noise unless verbose
                                vlog(f"[~] {fname}: {msg}")
                            else:
                                tqdm.write(f"[-] {fname}: {msg}")
                        except Exception as exc:
                            tqdm.write(f"[x] Exception processing {fname}: {exc}")

                        pbar.update(1)

            tqdm.write(f"    Result: {success_count}/{len(targets)} packed.")

            # Clean up _temp_build directory
            temp_build_dir = os.path.join(output_dir, "_temp_build")
            if os.path.exists(temp_build_dir):
                try:
                    shutil.rmtree(temp_build_dir)
                except Exception as e:
                    tqdm.write(f"    [!] Warning: Could not remove temp dir: {e}")

        case_bar.close()

    finally:
        if stop_event:
            stop_event.set()

        if killer_thread:
            killer_thread.join(timeout=1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-threaded packer runner.")
    parser.add_argument(
        "packer_name",
        type=str,
        help="Packer name (e.g., 'upx', 'exe32pack', or 'all')",
        default="all",
    )
    parser.add_argument(
        "--max-size-kb", type=int, default=0, help="Skip files larger than KB."
    )
    default_workers = min(cpu_count(), 1)
    parser.add_argument(
        "--workers",
        type=int,
        default=default_workers,
        help=f"Number of parallel threads (default: {default_workers})",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Run pack verification after packing to delete unverified samples.",
    )
    parser.add_argument(
        "--verify-dry-run",
        action="store_true",
        help="Run pack verification in dry-run mode (report only, no deletes).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print everything. Without it: only progress bars, failures, "
        "the active packer, and its test cases.",
    )

    args = parser.parse_args()
    VERBOSE = args.verbose
    main_config = load_yaml(YAML_CONFIG_FILE)

    if args.packer_name.lower() == "all":
        # Get all unique packer names from definitions
        packers = list(
            set([d["packer_name"] for d in main_config.get("definitions", [])])
        )
        print(f"=== RUNNING ALL PACKERS: {', '.join(packers)} ===")
        packer_bar = tqdm(
            packers,
            total=len(packers),
            unit="packer",
            desc="Packers completed",
            position=0,
            leave=True,
        )
        for p in packer_bar:
            packer_bar.set_postfix_str(p)
            run_packing(p, args.max_size_kb, main_config, args.workers)
            tqdm.write("=" * 40)
        packer_bar.close()
    else:
        run_packing(args.packer_name, args.max_size_kb, main_config, args.workers)

    # Post-packing verification
    if args.verify or args.verify_dry_run:
        print("\n" + "=" * 50)
        print("POST-PACKING VERIFICATION")
        print("=" * 50)
        from pack_verifier import verify_directory
        packed_dir = os.path.abspath(PACKED_OUTPUT_DIR)
        if os.path.exists(packed_dir):
            verify_directory(packed_dir, dry_run=args.verify_dry_run)
        else:
            print(f"[!] No packed output directory found at: {packed_dir}")
