"""
UPX Scrambler GUI Automation Wrapper - Using Base GUI Wrapper

Covers all UPX Scrambler versions (3.0.4, 3.06, RC1, RC1.03, RC1.05, RC1b10).
The UI is identical across versions; only the packer name (YAML key) differs.
"""

import sys
import os
import time
from pathlib import Path
from base_gui import BaseGUI
import pyautogui
import pyperclip
import pygetwindow as gw
import traceback

# Add utils directory to path for packer_runner import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "utils"))
from packer_runner import pack_single_file, load_yaml, sanitize_filename


class UpxScramblerBase(BaseGUI):
    """
    Base wrapper for UPX Scrambler GUI automation.

    UPX Scrambler scrambles headers of UPX-packed executables to prevent
    automatic unpacking. Requires the input file to be UPX-packed first.

    Output behavior is in-place (modifies the UPX-packed file directly).

    Flow:
        1. Pack input file with UPX (via packer_runner)
        2. Launch UPX Scrambler GUI
        3. Load the UPX-packed file via file picker
        4. Click "Scramble!" button
        5. Wait for file lock to release (in-place modification)
        6. Move scrambled file to output directory
    """

    def __init__(self, yaml_path, main_dir, packer_name="UPX_Scrambler"):
        super().__init__(yaml_path, main_dir)
        self._packer_name = packer_name

    def get_packer_name(self):
        """Return the packer name for YAML lookup"""
        return self._packer_name

    def find_file_picker_window(self, timeout=10):
        """
        Find the file picker window opened by UPX Scrambler.

        Overrides base class to use broader patterns and log all visible
        window titles for debugging when the picker isn't found.
        """
        print("\n[INFO] Searching for file picker window...")
        start_time = time.time()

        patterns = self.FILE_PICKER_PATTERNS + [
            "UPX",
            "Scrambler",
            "upxs",
            "Ouvrir",
            "Abrir",
            "Öffnen",
            "Save",
            "File",
        ]

        while time.time() - start_time < timeout:
            try:
                all_titles = [t for t in gw.getAllTitles() if t.strip()]

                for title in all_titles:
                    if any(p.lower() in title.lower() for p in patterns):
                        print(f"[SUCCESS] Found file picker: '{title}'")
                        return gw.getWindowsWithTitle(title)[0]

            except Exception as e:
                print(f"[DEBUG] Error during file picker search: {e}")

            time.sleep(0.3)

        # Print all titles for debugging
        print("[DEBUG] All visible window titles:")
        try:
            for title in gw.getAllTitles():
                if title.strip():
                    print(f"  - '{title}'")
        except Exception:
            pass

        print("[ERROR] File picker window not found within timeout")
        return None

    def pack_with_upx(self, input_file, temp_dir):
        """
        Pack the input file with UPX using packer_runner.

        Args:
            input_file: Path to the original input file
            temp_dir: Directory to output the UPX-packed file

        Returns:
            str: Path to the UPX-packed file, or None on failure
        """
        print("\n[INFO] === UPX PRE-PACKING STEP ===")
        print(f"[INFO] Input: {input_file}")
        print(f"[INFO] Temp dir: {temp_dir}")

        config = load_yaml(str(self.yaml_path))

        # Find UPX DEFAULT test case from YAML
        upx_test = None
        for case in config.get("test_cases", []):
            if case.get("packer_family", "").upper() == "UPX" and "DEFAULT" in case["id"]:
                upx_test = case
                break

        if not upx_test:
            print("[ERROR] UPX DEFAULT test case not found in YAML")
            return None

        # Get UPX binary path
        raw_bin = upx_test["binary_path"]
        if raw_bin.startswith("./"):
            raw_bin = raw_bin[2:]
        upx_bin = str(self.main_dir / raw_bin)

        if not os.path.exists(upx_bin):
            print(f"[ERROR] UPX binary not found at: {upx_bin}")
            return None

        print(f"[INFO] UPX binary: {upx_bin}")
        print(f"[INFO] CLI template: {upx_test['cli_template']}")

        # pack_single_file returns "Skipped (Exists)" if the destination already
        # exists, which would make a re-run fail. Remove any stale intermediate
        # from a previous run so UPX always packs fresh.
        safe_name = sanitize_filename(Path(input_file).name)
        upx_packed = Path(temp_dir) / safe_name
        try:
            if upx_packed.exists():
                upx_packed.unlink()
        except OSError as e:
            print(f"[WARNING] Could not remove stale UPX output {upx_packed}: {e}")

        # Build args tuple for pack_single_file. This is a throwaway
        # intermediate (the scrambler runs on top of it), so it must NOT go
        # through the SHA gate -- pass sha_gate=None. The 11th field
        # (packer_name) drives PACKER_SETTINGS; "upx" gets sensible defaults.
        args = (
            str(input_file),
            str(temp_dir),
            upx_bin,
            upx_test["cli_template"],
            0,
            1000,
            "explicit",
            [],
            config,
            "",
            "upx",       # packer_name (required 11th field)
            None,        # sha_gate: never gate the intermediate
            "upx",       # packer_dir_name (unused when gate is None)
        )

        success, msg = pack_single_file(args)
        print(f"[INFO] UPX result: {msg}")

        if success and upx_packed.exists():
            print(f"[SUCCESS] UPX packed file: {upx_packed}")
            print(f"[INFO] Size: {upx_packed.stat().st_size:,} bytes")
            return str(upx_packed)

        print(f"[ERROR] UPX packing failed: {msg}")
        return None

    def wait_for_scramble_complete(self, input_file_path):
        """
        Wait for the in-place scrambling to complete with stability verification.

        UPX Scrambler modifies the file in-place, so we watch the file
        for lock release. Requires N consecutive unlocked checks.

        Args:
            input_file_path: Path to the file being scrambled

        Returns:
            str: Path to scrambled file if successful, None otherwise
        """
        # Interaction is complete; release the input lock so other packers can
        # interact while this one watches its output file.
        self.release_input()
        timeout = self.EXTRA_LONG_TIMEOUT
        input_path = Path(input_file_path)
        check_interval = self.LONG_TIMEOUT

        required_stable_checks = 5
        stable_count = 0

        print("\n[INFO] Waiting for scrambling to complete...")
        print(f"[INFO] Watching: {input_path}")
        print(
            f"[INFO] Stability Requirement: {required_stable_checks} consecutive unlocked checks"
        )
        print(f"[INFO] Interval: {check_interval}s | Timeout: {timeout}s")

        start_time = time.time()

        # Initial buffer to let the scrambler start its work
        time.sleep(10)

        while time.time() - start_time < timeout:
            elapsed = int(time.time() - start_time)

            if input_path.exists():
                current_size = input_path.stat().st_size

                if self.is_file_locked(str(input_path)):
                    if stable_count > 0:
                        print(
                            f"  [{elapsed}s] Lock reappeared! Resetting stability counter."
                        )
                    stable_count = 0
                    print(f"  [{elapsed}s] Scrambling... {current_size:,} bytes")
                else:
                    stable_count += 1
                    print(
                        f"  [{elapsed}s] File unlocked. Verification {stable_count}/{required_stable_checks}..."
                    )

                    if stable_count >= required_stable_checks:
                        print(
                            f"\n[SUCCESS] Scrambling complete and verified stable! ({elapsed}s)"
                        )
                        print(f"[INFO] Output file: {input_path}")
                        print(f"[INFO] Final size: {current_size:,} bytes")
                        return str(input_path)
            else:
                print(f"  [{elapsed}s] File not found, waiting...")
                stable_count = 0

            time.sleep(check_interval)

        print(
            f"\n[ERROR] Timeout after {timeout}s waiting for stable scramble completion"
        )
        return None

    def run(self, click_mode="all", file_path=None, output_dir=None):
        """
        Main execution flow for UPX Scrambler.

        Args:
            click_mode: Configuration mode
            file_path: Path to the input file
            output_dir: Directory to move final output to (optional)

        Returns:
            bool: True if successful, False otherwise
        """
        input_file = None
        upx_packed_file = None

        try:
            # Step 1: Load packer info from YAML
            print("\n" + "=" * 60)
            print(f"UPX SCRAMBLER GUI AUTOMATION ({self._packer_name})")
            print("=" * 60)

            if not self.load_packer_info():
                print("[ERROR] Failed to load packer info from YAML")
                return False

            if not file_path:
                print("[ERROR] No file path provided")
                return False

            input_file = Path(file_path).resolve()
            print(f"[INFO] Input file: {input_file}")

            # Step 2: Pack with UPX first using packer_runner
            # Output the UPX-packed file to a temp directory
            temp_dir = (
                Path(output_dir) / "temp_upx"
                if output_dir
                else input_file.parent / "temp_upx"
            )
            temp_dir.mkdir(parents=True, exist_ok=True)

            upx_packed_file = self.pack_with_upx(str(input_file), str(temp_dir))
            if not upx_packed_file:
                print("[ERROR] Failed to pack file with UPX")
                return False

            # Step 3: Launch UPX Scrambler application
            print("\n[INFO] Launching UPX Scrambler...")
            if not self.launch_application():
                print("[ERROR] Failed to launch application")
                return False

            # Step 4: Find the window
            if not self.find_window():
                print("[WARNING] Could not find window by PID, trying title search...")
                if not self.find_window(window_title="UPX"):
                    print("[ERROR] Could not find UPX Scrambler window")
                    return False

            print("\n[SUCCESS] UPX Scrambler launched successfully!")
            print(f"[INFO] Window title: {self.window.title}")

            # Step 5: Center window on monitor
            time.sleep(0.3)
            self.center_window_on_monitor(monitor_number=1)

            # Step 6: Load the UPX-packed file via browse button and file picker
            print(f"\n[INFO] Loading UPX-packed file: {upx_packed_file}")

            # Click the browse/open button to open file picker
            time.sleep(0.5)
            self.click_at_percent(0.90, 0.50, "Browse/Open button")
            time.sleep(1.0)

            # Use the file picker to navigate and select the file
            app_name = self.extract_app_name(upx_packed_file)
            if not self.paste_file_path_in_picker(upx_packed_file, app_name):
                print("[ERROR] Failed to select file in picker")
                self.close_application()
                return False

            time.sleep(0.5)
            print("[SUCCESS] File loaded!")

            # Step 7: Click the "Scramble!" button
            time.sleep(0.5)
            self.click_at_percent(0.80, 0.75, "Scramble! button")

            print("[INFO] Scrambling process initiated!")

            # Step 8: Wait for scrambling to complete
            scrambled_file = self.wait_for_scramble_complete(upx_packed_file)

            if scrambled_file:
                # Step 9: Move to output directory if specified
                final_path = self.move_protected_file_to_output(
                    scrambled_file, output_dir
                )

                if final_path:
                    print(f"\n{'=' * 60}")
                    print("SCRAMBLING COMPLETE")
                    print(f"{'=' * 60}")
                    print(f"  Input:  {input_file}")
                    print(f"  Output: {final_path}")
                    print(f"{'=' * 60}")

                # Step 10: Close application
                self.close_application()

                # Cleanup temp UPX directory
                import shutil

                if temp_dir.exists():
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    print(f"[INFO] Cleaned up temp dir: {temp_dir}")

                print("\n[SUCCESS] Automation complete!")
                return True
            else:
                print("[ERROR] Scrambling process failed or timed out!")
                self.close_application()
                return False

        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")
            traceback.print_exc()
            if input_file:
                self.cleanup_on_failure(str(input_file))
            else:
                self.close_application()
            return False


# Version-specific subclasses — UI is identical across all versions;
# only the packer_name (YAML key) differs.

class UpxScrambler304(UpxScramblerBase):
    def __init__(self, yaml_path, main_dir):
        super().__init__(yaml_path, main_dir, "UPX_Scrambler")


class UpxScrambler306(UpxScramblerBase):
    def __init__(self, yaml_path, main_dir):
        super().__init__(yaml_path, main_dir, "UPX_Scrambler_3.06")


class UpxScramblerRC1(UpxScramblerBase):
    def __init__(self, yaml_path, main_dir):
        super().__init__(yaml_path, main_dir, "UPX_Scrambler_RC1")


class UpxScramblerRC103(UpxScramblerBase):
    def __init__(self, yaml_path, main_dir):
        super().__init__(yaml_path, main_dir, "UPX_Scrambler_RC1.03")


class UpxScramblerRC105(UpxScramblerBase):
    def __init__(self, yaml_path, main_dir):
        super().__init__(yaml_path, main_dir, "UPX_Scrambler_RC1.05")


class UpxScramblerRC1b10(UpxScramblerBase):
    def __init__(self, yaml_path, main_dir):
        super().__init__(yaml_path, main_dir, "UPX_Scrambler_RC1b10")


def main():
    """Entry point — defaults to UPX Scrambler 3.0.4"""
    import argparse

    parser = argparse.ArgumentParser(
        description="UPX Scrambler GUI Automation Wrapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--file-path", type=str, default=None, help="Full path to the file to process"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory to copy the scrambled file to",
    )

    args = parser.parse_args()

    script_dir = Path(__file__).parent
    main_dir = script_dir.parent
    yaml_path = main_dir / "manifest" / "packer_corpus.yaml"

    print(f"Script directory: {script_dir}")
    print(f"Main directory: {main_dir}")
    print(f"YAML path: {yaml_path}")

    if not yaml_path.exists():
        print(f"\n[ERROR] YAML file not found at: {yaml_path}")
        return 1

    wrapper = UpxScrambler304(yaml_path, main_dir)
    success = wrapper.run(file_path=args.file_path, output_dir=args.output_dir)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
