"""
Yoda's Crypter v1.2 GUI Automation Wrapper
"""

import sys
import time
from pathlib import Path
from base_gui import BaseGUI
import pyautogui
import traceback


class YodaCrypterV12(BaseGUI):
    """
    Wrapper for Yoda's Crypter (yC) v1.2 GUI automation.

    In-place packer: output file replaces the input file (same name/path).

    NOTE: v1.2 UI differences from v1.3:
      - TODO: document button positions / dialog titles once confirmed
    """

    def __init__(self, yaml_path, main_dir):
        """Initialize YodaCrypterV12 wrapper"""
        super().__init__(yaml_path, main_dir)

    def get_packer_name(self):
        """Return the packer name for YAML lookup"""
        return "yoda_crypter_v1.2"

    def wait_for_packing_complete(self, input_file_path):
        """
        Wait for in-place packing to complete with stability verification.

        Yoda's Crypter modifies the input file in-place, so we watch the
        input file itself for lock release. Requires N consecutive unlocked
        checks to confirm completion.

        Args:
            input_file_path: Path to the file being packed

        Returns:
            str: Path to packed file if successful, None otherwise
        """
        # Interaction is complete; release the input lock so other packers can
        # interact while this one watches its output file.
        self.release_input()
        timeout = self.EXTRA_LONG_TIMEOUT
        input_path = Path(input_file_path)
        check_interval = self.LONG_TIMEOUT

        required_stable_checks = 5
        stable_count = 0

        print("\n[INFO] Waiting for packing to complete...")
        print(f"[INFO] Watching: {input_path}")
        print(
            f"[INFO] Stability Requirement: {required_stable_checks} consecutive unlocked checks"
        )
        print(f"[INFO] Interval: {check_interval}s | Timeout: {timeout}s")

        start_time = time.time()

        # Initial buffer to let the packer start its work
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
                    print(f"  [{elapsed}s] Packing... {current_size:,} bytes")
                else:
                    stable_count += 1
                    print(
                        f"  [{elapsed}s] File unlocked. Verification {stable_count}/{required_stable_checks}..."
                    )

                    if stable_count >= required_stable_checks:
                        print(
                            f"\n[SUCCESS] Packing complete and verified stable! ({elapsed}s)"
                        )
                        print(f"[INFO] Output file: {input_path}")
                        print(f"[INFO] Final size: {current_size:,} bytes")
                        return str(input_path)
            else:
                print(f"  [{elapsed}s] File not found, waiting...")
                stable_count = 0

            time.sleep(check_interval)

        print(
            f"\n[ERROR] Timeout after {timeout}s waiting for stable packing completion"
        )
        return None

    def run(self, click_mode="all", file_path=None, output_dir=None):
        """
        Main execution flow for Yoda's Crypter v1.2.

        Args:
            click_mode: Configuration mode (reserved for future steps)
            file_path: Path to the input file
            output_dir: Directory to move the packed file to

        Returns:
            bool: True if successful, False otherwise
        """
        input_file = None

        try:
            print("\n" + "=" * 60)
            print("YODA'S CRYPTER v1.2 GUI AUTOMATION")
            print("=" * 60)

            # Step 1: Load packer info from YAML
            if not self.load_packer_info():
                print("[ERROR] Failed to load packer info from YAML")
                return False

            # Step 2: Launch application
            print("\n[INFO] Launching Yoda's Crypter v1.2...")
            if not self.launch_application():
                print("[ERROR] Failed to launch application")
                return False

            # Step 3: Find the window
            if not self.find_window():
                print("[WARNING] Could not find window by PID, trying title search...")
                if not self.find_window(window_title="yoda"):
                    print("[ERROR] Could not find Yoda's Crypter v1.2 window")
                    return False

            print("\n[SUCCESS] Yoda's Crypter v1.2 launched successfully!")
            print(f"[INFO] Window title: {self.window.title}")

            # Step 4: Center window on monitor
            time.sleep(0.3)
            self.center_window_on_monitor(monitor_number=1)

            # Step 5: Open file dialog via Tab then Enter
            if not file_path:
                print("[ERROR] No file path provided")
                self.close_application()
                return False

            input_file = Path(file_path).resolve()
            print(f"\n[INFO] Opening file dialog for: {input_file}")

            self.window.activate()
            time.sleep(0.3)
            pyautogui.press("tab")
            time.sleep(0.2)
            pyautogui.press("enter")
            print("[INFO] File open dialog triggered!")

            # Step 6: Navigate to directory and paste filename
            time.sleep(1.0)
            if not self.paste_file_path_in_picker(str(input_file), input_file.name):
                print("[ERROR] Failed to select file in dialog")
                self.close_application()
                return False

            print("[SUCCESS] File selected!")

            # Step 7: Re-find window — title changes after file is loaded
            time.sleep(0.5)
            print("\n[INFO] Re-finding window to capture updated title...")
            if not self.find_window():
                print(
                    "[WARNING] Could not re-find window by PID, trying title search..."
                )
                if not self.find_window(window_title="yoda"):
                    print(
                        "[ERROR] Could not find Yoda's Crypter v1.2 window after file selection"
                    )
                    self.close_application()
                    return False

            # Re-center so the window is fully on screen before coordinates are computed
            time.sleep(0.3)
            self.center_window_on_monitor(monitor_number=1)
            time.sleep(0.3)

            # Capture fresh window dimensions
            self.get_window_dimensions()

            # Step 8: Click Protect! button
            # TODO: verify click coordinates for v1.2 UI — may differ from v1.3 (0.85, 0.15)
            time.sleep(0.5)
            self.click_at_percent(0.85, 0.25, "Protect button")
            print("[INFO] Packing process initiated!")

            # Step 9: Wait for completion dialog, then dismiss it.
            print("\n[INFO] Waiting for completion dialog ':)'...")
            dialog_dismissed = False
            deadline = time.time() + self.EXTRA_LONG_TIMEOUT

            while time.time() < deadline:
                elapsed = int(time.time() - (deadline - self.EXTRA_LONG_TIMEOUT))
                if self.find_window(window_title=":)", timeout=2) and self.window:
                    print(f"\n[SUCCESS] Completion dialog found! ({elapsed}s)")
                    self.window.activate()
                    time.sleep(0.3)
                    pyautogui.press("enter")
                    time.sleep(0.5)
                    print("[SUCCESS] Completion dialog dismissed!")
                    dialog_dismissed = True
                    break
                print(f"  [{elapsed}s] Waiting for completion dialog...")

            if not dialog_dismissed:
                print("\n[ERROR] Completion dialog never appeared — timed out!")
                self.close_application()
                return False

            # Step 10: Confirm file is released and stable after dialog dismissal
            packed_file = self.wait_for_packing_complete(str(input_file))

            if packed_file:
                # Step 11: Move packed file to output directory
                final_path = self.move_protected_file_to_output(packed_file, output_dir)

                if final_path:
                    print(f"\n{'=' * 60}")
                    print("PACKING COMPLETE")
                    print(f"{'=' * 60}")
                    print(f"  Input:  {input_file}")
                    print(f"  Output: {final_path}")
                    print(f"{'=' * 60}")

                # Step 12: Close application
                self.close_application()
                print("\n[SUCCESS] Automation complete!")
                return True
            else:
                print("[ERROR] File watch failed after dialog dismissal!")
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


def main():
    """Entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Yoda's Crypter v1.2 GUI Automation Wrapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--file-path", type=str, default=None, help="Full path to the file to process"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory to copy the protected file to",
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

    wrapper = YodaCrypterV12(yaml_path, main_dir)
    success = wrapper.run(file_path=args.file_path, output_dir=args.output_dir)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
