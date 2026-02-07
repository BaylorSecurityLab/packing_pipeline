"""
MEW GUI Automation Wrapper - Using Base GUI Wrapper
"""

import sys
import time
from pathlib import Path
from base_gui import BaseGUI
import pyautogui
import pyperclip
import traceback


class Mew(BaseGUI):
    """
    Wrapper for MEW 11 SE GUI automation using the BaseGUIWrapper.

    MEW is a high-ratio compressor designed for very small executables (demoscene).
    Output behavior is in-place (modifies the input file directly).
    """

    def __init__(self, yaml_path, main_dir):
        """Initialize Mew wrapper"""
        super().__init__(yaml_path, main_dir)

    def get_packer_name(self):
        """Return the packer name for YAML lookup"""
        return "mew"

    def wait_for_packing_complete(self, input_file_path):
        """
        Wait for the in-place packing to complete with stability verification.

        MEW modifies the input file in-place, so we watch the input file itself
        for lock release. Requires N consecutive unlocked checks to confirm completion.

        Args:
            input_file_path: Path to the file being packed

        Returns:
            str: Path to packed file if successful, None otherwise
        """
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

        print(f"\n[ERROR] Timeout after {timeout}s waiting for stable packing completion")
        return None

    def run(self, click_mode="all", file_path=None, output_dir=None):
        """
        Main execution flow for MEW.

        Args:
            click_mode: Configuration mode
            file_path: Path to the input file
            output_dir: Directory to move final output to (optional)

        Returns:
            bool: True if successful, False otherwise
        """
        input_file = None

        try:
            # Step 1: Load packer info from YAML
            print("\n" + "=" * 60)
            print("MEW GUI AUTOMATION")
            print("=" * 60)

            if not self.load_packer_info():
                print("[ERROR] Failed to load packer info from YAML")
                return False

            # Step 2: Launch application
            print("\n[INFO] Launching MEW...")
            if not self.launch_application():
                print("[ERROR] Failed to launch application")
                return False

            # Step 3: Find the window
            if not self.find_window():
                print("[WARNING] Could not find window by PID, trying title search...")
                if not self.find_window(window_title="mew"):
                    print("[ERROR] Could not find MEW window")
                    return False

            print("\n[SUCCESS] MEW launched successfully!")
            print(f"[INFO] Window title: {self.window.title}")

            # Step 4: Center window on monitor 0
            time.sleep(0.3)
            self.center_window_on_monitor(monitor_number=1)

            # Step 5: Paste the absolute file path via Ctrl+V
            if file_path:
                input_file = Path(file_path).resolve()
                print(f"\n[INFO] Pasting file path: {input_file}")
                self.window.activate()
                time.sleep(0.3)
                pyperclip.copy(str(input_file))
                pyautogui.hotkey("ctrl", "v")
                time.sleep(0.3)
                print("[SUCCESS] File path pasted!")
            else:
                print("[ERROR] No file path provided")
                self.close_application()
                return False

            # Step 6: Click the "Do it" button
            time.sleep(0.5)
            self.click_at_percent(0.60, 0.95, "Do it button")

            print("[INFO] Packing process initiated!")

            # Step 7: Wait for packing to complete (file lock watch)
            packed_file = self.wait_for_packing_complete(str(input_file))

            if packed_file:
                # Step 8: Move to output directory if specified
                final_path = self.move_protected_file_to_output(
                    packed_file, output_dir
                )

                if final_path:
                    print(f"\n{'=' * 60}")
                    print("PACKING COMPLETE")
                    print(f"{'=' * 60}")
                    print(f"  Input:  {input_file}")
                    print(f"  Output: {final_path}")
                    print(f"{'=' * 60}")

                # Step 9: Close application
                self.close_application()
                print("\n[SUCCESS] Automation complete!")
                return True
            else:
                print("[ERROR] Packing process failed or timed out!")
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
        description="MEW GUI Automation Wrapper",
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

    # Determine paths
    script_dir = Path(__file__).parent
    main_dir = script_dir.parent
    yaml_path = main_dir / "manifest" / "packer_corpus.yaml"

    print(f"Script directory: {script_dir}")
    print(f"Main directory: {main_dir}")
    print(f"YAML path: {yaml_path}")

    if not yaml_path.exists():
        print(f"\n[ERROR] YAML file not found at: {yaml_path}")
        return 1

    wrapper = Mew(yaml_path, main_dir)
    success = wrapper.run(file_path=args.file_path, output_dir=args.output_dir)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
