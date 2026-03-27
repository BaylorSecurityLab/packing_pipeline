"""
Shrinker (Shrink32) GUI Automation Wrapper - Using Base GUI Wrapper
"""

import sys
import time
from pathlib import Path
from base_gui import BaseGUI
import pyautogui
import traceback


class Shrinker(BaseGUI):
    """
    Wrapper for Shrinker (Shrink32) GUI automation using the BaseGUIWrapper.

    Shrinker is a legacy packer by Blink Inc.
    Output behavior is in-place (modifies the input file directly).
    """

    def __init__(self, yaml_path, main_dir):
        """Initialize Shrinker wrapper"""
        super().__init__(yaml_path, main_dir)

    def get_packer_name(self):
        """Return the packer name for YAML lookup"""
        return "shrinker_v3.4_demo"

    def wait_for_packing_complete(self, input_file_path):
        """
        Wait for in-place packing to complete with stability verification.

        Shrinker modifies the input file in-place, so we watch the input file
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

        # Initial buffer to let Shrinker start its work
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
        Main execution flow for Shrinker.

        Step 1: Just open the application and find the window.

        Args:
            click_mode: Configuration mode
            file_path: Path to the input file
            output_dir: Directory to move final output to (optional)

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Step 1: Load packer info from YAML
            print("\n" + "=" * 60)
            print("SHRINKER GUI AUTOMATION")
            print("=" * 60)

            if not self.load_packer_info():
                print("[ERROR] Failed to load packer info from YAML")
                return False

            # Step 2: Launch application
            print("\n[INFO] Launching Shrinker...")
            if not self.launch_application():
                print("[ERROR] Failed to launch application")
                return False

            # Step 3: Find the window
            if not self.find_window():
                print("[WARNING] Could not find window by PID, trying title search...")
                if not self.find_window(window_title="Shrinker"):
                    print("[ERROR] Could not find Shrinker window")
                    return False

            print("\n[SUCCESS] Shrinker launched successfully!")
            print(f"[INFO] Window title: {self.window.title}")

            # Step 5: Dismiss "Welcome to Shrinker" dialog
            time.sleep(0.5)
            print("\n[INFO] Dismissing welcome dialog...")
            pyautogui.press("enter")
            time.sleep(0.5)
            print("[SUCCESS] Welcome dialog dismissed")

            # Step 3: Find the window
            if not self.find_window():
                print("[WARNING] Could not find window by PID, trying title search...")
                if not self.find_window(window_title="Shrinker"):
                    print("[ERROR] Could not find Shrinker window")
                    return False

            # Step 4: Center window on primary monitor
            time.sleep(0.3)
            self.center_window_on_monitor(monitor_number=1)

            # Step 5: Get window dimensions for mapping UI coordinates
            self.get_window_dimensions()

            # Step 6: Click input file button to open file picker
            time.sleep(0.5)
            self.click_at_percent(0.05, 0.05, "Input file button")

            # --- START NEW FILE NAVIGATION LOGIC ---

            if file_path:
                print(f"[INFO] Navigating file picker to: {file_path}")

                # 1. Give the "old" explorer window a moment to pop up and become active
                time.sleep(1.5)

                # 2. Force focus to the "File name" text box.
                # 'Alt+n' is the standard Windows shortcut for the filename field.
                # We press them individually to be safe.
                pyautogui.keyDown("alt")
                pyautogui.press("n")
                pyautogui.keyUp("alt")

                # Short pause to let the cursor jump
                time.sleep(0.5)

                # 3. Type the full path.
                # interval=0.01 prevents typos if the system is lagging.
                pyautogui.write(str(file_path), interval=0.01)

                # 4. Press Enter to confirm the file selection
                time.sleep(0.5)
                pyautogui.press("enter")

                # 5. Sometimes a generic "Confirm" dialog pops up if the file has
                # specific attributes, or the window takes a moment to close.
                time.sleep(1.0)

            else:
                print("[WARNING] No file_path provided, skipping file selection.")

            # Step 7: Click compress button
            time.sleep(0.5)
            self.click_at_percent(0.40, 0.05, "Compress button")
            print("[INFO] Compression initiated!")

            # Step 7: Click compress button
            time.sleep(0.5)
            pyautogui.press("enter")
            print("[INFO] Overwrite confirmation sent")

            # Step 9: Wait for packing to complete (file lock watch)
            if file_path:
                input_file = Path(file_path).resolve()
                packed_file = self.wait_for_packing_complete(str(input_file))

                if packed_file:
                    # Step 10: Move to output directory if specified
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

                    # Step 11: Close application
                    self.close_application()
                    print("\n[SUCCESS] Automation complete!")
                    return True
                else:
                    print("[ERROR] Packing process failed or timed out!")
                    self.close_application()
                    return False
            else:
                print("[ERROR] No file_path provided")
                self.close_application()
                return False

        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")
            traceback.print_exc()
            if file_path:
                self.cleanup_on_failure(str(Path(file_path).resolve()))
            else:
                self.close_application()
            return False


def main():
    """Entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Shrinker (Shrink32) GUI Automation Wrapper",
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

    wrapper = Shrinker(yaml_path, main_dir)
    success = wrapper.run(file_path=args.file_path, output_dir=args.output_dir)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
