"""
tElock GUI Automation Wrapper - Using Base GUI Wrapper
"""

import sys
import time
from pathlib import Path
from base_gui import BaseGUI
import pyautogui
import pyperclip
import pygetwindow as gw
import traceback


class Telock(BaseGUI):
    """
    Wrapper for tElock 0.98 GUI automation using the BaseGUIWrapper.

    tElock (The Experimental Lock) is a legacy PE protector with polymorphic encryption.
    Output behavior is in-place (modifies the input file directly).

    UI Flow:
        1. Launch tElock.exe
        2. Select file via browse button and file picker
        3. Click "tElock it!" button
        4. Wait for input file lock to release (in-place modification)
    """

    def __init__(self, yaml_path, main_dir):
        """Initialize Telock wrapper"""
        super().__init__(yaml_path, main_dir)

    def get_packer_name(self):
        """Return the packer name for YAML lookup"""
        return "telock_v0.98"

    def find_file_picker_window(self, timeout=10):
        """
        Find the file picker window opened by tElock.

        Overrides base class to log all visible window titles for debugging
        and use a broader set of patterns to catch tElock's dialog.
        """
        print("\n[INFO] Searching for file picker window...")
        start_time = time.time()

        # Broader patterns including the base ones
        patterns = self.FILE_PICKER_PATTERNS + [
            "telock",
            "Ouvrir",       # French
            "Abrir",        # Spanish
            "Öffnen",       # German
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

        # If we get here, print all titles for debugging
        print("[DEBUG] All visible window titles:")
        try:
            for title in gw.getAllTitles():
                if title.strip():
                    print(f"  - '{title}'")
        except Exception:
            pass

        print("[ERROR] File picker window not found within timeout")
        return None

    def check_for_error_dialog(self):
        """
        Check if tElock has opened an error dialog (title exactly "Error").

        Returns:
            bool: True if an error dialog is detected
        """
        try:
            for win in gw.getAllWindows():
                if win.title.strip() == "Error" and win.visible:
                    print(f"[WARNING] Error dialog detected: '{win.title}'")
                    try:
                        win.activate()
                        time.sleep(0.2)
                        pyautogui.press("enter")
                        time.sleep(0.2)
                    except Exception:
                        pass
                    return True
        except Exception as e:
            print(f"[DEBUG] Error dialog check failed: {e}")
        return False

    def wait_for_packing_complete(self, input_file_path):
        """
        Wait for the in-place packing to complete with stability verification.

        tElock modifies the input file in-place, so we watch the input file itself
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

            if self.check_for_error_dialog():
                print("\n[ERROR] tElock error dialog detected — packing failed.")
                return None

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
        Main execution flow for tElock.

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
            print("tElock GUI AUTOMATION")
            print("=" * 60)

            if not self.load_packer_info():
                print("[ERROR] Failed to load packer info from YAML")
                return False

            # Step 2: Launch application
            print("\n[INFO] Launching tElock...")
            if not self.launch_application():
                print("[ERROR] Failed to launch application")
                return False

            # Step 3: Find the window
            if not self.find_window():
                print("[WARNING] Could not find window by PID, trying title search...")
                if not self.find_window(window_title="telock"):
                    print("[ERROR] Could not find tElock window")
                    return False

            print("\n[SUCCESS] tElock launched successfully!")
            print(f"[INFO] Window title: {self.window.title}")

            # Step 4: Center window on monitor
            time.sleep(0.3)
            self.center_window_on_monitor(monitor_number=1)

            # Step 5: Load the file via browse button and file picker
            if file_path:
                input_file = Path(file_path).resolve()
                print(f"\n[INFO] Loading file: {input_file}")

                # Click the "..." / browse button to open file picker
                time.sleep(0.5)
                self.click_at_percent(0.10, 0.92, "Browse button")
                time.sleep(1.0)

                # Use the file picker to navigate and select the file
                app_name = self.extract_app_name(str(input_file))
                if not self.paste_file_path_in_picker(str(input_file), app_name):
                    print("[ERROR] Failed to select file in picker")
                    self.close_application()
                    return False

                time.sleep(0.5)
                print("[SUCCESS] File loaded!")
            else:
                print("[ERROR] No file path provided")
                self.close_application()
                return False

            # Step 6: Click the "tElock it!" button
            time.sleep(0.5)
            self.click_at_percent(0.50, 0.85, "tElock it! button")

            print("[INFO] Packing process initiated!")

            # Step 7: Wait for packing to complete
            packed_file = self.wait_for_packing_complete(str(input_file))

            if packed_file:
                # Step 8: Move to output directory if specified
                final_path = self.move_protected_file_to_output(packed_file, output_dir)

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
        description="tElock GUI Automation Wrapper",
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

    wrapper = Telock(yaml_path, main_dir)
    success = wrapper.run(file_path=args.file_path, output_dir=args.output_dir)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
