"""
RLPack GUI Automation Wrapper - Using Base GUI Wrapper
"""

import sys
import time
from pathlib import Path
from base_gui import BaseGUI
import pyautogui
import pyperclip
import traceback
import win32gui
import win32process
import win32api


class RLPack(BaseGUI):
    """
    Wrapper for RLPack 1.21 Basic GUI automation using the BaseGUIWrapper.

    RLPack is a compressing executable protector by ap0x.
    Output behavior is explicit (creates a separate output file).
    """

    def __init__(self, yaml_path, main_dir):
        """Initialize RLPack wrapper"""
        super().__init__(yaml_path, main_dir)
        self.hwnd = None

    def get_packer_name(self):
        """Return the packer name for YAML lookup"""
        return "rlpack"

    def wait_for_packing_complete(self, input_file_path):
        """
        Wait for packing to complete with stability verification.
        RLPack modifies the input file in-place, so we watch for lock release.

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
        Main execution flow for RLPack.

        Step 1: Open the application and center it on the monitor.

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
            print("RLPACK GUI AUTOMATION")
            print("=" * 60)

            if not self.load_packer_info():
                print("[ERROR] Failed to load packer info from YAML")
                return False

            # Step 2: Launch application
            print("\n[INFO] Launching RLPack...")
            if not self.launch_application():
                print("[ERROR] Failed to launch application")
                return False

            # Step 3: Find the window
            if not self.find_window():
                print("[WARNING] Could not find window by PID, trying title search...")
                if not self.find_window(window_title="rlpack"):
                    print("[ERROR] Could not find RLPack window")
                    return False

            print("\n[SUCCESS] RLPack launched successfully!")
            print(f"[INFO] Window title: {self.window.title}")

            # Step 4: Wait for window to fully load
            print("\n[INFO] Waiting for window to fully load...")
            time.sleep(2)

            # Step 5: Center window on monitor 1 (base class uses self.window)
            self.center_window_on_monitor(monitor_number=1)
            time.sleep(0.5)

            # Step 6: Focus window and move cursor off any screen corner via
            # win32api (bypasses pyautogui's fail-safe) before keyboard nav.
            self.window.activate()
            time.sleep(0.3)
            win32api.SetCursorPos(
                (
                    self.window.left + self.window.width // 2,
                    self.window.top + self.window.height // 2,
                )
            )
            time.sleep(0.2)

            # Step 7: Tab twice to reach the file browse button
            print("\n[INFO] Navigating to browse button (Tab x2)...")
            pyautogui.press("tab")
            time.sleep(0.2)
            pyautogui.press("tab")
            time.sleep(0.2)

            # Step 7: Press Enter to open Windows Explorer file picker
            print("[INFO] Opening file picker...")
            pyautogui.press("enter")
            time.sleep(1)

            # Step 8: Paste file path into the file picker
            if file_path:
                input_file = Path(file_path).resolve()
                directory = str(input_file.parent)
                filename = input_file.name

                # Ctrl+L to focus the address bar
                print(f"[INFO] Navigating to directory: {directory}")
                pyautogui.hotkey("ctrl", "l")
                time.sleep(0.3)

                # Type the directory path and press Enter
                pyperclip.copy(directory)
                pyautogui.hotkey("ctrl", "v")
                time.sleep(0.3)
                pyautogui.press("enter")
                time.sleep(1)

                # Alt+N to jump to the "File name:" box
                print("[INFO] Jumping to filename box...")
                pyautogui.hotkey("alt", "n")
                time.sleep(0.3)

                # Type the filename and press Enter (OK)
                print(f"[INFO] Entering filename: {filename}")
                pyperclip.copy(filename)
                pyautogui.hotkey("ctrl", "v")
                time.sleep(0.3)
                pyautogui.press("enter")
                time.sleep(0.5)

                print("[SUCCESS] File selected!")

                # Step 9: Tab 14 times to reach the Pack button
                print("\n[INFO] Navigating to Pack button (Tab x14)...")
                for _ in range(13):
                    pyautogui.press("tab")
                    time.sleep(0.1)

                # Step 10: Press Enter to start packing
                print("[INFO] Starting packing process...")
                pyautogui.press("enter")
                time.sleep(0.5)
                print("[INFO] Pack button pressed!")

                # Step 11: Wait for packing to complete (file lock watch)
                packed_file = self.wait_for_packing_complete(str(input_file))

                if packed_file:
                    # Step 12: Move to output directory if specified
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

                    # Step 13: Close application
                    self.close_application()
                    print("\n[SUCCESS] Automation complete!")
                    return True
                else:
                    print("[ERROR] Packing process failed or timed out!")
                    self.close_application()
                    return False

            else:
                print("[INFO] No file path provided - file picker left open")
                self.close_application()
                return False

        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")
            traceback.print_exc()
            self.close_application()
            return False


def main():
    """Entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="RLPack GUI Automation Wrapper",
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

    wrapper = RLPack(yaml_path, main_dir)
    success = wrapper.run(file_path=args.file_path, output_dir=args.output_dir)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
