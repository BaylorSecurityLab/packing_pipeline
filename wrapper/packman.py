"""
Packman GUI Automation Wrapper - Using Base GUI Wrapper
"""

import sys
import time
from pathlib import Path
from base_gui import BaseGUI
import pyautogui
import pyperclip
import traceback


class Packman(BaseGUI):
    """
    Wrapper for Packman 1.0 GUI automation using the BaseGUIWrapper.

    Packman is a legacy executable compressor. Primarily GUI-based.
    Output behavior is in-place (modifies the input file directly).
    """

    def __init__(self, yaml_path, main_dir):
        """Initialize Packman wrapper"""
        super().__init__(yaml_path, main_dir)

    def get_packer_name(self):
        """Return the packer name for YAML lookup"""
        return "packman"

    def wait_for_packing_complete(self, output_file_path):
        """
        Wait for the packed output file to appear and become stable.

        Since Packman writes to an explicit output path, we watch that file
        for creation and lock release. No move is needed afterwards.

        Args:
            output_file_path: Path to the expected output file

        Returns:
            str: Path to packed file if successful, None otherwise
        """
        # Interaction is complete; release the input lock so other packers can
        # interact while this one watches its output file.
        self.release_input()
        timeout = self.EXTRA_LONG_TIMEOUT
        output_path = Path(output_file_path)
        check_interval = self.LONG_TIMEOUT

        required_stable_checks = 5
        stable_count = 0

        print("\n[INFO] Waiting for packing to complete...")
        print(f"[INFO] Watching for: {output_path}")
        print(
            f"[INFO] Stability Requirement: {required_stable_checks} consecutive unlocked checks"
        )
        print(f"[INFO] Interval: {check_interval}s | Timeout: {timeout}s")

        start_time = time.time()

        # Initial buffer to let the packer start its work
        time.sleep(10)

        while time.time() - start_time < timeout:
            elapsed = int(time.time() - start_time)

            if output_path.exists():
                current_size = output_path.stat().st_size

                if self.is_file_locked(str(output_path)):
                    if stable_count > 0:
                        print(
                            f"  [{elapsed}s] Lock reappeared! Resetting stability counter."
                        )
                    stable_count = 0
                    print(f"  [{elapsed}s] Writing... {current_size:,} bytes")
                else:
                    stable_count += 1
                    print(
                        f"  [{elapsed}s] File unlocked. Verification {stable_count}/{required_stable_checks}..."
                    )

                    if stable_count >= required_stable_checks:
                        print(
                            f"\n[SUCCESS] Packing complete and verified stable! ({elapsed}s)"
                        )
                        print(f"[INFO] Output file: {output_path}")
                        print(f"[INFO] Final size: {current_size:,} bytes")
                        return str(output_path)
            else:
                print(
                    f"  [{elapsed}s] Processing (waiting for file creation)...",
                    end="\r",
                )
                stable_count = 0

            time.sleep(check_interval)

        print(f"\n[ERROR] Timeout after {timeout}s waiting for stable packing completion")
        return None

    def run(self, click_mode="all", file_path=None, output_dir=None):
        """
        Main execution flow for Packman.

        Opens the application and centers it on monitor 0.

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
            print("PACKMAN GUI AUTOMATION")
            print("=" * 60)

            if not self.load_packer_info():
                print("[ERROR] Failed to load packer info from YAML")
                return False

            # Step 2: Launch application
            print("\n[INFO] Launching Packman...")
            if not self.launch_application():
                print("[ERROR] Failed to launch application")
                return False

            # Step 3: Find the window
            if not self.find_window():
                print("[WARNING] Could not find window by PID, trying title search...")
                if not self.find_window(window_title="packman"):
                    print("[ERROR] Could not find Packman window")
                    return False

            print("\n[SUCCESS] Packman launched successfully!")
            print(f"[INFO] Window title: {self.window.title}")

            # Step 4: Center window on monitor 1
            time.sleep(0.3)
            self.center_window_on_monitor(monitor_number=1)

            print("\n[SUCCESS] Packman opened and centered on monitor 1!")

            # Step 5: Tab to input field, paste absolute file path
            if file_path:
                input_file = str(Path(file_path).resolve())
                print(f"\n[INFO] Pasting input file path: {input_file}")
                self.window.activate()
                time.sleep(0.3)
                pyautogui.press("tab")
                time.sleep(0.2)
                pyperclip.copy(input_file)
                pyautogui.hotkey("ctrl", "v")
                time.sleep(0.3)
                print("[SUCCESS] Input file path pasted!")

                # Step 6: Tab, Tab to output field, paste output path (with filename)
                input_name = Path(input_file).name
                output_path = (
                    str(Path(output_dir).resolve() / input_name)
                    if output_dir
                    else input_file
                )
                print(f"[INFO] Pasting output path: {output_path}")
                pyautogui.press("tab")
                time.sleep(0.2)
                pyautogui.press("tab")
                time.sleep(0.2)
                pyperclip.copy(output_path)
                pyautogui.hotkey("ctrl", "v")
                time.sleep(0.3)
                print("[SUCCESS] Output path pasted!")

                # Step 7: Navigate to Compress tab (9 tabs + 4 right arrows)
                time.sleep(0.3)
                print("[INFO] Navigating to Compress tab...")
                for _ in range(7):
                    pyautogui.press("tab")
                    time.sleep(0.1)
                for _ in range(4):
                    pyautogui.press("right")
                    time.sleep(0.1)
                print("[SUCCESS] Compress tab selected!")

                # Step 8: Tab to Pack button and press Enter
                time.sleep(0.3)
                pyautogui.press("tab")
                time.sleep(0.2)
                pyautogui.press("enter")
                print("[SUCCESS] Pack button pressed!")

                # Step 9: Wait for packing to complete (file watch)
                packed_file = self.wait_for_packing_complete(output_path)

                if packed_file:
                    print(f"\n{'=' * 60}")
                    print("PACKING COMPLETE")
                    print(f"{'=' * 60}")
                    print(f"  Input:  {input_file}")
                    print(f"  Output: {packed_file}")
                    print(f"{'=' * 60}")

                    self.close_application()
                    print("\n[SUCCESS] Automation complete!")
                    return True
                else:
                    print("[ERROR] Packing process failed or timed out!")
                    self.close_application()
                    return False
            else:
                print("[WARNING] No file path provided, skipping path entry")
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
        description="Packman GUI Automation Wrapper",
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

    wrapper = Packman(yaml_path, main_dir)
    success = wrapper.run(file_path=args.file_path, output_dir=args.output_dir)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
