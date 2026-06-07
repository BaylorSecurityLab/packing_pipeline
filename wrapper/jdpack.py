"""
JDPack GUI Automation Wrapper
"""

import sys
import time
import traceback
from pathlib import Path
from base_gui import BaseGUI
import pyautogui
import win32gui


class JDPack(BaseGUI):
    """
    Wrapper for JDPack v1.00 GUI automation.

    1. Launch jdpack.exe
    2. Dismiss startup error dialog
    3. Find main window
    4. Click Open button (0.9, 0.37) → file picker
    5. Select input file
    6. Click Compress button (0.9, 0.5)
    7. Watch file for lock release (packing complete)
    8. Move output, close application
    """

    def __init__(self, yaml_path, main_dir):
        super().__init__(yaml_path, main_dir)

    def get_packer_name(self) -> str:
        return "jdpack_v1.00"

    def _dismiss_error_and_find_main(self, timeout=15):
        """
        JDPack shows an 'Error' dialog on startup before the main window.
        Dismiss it with Enter, then wait for the real JDPack main window.

        Returns:
            bool: True if main window found, False on timeout
        """
        print("\n[INFO] Waiting for JDPack startup (error dialog + main window)...")
        start_time = time.time()

        error_dismissed = False

        while time.time() - start_time < timeout:
            found = [None]

            def _check(hwnd, _):
                if not win32gui.IsWindowVisible(hwnd):
                    return True
                title = win32gui.GetWindowText(hwnd)
                if not title:
                    return True
                if any(p in title.lower() for p in self.EXCLUDE_WINDOW_PATTERNS):
                    return True
                found[0] = (hwnd, title)
                return False  # stop on first match

            win32gui.EnumWindows(_check, None)

            if found[0]:
                hwnd, title = found[0]

                if title.lower() == "error" and not error_dismissed:
                    print(f"[INFO] Dismissing error dialog: '{title}'")
                    win32gui.SetForegroundWindow(hwnd)
                    time.sleep(0.3)
                    pyautogui.press("enter")
                    error_dismissed = True
                    time.sleep(1)
                    continue

                # Any non-error window from the process is the main window
                if title.lower() != "error":
                    import pygetwindow as gw

                    wins = gw.getWindowsWithTitle(title)
                    if wins:
                        self.window = wins[0]
                        print(f"[SUCCESS] JDPack main window found: '{title}'")
                        return True

            time.sleep(0.5)

        print("[ERROR] JDPack main window not found after dismissing error dialog")
        return False

    def wait_for_packing_complete(self, input_file_path):
        """
        Watch the input file for lock release after JDPack finishes writing.
        Requires 5 consecutive unlocked checks before declaring success.
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
        print(f"[INFO] Stability requirement: {required_stable_checks} consecutive unlocked checks")
        print(f"[INFO] Interval: {check_interval}s | Timeout: {timeout}s")

        start_time = time.time()
        time.sleep(10)

        while time.time() - start_time < timeout:
            elapsed = int(time.time() - start_time)

            if input_path.exists():
                current_size = input_path.stat().st_size

                if self.is_file_locked(str(input_path)):
                    if stable_count > 0:
                        print(f"  [{elapsed}s] Lock reappeared! Resetting stability counter.")
                    stable_count = 0
                    print(f"  [{elapsed}s] Packing... {current_size:,} bytes")
                else:
                    stable_count += 1
                    print(f"  [{elapsed}s] File unlocked. Verification {stable_count}/{required_stable_checks}...")
                    if stable_count >= required_stable_checks:
                        print(f"\n[SUCCESS] Packing complete and verified stable! ({elapsed}s)")
                        print(f"[INFO] Output file: {input_path}")
                        print(f"[INFO] Final size: {current_size:,} bytes")
                        return str(input_path)
            else:
                print(f"  [{elapsed}s] File not found, waiting...")
                stable_count = 0

            time.sleep(check_interval)

        print(f"\n[ERROR] Timeout after {timeout}s waiting for stable packing completion")
        return None

    def run(self, click_mode="all", file_path=None, output_dir=None) -> bool:
        """
        Main execution flow for JDPack.

        1. Launch jdpack.exe
        2. Dismiss startup error dialog, find main window
        3. Click Open button (0.9, 0.37) → file picker
        4. Select input file
        5. Click Compress button (0.9, 0.5)
        6. Watch file for lock release (packing complete)
        7. Move output, close application
        """
        input_file = None

        try:
            print("\n" + "=" * 60)
            print("JDPACK GUI AUTOMATION")
            print("=" * 60)

            if not self.load_packer_info():
                print("[ERROR] Failed to load packer info from YAML")
                return False

            if not file_path:
                print("[ERROR] No file path provided")
                return False

            input_file = Path(file_path).resolve()

            # Step 1: Launch JDPack
            print("\n[INFO] Launching JDPack...")
            if not self.launch_application():
                print("[ERROR] Failed to launch application")
                return False

            # Step 2: Dismiss startup error dialog, find main window
            if not self._dismiss_error_and_find_main(timeout=self.LONG_TIMEOUT):
                print("[ERROR] Could not find JDPack main window")
                self.close_application()
                return False

            self.center_window_on_monitor(monitor_number=0)
            print(f"[INFO] JDPack window found: '{self.window.title}'")
            time.sleep(0.5)

            # Step 3: Click Open button → launches Windows Explorer file picker
            self.click_at_percent(0.9, 0.37, "Open button")
            time.sleep(1)

            # Step 4: Select file via picker
            app_name = input_file.name
            if not self.paste_file_path_in_picker(str(input_file), app_name):
                print("[ERROR] Failed to select file in picker")
                self.close_application()
                return False

            time.sleep(1)

            # Step 5: Click Compress button
            self.click_at_percent(0.9, 0.5, "Compress button")
            time.sleep(1)
            print("[INFO] Compression initiated!")

            # Step 6: Watch file for lock release
            packed_file = self.wait_for_packing_complete(str(input_file))

            if packed_file:
                final_path = self.move_protected_file_to_output(packed_file, output_dir)
                if final_path:
                    print(f"\n{'=' * 60}")
                    print("PACKING COMPLETE")
                    print(f"{'=' * 60}")
                    print(f"  Input:  {input_file}")
                    print(f"  Output: {final_path}")
                    print(f"{'=' * 60}")
                self.close_application()
                print("\n[SUCCESS] JDPack automation complete!")
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
    import argparse

    parser = argparse.ArgumentParser(description="JDPack GUI Automation Wrapper")
    parser.add_argument(
        "--file-path", type=str, default=None, help="Full path to the file to process"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory to copy the packed file to",
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

    wrapper = JDPack(yaml_path, main_dir)
    success = wrapper.run(file_path=args.file_path, output_dir=args.output_dir)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
