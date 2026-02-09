"""
PE Diminisher (PED) GUI Automation Wrapper - Using Base GUI Wrapper
"""

import sys
import time
from pathlib import Path
from base_gui import BaseGUI
import pyautogui
import pyperclip
import pygetwindow as gw
import subprocess
import traceback


class PEDiminisher(BaseGUI):
    """
    Wrapper for PE Diminisher GUI automation using the BaseGUIWrapper.

    PED is a legacy GUI tool designed to reduce executable size by
    stripping DOS headers and optimizing PE structures.
    Output behavior is in-place (modifies the input file directly).
    """

    UI_POSITIONS = {
        "window_focus": (0.50, 0.50),
    }

    def __init__(self, yaml_path, main_dir):
        """Initialize PEDiminisher wrapper"""
        super().__init__(yaml_path, main_dir)

    def get_packer_name(self):
        """Return the packer name for YAML lookup"""
        return "pe_diminisher"

    def get_ped_windows(self):
        """
        Get only actual PED windows.

        Returns:
            list: PED window objects
        """
        ped_windows = []
        for win in gw.getAllWindows():
            if win.title and "pe diminisher" in win.title.lower():
                ped_windows.append(win)
        return ped_windows

    def move_to_percent(self, x_percent, y_percent, description=""):
        """
        Move the mouse to a position specified as percentage of window dimensions.
        Does NOT click.

        Args:
            x_percent: X position as percentage (0.0 to 1.0)
            y_percent: Y position as percentage (0.0 to 1.0)
            description: Description of the target location
        """
        if not self.window:
            print("[ERROR] No window found")
            return False

        try:
            self.window.activate()
            time.sleep(0.2)

            client_info = self._get_client_area_info(self.window.title)
            if not client_info:
                return False

            client_width, client_height, client_point = client_info
            abs_x = client_point[0] + int(client_width * x_percent)
            abs_y = client_point[1] + int(client_height * y_percent)

            if description:
                print(f"\n[ACTION] Moving mouse to: {description}")
            print(f"  Position: {x_percent * 100:.1f}% x, {y_percent * 100:.1f}% y")
            print(f"  Absolute coords: ({abs_x}, {abs_y})")

            pyautogui.moveTo(abs_x, abs_y)
            print("[+] Mouse moved")
            return True

        except Exception as e:
            print(f"[ERROR] Mouse move failed: {e}")
            return False

    def ensure_ped_closed(self):
        """Ensure no PED instance is running before starting."""
        windows = self.get_ped_windows()
        if windows:
            print(
                f"\n[WARNING] Found {len(windows)} existing PED window(s), closing..."
            )
            self.force_close_ped()
        else:
            print("[INFO] No existing PED instance found")

    def force_close_ped(self, max_attempts=5, wait_between=1):
        """Force close PED and verify it's actually closed."""
        for attempt in range(max_attempts):
            windows = self.get_ped_windows()
            if not windows:
                print("[SUCCESS] PED is closed")
                return True

            print(
                f"[INFO] Close attempt {attempt + 1}/{max_attempts} - Found {len(windows)} window(s)"
            )

            try:
                for win in windows:
                    try:
                        win.activate()
                        time.sleep(0.2)
                    except:
                        pass

                pyautogui.hotkey("alt", "F4")
                time.sleep(0.5)

                if not self.get_ped_windows():
                    print("[SUCCESS] PED closed via Alt+F4")
                    return True

                print("[INFO] Trying taskkill...")
                subprocess.run(
                    ["taskkill", "/IM", "ped.exe", "/F"],
                    capture_output=True,
                    timeout=5,
                )
                time.sleep(wait_between)

            except Exception as e:
                print(f"[WARNING] Close attempt failed: {e}")
                time.sleep(wait_between)

        if not self.get_ped_windows():
            return True

        print(f"[ERROR] Failed to close PED after {max_attempts} attempts")
        return False

    def close_ped(self):
        """Close PED application and verify it's closed."""
        print("\n[INFO] Closing PED...")
        return self.force_close_ped()

    def wait_for_packing_complete(self, input_file_path):
        """
        Wait for PED in-place packing to complete with stability verification.

        PED modifies the input file in-place, so we watch the input file itself
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

        # Initial buffer to let PED start its work
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
        Main execution flow for PED.

        Args:
            click_mode: Configuration mode
            file_path: Path to the input file
            output_dir: Directory to move final output to (optional)

        Returns:
            bool: True if successful, False otherwise
        """
        input_file = None

        try:
            # Step 0: Ensure no existing PED is running
            self.ensure_ped_closed()

            # Step 1: Load packer info from YAML
            print("\n" + "=" * 60)
            print("PE DIMINISHER GUI AUTOMATION")
            print("=" * 60)

            if not self.load_packer_info():
                print("[ERROR] Failed to load packer info from YAML")
                return False

            # Step 2: Launch application
            print("\n[INFO] Launching PED...")
            if not self.launch_application():
                print("[ERROR] Failed to launch application")
                return False

            # Step 3: Find the window
            if not self.find_window():
                print("[WARNING] Could not find window by PID, trying title search...")
                if not self.find_window(window_title="PE Diminisher"):
                    print("[ERROR] Could not find PED window")
                    return False

            print("\n[SUCCESS] PED launched successfully!")
            print(f"[INFO] Window title: {self.window.title}")

            # Step 4: Center window on primary monitor
            time.sleep(0.3)
            self.center_window_on_monitor(monitor_number=1)

            # Step 5: Click "Open Folder" button to launch file picker
            time.sleep(0.5)
            self.click_at_percent(0.03, 0.08, "Open Folder button")
            time.sleep(1)

            # Step 6: Navigate file picker using file_path
            if file_path:
                input_path = Path(file_path).resolve()
                directory_path = str(input_path.parent)
                file_name = input_path.name

                # Wait for Explorer dialog to appear
                picker_window = self.find_file_picker_window(timeout=self.LONG_TIMEOUT)
                if not picker_window:
                    print("[ERROR] File picker window did not appear")
                    return False

                picker_window.activate()
                time.sleep(0.3)

                # Ctrl+L to focus address bar, type directory path
                print(f"[INFO] Navigating to directory: {directory_path}")
                pyautogui.hotkey("ctrl", "l")
                time.sleep(0.3)
                pyperclip.copy(directory_path)
                pyautogui.hotkey("ctrl", "v")
                time.sleep(0.2)
                pyautogui.press("enter")
                time.sleep(0.5)

                # Ctrl+E to jump to file name field, type filename
                print(f"[INFO] Entering file name: {file_name}")
                pyautogui.hotkey("alt", "n")
                time.sleep(0.3)
                pyperclip.copy(file_name)
                pyautogui.hotkey("ctrl", "v")
                time.sleep(0.2)
                pyautogui.press("enter")
                time.sleep(0.5)

                print("[SUCCESS] File selected in picker")
            else:
                print("[WARNING] No file_path provided, skipping file picker")

            # Step 7: Click Encrypt button
            time.sleep(0.5)
            self.click_at_percent(0.10, 0.08, "Encrypt button")
            print("[INFO] Packing process initiated!")

            # Step 8: Wait for packing to complete (file lock watch)
            if file_path:
                input_file = Path(file_path).resolve()
                packed_file = self.wait_for_packing_complete(str(input_file))

                if packed_file:
                    # Step 9: Move to output directory if specified
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

                    # Step 10: Close application
                    self.close_ped()
                    print("\n[SUCCESS] Automation complete!")
                    return True
                else:
                    print("[ERROR] Packing process failed or timed out!")
                    self.close_ped()
                    return False
            else:
                print("[WARNING] No file_path provided, skipping file watch")
                self.close_ped()
                return False

        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")
            traceback.print_exc()
            if file_path:
                self.cleanup_on_failure(str(Path(file_path).resolve()))
            else:
                self.close_ped()
            return False


def main():
    """Entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="PE Diminisher (PED) GUI Automation Wrapper",
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

    wrapper = PEDiminisher(yaml_path, main_dir)
    success = wrapper.run(file_path=args.file_path, output_dir=args.output_dir)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
