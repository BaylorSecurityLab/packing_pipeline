"""
ACProtect GUI Automation Wrapper - Using Base GUI Wrapper
"""

import sys
import time
from pathlib import Path
from base_gui import BaseGUI
import pyautogui
import pyperclip
from screeninfo import get_monitors
import win32gui
import win32con


class ACProtect(BaseGUI):
    """
    Wrapper for ACProtect GUI automation using the BaseGUIWrapper.
    """

    # UI element positions (x_percent, y_percent)
    UI_POSITIONS = {
        "window_focus": (0.90, 0.30),
        "protect_tab": (0.35, 0.15),  # "Protect" tab at top
    }

    def __init__(self, yaml_path, main_dir):
        """Initialize ACProtect wrapper"""
        super().__init__(yaml_path, main_dir)

    def get_packer_name(self):
        """Return the packer name for YAML lookup"""
        return "acprotect"

    def click_window_to_focus(self):
        """Click somewhere safe on the window to give it focus"""
        x, y = self.UI_POSITIONS["window_focus"]
        return self.click_at_percent(x, y, "Window (for focus)")

    def click_protect_tab(self):
        """Click the Protect tab to start protection"""
        x, y = self.UI_POSITIONS["protect_tab"]
        return self.click_at_percent(x, y, "Protect tab")

    def enter_file_path(self, file_path):
        """
        Click window, Tab to text boxes, then paste file path to both.

        Args:
            file_path: Absolute path to the file

        Returns:
            bool: True if successful
        """
        # Step 1: Click window to give it focus
        print("[INFO] Clicking window to focus...")
        if not self.click_window_to_focus():
            return False
        time.sleep(0.3)

        # Step 2: Press Tab to jump to the first text box (File to Protected)
        print("[INFO] Pressing Tab to jump to 'File to Protected' text box...")
        pyautogui.press("tab")
        time.sleep(0.2)

        # Step 3: Paste the file path
        print(f"[INFO] Pasting file path: {file_path}")
        pyperclip.copy(str(file_path))
        pyautogui.hotkey("ctrl", "v")
        time.sleep(0.2)

        # Step 4: Press Tab to jump to the second text box (File to Save)
        print("[INFO] Pressing Tab to jump to 'File to Save' text box...")
        pyautogui.press("tab")
        time.sleep(0.2)

        # Step 5: Paste the same file path (in-place protection)
        print(f"[INFO] Pasting file path to 'File to Save': {file_path}")
        pyautogui.hotkey("ctrl", "v")
        time.sleep(0.2)

        print(f"[SUCCESS] Entered file path in both text boxes: {file_path}")
        return True

    def wait_for_protection_complete(self, file_path):
        """
        Wait for the protection process to complete with stability verification.

        Requires the file to remain unlocked for 5 consecutive checks to ensure
        the packer hasn't just momentarily dropped the lock due to an error.
        """
        timeout = self.EXTRA_LONG_TIMEOUT
        file_path = Path(file_path)
        check_interval = self.LONG_TIMEOUT

        # Stability settings
        required_stable_checks = 5
        stable_count = 0
        check_interval = self.LONG_TIMEOUT

        print("\n[INFO] Waiting for protection to complete...")
        print(f"[INFO] Watching: {file_path}")
        print(
            f"[INFO] Stability Requirement: {required_stable_checks} consecutive unlocked checks"
        )
        print(f"[INFO] Interval: {check_interval}s | Timeout: {timeout}s")

        start_time = time.time()

        # Initial buffer to let the packer start its work
        time.sleep(20)

        while time.time() - start_time < timeout:
            elapsed = int(time.time() - start_time)

            if file_path.exists():
                current_size = file_path.stat().st_size

                if self.is_file_locked(str(file_path)):
                    # File is busy; reset the stability counter
                    if stable_count > 0:
                        print(
                            f"  [{elapsed}s] Lock reappeared! Resetting stability counter."
                        )

                    stable_count = 0
                    print(f"  [{elapsed}s] Protecting... {current_size:,} bytes")
                else:
                    # File is unlocked; increment stability counter
                    stable_count += 1
                    print(
                        f"  [{elapsed}s] File unlocked. Verification {stable_count}/{required_stable_checks}..."
                    )

                    if stable_count >= required_stable_checks:
                        print(
                            f"\n[SUCCESS] Protection complete and verified stable! ({elapsed}s)"
                        )
                        print(f"[INFO] Output file: {file_path}")
                        print(f"[INFO] Final size: {current_size:,} bytes")
                        return str(file_path)
            else:
                print(f"  [{elapsed}s] File not found, waiting...")
                stable_count = 0  # Reset if file disappears

            time.sleep(check_interval)

        # Timeout reached
        print(
            f"\n[ERROR] Timeout after {timeout}s waiting for stable protection completion"
        )
        return None

    def close_acprotect(self):
        """
        Close ACProtect application and handle the save project popup.

        Popup asks to save project - Tab to 'No' and press Enter.
        """
        print("\n[INFO] Closing ACProtect...")

        try:
            # Send Alt+F4 to close the window
            pyautogui.hotkey("alt", "F4")
            time.sleep(0.5)

            # Popup appears - Tab to 'No' button
            print("[INFO] Handling save project popup - pressing Tab then Enter...")
            pyautogui.press("tab")
            time.sleep(0.2)

            # Press Enter to click 'No'
            pyautogui.press("enter")
            time.sleep(0.3)

            print("[SUCCESS] ACProtect closed")
            return True

        except Exception as e:
            print(f"[ERROR] Failed to close ACProtect: {e}")
            return False

    def center_window_on_monitor(self, monitor_number=0):
        """
        Move and center the window on a specific monitor.
        """
        try:
            if not self.window:
                print("[ERROR] No window available")
                return False

            hwnd = self.window._hWnd

            monitors = get_monitors()
            if monitor_number >= len(monitors):
                print(f"[WARNING] Monitor {monitor_number} not found, using primary")
                monitor_number = 0

            monitor = monitors[monitor_number]

            # Get window dimensions
            rect = win32gui.GetWindowRect(hwnd)
            window_width = rect[2] - rect[0]
            window_height = rect[3] - rect[1]

            # Calculate centered position
            new_x = monitor.x + (monitor.width - window_width) // 2
            new_y = monitor.y + (monitor.height - window_height) // 2

            # Move the window
            win32gui.SetWindowPos(
                hwnd,
                win32con.HWND_TOP,
                new_x,
                new_y,
                window_width,
                window_height,
                win32con.SWP_SHOWWINDOW,
            )

            print(f"[SUCCESS] Window centered on monitor {monitor_number}")
            return True

        except Exception as e:
            print(f"[ERROR] Failed to center window: {e}")
            return False

    def run(self, click_mode="all", file_path=None, output_dir=None):
        """
        Main execution flow for ACProtect.
        """
        input_file = None

        try:
            # Step 1: Load packer info from YAML
            if not self.load_packer_info():
                return False

            # Step 2: Launch application with shell=True
            print("\n[INFO] Launching ACProtect with shell=True...")
            if not self.launch_application(shell=True):
                print("[ERROR] Failed to launch application")
                return False

            # Step 3: Find the window by title
            if not self.find_window(window_title="ACProtector"):
                print("[ERROR] Could not find ACProtect window")
                return False

            print("\n[SUCCESS] ACProtect launched successfully!")

            # Step 3b: Center window on primary monitor
            time.sleep(0.3)
            self.center_window_on_monitor(monitor_number=1)

            # Step 4: Enter file path (click, tab, paste)
            time.sleep(0.5)
            if file_path:
                input_file = Path(file_path).resolve()
                if not self.enter_file_path(input_file):
                    print("[ERROR] Failed to enter file path")
                    return False
            else:
                print("[ERROR] No file path provided")
                return False

            # Step 5: Click the Protect tab to start protection
            time.sleep(0.3)
            print("\n[INFO] Clicking Protect tab...")
            if not self.click_protect_tab():
                print("[ERROR] Failed to click Protect tab")
                return False

            print("[INFO] Protection process started!")

            # Step 6: Wait for protection to complete
            protected_file = self.wait_for_protection_complete(str(input_file))

            if protected_file:
                # Step 7: Move to output directory if specified
                final_path = self.move_protected_file_to_output(
                    protected_file, output_dir
                )

                if final_path:
                    print(f"\n{'=' * 60}")
                    print("PROTECTION COMPLETE")
                    print(f"{'=' * 60}")
                    print(f"  Input:  {input_file}")
                    print(f"  Output: {final_path}")
                    print(f"{'=' * 60}")

                # Step 8: Close application after success
                self.close_acprotect()
                print("\n[SUCCESS] Automation complete!")
                return True
            else:
                print("[ERROR] Protection process failed or timed out")
                self.close_acprotect()
                return False

        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")
            import traceback

            traceback.print_exc()
            self.close_acprotect()
            return False


def main():
    """Entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="ACProtect GUI Automation Wrapper",
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

    wrapper = ACProtect(yaml_path, main_dir)
    success = wrapper.run(file_path=args.file_path, output_dir=args.output_dir)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
