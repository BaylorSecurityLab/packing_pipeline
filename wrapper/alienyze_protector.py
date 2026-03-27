"""
Alienyze GUI Automation Wrapper - Using Base GUI Wrapper
"""

import sys
import time
from pathlib import Path
from base_gui import BaseGUI
import pyautogui
import pyperclip
import subprocess
import pygetwindow as gw
import traceback


class AlienyzeProtector(BaseGUI):
    """
    Wrapper for Alienyze GUI automation using the BaseGUIWrapper.
    """

    # UI element positions (x_percent, y_percent)
    UI_POSITIONS = {
        "file_dir": (0.50, 0.10),
        "settings_button": (0.40, 0.70),
        "build_button": (0.70, 0.70),
    }

    # Settings dialog positions
    SETTINGS_DIALOG_POSITIONS = {
        "compression_dropdown": (0.50, 0.18),
        "debugger_dropdown": (0.50, 0.33),
        "vm_dropdown": (0.50, 0.48),
        "integrity_dropdown": (0.50, 0.63),
        "ok_button": (0.65, 0.90),
    }

    def __init__(self, yaml_path, main_dir):
        """Initialize Alienyze wrapper"""
        super().__init__(yaml_path, main_dir)

    def get_packer_name(self):
        """Return the packer name for YAML lookup"""
        return "alienyze_protector"

    def click_window_to_file_dir(self):
        """Click somewhere safe on the window to give it focus"""
        x, y = self.UI_POSITIONS["file_dir"]
        return self.click_at_percent(x, y, "File directory text box")

    def click_settings_button(self):
        """Click somewhere safe on the window to give it focus"""
        x, y = self.UI_POSITIONS["settings_button"]
        return self.click_at_percent(x, y, "Settings Button")

    def click_build_button(self):
        """Click somewhere safe on the window to give it focus"""
        x, y = self.UI_POSITIONS["build_button"]
        return self.click_at_percent(x, y, "Build Button")

    def configure_settings_dialog(self):
        """
        Configure all settings in the Settings dialog.
        For each dropdown: click it, press Down, press Enter.
        Then click OK.
        """
        print("\n[INFO] Configuring Settings dialog...")

        # Wait for dialog to fully open
        time.sleep(0.5)

        settings_window = None
        for win in gw.getAllWindows():
            if win.title and "settings" in win.title.lower():
                settings_window = win
                break

        if not settings_window:
            print("[WARNING] Settings dialog not found, using main window coordinates")
            # Fall back to clicking at absolute screen positions
            settings_window = self.window

        # Get dialog bounds
        left = settings_window.left
        top = settings_window.top
        width = settings_window.width
        height = settings_window.height

        dropdowns = [
            ("compression_dropdown", "Compression"),
            ("debugger_dropdown", "Debugger Detection"),
            ("vm_dropdown", "VM Detection"),
            ("integrity_dropdown", "Integrity Detection"),
        ]

        for key, name in dropdowns:
            x_pct, y_pct = self.SETTINGS_DIALOG_POSITIONS[key]
            click_x = left + int(width * x_pct)
            click_y = top + int(height * y_pct)

            print(f"[INFO] Setting {name}...")
            pyautogui.click(click_x, click_y)
            time.sleep(0.2)
            pyautogui.press("down")
            time.sleep(0.1)
            pyautogui.press("enter")
            time.sleep(0.2)

        # Click OK button
        print("[INFO] Clicking OK button...")
        x_pct, y_pct = self.SETTINGS_DIALOG_POSITIONS["ok_button"]
        click_x = left + int(width * x_pct)
        click_y = top + int(height * y_pct)
        pyautogui.click(click_x, click_y)
        time.sleep(0.3)

        print("[SUCCESS] Settings configured!")
        return True

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
        if not self.click_window_to_file_dir():
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

        print(f"[SUCCESS] Entered file path in both text boxes: {file_path}")
        return True

    def center_window_on_monitor(self, monitor_number=0):
        """
        Move and center the window on a specific monitor.
        """
        try:
            from screeninfo import get_monitors
            import win32gui
            import win32con

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

    def wait_for_protection_complete(self, file_path):
        """
        Wait for the protection process to complete with stability verification.

        Requires the file to remain unlocked for 5 consecutive checks to ensure
        the packer hasn't just momentarily dropped the lock due to an error.

        Args:
            file_path: Path to the file being protected

        Returns:
            str: Path to protected file if successful, None otherwise
        """
        timeout = self.EXTRA_LONG_TIMEOUT
        file_path = Path(file_path)
        check_interval = self.LONG_TIMEOUT

        # Stability settings
        required_stable_checks = 5
        stable_count = 0

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

    def get_alienyze_windows(self):
        """
        Get only actual Alienyze windows (exclude editors).

        Returns:
            list: Alienyze window objects
        """
        import pygetwindow as gw

        alienyze_windows = []

        # Titles to exclude (editors, IDEs, etc.)
        exclude_patterns = [
            "visual studio code",
            "vs code",
            "pycharm",
            "sublime",
            "notepad",
            ".py -",  # Python files open in editors
            ".py —",  # Em dash variant
        ]

        for win in gw.getAllWindows():
            if win.title and "alienyze" in win.title.lower():
                title_lower = win.title.lower()
                # Skip if it matches any exclude pattern
                if not any(pattern in title_lower for pattern in exclude_patterns):
                    alienyze_windows.append(win)

        return alienyze_windows

    def force_close_alienyze(self, max_attempts=10, wait_between=1):
        """
        Force close Alienyze and verify it's actually closed.

        Args:
            max_attempts: Maximum number of close attempts
            wait_between: Seconds to wait between attempts

        Returns:
            bool: True if closed successfully
        """
        for attempt in range(max_attempts):
            windows = self.get_alienyze_windows()

            if not windows:
                print("[SUCCESS] Alienyze is closed")
                return True

            print(
                f"[INFO] Close attempt {attempt + 1}/{max_attempts} - Found {len(windows)} window(s)"
            )

            try:
                for win in windows:
                    try:
                        print(f"[DEBUG] Closing window: '{win.title}'")
                        win.activate()
                        time.sleep(0.2)
                    except:
                        pass

                # Method 1: Alt+F4
                pyautogui.hotkey("alt", "F4")
                time.sleep(0.5)

                # Check if closed without pressing anything else
                if not self.get_alienyze_windows():
                    print("[SUCCESS] Alienyze closed via Alt+F4")
                    return True

                # Method 2: Taskkill (update process name as needed)
                print("[INFO] Trying taskkill...")
                subprocess.run(
                    ["taskkill", "/IM", "alienyze.exe", "/F"],
                    capture_output=True,
                    timeout=5,
                )
                time.sleep(wait_between)

            except Exception as e:
                print(f"[WARNING] Close attempt failed: {e}")
                time.sleep(wait_between)

        if not self.get_alienyze_windows():
            return True

        print(f"[ERROR] Failed to close Alienyze after {max_attempts} attempts")
        return False

    def ensure_alienyze_closed(self):
        """
        Ensure no Alienyze instance is running before starting.
        """
        windows = self.get_alienyze_windows()

        if windows:
            print(
                f"\n[WARNING] Found {len(windows)} existing Alienyze window(s), closing..."
            )
            self.force_close_alienyze()
        else:
            print("[INFO] No existing Alienyze instance found")

    def close_alienyze(self):
        """
        Close Alienyze application and verify it's closed.
        """
        print("\n[INFO] Closing Alienyze...")
        return self.force_close_alienyze()

    def run(self, click_mode="all", file_path=None, output_dir=None):
        """
        Main execution flow for Alienyze.

        Args:
            click_mode: Configuration mode (e.g., 'all', 'none', dict, list)
            file_path: Path to the input file
            output_dir: Directory to move final output to (optional)

        Returns:
            bool: True if successful, False otherwise
        """
        input_file = None

        try:
            # Step 0: Ensure no existing Alienyze is running
            self.ensure_alienyze_closed()

            # Step 1: Load packer info from YAML
            print("\n" + "=" * 60)
            print("ALIENYZE GUI AUTOMATION")
            print("=" * 60)

            if not self.load_packer_info():
                print("[ERROR] Failed to load packer info from YAML")
                return False

            # Step 2: Launch application
            print("\n[INFO] Launching Alienyze...")
            if not self.launch_application(shell=True):
                print("[ERROR] Failed to launch application")
                return False

            # Step 3: Find the window by title
            # Try to find by process first, then by partial title match
            if not self.find_window(window_title="alienyze"):
                print(
                    "[WARNING] Could not find window by exact title, trying process search..."
                )
                if not self.find_window():
                    print("[ERROR] Could not find Alienyze window")
                    return False

            print("\n[SUCCESS] Alienyze launched successfully!")

            # Step 3b: Center window on primary monitor
            time.sleep(0.3)
            self.center_window_on_monitor(monitor_number=1)

            print("\n[SUCCESS] Alienyze launched and window found!")
            print(f"[INFO] Window title: {self.window.title}")

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

            # Step 5: Click build button
            time.sleep(0.5)
            print("\n[INFO] Clicking settings button...")

            # Ensure window is active before clicking
            if self.window:
                try:
                    self.window.activate()
                    time.sleep(0.2)
                    print(f"[DEBUG] Window activated: {self.window.title}")
                except Exception as e:
                    print(f"[WARNING] Could not activate window: {e}")

            # Step 5: Open Settings and configure
            time.sleep(0.5)
            print("\n[INFO] Opening Settings...")
            if not self.click_settings_button():
                print("[ERROR] Failed to click settings button")
                return False

            time.sleep(0.5)
            self.configure_settings_dialog()

            # Step 6: Click build button (existing code)
            time.sleep(0.5)
            print("\n[INFO] Clicking build button...")

            print("[SUCCESS] Build settings clicked!")
            print("[INFO] Protection process started!")

            # Step 5: Click build button
            time.sleep(0.5)
            print("\n[INFO] Clicking build button...")

            # Ensure window is active before clicking
            if self.window:
                try:
                    self.window.activate()
                    time.sleep(0.2)
                    print(f"[DEBUG] Window activated: {self.window.title}")
                except Exception as e:
                    print(f"[WARNING] Could not activate window: {e}")

            if not self.click_build_button():
                print("[ERROR] Failed to click build button")
                return False

            print("[SUCCESS] Build button clicked!")
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
                self.close_alienyze()
                print("\n[SUCCESS] Automation complete!")
                return True
            else:
                print("[ERROR] Protection process failed or timed out")
                self.close_alienyze()
                return False

        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")

            traceback.print_exc()
            # self.close_alienyze()
            return False


def main():
    """Entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Alienyze GUI Automation Wrapper",
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

    wrapper = Alienyze(yaml_path, main_dir)
    success = wrapper.run(file_path=args.file_path, output_dir=args.output_dir)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
