"""
Armadillo GUI Wrapper - Launch, dismiss trial dialogs, wait 60 seconds, close.

Armadillo is GUI-only and cannot be scripted via CLI.
On startup it shows a trial edition dialog (and possibly a second one);
this wrapper clicks "Basic" to dismiss each, then holds the main window
open for 60 seconds before terminating.
"""

import sys
import time
from pathlib import Path
import pyautogui
import pygetwindow as gw
from base_gui import BaseGUI

TRIAL_DIALOG_TITLE = "The Armadillo Software Protection System, Trial Edition"

# "Basic" button position as percentage of the dialog's client area.
# Measured from the screenshot: button row near the bottom-left of the dialog.
BASIC_BTN_X = 0.11
BASIC_BTN_Y = 0.83


class Armadillo(BaseGUI):
    """
    Wrapper for Armadillo PE protector.

    1. Launches the application
    2. Dismisses the trial-edition startup dialog(s) by clicking Basic
    3. Finds the main window
    4. Waits 60 seconds
    5. Closes the application
    """

    def get_packer_name(self) -> str:
        return "armadillo"

    def _click_basic_on_dialog(self, dialog_window) -> bool:
        """Activate a dialog window and click its Basic button."""
        try:
            dialog_window.activate()
            time.sleep(0.3)

            client_info = self._get_client_area_info(dialog_window.title)
            if not client_info:
                print(
                    "[WARNING] Could not get dialog client area; using fallback click"
                )
                # Fallback: click at absolute center-ish of the dialog
                rect = dialog_window
                pyautogui.click(
                    dialog_window.left + int(dialog_window.width * BASIC_BTN_X),
                    dialog_window.top + int(dialog_window.height * BASIC_BTN_Y),
                )
                return True

            client_width, client_height, client_point = client_info
            abs_x = client_point[0] + int(client_width * BASIC_BTN_X)
            abs_y = client_point[1] + int(client_height * BASIC_BTN_Y)

            print(f"[ACTION] Clicking Basic at ({abs_x}, {abs_y})")
            pyautogui.click(abs_x, abs_y)
            time.sleep(0.5)
            return True

        except Exception as e:
            print(f"[ERROR] Failed to click Basic: {e}")
            return False

    def dismiss_trial_dialogs(self, count=2, timeout=10) -> int:
        """
        Wait for and dismiss up to `count` trial-edition dialogs by clicking Basic.

        Returns the number of dialogs successfully dismissed.
        """
        dismissed = 0
        for i in range(count):
            print(f"\n[INFO] Waiting for trial dialog {i + 1}/{count}...")
            start = time.time()
            dialog = None

            while time.time() - start < timeout:
                try:
                    matches = gw.getWindowsWithTitle(TRIAL_DIALOG_TITLE)
                    if matches:
                        dialog = matches[0]
                        break
                except Exception:
                    pass
                time.sleep(0.3)

            if dialog:
                print(f"[SUCCESS] Found trial dialog: '{dialog.title}'")
                if self._click_basic_on_dialog(dialog):
                    dismissed += 1
                    print(f"[INFO] Dismissed dialog {dismissed}/{count}")
                    time.sleep(0.5)  # brief pause before looking for the next one
            else:
                print(
                    f"[INFO] No more trial dialogs found after {timeout}s (dismissed {dismissed})"
                )
                break

        return dismissed

    def fill_edit_project_dialog(self, file_path) -> bool:
        """
        Fill the Edit Project dialog:
          1. Type project name (file stem)
          2. Tab → paste absolute file path
          3. Tab x16 to reach Certificates area
          4. Click New x3
        """
        import pyperclip

        file_path = Path(file_path)
        project_name = file_path.stem
        abs_path = str(file_path.resolve())

        # Find the Edit Project dialog
        print("[INFO] Waiting for Edit Project dialog...")
        start = time.time()
        dialog = None
        while time.time() - start < 10:
            try:
                matches = gw.getWindowsWithTitle("Edit Project")
                if matches:
                    dialog = matches[0]
                    break
            except Exception:
                pass
            time.sleep(0.3)

        if not dialog:
            print("[ERROR] Edit Project dialog not found")
            return False

        print("[SUCCESS] Found Edit Project dialog")
        dialog.activate()
        time.sleep(0.3)

        # Type project name (Project Name field is focused on open)
        print(f"[INFO] Typing project name: {project_name}")
        pyautogui.hotkey("ctrl", "a")
        pyautogui.typewrite(project_name, interval=0.04)

        # Tab → File to Protect field, paste path
        pyautogui.press("tab")
        pyautogui.press("tab")
        time.sleep(0.2)
        print(f"[INFO] Pasting file path: {abs_path}")
        pyperclip.copy(abs_path)
        pyautogui.hotkey("ctrl", "v")
        time.sleep(0.2)

        # Tab x16 to reach the Certificates / New button area
        print("[INFO] Tabbing 16 times...")
        for _ in range(16):
            pyautogui.press("tab")
            time.sleep(0.08)

        # Click New x3, filling the certificate dialog each time
        original_window = self.window
        self.window = dialog
        for i in range(1):
            print(f"[ACTION] Clicking New ({i + 1}/3)...")
            self.click_at_percent(0.66, 0.87, description=f"New button {i + 1}")
            time.sleep(0.5)
            self.window = original_window
            self.fill_edit_security_certificate(cert_name=file_path.stem)
            self.window = dialog
        self.window = original_window

        # Confirm Edit Project dialog
        pyautogui.press("tab")
        time.sleep(0.15)
        pyautogui.press("enter")
        time.sleep(0.3)
        print("[ACTION] Confirmed Edit Project dialog via Tab + Enter")

        return True

    def fill_edit_security_certificate(self, cert_name: str) -> bool:
        """
        Fill the Edit Security Certificate dialog:
          1. Type certificate name
          2. Tab once
          3. Tick the Default checkbox (click by position)
          4. Tab x14
          5. Click OK
        """
        print("[INFO] Waiting for Edit Security Certificate dialog...")
        start = time.time()
        dialog = None
        while time.time() - start < 10:
            try:
                matches = gw.getWindowsWithTitle("Edit Security Certificate")
                if matches:
                    dialog = matches[0]
                    break
            except Exception:
                pass
            time.sleep(0.3)

        if not dialog:
            print("[ERROR] Edit Security Certificate dialog not found")
            return False

        print("[SUCCESS] Found Edit Security Certificate dialog")
        dialog.activate()
        time.sleep(0.3)

        # Type certificate name
        print(f"[INFO] Typing certificate name: {cert_name}")
        pyautogui.hotkey("ctrl", "a")
        pyautogui.typewrite(cert_name, interval=0.04)

        # Tab once → Encryption template field, Tab again → Default checkbox, Space to tick
        pyautogui.press("tab")
        time.sleep(0.15)

        pyautogui.press("space")
        time.sleep(0.15)

        pyautogui.press("tab")
        time.sleep(0.15)

        print("[ACTION] Ticked Default checkbox via Space")

        # Tab x14
        print("[INFO] Tabbing 14 times...")
        for _ in range(14):
            pyautogui.press("tab")
            time.sleep(0.08)

        # Click OK
        original_window = self.window
        self.window = dialog
        self.click_at_percent(0.59, 0.943, description="OK button")
        self.window = original_window
        time.sleep(0.3)

        print("[SUCCESS] Edit Security Certificate filled and confirmed")
        return True

    def protect_file(self) -> bool:
        """Open Protection menu via Alt+P, arrow down 3x, Enter to trigger Protect File..."""
        if not self.window:
            print("[ERROR] No window to send keys to")
            return False
        try:
            self.window.activate()
            time.sleep(0.3)
            pyautogui.hotkey("alt", "p")
            time.sleep(0.3)
            for _ in range(2):
                pyautogui.press("down")
                time.sleep(0.1)
            pyautogui.press("enter")
            time.sleep(0.5)
            print("[ACTION] Protection > Protect File... triggered")
            return True
        except Exception as e:
            print(f"[ERROR] protect_file failed: {e}")
            return False

    def wait_for_protection_complete(self, file_path) -> str | None:
        """
        Wait for Armadillo to finish protecting the file.

        Armadillo overwrites the input file in-place, so we watch the input
        file: wait for it to be locked (packer working), then wait until it
        stays unlocked for several consecutive checks (stable = done).

        Returns the file path on success, None on timeout.
        """
        timeout = self.EXTRA_LONG_TIMEOUT
        check_interval = self.LONG_TIMEOUT
        required_stable_checks = 5
        stable_count = 0

        file_path = Path(file_path)

        print("\n[INFO] Waiting for Armadillo protection to complete...")
        print(f"[INFO] Watching: {file_path}")
        print(f"[INFO] Stability: {required_stable_checks} consecutive unlocked checks")
        print(f"[INFO] Interval: {check_interval}s | Timeout: {timeout}s")

        # Initial buffer — let Armadillo start working
        time.sleep(15)

        start_time = time.time()
        while time.time() - start_time < timeout:
            elapsed = int(time.time() - start_time)

            if file_path.exists():
                current_size = file_path.stat().st_size

                if self.is_file_locked(str(file_path)):
                    if stable_count > 0:
                        print(f"  [{elapsed}s] Lock reappeared — resetting stability counter.")
                    stable_count = 0
                    print(f"  [{elapsed}s] Protecting... {current_size:,} bytes")
                else:
                    stable_count += 1
                    print(f"  [{elapsed}s] Unlocked. Stability {stable_count}/{required_stable_checks}...")
                    if stable_count >= required_stable_checks:
                        print(f"\n[SUCCESS] Protection complete and stable! ({elapsed}s)")
                        print(f"[INFO] Output: {file_path} ({current_size:,} bytes)")
                        return str(file_path)
            else:
                print(f"  [{elapsed}s] File not yet found, waiting...")
                stable_count = 0

            time.sleep(check_interval)

        print(f"\n[ERROR] Timeout after {timeout}s waiting for protection to complete")
        return None

    def open_new_project(self) -> bool:
        """Open File > New Project via keyboard (Alt+F, N)."""
        if not self.window:
            print("[ERROR] No window to send keys to")
            return False
        try:
            self.window.activate()
            time.sleep(0.3)
            pyautogui.hotkey("alt", "f")
            time.sleep(0.3)
            pyautogui.press("n")
            time.sleep(0.5)
            print("[ACTION] File > New Project opened via keyboard")
            return True
        except Exception as e:
            print(f"[ERROR] open_new_project failed: {e}")
            return False

    def run(self, click_mode="all", file_path=None, output_dir=None) -> bool:
        """
        Launch Armadillo, dismiss trial dialogs, set up project, protect file, move output.
        """
        print("\n" + "=" * 60)
        print("ARMADILLO WRAPPER - Launch / Dismiss / Wait / Close")
        print("=" * 60)

        try:
            # Step 1: Load configuration
            if not self.load_packer_info():
                return False

            # Step 2: Launch application
            if not self.launch_application():
                return False

            # Step 3: Dismiss trial edition dialog(s) — click Basic on each
            dismissed = self.dismiss_trial_dialogs(count=2, timeout=10)
            print(f"[INFO] Dismissed {dismissed} trial dialog(s)")

            # Step 4: Find main window by title (Armadillo spawns with a different PID)
            if not self.find_window(
                window_title="Armadillo Software Protection System"
            ):
                print("[WARNING] Could not find Armadillo main window within timeout")
            else:
                self.center_window_on_monitor(monitor_number=0)
                self.get_window_dimensions()
                time.sleep(0.5)

                # Step 5: File → New Project
                print("\n[INFO] Opening File > New Project...")
                self.open_new_project()

                # Step 6: Fill Edit Project dialog
                if file_path:
                    self.fill_edit_project_dialog(file_path)

                # Step 7: Protection > Protect File...
                print("\n[INFO] Triggering Protection > Protect File...")
                self.protect_file()

            # Step 8: Watch file until stable
            if file_path:
                input_file = Path(file_path).resolve()
                protected_file = self.wait_for_protection_complete(str(input_file))

                if protected_file:
                    # Step 9: Move to output directory
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

                    self.close_application()
                    print("\n[SUCCESS] Armadillo automation complete!")
                    return True
                else:
                    print("[ERROR] Protection timed out or failed")
                    self.cleanup_on_failure(str(input_file))
                    return False
            else:
                # No file_path — fallback to fixed wait then close
                print("\n[INFO] No file path — holding open 60 seconds...")
                for remaining in range(60, 0, -5):
                    print(f"  [{remaining}s remaining]")
                    time.sleep(5)
                self.close_application()
                return True

        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            if file_path:
                self.cleanup_on_failure(str(Path(file_path).resolve()))
            else:
                self.close_application()
            return False


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Armadillo GUI Wrapper - launch, wait 60s, close"
    )
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    main_dir = script_dir.parent
    yaml_path = main_dir / "manifest" / "packer_corpus.yaml"

    if not yaml_path.exists():
        print(f"[ERROR] YAML not found: {yaml_path}")
        return 1

    wrapper = Armadillo(str(yaml_path), str(main_dir))
    success = wrapper.run()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
