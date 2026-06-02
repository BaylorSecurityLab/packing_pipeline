"""
Themida GUI Wrapper - Launch, fill filenames, click Protect, watch output, close.

Themida is GUI-only with no CLI interface. This wrapper:
  1. Launches Themida.exe
  2. Finds the main window
  3. Pastes Input / Output Filename into the Application Information panel
  4. Clicks the Protect toolbar button
  5. Watches the output file until it is written and stable
  6. Moves the output to the configured output directory
  7. Closes the application
"""

import sys
import time
import traceback
import pyautogui
import pyperclip
from pathlib import Path
from base_gui import BaseGUI

# Window title fragment to locate the main Themida window
WINDOW_TITLE = "Themida x86"

# --- Percentage-based coordinates within the client area ---
# Derived from screenshot: 1196×955 window, title bar ~30px

# Application Information panel fields (right panel)
INPUT_FILENAME_FIELD_X = 0.61
INPUT_FILENAME_FIELD_Y = 0.38
OUTPUT_FILENAME_FIELD_X = 0.61
OUTPUT_FILENAME_FIELD_Y = 0.41

# Toolbar "Protect" button (5th item in toolbar row)
PROTECT_BTN_X = 0.27
PROTECT_BTN_Y = 0.15


class ThemidaGUI(BaseGUI):
    """
    Wrapper for Themida GUI packer (v3.2.4.34 Demo).

    Flow:
        1. Load config / launch
        2. Find & centre window
        3. Fill Input Filename + Output Filename fields
        4. Click Protect
        5. Wait for output file to appear and stabilise
        6. Move output to output_dir
        7. Close
    """

    def get_packer_name(self) -> str:
        return "themida_v3.2.4.34"

    # ------------------------------------------------------------------ #
    #  Fill Application Information fields                                 #
    # ------------------------------------------------------------------ #

    def fill_application_info(self, file_path: str, output_path: str) -> bool:
        """
        Navigate entirely by keyboard — no coordinate clicks.

        Tab order on the Application Information panel:
          focus → Application field
          Tab×1 → Input Filename text
          Tab×1 → ... (browse input)
          Tab×1 → ↺ refresh
          Tab×1 → Output Filename text

        So: Tab×1 → Input, Tab×3 more → Output.
        """
        if not self.window:
            print("[ERROR] No window available for field input")
            return False

        try:
            self.window.activate()
            time.sleep(0.4)

            # --- Tab×2 to Input Filename (no focus → Application → Input) ---
            print("\n[ACTION] Tabbing to Input Filename field (Tab×2)...")
            for _ in range(2):
                pyautogui.press("tab")
                time.sleep(0.2)
            pyautogui.hotkey("ctrl", "a")
            pyperclip.copy(str(file_path))
            pyautogui.hotkey("ctrl", "v")
            time.sleep(0.4)
            print(f"  Pasted: {file_path}")

            # --- Tab×2 to Output Filename ---
            print("\n[ACTION] Tabbing to Output Filename field (Tab×2)...")
            for _ in range(2):
                pyautogui.press("tab")
                time.sleep(0.2)
            pyautogui.hotkey("ctrl", "a")
            pyperclip.copy(str(output_path))
            pyautogui.hotkey("ctrl", "v")
            time.sleep(0.4)
            print(f"  Pasted: {output_path}")

            return True

        except Exception as e:
            print(f"[ERROR] fill_application_info failed: {e}")
            return False

    # ------------------------------------------------------------------ #
    #  Force-close entire Themida process tree                             #
    # ------------------------------------------------------------------ #

    def close_application(self, SHORT_TIMEOUT=BaseGUI.SHORT_TIMEOUT):
        """
        Override base close: kill the full Themida process tree via taskkill.
        Base terminate() only kills the launched PID; Themida spawns children
        during protection that must also be killed.
        """
        import subprocess as sp

        print("[INFO] Closing Themida (taskkill /F /IM Themida.exe /T)...")
        try:
            sp.run(
                ["taskkill", "/F", "/IM", "Themida.exe", "/T"],
                capture_output=True,
            )
            print("[INFO] taskkill issued for Themida.exe")
        except Exception as e:
            print(f"[WARNING] taskkill failed: {e}")

        # Also terminate the tracked process handle if still alive
        try:
            if self.process and self.process.poll() is None:
                self.process.kill()
        except Exception:
            pass

        self.process = None
        self.window = None

    # ------------------------------------------------------------------ #
    #  Click Protect                                                        #
    # ------------------------------------------------------------------ #

    def click_protect(self) -> bool:
        """Click the Protect button in the Themida toolbar."""
        if not self.window:
            print("[ERROR] No window to click Protect on")
            return False
        try:
            self.window.activate()
            time.sleep(0.3)
            self.click_at_percent(
                PROTECT_BTN_X,
                PROTECT_BTN_Y,
                description="Protect toolbar button",
            )
            time.sleep(0.5)
            print("[ACTION] Protect clicked")
            return True
        except Exception as e:
            print(f"[ERROR] click_protect failed: {e}")
            return False

    # ------------------------------------------------------------------ #
    #  Dismiss DEMO Warning dialog                                         #
    # ------------------------------------------------------------------ #

    def dismiss_warning_dialog(self, timeout: int = 15) -> bool:
        """
        Wait for the Themida DEMO 'Warning' dialog and dismiss it via Enter.

        Themida shows this dialog after clicking Protect:
            'This application will be protected with some DEMO restrictions'
        The OK button is the default focused control, so pressing Enter suffices.
        """
        import pygetwindow as gw

        print("\n[INFO] Waiting for Warning dialog...")
        start = time.time()
        while time.time() - start < timeout:
            try:
                matches = gw.getWindowsWithTitle("Warning")
                if matches:
                    dialog = matches[0]
                    print(f"[SUCCESS] Found Warning dialog: '{dialog.title}'")
                    dialog.activate()
                    time.sleep(0.3)
                    pyautogui.press("enter")
                    time.sleep(0.3)
                    print("[ACTION] Warning dialog dismissed (Enter)")
                    return True
            except Exception:
                pass
            time.sleep(0.3)

        print("[WARNING] Warning dialog not found within timeout — continuing anyway")
        return False

    # ------------------------------------------------------------------ #
    #  Wait for output file to appear and stabilise                        #
    # ------------------------------------------------------------------ #

    def wait_for_protection_complete(self, output_path: str) -> str | None:
        """
        Poll the output file until it exists and is no longer locked.

        Strategy (mirrors armadillo.py):
          - Give Themida an initial buffer to start writing
          - Poll every CHECK_INTERVAL seconds
          - Require REQUIRED_STABLE_CHECKS consecutive unlocked polls
          - Bail out after EXTRA_LONG_TIMEOUT seconds total

        Returns the output path string on success, None on timeout.
        """
        timeout = self.EXTRA_LONG_TIMEOUT  # 500 s
        check_interval = 5  # seconds between polls
        required_stable_checks = 4
        stable_count = 0

        output_file = Path(output_path)

        print("\n[INFO] Waiting for Themida protection to complete...")
        print(f"[INFO] Watching: {output_file}")
        print(f"[INFO] Stability: {required_stable_checks} consecutive unlocked checks")
        print(f"[INFO] Interval: {check_interval}s | Timeout: {timeout}s")

        # Give Themida time to start the protection pass
        time.sleep(10)

        start_time = time.time()
        while time.time() - start_time < timeout:
            elapsed = int(time.time() - start_time)

            if output_file.exists():
                current_size = output_file.stat().st_size

                if self.is_file_locked(str(output_file)):
                    if stable_count > 0:
                        print(
                            f"  [{elapsed}s] Lock reappeared — resetting stability counter."
                        )
                    stable_count = 0
                    print(f"  [{elapsed}s] Writing... {current_size:,} bytes")
                else:
                    stable_count += 1
                    print(
                        f"  [{elapsed}s] Unlocked. "
                        f"Stability {stable_count}/{required_stable_checks}..."
                    )
                    if stable_count >= required_stable_checks:
                        print(
                            f"\n[SUCCESS] Protection complete and stable! ({elapsed}s)"
                        )
                        print(f"[INFO] Output: {output_file} ({current_size:,} bytes)")
                        return str(output_file)
            else:
                print(f"  [{elapsed}s] Output file not yet found, waiting...")
                stable_count = 0

            time.sleep(check_interval)

        print(f"\n[ERROR] Timeout after {timeout}s — protection did not complete.")
        return None

    # ------------------------------------------------------------------ #
    #  Main run flow                                                        #
    # ------------------------------------------------------------------ #

    def run(self, click_mode="all", file_path=None, output_dir=None) -> bool:
        """
        Full Themida automation: launch → fill fields → protect → watch → move → close.
        """
        print("\n" + "=" * 60)
        print("THEMIDA WRAPPER - Launch / Fill / Protect / Watch / Close")
        print("=" * 60)

        try:
            # Step 1: Load configuration
            if not self.load_packer_info():
                return False

            # Step 2: Launch application
            if not self.launch_application():
                return False

            # Step 3: Find main window
            if not self.find_window(
                window_title=WINDOW_TITLE, timeout=self.LONG_TIMEOUT
            ):
                print("[WARNING] Could not find Themida main window; continuing anyway")
            else:
                self.center_window_on_monitor(monitor_number=0)
                time.sleep(0.5)

            # Step 4: Build output path and fill fields
            if not file_path:
                print("[ERROR] No input file provided")
                self.close_application()
                return False

            input_path = Path(file_path).resolve()
            out_dir = Path(output_dir) if output_dir else input_path.parent
            out_dir.mkdir(parents=True, exist_ok=True)
            output_path = out_dir / (input_path.stem + "_protected" + input_path.suffix)

            if not self.fill_application_info(str(input_path), str(output_path)):
                self.cleanup_on_failure(str(input_path))
                return False

            # Step 5: Click Protect and dismiss the DEMO warning dialog
            if not self.click_protect():
                self.cleanup_on_failure(str(input_path))
                return False

            self.dismiss_warning_dialog()

            # Step 6: Wait for output file to stabilise
            protected_file = self.wait_for_protection_complete(str(output_path))

            if protected_file:
                # Step 7: Move to final output directory (already there — log it)
                print(f"\n{'=' * 60}")
                print("PROTECTION COMPLETE")
                print(f"{'=' * 60}")
                print(f"  Input:  {input_path}")
                print(f"  Output: {protected_file}")
                print(f"{'=' * 60}")
                self.close_application()
                print("\n[SUCCESS] Themida automation complete!")
                return True
            else:
                print("[ERROR] Protection timed out or failed")
                self.cleanup_on_failure(str(input_path))
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
    import argparse

    parser = argparse.ArgumentParser(
        description="Themida GUI Wrapper - launch, fill fields, protect, watch output, close"
    )
    parser.add_argument("--file", required=True, help="Input executable path")
    parser.add_argument("--output-dir", help="Output directory for protected file")
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    main_dir = script_dir.parent
    yaml_path = main_dir / "manifest" / "packer_corpus.yaml"

    if not yaml_path.exists():
        print(f"[ERROR] YAML not found: {yaml_path}")
        return 1

    wrapper = ThemidaGUI(str(yaml_path), str(main_dir))
    success = wrapper.run(file_path=args.file, output_dir=args.output_dir)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
