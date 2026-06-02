"""
XPA v1.43 GUI Wrapper

XPA (eXecutable Packer for Applications) v1.43 is GUI-only.
This wrapper:
  1. Launches XPA.EXE
  2. Finds the main window
  3. Clicks the filepath field (0.75 x, 0.42 y) and pastes the input path
  4. Tab → Enter to confirm path, Tab → Enter to click Pack
  5. Dismisses any XPA error/info dialog that appears after Pack
  6. Watches for the output file (packed in-place, same name)
  7. Moves the output to output_dir
  8. Closes the application
"""

import sys
import time
import traceback
import pyautogui
import pyperclip
import pygetwindow as gw
import win32gui
from pathlib import Path
from base_gui import BaseGUI

# XPA dialog title for error/info popups
XPA_DIALOG_TITLE = "XPA"

# Keywords that indicate a fatal error in the dialog text
XPA_ERROR_KEYWORDS = ["failed", "error", "cannot", "invalid"]


class XPAV143GUI(BaseGUI):
    def get_packer_name(self) -> str:
        return "xpa_v1.43"

    def _get_dialog_text(self, hwnd: int) -> str:
        """Collect all child window texts from a dialog into a single string."""
        texts = []

        def _enum(child_hwnd, _):
            t = win32gui.GetWindowText(child_hwnd)
            if t:
                texts.append(t)
            return True

        win32gui.EnumChildWindows(hwnd, _enum, None)
        return " ".join(texts).lower()

    def dismiss_xpa_dialog(self, timeout: int = 10) -> str | None:
        """
        Wait for any XPA modal dialog, dismiss it, and return:
          "error"  — dialog text contains a known error keyword
          "info"   — dialog appeared but is not an error
          None     — no dialog appeared within timeout
        """
        print("\n[INFO] Checking for XPA dialog...")
        start = time.time()
        while time.time() - start < timeout:
            try:
                matches = [w for w in gw.getWindowsWithTitle(XPA_DIALOG_TITLE) if w.title == XPA_DIALOG_TITLE]
                if matches:
                    dialog = matches[0]
                    hwnd = dialog._hWnd
                    text = self._get_dialog_text(hwnd)
                    if text:
                        is_error = any(kw in text for kw in XPA_ERROR_KEYWORDS)
                    else:
                        # Could not read dialog text — treat as error to be safe
                        is_error = True
                    print(
                        f"[{'ERROR' if is_error else 'INFO'}] XPA dialog text: '{text.strip() or '(unreadable)'}'"
                    )
                    dialog.activate()
                    time.sleep(0.3)
                    pyautogui.press("enter")
                    time.sleep(0.3)
                    return "error" if is_error else "info"
            except Exception:
                pass
            time.sleep(0.3)
        print("[INFO] No XPA dialog appeared")
        return None

    def wait_for_pack_complete(self, output_path: str) -> str | None:
        """
        Poll the output file until it exists and is stable (not locked).
        XPA packs in-place so output_path == input_path.
        """
        timeout = self.EXTRA_LONG_TIMEOUT
        check_interval = 3
        required_stable_checks = 3
        stable_count = 0

        output_file = Path(output_path)

        print(f"\n[INFO] Watching for output: {output_file}")
        print(f"[INFO] Interval: {check_interval}s | Timeout: {timeout}s")

        time.sleep(5)  # give XPA time to start writing

        start_time = time.time()
        while time.time() - start_time < timeout:
            elapsed = int(time.time() - start_time)

            if output_file.exists():
                current_size = output_file.stat().st_size
                if self.is_file_locked(str(output_file)):
                    stable_count = 0
                    print(f"  [{elapsed}s] Writing... {current_size:,} bytes")
                else:
                    stable_count += 1
                    print(
                        f"  [{elapsed}s] Unlocked. Stability {stable_count}/{required_stable_checks}..."
                    )
                    if stable_count >= required_stable_checks:
                        print(f"\n[SUCCESS] Pack complete and stable! ({elapsed}s)")
                        print(f"[INFO] Output: {output_file} ({current_size:,} bytes)")
                        return str(output_file)
            else:
                print(f"  [{elapsed}s] Output file not yet found, waiting...")
                stable_count = 0

            time.sleep(check_interval)

        print(f"\n[ERROR] Timeout after {timeout}s — pack did not complete.")
        return None

    def run(self, click_mode="all", file_path=None, output_dir=None) -> bool:
        print("\n" + "=" * 60)
        print("XPA v1.43 WRAPPER")
        print("=" * 60)

        try:
            if not self.load_packer_info():
                return False

            if not file_path:
                print("[ERROR] No input file provided")
                return False

            input_path = Path(file_path).resolve()
            abs_path = str(input_path)

            # XPA packs in-place — output has the same name in the same directory
            output_path = input_path

            if not self.launch_application():
                return False

            if not self.find_window(timeout=self.LONG_TIMEOUT):
                print("[ERROR] Could not find XPA main window")
                self.close_application()
                return False

            self.center_window_on_monitor(monitor_number=1)
            time.sleep(0.5)

            # Click filepath field and paste absolute input path
            if not self.click_at_percent(0.75, 0.42, "filepath field"):
                self.close_application()
                return False

            time.sleep(0.3)
            print(f"[INFO] Pasting file path: {abs_path}")
            pyautogui.hotkey("ctrl", "a")
            pyperclip.copy(abs_path)
            pyautogui.hotkey("ctrl", "v")
            time.sleep(0.3)

            # Tab → Enter to confirm path selection
            pyautogui.press("tab")
            time.sleep(0.1)
            pyautogui.press("enter")
            time.sleep(0.3)

            # Tab → Enter to click Pack
            pyautogui.press("tab")
            time.sleep(0.1)
            pyautogui.press("enter")
            print("[INFO] Clicked Pack")

            # Dismiss any XPA dialog — only "error" dialogs mean failure
            dialog_result = self.dismiss_xpa_dialog(timeout=10)
            if dialog_result == "error":
                print("[ERROR] XPA reported an error — packing failed")
                self.cleanup_on_failure(abs_path)
                return False

            # Wait for output file to stabilise
            packed_file = self.wait_for_pack_complete(str(output_path))

            if packed_file:
                # Move to final output directory
                final_path = self.move_protected_file_to_output(packed_file, output_dir)
                if final_path:
                    print(f"\n{'=' * 60}")
                    print("PACK COMPLETE")
                    print(f"{'=' * 60}")
                    print(f"  Input:  {input_path}")
                    print(f"  Output: {final_path}")
                    print(f"{'=' * 60}")
                    self.close_application()
                    return True
                else:
                    print("[ERROR] Failed to move output file")
                    self.cleanup_on_failure(abs_path)
                    return False
            else:
                print("[ERROR] Pack timed out or failed")
                self.cleanup_on_failure(abs_path)
                return False

        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")
            traceback.print_exc()
            self.close_application()
            return False


def main():
    import argparse

    parser = argparse.ArgumentParser(description="XPA v1.43 GUI Wrapper")
    parser.add_argument("--file", required=True, help="Input executable path")
    parser.add_argument("--output-dir", help="Output directory for packed file")
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    main_dir = script_dir.parent
    yaml_path = main_dir / "manifest" / "packer_corpus.yaml"

    if not yaml_path.exists():
        print(f"[ERROR] YAML not found: {yaml_path}")
        return 1

    wrapper = XPAV143GUI(str(yaml_path), str(main_dir))
    success = wrapper.run(file_path=args.file, output_dir=args.output_dir)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
