"""
Obsidium v1.5.2 GUI Wrapper

Obsidium v1.5.2 shares the same UI as v1.8.8. This wrapper:
  1. Launches Obsidium.exe
  2. Clicks "New Project" — saves project file
  3. Dismisses "Project/Application Name" dialog
  4. Configures settings (output directory)
  5. Adds executable to protect
  6. Clicks "Protect All"
  7. Waits for packing to complete (file lock monitoring)
  8. Moves output to target directory
"""

import os
import sys
import time
import traceback
import pyautogui
import pyperclip
import win32gui
import win32con
from pathlib import Path
from base_gui import BaseGUI

WINDOW_TITLE = "Obsidium Software Protection System"

# "New Project" button — approximate percentage of client area
NEW_PROJECT_BTN_X = 0.24
NEW_PROJECT_BTN_Y = 0.23

# Save dialog patterns to look for
SAVE_DIALOG_PATTERNS = ["Save", "Enregistrer", "Guardar", "Speichern", "Opslaan"]


class ObsidiumV152GUI(BaseGUI):
    def get_packer_name(self) -> str:
        return "obsidium_v1.5.2"

    def click_new_project(self) -> bool:
        """Click the New Project button on the Project management panel."""
        return self.click_at_percent(
            NEW_PROJECT_BTN_X, NEW_PROJECT_BTN_Y, "New Project button"
        )

    def dismiss_project_name_dialog(self) -> bool:
        """
        Dismiss the 'Project/Application Name' dialog that appears AFTER saving.
        Tries: win32gui enumeration (owned windows), then polling with pyautogui click fallback.
        """
        print("\n[INFO] Waiting for Project/Application Name dialog...")
        # Window title may have changed after saving — find by partial match
        main_hwnd = None

        def find_main(hwnd, _):
            nonlocal main_hwnd
            if win32gui.IsWindowVisible(hwnd):
                title = win32gui.GetWindowText(hwnd)
                if (
                    "obsidium" in title.lower()
                    and "software protection" in title.lower()
                ):
                    main_hwnd = hwnd

        win32gui.EnumWindows(find_main, None)
        if not main_hwnd:
            # Fallback to stored title
            main_hwnd = win32gui.FindWindow(None, self.window.title)
        print(
            f"[DEBUG] Main HWND: {main_hwnd}, title: '{win32gui.GetWindowText(main_hwnd) if main_hwnd else 'N/A'}')"
        )

        # Poll for up to 10 seconds for the dialog to appear
        start = time.time()
        while time.time() - start < 10:
            # Check for owned top-level windows (modal dialogs)
            owned = []

            def enum_owned(hwnd, results):
                if win32gui.IsWindowVisible(hwnd):
                    title = win32gui.GetWindowText(hwnd)
                    if title:
                        owner = win32gui.GetWindow(hwnd, 4)  # GW_OWNER
                        if owner == main_hwnd:
                            results.append((hwnd, title))

            win32gui.EnumWindows(enum_owned, owned)

            for hwnd, title in owned:
                print(f"  [DEBUG] Owned window: '{title}' (HWND: {hwnd})")
                # Try clicking OK button via BM_CLICK
                ok_hwnd = win32gui.FindWindowEx(hwnd, 0, "Button", "OK")
                if not ok_hwnd:
                    ok_hwnd = win32gui.FindWindowEx(hwnd, 0, "Button", "&OK")
                if ok_hwnd:
                    print(f"[SUCCESS] Found OK button (HWND: {ok_hwnd}) on '{title}'")
                    win32gui.SendMessage(ok_hwnd, win32con.BM_CLICK, 0, 0)
                    time.sleep(0.5)
                    return True
                else:
                    # No OK button found by name — click center-bottom of dialog
                    rect = win32gui.GetWindowRect(hwnd)
                    dlg_w = rect[2] - rect[0]
                    dlg_h = rect[3] - rect[1]
                    ok_x = rect[0] + int(dlg_w * 0.10)
                    ok_y = rect[1] + int(dlg_h * 0.85)
                    print(f"[INFO] Clicking OK at dialog coords ({ok_x}, {ok_y})")
                    pyautogui.click(ok_x, ok_y)
                    time.sleep(0.5)
                    return True

            time.sleep(0.5)

        # Final fallback: press Enter on whatever has focus
        print("[WARNING] Dialog not found after 10s — pressing Enter as fallback")
        pyautogui.press("enter")
        time.sleep(0.5)
        return True

    def wait_for_packing_complete(self, input_file_path):
        """
        Wait for in-place packing to complete with stability verification.
        Watches the input file for lock release after Obsidium finishes writing.
        """
        timeout = self.EXTRA_LONG_TIMEOUT
        input_path = Path(input_file_path)
        check_interval = self.LONG_TIMEOUT
        required_stable_checks = 5
        stable_count = 0

        print("\n[INFO] Waiting for packing to complete...")
        print(f"[INFO] Watching: {input_path}")
        print(f"[INFO] Stability: {required_stable_checks} consecutive unlocked checks")
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

        print(f"\n[ERROR] Timed out after {timeout}s waiting for packing to complete")
        return None

    def save_project_file(self, project_path: str) -> bool:
        """
        Navigate the Save dialog and save the project file.
        Pastes the full path into the filename field and confirms.
        """
        import pygetwindow as gw

        print("\n[INFO] Waiting for Save dialog...")
        start = time.time()
        picker = None
        while time.time() - start < 10:
            try:
                for title in gw.getAllTitles():
                    if not title:
                        continue
                    if any(p.lower() in title.lower() for p in SAVE_DIALOG_PATTERNS):
                        picker = gw.getWindowsWithTitle(title)[0]
                        print(f"[SUCCESS] Found Save dialog: '{title}'")
                        break
                if picker:
                    break
            except Exception:
                pass
            time.sleep(0.3)

        if not picker:
            print("[ERROR] Save dialog not found")
            return False

        try:
            picker.activate()
            time.sleep(0.4)

            save_path = Path(project_path)

            # Paste the FULL path (directory + filename) into the filename field
            # The Save dialog resolves the directory automatically
            full_path = str(save_path.with_suffix(""))  # without extension (Obsidium adds .opf)
            print(f"[INFO] Entering full path: {full_path}")
            pyautogui.hotkey("ctrl", "a")
            pyperclip.copy(full_path)
            pyautogui.hotkey("ctrl", "v")
            time.sleep(0.5)

            # Confirm save
            pyautogui.press("enter")
            time.sleep(1.5)
            print(f"[SUCCESS] Project saved: {project_path}")
            return True

        except Exception as e:
            print(f"[ERROR] save_project_file failed: {e}")
            return False

    def run(self, click_mode="all", file_path=None, output_dir=None) -> bool:
        print("\n" + "=" * 60)
        print("OBSIDIUM v1.5.2 WRAPPER")
        print("=" * 60)

        try:
            if not self.load_packer_info():
                return False

            if not file_path:
                print("[ERROR] No input file provided")
                return False

            input_stem = Path(file_path).stem

            # Project file goes into the packer's temp directory
            if output_dir:
                temp_dir = Path(output_dir) / "temp"
            else:
                temp_dir = self.get_output_directory() / "temp"
            temp_dir.mkdir(parents=True, exist_ok=True)

            project_path = str(temp_dir / f"{input_stem}_project.opf")
            print(f"[INFO] Project file target: {project_path}")

            if not self.launch_application():
                return False

            if not self.find_window(
                window_title=WINDOW_TITLE, timeout=self.LONG_TIMEOUT
            ):
                print("[ERROR] Could not find Obsidium main window")
                self.close_application()
                return False

            self.center_window_on_monitor(monitor_number=0)
            time.sleep(0.5)

            # Click New Project
            if not self.click_new_project():
                self.close_application()
                return False

            # Handle Save dialog FIRST (Obsidium shows Save before the Name dialog)
            if not self.save_project_file(project_path):
                self.close_application()
                return False

            # NOW dismiss "Project/Application Name" dialog that appears after saving
            if not self.dismiss_project_name_dialog():
                self.close_application()
                return False

            # Re-find window — title changed after project creation
            time.sleep(0.5)
            print("\n[INFO] Re-finding window after project creation...")
            if not self.find_window(window_title=None, timeout=self.LONG_TIMEOUT):
                # Try partial title match
                import pygetwindow as gw

                for title in gw.getAllTitles():
                    if title and "obsidium" in title.lower():
                        self.window = gw.getWindowsWithTitle(title)[0]
                        print(f"[SUCCESS] Re-found window: '{title}'")
                        break
            if not self.window:
                print(
                    "[ERROR] Could not re-find Obsidium window after project creation"
                )
                self.close_application()
                return False
            self.center_window_on_monitor(monitor_number=0)

            # Click PROTECT menu on the left sidebar
            time.sleep(0.5)
            if not self.click_at_percent(0.05, 0.65, "Protect menu"):
                self.close_application()
                return False

            # Click SETTINGS tab
            time.sleep(0.5)
            if not self.click_at_percent(0.15, 0.20, "Settings tab"):
                self.close_application()
                return False

            # Click Select button for output directory
            time.sleep(0.5)
            if not self.click_at_percent(0.90, 0.29, "Select output directory button"):
                self.close_application()
                return False

            # Handle folder browse dialog
            time.sleep(1.5)
            out_dir = (
                str(Path(output_dir).resolve())
                if output_dir
                else str(Path(file_path).resolve().parent)
            )
            print(f"[INFO] Navigating folder dialog to: {out_dir}")

            pyautogui.hotkey("ctrl", "l")
            time.sleep(0.5)
            pyperclip.copy(out_dir)
            pyautogui.hotkey("ctrl", "v")
            time.sleep(0.5)
            pyautogui.press("enter")
            time.sleep(2.0)

            # Find the folder dialog and click Select Folder via win32gui
            folder_hwnd = None

            def find_folder_dlg(hwnd, _):
                nonlocal folder_hwnd
                if win32gui.IsWindowVisible(hwnd):
                    title = win32gui.GetWindowText(hwnd)
                    if title and (
                        "select" in title.lower()
                        or "browse" in title.lower()
                        or "folder" in title.lower()
                        or "output" in title.lower()
                    ):
                        folder_hwnd = hwnd
                        print(f"[DEBUG] Found folder dialog: '{title}' (HWND: {hwnd})")

            win32gui.EnumWindows(find_folder_dlg, None)

            if folder_hwnd:
                button_hwnd = None

                def find_button(hwnd, _):
                    nonlocal button_hwnd
                    cls = win32gui.GetClassName(hwnd)
                    text = win32gui.GetWindowText(hwnd)
                    if cls == "Button" and text:
                        print(f"  [DEBUG] Button: '{text}' (HWND: {hwnd})")
                        if "select" in text.lower() or text == "OK" or text == "&OK":
                            button_hwnd = hwnd

                win32gui.EnumChildWindows(folder_hwnd, find_button, None)

                if button_hwnd:
                    print(
                        f"[INFO] Clicking button: '{win32gui.GetWindowText(button_hwnd)}'"
                    )
                    win32gui.SendMessage(button_hwnd, win32con.BM_CLICK, 0, 0)
                    time.sleep(0.5)
                else:
                    print("[INFO] No Select/OK button found — pressing Enter")
                    win32gui.SetForegroundWindow(folder_hwnd)
                    time.sleep(0.3)
                    pyautogui.press("enter")
                    time.sleep(0.5)
            else:
                print("[WARNING] Folder dialog not found — pressing Enter")
                pyautogui.press("enter")
                time.sleep(0.5)

            # Click Executables tab
            time.sleep(0.5)
            if not self.click_at_percent(0.25, 0.20, "Executables tab"):
                self.close_application()
                return False

            # Click Add button
            time.sleep(0.5)
            if not self.click_at_percent(0.20, 0.50, "Add button"):
                self.close_application()
                return False

            # Fill "Select files" dialog: Input file + Relative output path
            time.sleep(1.0)
            print("[INFO] Filling Select files dialog...")
            input_path = str(Path(file_path).resolve())
            print(f"[INFO] Pasting input file: {input_path}")
            pyperclip.copy(input_path)
            pyautogui.hotkey("ctrl", "v")
            time.sleep(0.3)
            pyautogui.press("tab")
            time.sleep(0.3)
            input_dir = Path(file_path).resolve().parent
            if output_dir:
                output_abs = Path(output_dir).resolve() / Path(file_path).name
            else:
                output_abs = Path(file_path).resolve()
            try:
                output_path = str(output_abs.relative_to(input_dir))
            except ValueError:
                output_path = str(os.path.relpath(str(output_abs), str(input_dir)))
            print(f"[INFO] Pasting output path (relative to input): {output_path}")
            pyperclip.copy(output_path)
            pyautogui.hotkey("ctrl", "v")
            time.sleep(0.3)
            pyautogui.press("enter")
            time.sleep(0.5)

            # Click Protect All button
            time.sleep(0.5)
            if not self.click_at_percent(0.95, 0.95, "Protect All button"):
                self.close_application()
                return False

            # Wait for packing to complete (file lock monitoring)
            packed_file = self.wait_for_packing_complete(file_path)

            if packed_file:
                final_path = self.move_protected_file_to_output(packed_file, output_dir)
                if final_path:
                    print(f"\n{'=' * 60}")
                    print("PACKING COMPLETE")
                    print(f"{'=' * 60}")
                    print(f"  Input:  {file_path}")
                    print(f"  Output: {final_path}")
                    print(f"{'=' * 60}")
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
            self.close_application()
            return False


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Obsidium v1.5.2 GUI Wrapper")
    parser.add_argument("--file", required=True, help="Input executable path")
    parser.add_argument("--output-dir", help="Output directory for protected file")
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    main_dir = script_dir.parent
    yaml_path = main_dir / "manifest" / "packer_corpus.yaml"

    if not yaml_path.exists():
        print(f"[ERROR] YAML not found: {yaml_path}")
        return 1

    wrapper = ObsidiumV152GUI(str(yaml_path), str(main_dir))
    success = wrapper.run(file_path=args.file, output_dir=args.output_dir)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
