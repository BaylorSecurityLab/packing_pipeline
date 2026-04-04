"""
Obsidium v1.8.8 GUI Wrapper

Obsidium v1.8.8 is GUI-only. This wrapper:
  1. Launches Obsidium.exe
  2. Finds the main window
  3. Clicks "New Project" — opens a Save dialog
  4. Saves the project file to packers/obsidium/default.opf
  5. (Future steps: configure settings, load file, protect, collect output)

Current state: Step 1 — create and save a default project file, then close.
"""

import sys
import time
import traceback
import pyautogui
import pyperclip
from pathlib import Path
from base_gui import BaseGUI

WINDOW_TITLE = "Obsidium Software Protection System"

# "New Project" button — approximate percentage of client area
NEW_PROJECT_BTN_X = 0.24
NEW_PROJECT_BTN_Y = 0.23

# Save dialog patterns to look for
SAVE_DIALOG_PATTERNS = ["Save", "Enregistrer", "Guardar", "Speichern", "Opslaan"]


class ObsidiumV1880GUI(BaseGUI):
    def get_packer_name(self) -> str:
        return "obsidium_v1.8.8"

    def click_new_project(self) -> bool:
        """Click the New Project button on the Project management panel."""
        return self.click_at_percent(
            NEW_PROJECT_BTN_X, NEW_PROJECT_BTN_Y, "New Project button"
        )

    def save_project_file(self, project_path: str) -> bool:
        """
        Navigate the Save dialog and save the project file.

        Uses Ctrl+L to set directory, Alt+N to focus filename field,
        then pastes the filename and confirms with Enter.
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
            directory = str(save_path.parent)
            filename = save_path.stem  # without extension

            # Step 1: Focus is already on filename field — paste filename
            print(f"[INFO] Entering filename: {filename}")
            pyautogui.hotkey("ctrl", "a")
            pyperclip.copy(filename)
            pyautogui.hotkey("ctrl", "v")
            time.sleep(0.3)

            # Step 2: Navigate address bar to target directory
            print(f"[INFO] Navigating to directory: {directory}")
            pyautogui.hotkey("ctrl", "l")
            time.sleep(0.3)
            pyperclip.copy(directory)
            pyautogui.hotkey("ctrl", "v")
            time.sleep(0.2)
            pyautogui.press("enter")
            time.sleep(0.8)

            # Step 3: Confirm save
            pyautogui.press("enter")
            time.sleep(1.0)
            print(f"[SUCCESS] Project saved: {project_path}")
            return True

        except Exception as e:
            print(f"[ERROR] save_project_file failed: {e}")
            return False

    def run(self, click_mode="all", file_path=None, output_dir=None) -> bool:
        print("\n" + "=" * 60)
        print("OBSIDIUM v1.8.8 WRAPPER - New Project (Step 1)")
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

            # Dismiss "Project/Application Name" dialog
            # This is a modal dialog — it always gets keyboard focus automatically.
            print("[INFO] Waiting for Project/Application Name dialog...")
            time.sleep(1.5)
            # Click OK button directly: dialog is centered on main window
            # OK button is at roughly left-third, bottom of the dialog
            if self.window:
                import pygetwindow as gw
                dialogs = gw.getWindowsWithTitle("Project/Application Name")
                if dialogs:
                    d = dialogs[0]
                    print(f"[SUCCESS] Found dialog: '{d.title}'")
                    d.activate()
                    time.sleep(0.3)
                    # Click OK at ~32% x, ~82% y of the dialog client area
                    ci = self._get_client_area_info(d.title)
                    if ci:
                        cw, ch, cp = ci
                        pyautogui.click(cp[0] + int(cw * 0.32), cp[1] + int(ch * 0.82))
                    else:
                        pyautogui.press("enter")
                else:
                    print("[INFO] Dialog not found by title — sending Enter to focused window")
                    pyautogui.press("enter")
            time.sleep(0.5)

            # Handle Save dialog
            if not self.save_project_file(project_path):
                self.close_application()
                return False

            # Hold open for inspection
            print("\n[INFO] Holding window open for 60 seconds...")
            time.sleep(60)

            self.close_application()
            print(
                "\n[INFO] Step 1 complete — project file created, returning False (not yet fully implemented)"
            )
            return False

        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")
            traceback.print_exc()
            self.close_application()
            return False


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Obsidium v1.8.8 GUI Wrapper")
    parser.add_argument("--file", required=True, help="Input executable path")
    parser.add_argument("--output-dir", help="Output directory for protected file")
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    main_dir = script_dir.parent
    yaml_path = main_dir / "manifest" / "packer_corpus.yaml"

    if not yaml_path.exists():
        print(f"[ERROR] YAML not found: {yaml_path}")
        return 1

    wrapper = ObsidiumV1880GUI(str(yaml_path), str(main_dir))
    success = wrapper.run(file_path=args.file, output_dir=args.output_dir)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
