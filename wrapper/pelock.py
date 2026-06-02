"""
PELock GUI Automation Wrapper - Using Base GUI Wrapper
"""

import sys
import time
import traceback
from pathlib import Path
from base_gui import BaseGUI
import pygetwindow as gw


class PELock(BaseGUI):
    """
    Wrapper for PELock GUI automation.

    UI Flow:
        1. Launch PELock.exe — it immediately opens a Windows Explorer file picker
        2. Navigate the file picker to the target file and confirm
        3. Find the main PELock window
        4. Wait 60 seconds for processing
        5. Close the application
    """

    WAIT_DURATION = 60  # seconds

    # Extra file picker patterns PELock may use
    FILE_PICKER_PATTERNS = BaseGUI.FILE_PICKER_PATTERNS + [
        "Please select language file",
        "pelock",
        "PELock",
        "Ouvrir",  # French
        "Abrir",  # Spanish
        "Öffnen",  # German
    ]

    def __init__(self, yaml_path, main_dir):
        super().__init__(yaml_path, main_dir)

    def get_packer_name(self):
        return "pelock_v2.40"

    def find_file_picker_window(self, timeout=10):
        """Override to debug-print all visible window titles when picker not found."""
        print("\n[INFO] Searching for file picker window...")
        start_time = time.time()

        patterns = self.FILE_PICKER_PATTERNS

        while time.time() - start_time < timeout:
            try:
                all_titles = [t for t in gw.getAllTitles() if t.strip()]
                for title in all_titles:
                    if any(p.lower() in title.lower() for p in patterns):
                        print(f"[SUCCESS] Found file picker: '{title}'")
                        return gw.getWindowsWithTitle(title)[0]
            except Exception as e:
                print(f"[DEBUG] Error during search: {e}")
            time.sleep(0.3)

        print("[DEBUG] All visible window titles at timeout:")
        try:
            for title in gw.getAllTitles():
                if title.strip():
                    print(f"  - '{title}'")
        except Exception:
            pass

        print("[ERROR] File picker window not found within timeout")
        return None

    def run(self, click_mode="all", file_path=None, output_dir=None):
        """
        Main execution flow for PELock.

        UI Flow:
            1. Launch PELock — language file picker appears
            2. Press Enter to accept default language file
            3. Find main PELock window
            4. Click "Add File" button at (0.1, 0.8) — opens Windows Explorer
            5. Navigate file picker to target PE file and confirm
            6. Wait 60 seconds
            7. Close

        Args:
            click_mode: Unused, kept for interface consistency
            file_path: Path to the input file
            output_dir: Directory to move final output to (optional)

        Returns:
            bool: True if successful, False otherwise
        """
        import pyautogui

        input_file = None

        try:
            print("\n" + "=" * 60)
            print("PELock GUI AUTOMATION")
            print("=" * 60)

            # Step 1: Load packer info from YAML
            if not self.load_packer_info():
                print("[ERROR] Failed to load packer info from YAML")
                return False

            if not file_path:
                print("[ERROR] No file path provided")
                return False

            input_file = Path(file_path).resolve()
            print(f"\n[INFO] File: {input_file}")

            # Step 2: Launch application
            print("\n[INFO] Launching PELock...")
            if not self.launch_application():
                print("[ERROR] Failed to launch application")
                return False

            # Step 3: Language file picker appears on launch — press Enter to accept default
            print("\n[INFO] Dismissing language file picker (Enter)...")
            time.sleep(1.5)
            pyautogui.press("enter")
            time.sleep(1.0)

            # Step 4: Find the main PELock window
            if not self.find_window():
                print("[WARNING] Could not find window by PID, trying title search...")
                if not self.find_window(window_title="PELock"):
                    print("[ERROR] Could not find PELock window")
                    return False

            print(f"\n[SUCCESS] PELock launched successfully!")
            print(f"[INFO] Window title: {self.window.title}")

            # Step 5: Center window on monitor
            time.sleep(0.3)
            self.center_window_on_monitor(monitor_number=0)

            # Step 6: Click "Remove All" button at (0.6, 0.85) to clear any previous files
            time.sleep(0.5)
            self.click_at_percent(0.6, 0.9, "Remove All button")
            time.sleep(0.5)

            # Step 7: Click "Add File" button at (0.1, 0.85) to open Windows Explorer
            self.click_at_percent(0.1, 0.85, "Add File button")
            time.sleep(1.0)

            # Step 7: Navigate the file picker to the target PE file
            app_name = self.extract_app_name(str(input_file))
            if not self.paste_file_path_in_picker(str(input_file), app_name):
                print("[ERROR] Failed to select file in picker")
                self.close_application()
                return False

            print("[SUCCESS] File loaded!")

            # Step 8: Click "Protect File" button at (0.25, 0.85)
            time.sleep(0.5)
            self.click_at_percent(0.25, 0.85, "Protect File button")
            print("[INFO] Protection initiated!")

            # Step 9: Wait 60 seconds for processing
            print(f"\n[INFO] Waiting {self.WAIT_DURATION} seconds...")
            for elapsed in range(0, self.WAIT_DURATION, 10):
                remaining = self.WAIT_DURATION - elapsed
                print(f"  [{elapsed}s elapsed] {remaining}s remaining...")
                time.sleep(min(10, remaining))
            print(f"[INFO] Wait complete ({self.WAIT_DURATION}s elapsed)")

            # Step 10: Move output if specified
            if output_dir:
                final_path = self.move_protected_file_to_output(
                    str(input_file), output_dir
                )
                if final_path:
                    print(f"\n{'=' * 60}")
                    print("PACKING COMPLETE")
                    print(f"{'=' * 60}")
                    print(f"  Input:  {input_file}")
                    print(f"  Output: {final_path}")
                    print(f"{'=' * 60}")

            # Step 11: Close application
            self.close_application()
            print("\n[SUCCESS] Automation complete!")
            return True

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

    parser = argparse.ArgumentParser(
        description="PELock GUI Automation Wrapper",
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

    script_dir = Path(__file__).parent
    main_dir = script_dir.parent
    yaml_path = main_dir / "manifest" / "packer_corpus.yaml"

    print(f"Script directory: {script_dir}")
    print(f"Main directory:   {main_dir}")
    print(f"YAML path:        {yaml_path}")

    if not yaml_path.exists():
        print(f"\n[ERROR] YAML file not found at: {yaml_path}")
        return 1

    wrapper = PELock(yaml_path, main_dir)
    success = wrapper.run(file_path=args.file_path, output_dir=args.output_dir)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
