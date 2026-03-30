"""
Obsidium v1.5.2 GUI Wrapper - STUB (Step 1: Launch and hold open)

Obsidium v1.5.2 is GUI-only with a valid license (Obsidium_License.txt).
This wrapper will eventually:
  1. Launch Obsidium.exe (v1.5.2)
  2. Find the main window
  3. Load the input file
  4. Trigger protection
  5. Wait for output and move it to output_dir
  6. Close the application

Current state: launches the app, holds open for 60 seconds, returns False.
"""

import sys
import time
import traceback
from pathlib import Path
from base_gui import BaseGUI

WINDOW_TITLE = "Obsidium"


class ObsidiumV152GUI(BaseGUI):

    def get_packer_name(self) -> str:
        return "obsidium_v1.5.2"

    def run(self, click_mode="all", file_path=None, output_dir=None) -> bool:
        print("\n" + "=" * 60)
        print("OBSIDIUM v1.5.2 WRAPPER - Launch / Hold / Close (STUB)")
        print("=" * 60)

        try:
            if not self.load_packer_info():
                return False

            if not self.launch_application():
                return False

            if not self.find_window(window_title=WINDOW_TITLE, timeout=self.LONG_TIMEOUT):
                print("[WARNING] Could not find Obsidium main window; continuing anyway")
            else:
                self.center_window_on_monitor(monitor_number=0)

            print(f"\n[INFO] Holding window open for 60 seconds (stub)...")
            time.sleep(60)

            self.close_application()
            print("[INFO] Stub complete — returning False (not yet implemented)")
            return False

        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")
            traceback.print_exc()
            self.close_application()
            return False


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Obsidium v1.5.2 GUI Wrapper (stub)"
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

    wrapper = ObsidiumV152GUI(str(yaml_path), str(main_dir))
    success = wrapper.run(file_path=args.file, output_dir=args.output_dir)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
