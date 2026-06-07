"""
ZProtect v1.4.2.0 GUI Wrapper

ZProtect by Licho is a GUI-only PE protector.
This wrapper:
  1. Launches ZProtect.exe
  2. Finds the main window
  3. Clicks the file open button (0.8 x, 0.15 y) to open Windows Explorer
  4. Selects the input file via the file picker
  5. Presses Enter to confirm
  6. Clicks second File menu option (0.12 x, 0.05 y) to trigger protection
  7. Watches for output file ({stem}.zp.exe in input directory)
  8. Moves output to output_dir
  9. Closes the application
"""

import sys
import time
import traceback
import pyautogui
from pathlib import Path
from base_gui import BaseGUI

ZPROTECT_TIMEOUT = 60


class ZProtectGUI(BaseGUI):
    def get_packer_name(self) -> str:
        return "zprotect"

    def get_output_file_path(self, input_path: Path) -> Path:
        """ZProtect produces {stem}.zp.exe alongside the input file."""
        return input_path.parent / f"{input_path.stem}.zp.exe"

    def wait_for_pack_complete(self, output_path: Path) -> str | None:
        """
        Poll for the output file until it exists and is stable (not locked).
        Returns the output path string on success, None on timeout.
        """
        # Interaction is complete; release the input lock so other packers can
        # interact while this one watches its output file.
        self.release_input()
        check_interval = 3
        required_stable_checks = 3
        stable_count = 0

        print(f"\n[INFO] Watching for output: {output_path}")
        print(f"[INFO] Interval: {check_interval}s | Timeout: {ZPROTECT_TIMEOUT}s")

        time.sleep(3)  # give ZProtect time to start writing

        start_time = time.time()
        while time.time() - start_time < ZPROTECT_TIMEOUT:
            elapsed = int(time.time() - start_time)

            if output_path.exists():
                current_size = output_path.stat().st_size
                if self.is_file_locked(str(output_path)):
                    stable_count = 0
                    print(f"  [{elapsed}s] Writing... {current_size:,} bytes")
                else:
                    stable_count += 1
                    print(
                        f"  [{elapsed}s] Unlocked. Stability {stable_count}/{required_stable_checks}..."
                    )
                    if stable_count >= required_stable_checks:
                        print(f"\n[SUCCESS] Pack complete and stable! ({elapsed}s)")
                        print(f"[INFO] Output: {output_path} ({current_size:,} bytes)")
                        return str(output_path)
            else:
                print(f"  [{elapsed}s] Output file not yet found, waiting...")
                stable_count = 0

            time.sleep(check_interval)

        print(f"\n[ERROR] Timeout after {ZPROTECT_TIMEOUT}s — pack did not complete.")
        return None

    def run(self, click_mode="all", file_path=None, output_dir=None) -> bool:
        print("\n" + "=" * 60)
        print("ZProtect v1.4.2.0 WRAPPER")
        print("=" * 60)

        try:
            if not self.load_packer_info():
                return False

            if not file_path:
                print("[ERROR] No input file provided")
                return False

            input_path = Path(file_path).resolve()
            output_path = self.get_output_file_path(input_path)

            if not self.launch_application():
                return False

            if not self.find_window(timeout=self.LONG_TIMEOUT):
                print("[ERROR] Could not find ZProtect main window")
                self.close_application()
                return False

            self.center_window_on_monitor(monitor_number=1)
            time.sleep(0.5)

            # Click file open button to trigger Windows Explorer file picker
            if not self.click_at_percent(0.8, 0.15, "file open button"):
                self.close_application()
                return False

            # Select input file via the file picker
            app_name = input_path.name
            if not self.paste_file_path_in_picker(str(input_path), app_name):
                self.close_application()
                return False

            time.sleep(0.3)
            pyautogui.press("enter")
            print("[INFO] Pressed Enter to confirm file selection")
            time.sleep(0.5)

            # Click second File menu option to trigger protection
            if not self.click_at_percent(0.12, 0.05, "File menu second option"):
                self.close_application()
                return False
            time.sleep(0.5)

            # Watch for output file
            packed_file = self.wait_for_pack_complete(output_path)

            if packed_file:
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
                    self.cleanup_on_failure(str(input_path))
                    return False
            else:
                print("[ERROR] Pack timed out or failed")
                self.cleanup_on_failure(str(input_path))
                return False

        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")
            traceback.print_exc()
            self.close_application()
            return False


def main():
    import argparse

    parser = argparse.ArgumentParser(description="ZProtect v1.4.2.0 GUI Wrapper")
    parser.add_argument("--file", required=True, help="Input executable path")
    parser.add_argument("--output-dir", help="Output directory for packed file")
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    main_dir = script_dir.parent
    yaml_path = main_dir / "manifest" / "packer_corpus.yaml"

    if not yaml_path.exists():
        print(f"[ERROR] YAML not found: {yaml_path}")
        return 1

    wrapper = ZProtectGUI(str(yaml_path), str(main_dir))
    success = wrapper.run(file_path=args.file, output_dir=args.output_dir)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
