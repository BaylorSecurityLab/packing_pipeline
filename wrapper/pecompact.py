"""
PECompact v1.84 GUI Wrapper

UI Flow:
    1. Launch pecompact.exe
    2. Find main window ("PECompact")
    3. Paste file path into Filename field (cursor already focused)
    4. Click Compress button
    5. Wait for in-place file lock to release (stable)
    6. Move output to output_dir
    7. Close
"""

import sys
import time
from pathlib import Path
import pyautogui
import pyperclip
from base_gui import BaseGUI

# Button positions as percentage of window client area (from screenshot)
FILENAME_FIELD_X = 0.50
FILENAME_FIELD_Y = 0.14
COMPRESS_BTN_X = 0.87
COMPRESS_BTN_Y = 0.22


class PECompact(BaseGUI):
    """
    Wrapper for PECompact v1.84 PE compressor.

    1. Launches the application
    2. Finds the main window
    3. Pastes the file path into the Filename field
    4. Clicks Compress
    5. Waits for in-place packing to complete (file lock release)
    6. Moves output to output_dir
    7. Closes the application
    """

    def get_packer_name(self) -> str:
        return "pecompact_v1.84"

    def wait_for_packing_complete(self, input_file_path: str) -> str | None:
        """
        Wait for PECompact to finish compressing in-place.
        Watches the input file for lock release, requires N stable unlocked
        checks before declaring done.
        """
        timeout = self.EXTRA_LONG_TIMEOUT
        check_interval = self.LONG_TIMEOUT
        required_stable_checks = 5
        stable_count = 0

        input_path = Path(input_file_path)

        print("\n[INFO] Waiting for packing to complete...")
        print(f"[INFO] Watching: {input_path}")
        print(f"[INFO] Stability: {required_stable_checks} consecutive unlocked checks")
        print(f"[INFO] Interval: {check_interval}s | Timeout: {timeout}s")

        # Give PECompact a moment to start working
        time.sleep(5)

        start_time = time.time()
        while time.time() - start_time < timeout:
            elapsed = int(time.time() - start_time)

            if input_path.exists():
                current_size = input_path.stat().st_size

                if self.is_file_locked(str(input_path)):
                    if stable_count > 0:
                        print(
                            f"  [{elapsed}s] Lock reappeared — resetting stability counter."
                        )
                    stable_count = 0
                    print(f"  [{elapsed}s] Compressing... {current_size:,} bytes")
                else:
                    stable_count += 1
                    print(
                        f"  [{elapsed}s] Unlocked. Stability {stable_count}/{required_stable_checks}..."
                    )
                    if stable_count >= required_stable_checks:
                        print(f"\n[SUCCESS] Packing complete and stable! ({elapsed}s)")
                        print(f"[INFO] Output: {input_path} ({current_size:,} bytes)")
                        return str(input_path)
            else:
                print(f"  [{elapsed}s] File not found, waiting...")
                stable_count = 0

            time.sleep(check_interval)

        print(f"\n[ERROR] Timeout after {timeout}s waiting for packing to complete")
        return None

    def run(self, click_mode="none", file_path=None, output_dir=None) -> bool:
        print("\n" + "=" * 60)
        print("PECOMPACT WRAPPER - Launch / Compress / Wait / Close")
        print("=" * 60)

        input_file = None

        try:
            # Step 1: Load configuration
            if not self.load_packer_info():
                return False

            # Step 2: Launch application
            if not self.launch_application():
                return False

            # Step 3: Find main window
            if not self.find_window(window_title="PECompact"):
                print("[ERROR] Could not find PECompact main window")
                return False

            self.center_window_on_monitor(monitor_number=0)
            self.get_window_dimensions()
            time.sleep(0.5)

            # Step 4: Paste file path into Filename field
            if not file_path:
                print("[ERROR] No file path provided")
                self.close_application()
                return False

            input_file = Path(file_path).resolve()
            abs_path = str(input_file)

            print("\n[ACTION] Clicking Filename field...")
            self.click_at_percent(
                FILENAME_FIELD_X, FILENAME_FIELD_Y, description="Filename field"
            )
            time.sleep(0.3)

            print(f"[ACTION] Pasting file path: {abs_path}")
            pyautogui.hotkey("ctrl", "a")
            pyperclip.copy(abs_path)
            pyautogui.hotkey("ctrl", "v")
            time.sleep(0.5)

            # Step 5: Click Compress
            print("\n[ACTION] Clicking Compress...")
            self.click_at_percent(
                COMPRESS_BTN_X, COMPRESS_BTN_Y, description="Compress button"
            )
            time.sleep(1.0)

            # Step 6: Wait for in-place packing to complete
            packed_file = self.wait_for_packing_complete(abs_path)

            if packed_file:
                # Step 7: Move to output directory
                final_path = self.move_protected_file_to_output(packed_file, output_dir)

                if final_path:
                    print(f"\n{'=' * 60}")
                    print("PACKING COMPLETE")
                    print(f"{'=' * 60}")
                    print(f"  Input:  {input_file}")
                    print(f"  Output: {final_path}")
                    print(f"{'=' * 60}")

                self.close_application()
                print("\n[SUCCESS] PECompact automation complete!")
                return True
            else:
                print("[ERROR] Packing timed out or failed")
                self.cleanup_on_failure(abs_path)
                return False

        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")
            import traceback

            traceback.print_exc()
            if input_file:
                self.cleanup_on_failure(str(input_file))
            else:
                self.close_application()
            return False


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="PECompact GUI Wrapper - compress a file and close"
    )
    parser.add_argument("--file-path", type=str, default=None)
    parser.add_argument("--output-dir", type=str, default=None)
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    main_dir = script_dir.parent
    yaml_path = main_dir / "manifest" / "packer_corpus.yaml"

    if not yaml_path.exists():
        print(f"[ERROR] YAML not found: {yaml_path}")
        return 1

    wrapper = PECompact(str(yaml_path), str(main_dir))
    success = wrapper.run(file_path=args.file_path, output_dir=args.output_dir)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
