"""
Yoda's Protector v1.03.x Base GUI Automation Wrapper

Shared UI logic for v1.03.2 and v1.03.3 — both have the same interface.
Subclasses only need to override get_packer_name().
"""

import time
from pathlib import Path
from base_gui import BaseGUI
import pyautogui
import traceback


class YodaProtectorV103Base(BaseGUI):
    """
    Base wrapper for Yoda's Protector v1.03.x GUI automation.
    Both v1.03.2 and v1.03.3 share the same UI layout.
    """

    def __init__(self, yaml_path, main_dir):
        super().__init__(yaml_path, main_dir)

    def get_packer_name(self):
        raise NotImplementedError("Subclasses must override get_packer_name()")

    def wait_for_packing_complete(self, input_file_path):
        """
        Wait for in-place packing to complete with stability verification.

        Yoda's Protector modifies the input file in-place, so we watch the
        input file itself for lock release. Requires N consecutive unlocked
        checks to confirm completion.

        Args:
            input_file_path: Path to the file being packed

        Returns:
            str: Path to packed file if successful, None otherwise
        """
        # Interaction is complete; release the input lock so other packers can
        # interact while this one watches its output file.
        self.release_input()
        timeout = self.EXTRA_LONG_TIMEOUT
        input_path = Path(input_file_path)
        check_interval = self.LONG_TIMEOUT

        required_stable_checks = 5
        stable_count = 0

        print("\n[INFO] Waiting for packing to complete...")
        print(f"[INFO] Watching: {input_path}")
        print(
            f"[INFO] Stability Requirement: {required_stable_checks} consecutive unlocked checks"
        )
        print(f"[INFO] Interval: {check_interval}s | Timeout: {timeout}s")

        start_time = time.time()

        # Initial buffer to let the packer start its work
        time.sleep(10)

        while time.time() - start_time < timeout:
            elapsed = int(time.time() - start_time)

            if input_path.exists():
                current_size = input_path.stat().st_size

                if self.is_file_locked(str(input_path)):
                    if stable_count > 0:
                        print(
                            f"  [{elapsed}s] Lock reappeared! Resetting stability counter."
                        )
                    stable_count = 0
                    print(f"  [{elapsed}s] Packing... {current_size:,} bytes")
                else:
                    stable_count += 1
                    print(
                        f"  [{elapsed}s] File unlocked. Verification {stable_count}/{required_stable_checks}..."
                    )

                    if stable_count >= required_stable_checks:
                        print(
                            f"\n[SUCCESS] Packing complete and verified stable! ({elapsed}s)"
                        )
                        print(f"[INFO] Output file: {input_path}")
                        print(f"[INFO] Final size: {current_size:,} bytes")
                        return str(input_path)
            else:
                print(f"  [{elapsed}s] File not found, waiting...")
                stable_count = 0

            time.sleep(check_interval)

        print(
            f"\n[ERROR] Timeout after {timeout}s waiting for stable packing completion"
        )
        return None

    def run(self, click_mode="all", file_path=None, output_dir=None):
        """
        Main execution flow for Yoda's Protector v1.03.x.

        Args:
            click_mode: Configuration mode (reserved for future steps)
            file_path: Path to the input file
            output_dir: Directory to move the packed file to

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            packer_name = self.get_packer_name()
            print("\n" + "=" * 60)
            print(f"YODA'S PROTECTOR ({packer_name}) GUI AUTOMATION")
            print("=" * 60)

            # Step 1: Load packer info from YAML
            if not self.load_packer_info():
                print("[ERROR] Failed to load packer info from YAML")
                return False

            # Step 2: Launch application
            print(f"\n[INFO] Launching Yoda's Protector ({packer_name})...")
            if not self.launch_application():
                print("[ERROR] Failed to launch application")
                return False

            # Step 3: Find the window
            if not self.find_window():
                print("[WARNING] Could not find window by PID, trying title search...")
                if not self.find_window(window_title="yoda"):
                    print("[ERROR] Could not find Yoda's Protector window")
                    return False

            print("\n[SUCCESS] Yoda's Protector launched successfully!")
            print(f"[INFO] Window title: {self.window.title}")

            # Step 4: Center window on primary monitor
            time.sleep(0.3)
            self.center_window_on_monitor(monitor_number=1)

            # Step 5: Get window dimensions for coordinate mapping
            self.get_window_dimensions()

            if not file_path:
                print("[ERROR] No file path provided")
                self.close_application()
                return False

            input_file = Path(file_path).resolve()
            print(f"\n[INFO] Opening file dialog for: {input_file}")

            # Step 6: Click the browse/open button to open Windows Explorer file picker
            time.sleep(0.5)
            self.click_at_percent(0.95, 0.63, "Open file button")
            print("[INFO] File picker opened!")

            # Step 7: Navigate to directory and paste filename
            time.sleep(1.0)
            if not self.paste_file_path_in_picker(str(input_file), input_file.name):
                print("[ERROR] Failed to select file in dialog")
                self.close_application()
                return False

            print("[SUCCESS] File selected!")

            # Step 8: Click the Protect tab
            time.sleep(0.5)
            self.click_at_percent(0.5, 0.12, "Protect tab")
            print("[INFO] Protect tab clicked!")

            # Step 9: Click the Protect button to start protection
            time.sleep(0.5)
            self.click_at_percent(0.05, 0.9, "Protect button")
            print("[INFO] Protection initiated!")

            # Step 10: Handle optional "Invalid PE file" warning dialog
            time.sleep(1.0)
            if self.find_window(window_title="Warning", timeout=3):
                print("[INFO] Warning dialog detected — clicking Yes...")
                pyautogui.press("enter")
                time.sleep(0.5)
                print("[INFO] Warning dialog dismissed!")
            else:
                print("[INFO] No warning dialog appeared, continuing...")

            # Step 11: Wait for ":)" completion dialog, then dismiss it.
            # yP holds the file lock until this dialog is acknowledged, so we
            # must dismiss it BEFORE running the file watch — not after.
            print("\n[INFO] Waiting for completion dialog ':)'...")
            dialog_dismissed = False
            deadline = time.time() + self.EXTRA_LONG_TIMEOUT

            while time.time() < deadline:
                elapsed = int(time.time() - (deadline - self.EXTRA_LONG_TIMEOUT))
                # Check if the packer process crashed / exited unexpectedly
                if self.process and self.process.poll() is not None:
                    print(f"\n[ERROR] Packer process exited unexpectedly (exit code: {self.process.returncode})")
                    return False
                if self.find_window(window_title=":)", timeout=2) and self.window:
                    print(f"\n[SUCCESS] Completion dialog found! ({elapsed}s)")
                    self.window.activate()
                    time.sleep(0.3)
                    pyautogui.press("enter")
                    time.sleep(0.5)
                    print("[SUCCESS] Completion dialog dismissed!")
                    dialog_dismissed = True
                    break
                print(f"  [{elapsed}s] Waiting for completion dialog...")

            if not dialog_dismissed:
                print("\n[ERROR] Completion dialog never appeared — timed out!")
                self.close_application()
                return False

            # Step 12: Close application to release the file lock
            print("\n[INFO] Closing Yoda's Protector to release file lock...")
            self.close_application()
            time.sleep(2)

            # Step 13: Confirm file is released and stable after app is closed
            packed_file = self.wait_for_packing_complete(str(input_file))

            if packed_file:
                # Step 14: Move packed file to output directory
                final_path = self.move_protected_file_to_output(packed_file, output_dir)

                if final_path:
                    print(f"\n{'=' * 60}")
                    print("PACKING COMPLETE")
                    print(f"{'=' * 60}")
                    print(f"  Input:  {input_file}")
                    print(f"  Output: {final_path}")
                    print(f"{'=' * 60}")

                print("\n[SUCCESS] Automation complete!")
                return True
            else:
                print("[ERROR] File watch failed after app close!")
                return False

        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")
            traceback.print_exc()
            if file_path:
                self.cleanup_on_failure(str(Path(file_path).resolve()))
            else:
                self.close_application()
            return False
