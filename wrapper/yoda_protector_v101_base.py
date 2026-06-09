"""
Yoda's Protector v1.01/v1.02 Base GUI Automation Wrapper

Shared UI logic for v1.01 and v1.02 — both have the same interface,
which differs from the v1.03.x line.
Subclasses only need to override get_packer_name().
"""

import os
import subprocess
import time
from pathlib import Path
from base_gui import BaseGUI
import pyautogui
import traceback


class YodaProtectorV101Base(BaseGUI):
    """
    Base wrapper for Yoda's Protector v1.01/v1.02 GUI automation.
    Both v1.01 and v1.02 share the same UI layout.
    """

    def __init__(self, yaml_path, main_dir):
        super().__init__(yaml_path, main_dir)

    def get_packer_name(self):
        raise NotImplementedError("Subclasses must override get_packer_name()")

    def _close_yoda_window(self):
        """Close the yoda window by title, since self.process is the cmd shell."""
        if self.find_window(window_title="yoda", timeout=3) and self.window:
            import win32gui
            win32gui.PostMessage(self.window._hWnd, 0x0010, 0, 0)  # WM_CLOSE
            time.sleep(1)
            print("[INFO] Yoda's Protector window closed.")

    def wait_for_packing_complete(self, input_file_path):
        """
        Wait for in-place packing to complete with stability verification.

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
        Main execution flow for Yoda's Protector v1.01/v1.02.

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

            # Step 2: Launch application via 'cmd /c start' to fully isolate
            # the old binary from our Python process.
            exe_path = self.get_exe_path()
            print(f"\n[INFO] Launching application via cmd start: {exe_path}")
            subprocess.Popen(
                f'cmd /c start "" "{exe_path}"',
                cwd=str(exe_path.parent),
                shell=True,
            )
            print("[INFO] Waiting for GUI window to appear...")
            time.sleep(4)

            # Step 3: Find the window by title (no PID with cmd start)
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
            print(f"\n[INFO] Pasting file path: {input_file}")

            # Step 6: Click browse button to open Windows Explorer file picker
            time.sleep(0.5)
            self.click_at_percent(0.95, 0.15, "Browse button")
            print("[INFO] File picker opened!")

            # Step 7: Navigate to directory and paste filename
            time.sleep(1.0)
            if not self.paste_file_path_in_picker(str(input_file), input_file.name):
                print("[ERROR] Failed to select file in dialog")
                self.close_application()
                return False

            print("[SUCCESS] File selected!")

            # Step 8: Click the Protect button to start protection
            time.sleep(0.5)
            self.click_at_percent(0.12, 0.86, "Protect button")
            print("[INFO] Protection initiated!")

            # Step 9: Handle optional warning dialog
            time.sleep(1.0)
            if self.find_window(window_title="Warning", timeout=3):
                print("[INFO] Warning dialog detected — clicking Yes...")
                pyautogui.press("enter")
                time.sleep(0.5)
                print("[INFO] Warning dialog dismissed!")
            else:
                print("[INFO] No warning dialog appeared, continuing...")

            # Step 10: Wait for ":)" completion dialog, then dismiss it.
            # yP holds the file lock until this dialog is acknowledged.
            print("\n[INFO] Waiting for completion dialog ':)'...")
            dialog_dismissed = False
            deadline = time.time() + self.EXTRA_LONG_TIMEOUT

            while time.time() < deadline:
                elapsed = int(time.time() - (deadline - self.EXTRA_LONG_TIMEOUT))
                # Check if the packer process crashed
                if self.process and self.process.poll() is not None:
                    print(
                        f"\n[ERROR] Packer process exited unexpectedly (exit code: {self.process.returncode})"
                    )
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

            # Step 11: Confirm file is released and stable
            packed_file = self.wait_for_packing_complete(str(input_file))

            if packed_file:
                # Step 12: Move packed file to output directory
                final_path = self.move_protected_file_to_output(packed_file, output_dir)

                if final_path:
                    print(f"\n{'=' * 60}")
                    print("PACKING COMPLETE")
                    print(f"{'=' * 60}")
                    print(f"  Input:  {input_file}")
                    print(f"  Output: {final_path}")
                    print(f"{'=' * 60}")

                # Step 13: Close packer if still open
                self._close_yoda_window()
                print("\n[SUCCESS] Automation complete!")
                return True
            else:
                self._close_yoda_window()
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
