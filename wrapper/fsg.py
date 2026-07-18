"""
FSG GUI Automation Wrapper - Using Base GUI Wrapper
"""

import sys
import time
import traceback
from pathlib import Path
from base_gui import BaseGUI
import pyautogui
import pyperclip
import win32gui
import win32process


class FSG(BaseGUI):
    """
    Wrapper for FSG 1.0 GUI automation using the BaseGUIWrapper.

    FSG (Fast Small Good) is a GUI-only PE compressor. On launch it immediately
    opens a Windows Explorer file picker. After file selection it shows EITHER:
      - The main FSG window (proceed with compress), OR
      - A TLS error dialog (file is incompatible — abort)
    The main window never appears when TLS is detected.
    """

    def __init__(self, yaml_path, main_dir):
        super().__init__(yaml_path, main_dir)

    def get_packer_name(self) -> str:
        return "fsg_v1.0"

    def _drive_fsg_picker_via_win32(self, full_path, timeout=10):
        """
        Drive FSG's standard #32770 file picker via Win32 SendMessage.

        FSG's "please select file" dialog is a regular Windows Open dialog
        (verified: class #32770, contains a ComboBoxEx32 + Edit for the File
        name field, Button labeled &Open). We find the File name Edit by
        class + lower-screen position, WM_SETTEXT the full path, and click
        Open via BM_CLICK. No screen coordinates, no pyautogui, no
        SetForegroundWindow -- so UIPI doesn't get in the way.

        Returns True if the Open button was clicked (file selection accepted),
        False if we couldn't find/click the controls (caller falls back to
        pyautogui).
        """
        import win32con

        start = time.time()
        fsg_dialog_hwnd = None
        # Find FSG's main dialog (the "please select file to compress" window).
        while time.time() - start < timeout:
            found = [None]

            def _cb(h, _):
                if win32gui.IsWindowVisible(h):
                    t = win32gui.GetWindowText(h)
                    if "FSG" in t and "dulek" in t:
                        found[0] = h
                        return False
                return True

            win32gui.EnumWindows(_cb, None)
            if found[0]:
                fsg_dialog_hwnd = found[0]
                break
            time.sleep(0.3)

        if not fsg_dialog_hwnd:
            print("[ERROR] FSG dialog never appeared (Win32)")
            return False

        # Find the File name Edit control (lower Edit in the dialog, by rect).
        edit_hwnd = None

        def _edit_cb(h, _):
            nonlocal edit_hwnd
            if win32gui.GetClassName(h) != "Edit":
                return True
            # The File name Edit sits below the file-list area; the
            # toolbar/address Edit is much higher up. Pick the lowest Edit.
            rect = win32gui.GetWindowRect(h)
            if edit_hwnd is None or rect[1] > win32gui.GetWindowRect(edit_hwnd)[1]:
                edit_hwnd = h
            return True

        win32gui.EnumChildWindows(fsg_dialog_hwnd, _edit_cb, None)
        if not edit_hwnd:
            print("[ERROR] FSG File name Edit not found (Win32)")
            return False

        # WM_SETTEXT the full path.
        win32gui.SendMessage(edit_hwnd, win32con.WM_SETTEXT, 0, full_path)
        time.sleep(0.3)
        actual = win32gui.GetWindowText(edit_hwnd)
        if actual != full_path:
            print(
                f"[ERROR] WM_SETTEXT rejected (got {actual!r}, "
                f"expected {full_path!r}). UIPI likely blocks the wrapper."
            )
            return False

        # Find &Open button.
        open_btn = None

        def _btn_cb(h, _):
            nonlocal open_btn
            if win32gui.GetClassName(h) == "Button" and "&Open" in win32gui.GetWindowText(h):
                open_btn = h
                return False
            return True

        win32gui.EnumChildWindows(fsg_dialog_hwnd, _btn_cb, None)
        if not open_btn:
            print("[ERROR] FSG Open button not found (Win32)")
            return False

        # BM_CLICK the Open button. This is the same as a real mouse click on
        # the button and triggers the dialog's OK handler.
        win32gui.SendMessage(open_btn, win32con.BM_CLICK, 0, 0)
        time.sleep(1)
        return True

    def _wait_for_fsg_window_or_dialog(self, timeout=15):
        """
        After file selection, wait for either the FSG main window or a TLS dialog.

        Note: shell=True means self.process.pid is cmd.exe, not fsg.exe,
        so we match by title ('fsg') instead of PID.

        Distinguishes dialog vs main window by Win32 class:
          - '#32770' = dialog box  → TLS detected, file incompatible
          - anything else          → main FSG window, proceed

        Returns:
            str: 'dialog' if TLS popup appeared, 'main' if main window appeared, 'timeout' if neither
        """
        import pygetwindow as gw
        start_time = time.time()

        print("\n[INFO] Waiting for FSG window or TLS dialog...")

        while time.time() - start_time < timeout:
            result = [None]

            def _check(hwnd, _):
                if not win32gui.IsWindowVisible(hwnd):
                    return True
                title = win32gui.GetWindowText(hwnd)
                if not title:
                    return True

                cls = win32gui.GetClassName(hwnd)

                # Skip File Explorer / file picker windows
                if cls in ("CabinetWClass", "ExploreWClass", "WorkerW"):
                    return True
                if any(p in title.lower() for p in self.EXCLUDE_WINDOW_PATTERNS):
                    return True

                # Only consider actual FSG app windows — exclude File Explorer
                # File Explorer shows the folder name (e.g. "fsg - File Explorer")
                if "explorer" in title.lower():
                    return True
                if not title.upper().startswith("FSG"):
                    return True

                if cls == "#32770":
                    print(f"[WARNING] TLS dialog detected: '{title}' (class={cls}, HWND={hwnd})")
                    win32gui.SetForegroundWindow(hwnd)
                    time.sleep(0.3)
                    pyautogui.press("enter")
                    result[0] = "dialog"
                    return False
                else:
                    wins = gw.getWindowsWithTitle(title)
                    if wins:
                        self.window = wins[0]
                        print(f"[SUCCESS] FSG main window found: '{title}' (HWND={hwnd})")
                        result[0] = "main"
                        return False

                return True

            win32gui.EnumWindows(_check, None)

            if result[0]:
                return result[0]

            time.sleep(0.5)

        return "timeout"

    def wait_for_packing_complete(self, input_file_path):
        """
        Wait for in-place packing to complete with stability verification.
        Watches the input file for lock release after FSG finishes writing.
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
        print(f"[INFO] Stability Requirement: {required_stable_checks} consecutive unlocked checks")
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

        print(f"\n[ERROR] Timeout after {timeout}s waiting for stable packing completion")
        return None

    def run(self, click_mode="all", file_path=None, output_dir=None) -> bool:
        """
        Main execution flow for FSG.

        1. Launch FSG  → file picker opens immediately
        2. Select file via file picker
        3. Detect what appears next:
             - TLS dialog  → dismiss, return False (incompatible file)
             - Main window → click Compress, watch file, move output
        """
        input_file = None

        try:
            print("\n" + "=" * 60)
            print("FSG GUI AUTOMATION")
            print("=" * 60)

            if not self.load_packer_info():
                print("[ERROR] Failed to load packer info from YAML")
                return False

            if not file_path:
                print("[ERROR] No file path provided")
                return False

            input_file = Path(file_path).resolve()

            # Step 1: Launch FSG — file picker opens immediately
            print("\n[INFO] Launching FSG...")
            if not self.launch_application(shell=True):
                print("[ERROR] Failed to launch application")
                return False

            # Step 2: Handle the Windows Explorer file picker
            print("\n[INFO] Waiting for file picker to appear...")
            time.sleep(1)

            directory = str(input_file.parent)
            filename = input_file.name
            full_path = str(input_file)

            print(f"[INFO] Navigating to directory: {directory}")
            print(f"[INFO] Entering filename: {filename}")

            # Drive the file picker via Win32 directly instead of pyautogui. FSG's
            # dialog is a standard #32770 Open dialog, so we can find the File
            # name Edit control by class+rect, write the full path with
            # WM_SETTEXT, and click the Open button with BM_CLICK. This bypasses
            # UIPI / SetForegroundWindow blocking that pyautogui hits when the
            # wrapper runs at a different integrity level than FSG.
            picker_done = self._drive_fsg_picker_via_win32(full_path)
            if not picker_done:
                # Fallback to pyautogui if Win32 path didn't work (e.g. dialog
                # structure changed in a future FSG build).
                print("[WARNING] Win32 picker drive failed; falling back to pyautogui")
                pyautogui.hotkey("ctrl", "l")
                time.sleep(0.3)
                pyperclip.copy(directory)
                pyautogui.hotkey("ctrl", "v")
                time.sleep(0.3)
                pyautogui.press("enter")
                time.sleep(1)
                pyautogui.hotkey("alt", "n")
                time.sleep(0.3)
                pyperclip.copy(filename)
                pyautogui.hotkey("ctrl", "v")
                time.sleep(0.3)
                pyautogui.press("enter")
                time.sleep(1)
            else:
                print("[SUCCESS] File selected (via Win32)!")

            # Step 3: Detect TLS dialog vs main window
            outcome = self._wait_for_fsg_window_or_dialog(timeout=15)

            if outcome == "dialog":
                print("[ERROR] TLS detected — FSG cannot pack this file.")
                self.close_application()
                return False

            if outcome == "timeout":
                print("[ERROR] Neither FSG main window nor TLS dialog appeared.")
                self.close_application()
                return False

            # outcome == "main" — main window found, self.window is set
            self.center_window_on_monitor(monitor_number=0)
            time.sleep(0.5)

            # Step 4: Click the Compress button
            print("\n[INFO] Clicking Compress button...")
            self.click_at_percent(0.50, 0.85, "Compress button")
            time.sleep(1)

            print("[INFO] Compression initiated!")

            # Step 5: Wait for packing to complete (file lock watch)
            packed_file = self.wait_for_packing_complete(str(input_file))

            if packed_file:
                final_path = self.move_protected_file_to_output(packed_file, output_dir)
                if final_path:
                    print(f"\n{'=' * 60}")
                    print("PACKING COMPLETE")
                    print(f"{'=' * 60}")
                    print(f"  Input:  {input_file}")
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
            if input_file:
                self.cleanup_on_failure(str(input_file))
            else:
                self.close_application()
            return False


def main():
    import argparse

    parser = argparse.ArgumentParser(description="FSG GUI Automation Wrapper")
    parser.add_argument("--file-path", type=str, default=None, help="Full path to the file to process")
    parser.add_argument("--output-dir", type=str, default=None, help="Directory to copy the packed file to")
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    main_dir = script_dir.parent
    yaml_path = main_dir / "manifest" / "packer_corpus.yaml"

    print(f"Script directory: {script_dir}")
    print(f"Main directory: {main_dir}")
    print(f"YAML path: {yaml_path}")

    if not yaml_path.exists():
        print(f"\n[ERROR] YAML file not found at: {yaml_path}")
        return 1

    wrapper = FSG(yaml_path, main_dir)
    success = wrapper.run(file_path=args.file_path, output_dir=args.output_dir)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
