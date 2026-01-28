"""
ASM Guard GUI Automation Wrapper
"""

import yaml
import sys
import time
from pathlib import Path
import subprocess
import pygetwindow as gw
import win32gui
import win32process


class AsmGuardWrapper:
    # Class-level constants to avoid repetition
    DEFAULT_CHECKBOX_STATES = {
        "maximum_instruction_compression": False,
        "add_junk_cpp_functions": True,
        "add_junk_partitions": True,
        "enhanced_flood_mode": False,
        "add_different_types": False,
    }

    # Short name to full name mapping
    NAME_MAP = {
        "max_compression": "maximum_instruction_compression",
        "junk_cpp": "add_junk_cpp_functions",
        "junk_partitions": "add_junk_partitions",
        "flood_mode": "enhanced_flood_mode",
        "different_types": "add_different_types",
    }

    # Checkbox click positions (x_percent, y_percent)
    CHECKBOX_POSITIONS = {
        "maximum_instruction_compression": (0.08, 0.18),
        "add_junk_cpp_functions": (0.08, 0.23),
        "add_junk_partitions": (0.08, 0.28),
        "enhanced_flood_mode": (0.08, 0.33),
        "add_different_types": (0.08, 0.38),
    }

    EXCLUDE_WINDOW_PATTERNS = [
        "visual studio code",
        "vscode",
        "explorer",
        "chrome",
        "firefox",
        "notepad++",
        "cmd",
        "powershell",
        "python",
    ]

    FILE_PICKER_PATTERNS = [
        "Open file or project",
        "Open",
        "Browse",
        "Select File",
        "Choose File",
    ]

    def __init__(self, yaml_path, main_dir):
        self.yaml_path = yaml_path
        self.main_dir = Path(main_dir)
        self.packer_info = None
        self.process = None
        self.window = None
        self.checkbox_states = self.DEFAULT_CHECKBOX_STATES.copy()

    def load_packer_info(self):
        """Load asm_guard configuration from YAML"""
        print("[INFO] Loading packer configuration from YAML...")

        with open(self.yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        for packer in data.get("definitions", []):
            if packer.get("packer_name") == "asm_guard":
                self.packer_info = packer
                print(f"[SUCCESS] Found asm_guard v{packer['version']}")
                print(f"[INFO] Binary path: {packer['binary_path']}")
                return True

        print("[ERROR] asm_guard not found in YAML definitions")
        return False

    def extract_app_name(self, file_path):
        """Extract application name from file path"""
        return Path(file_path).name

    def get_output_path(self, input_file_path, output_suffix="_packed"):
        """Generate output path in main_dir/wrapper/"""
        app_name = self.extract_app_name(input_file_path)
        name_parts = Path(app_name)
        output_name = f"{name_parts.stem}{output_suffix}{name_parts.suffix}"
        return self.get_output_directory() / output_name

    def get_output_directory(self):
        """Get the wrapper output directory"""
        output_dir = self.main_dir / "wrapper"
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    def get_exe_path(self):
        """Get the full path to asm_guard.exe"""
        if not self.packer_info:
            raise ValueError("Packer info not loaded")

        relative_path = self.packer_info["binary_path"].lstrip("./")
        exe_path = self.main_dir / relative_path

        if not exe_path.exists():
            raise FileNotFoundError(f"Executable not found at: {exe_path}")

        return exe_path

    def launch_application(self):
        """Launch the asm_guard GUI application"""
        exe_path = self.get_exe_path()
        print(f"\n[INFO] Launching application: {exe_path}")

        self.process = subprocess.Popen(
            str(exe_path),
            cwd=exe_path.parent,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        print(f"[SUCCESS] Process started with PID: {self.process.pid}")
        print("[INFO] Waiting for GUI window to appear...")
        time.sleep(2)

        return True

    def find_window(self, timeout=10):
        """Find the asm_guard window by process ID"""
        print("\n[INFO] Searching for asm_guard window by process...")

        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                windows = []

                def enum_windows_callback(hwnd, results):
                    if win32gui.IsWindowVisible(hwnd):
                        title = win32gui.GetWindowText(hwnd)
                        if title:
                            _, window_pid = win32process.GetWindowThreadProcessId(hwnd)
                            if window_pid == self.process.pid:
                                results.append((hwnd, title))
                    return True

                win32gui.EnumWindows(enum_windows_callback, windows)

                for _, title in windows:
                    title_lower = title.lower()
                    if any(p in title_lower for p in self.EXCLUDE_WINDOW_PATTERNS):
                        continue
                    print(
                        f"[SUCCESS] Found window: '{title}' (PID: {self.process.pid})"
                    )
                    self.window = gw.getWindowsWithTitle(title)[0]
                    return True

            except Exception as e:
                print(f"[DEBUG] Error during window search: {e}")

            time.sleep(0.5)

        print("[ERROR] Window not found within timeout")
        return False

    def _get_client_area_info(self, window_title):
        """
        Helper to get client area info for a window.
        Returns (client_width, client_height, client_point) or None on failure.
        """
        try:
            hwnd = win32gui.FindWindow(None, window_title)
            client_rect = win32gui.GetClientRect(hwnd)
            _, _, client_width, client_height = client_rect
            client_point = win32gui.ClientToScreen(hwnd, (0, 0))
            return client_width, client_height, client_point
        except Exception as e:
            print(f"[WARNING] Could not get client area details: {e}")
            return None

    def get_window_dimensions(self):
        """Get and print window dimensions"""
        if not self.window:
            print("[ERROR] No window found")
            return None

        print("\n" + "=" * 60)
        print("WINDOW DIMENSIONS")
        print("=" * 60)

        print("\n[FULL WINDOW] (includes title bar and borders)")
        print(f"  Left:   {self.window.left}")
        print(f"  Top:    {self.window.top}")
        print(f"  Width:  {self.window.width}")
        print(f"  Height: {self.window.height}")
        print(f"  Right:  {self.window.left + self.window.width}")
        print(f"  Bottom: {self.window.top + self.window.height}")

        client_info = self._get_client_area_info(self.window.title)
        if client_info:
            client_width, client_height, client_point = client_info
            hwnd = win32gui.FindWindow(None, self.window.title)
            window_rect = win32gui.GetWindowRect(hwnd)
            win_left, win_top, _, _ = window_rect

            print("\n[CLIENT AREA] (actual usable space, excludes borders)")
            print(f"  Width:  {client_width}")
            print(f"  Height: {client_height}")
            print(f"  Screen Position: {client_point}")

            print("\n[CHROME SIZES]")
            print(f"  Title bar height: {client_point[1] - win_top}px")
            print(f"  Border width:     {client_point[0] - win_left}px")

        print("\n" + "=" * 60)

        return {
            "full_window": {
                "left": self.window.left,
                "top": self.window.top,
                "width": self.window.width,
                "height": self.window.height,
            }
        }

    def click_at_percent(self, x_percent, y_percent, description="", track_state=None):
        """Click at a position specified as percentage of window dimensions"""
        if not self.window:
            print("[ERROR] No window found")
            return False

        try:
            import pyautogui

            self.window.activate()
            time.sleep(0.2)

            client_info = self._get_client_area_info(self.window.title)
            if not client_info:
                return False

            client_width, client_height, client_point = client_info
            abs_x = client_point[0] + int(client_width * x_percent)
            abs_y = client_point[1] + int(client_height * y_percent)

            if description:
                print(f"\n[ACTION] Clicking: {description}")
            print(f"  Position: {x_percent * 100:.1f}% x, {y_percent * 100:.1f}% y")
            print(f"  Client area: {client_width}x{client_height}")
            print(f"  Absolute coords: ({abs_x}, {abs_y})")

            if track_state and track_state in self.checkbox_states:
                old_state = self.checkbox_states[track_state]
                print(f"  Current state: {'☑ CHECKED' if old_state else '☐ UNCHECKED'}")

            pyautogui.click(abs_x, abs_y)
            time.sleep(0.1)

            if track_state and track_state in self.checkbox_states:
                self.checkbox_states[track_state] = not self.checkbox_states[
                    track_state
                ]
                new_state = self.checkbox_states[track_state]
                print(f"  New state: {'☑ CHECKED' if new_state else '☐ UNCHECKED'}")

            print("[+] Click successful")
            return True

        except Exception as e:
            print(f"[ERROR] Click failed: {e}")
            return False

    def get_checkbox_state(self, checkbox_name):
        """Get the current tracked state of a checkbox"""
        return self.checkbox_states.get(checkbox_name)

    def print_checkbox_states(self):
        """Print current state of all checkboxes"""
        print("\n" + "=" * 60)
        print("CURRENT CHECKBOX STATES")
        print("=" * 60)
        for name, state in self.checkbox_states.items():
            print(f"  {name:40s} {'☑ CHECKED' if state else '☐ UNCHECKED'}")
        print("=" * 60)

    # ========== UNIFIED CHECKBOX TOGGLE METHOD ==========

    def toggle_checkbox(self, checkbox_name):
        """
        Toggle any checkbox by name.

        Args:
            checkbox_name: Full checkbox name (e.g., 'maximum_instruction_compression')
                          or short name (e.g., 'max_compression')
        """
        # Resolve short name to full name if needed
        full_name = self.NAME_MAP.get(checkbox_name, checkbox_name)

        if full_name not in self.CHECKBOX_POSITIONS:
            print(f"[ERROR] Unknown checkbox: {checkbox_name}")
            return False

        x_percent, y_percent = self.CHECKBOX_POSITIONS[full_name]
        description = full_name.replace("_", " ").title()

        return self.click_at_percent(
            x_percent=x_percent,
            y_percent=y_percent,
            description=description,
            track_state=full_name,
        )

    # Convenience methods that use the unified toggle
    def toggle_maximum_instruction_compression(self):
        return self.toggle_checkbox("maximum_instruction_compression")

    def toggle_add_junk_cpp_functions(self):
        return self.toggle_checkbox("add_junk_cpp_functions")

    def toggle_add_junk_partitions(self):
        return self.toggle_checkbox("add_junk_partitions")

    def toggle_enhanced_flood_mode(self):
        return self.toggle_checkbox("enhanced_flood_mode")

    def toggle_add_different_types(self):
        return self.toggle_checkbox("add_different_types")

    def click_folder_finder(self):
        return self.click_at_percent(
            x_percent=0.08,
            y_percent=0.05,
            description="FILE",
        )

    def click_protect_application(self):
        """Click the 'PROTECT THE APPLICATION' button"""
        return self.click_at_percent(
            x_percent=0.22,
            y_percent=0.50,
            description="PROTECT THE APPLICATION",
        )

    # ========== FILE PICKER METHODS ==========

    def find_file_picker_window(self, timeout=5):
        """Find the Windows Explorer/File Picker window"""
        print("\n[INFO] Searching for file picker window...")
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                for title in gw.getAllTitles():
                    if not title:
                        continue
                    if any(
                        p.lower() in title.lower() for p in self.FILE_PICKER_PATTERNS
                    ):
                        print(f"[SUCCESS] Found file picker: '{title}'")
                        return gw.getWindowsWithTitle(title)[0]
            except Exception as e:
                print(f"[DEBUG] Error during file picker search: {e}")

            time.sleep(0.2)

        print("[ERROR] File picker window not found within timeout")
        return None

    def paste_file_path_in_picker(self, file_path, app_name):
        """
        Find the file picker window, navigate to directory, and enter the filename

        Args:
            file_path: Full path to the file (used to extract directory)
            app_name: Just the filename to type in the File name field

        Returns:
            bool: True if successful
        """
        try:
            import pyautogui
            import pyperclip  # Add this import at top of file too

            time.sleep(0.5)

            picker_window = self.find_file_picker_window()
            if not picker_window:
                print("[ERROR] Could not find file picker window")
                return False

            print(f"\n[INFO] Activating file picker window: '{picker_window.title}'")
            picker_window.activate()
            time.sleep(0.3)

            # ALWAYS use absolute path
            directory_path = str(Path(file_path).resolve().parent)
            print(f"[INFO] Navigating to directory: {directory_path}")

            # Use clipboard for directory path (supports Unicode)
            pyautogui.hotkey("ctrl", "l")
            time.sleep(0.2)
            pyperclip.copy(directory_path)
            pyautogui.hotkey("ctrl", "v")
            time.sleep(0.2)
            pyautogui.press("enter")
            time.sleep(0.5)

            # Focus file name field
            print(f"[INFO] Focusing file name field...")
            pyautogui.hotkey("alt", "n")
            time.sleep(0.2)
            pyautogui.hotkey("ctrl", "a")
            time.sleep(0.1)

            # Use clipboard for filename (supports Unicode/Chinese characters)
            print(f"[INFO] Pasting filename: {app_name}")
            pyperclip.copy(app_name)
            pyautogui.hotkey("ctrl", "v")
            time.sleep(0.3)

            # Click Open button
            print("[INFO] Clicking the Open button...")
            client_info = self._get_client_area_info(picker_window.title)
            if client_info:
                client_width, client_height, client_point = client_info
                open_button_x = client_point[0] + int(client_width * 0.85)
                open_button_y = client_point[1] + int(client_height * 0.97)
                pyautogui.click(open_button_x, open_button_y)
                time.sleep(0.5)

            print("[SUCCESS] Directory navigated and filename entered")
            return True

        except Exception as e:
            print(f"[ERROR] Failed to paste file path: {e}")
            return False

    # ========== STATE-AWARE METHODS ==========

    def ensure_checkbox_state(self, checkbox_name, desired_state):
        """Ensure a checkbox is in the desired state"""
        # Resolve short name to full name if needed
        full_name = self.NAME_MAP.get(checkbox_name, checkbox_name)

        current_state = self.checkbox_states.get(full_name)

        if current_state is None:
            print(f"[ERROR] Unknown checkbox: {checkbox_name}")
            return False

        if current_state == desired_state:
            state_str = "CHECKED" if desired_state else "UNCHECKED"
            print(f"[INFO] {full_name} already {state_str}, skipping")
            return True

        return self.toggle_checkbox(full_name)

    def ensure_checked(self, checkbox_name):
        """Ensure a checkbox is checked"""
        return self.ensure_checkbox_state(checkbox_name, True)

    def ensure_unchecked(self, checkbox_name):
        """Ensure a checkbox is unchecked"""
        return self.ensure_checkbox_state(checkbox_name, False)

    def set_checkbox_configuration(self, config):
        """Set multiple checkboxes to specific states"""
        print("\n" + "=" * 60)
        print(f"CONFIGURING CHECKBOXES ({len(config)} items)")
        print("=" * 60)

        results = {}
        for checkbox_name, desired_state in config.items():
            # Resolve short name to full name
            full_name = self.NAME_MAP.get(checkbox_name, checkbox_name)
            results[full_name] = self.ensure_checkbox_state(full_name, desired_state)

        # Summary
        print("\n" + "=" * 60)
        print("CONFIGURATION SUMMARY")
        print("=" * 60)
        successful = sum(1 for v in results.values() if v)

        for name, status in results.items():
            status_str = "✓ SUCCESS" if status else "✗ FAILED"
            # Get desired state from config (handle both short and full names)
            desired_state = config.get(name) or config.get(
                next((k for k, v in self.NAME_MAP.items() if v == name), None)
            )
            state_str = "CHECKED" if desired_state else "UNCHECKED"
            print(f"  {name:40s} → {state_str:10s} {status_str}")

        print(f"\n  Total: {successful}/{len(results)} successful")
        print("=" * 60)

        return results

    def set_all_checked(self):
        """Ensure all checkboxes are checked"""
        return self.set_checkbox_configuration(
            {name: True for name in self.checkbox_states}
        )

    def set_all_unchecked(self):
        """Ensure all checkboxes are unchecked"""
        return self.set_checkbox_configuration(
            {name: False for name in self.checkbox_states}
        )

    # ========== PROTECTION PROCESS METHODS ==========

    def is_file_locked(self, file_path):
        """Check if a file is locked (still being written to)"""
        try:
            with open(file_path, "r+b") as f:
                import msvcrt

                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            return False
        except (IOError, OSError, PermissionError):
            return True

    def wait_for_protection_complete(
        self, input_file_path, timeout=120, check_interval=2
    ):
        """Wait for the protection process to complete"""
        input_path = Path(input_file_path)
        protected_name = f"{input_path.stem}_protected{input_path.suffix}"
        protected_path = input_path.parent / protected_name

        print(f"\n[INFO] Waiting for protection to complete...")
        print(f"[INFO] Watching for: {protected_path}")
        print(f"[INFO] Timeout: {timeout}s")

        start_time = time.time()
        last_size = 0
        stable_count = 0

        while time.time() - start_time < timeout:
            elapsed = int(time.time() - start_time)

            if protected_path.exists():
                current_size = protected_path.stat().st_size

                if self.is_file_locked(protected_path):
                    print(f"  [{elapsed}s] Writing... {current_size:,} bytes")
                    last_size = current_size
                    stable_count = 0
                else:
                    # File exists and is not locked - it's complete!
                    print(f"\n[SUCCESS] Protection complete! ({elapsed}s)")
                    print(f"[INFO] Output file: {protected_path}")
                    print(f"[INFO] File size: {current_size:,} bytes")
                    return str(protected_path)
            else:
                print(f"  [{elapsed}s] Processing...", end="\r")

            time.sleep(check_interval)

        # Timeout reached
        print(f"\n[ERROR] Timeout after {timeout}s waiting for protected file")
        return None

    def move_protected_file_to_output(self, protected_file_path, output_dir=None):
        """
        Move the protected file to specified output directory

        Args:
            protected_file_path: Path to the protected file
            output_dir: Destination directory (if None, file stays in place)

        Returns:
            str: Final file path
        """
        import shutil

        if not protected_file_path:
            return None

        source = Path(protected_file_path)
        if not source.exists():
            print(f"[ERROR] Protected file not found: {source}")
            return None

        # If no output directory specified, leave file in place
        if output_dir is None:
            print(f"\n[INFO] No output directory specified, file remains at: {source}")
            return str(source)

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        destination = output_dir / source.name

        print(f"\n[INFO] Moving protected file to output directory...")
        print(f"  From: {source}")
        print(f"  To:   {destination}")

        try:
            shutil.move(str(source), str(destination))
            print(f"[SUCCESS] File moved to: {destination}")
            return str(destination)
        except Exception as e:
            print(f"[ERROR] Failed to move file: {e}")
            return None

    def cleanup_asmg_files(self, directory):
        """
        Delete .asmg files created by ASM Guard

        Args:
            directory: Directory to clean up

        Returns:
            list: List of deleted file paths
        """
        import glob

        directory = Path(directory)
        deleted_files = []

        print(f"\n[INFO] Cleaning up .asmg files in: {directory}")

        # Find all .asmg files
        asmg_files = list(directory.glob("*.asmg"))

        if not asmg_files:
            print("[INFO] No .asmg files found")
            return deleted_files

        for asmg_file in asmg_files:
            try:
                asmg_file.unlink()
                deleted_files.append(str(asmg_file))
                print(f"  [DELETED] {asmg_file.name}")
            except Exception as e:
                print(f"  [ERROR] Failed to delete {asmg_file.name}: {e}")

        print(f"[INFO] Cleaned up {len(deleted_files)} .asmg file(s)")
        return deleted_files

    def cleanup_on_failure(self, input_file_path):
        """
        Clean up after a failed or timed out protection attempt

        Args:
            input_file_path: Path to the input file (to find its directory)
        """
        print("\n[INFO] Cleaning up after failure...")

        input_path = Path(input_file_path)

        # Clean up .asmg files
        self.cleanup_asmg_files(input_path.parent)

        # Clean up partial _protected.exe if it exists
        protected_name = f"{input_path.stem}_protected{input_path.suffix}"
        protected_path = input_path.parent / protected_name

        if protected_path.exists():
            try:
                protected_path.unlink()
                print(f"[DELETED] Partial protected file: {protected_path.name}")
            except Exception as e:
                print(f"[WARNING] Could not delete partial file: {e}")

        # Close the GUI application
        self.close_application()

    def close_application(self):
        """
        Close the ASM Guard application
        """
        print("[INFO] Closing ASM Guard application...")

        try:
            if self.process:
                self.process.terminate()
                self.process.wait(timeout=5)  # Wait up to 5 seconds for graceful close
                print("[INFO] Application terminated gracefully")
        except Exception as e:
            print(f"[WARNING] Graceful termination failed: {e}")
            try:
                if self.process:
                    self.process.kill()  # Force kill
                    print("[INFO] Application force killed")
            except Exception as e2:
                print(f"[ERROR] Could not kill application: {e2}")

        self.process = None
        self.window = None

    # ========== MAIN EXECUTION ==========

    def run(self, click_mode="all", file_path=None, output_dir=None):
        """
        Main execution flow

        Args:
            click_mode: 'all', 'none', or dict with desired checkbox states
            file_path: Path to the input file
            output_dir: Directory to copy final output to (optional)
        """
        print("\n" + "=" * 60)
        print("ASM GUARD WRAPPER - Checkbox Automation")
        print("=" * 60)

        # Track input file for cleanup purposes
        input_file = None

        try:
            # Step 1: Load configuration
            if not self.load_packer_info():
                return False

            # Step 2: Launch application
            if not self.launch_application():
                return False

            # Step 3: Find window
            if not self.find_window():
                print("[ERROR] Could not find window within timeout")
                self.close_application()
                return False

            # Step 4: Wait for window to fully load
            print("\n[INFO] Waiting for window to fully load...")
            time.sleep(2)

            try:
                self.window = gw.getWindowsWithTitle(self.window.title)[0]
            except:
                pass

            # Step 5: Get dimensions
            self.get_window_dimensions()

            # Step 6: Show initial checkbox states
            print("\n" + "=" * 60)
            print("INITIAL CHECKBOX STATES (defaults when app opens)")
            print("=" * 60)
            for name, state in self.checkbox_states.items():
                print(f"  {name:40s} {'☑ CHECKED' if state else '☐ UNCHECKED'}")
            print("=" * 60)

            # Step 7: Click the file finder
            print("\n[INFO] Clicking file finder...")
            if not self.click_folder_finder():
                print("[WARNING] File finder click may have failed")

            # Step 8: Handle file path - ALWAYS USE ABSOLUTE PATH
            if file_path is None:
                print("[ERROR] No file path provided")
                self.close_application()
                return False

            # Resolve to absolute path immediately
            input_file = Path(file_path).resolve()
            app_name = input_file.name

            print(f"\n[INFO] Input file: {app_name}")
            print(f"[INFO] Input directory: {input_file.parent}")
            if output_dir:
                print(f"[INFO] Output will be moved to: {output_dir}")

            # Step 9: Paste the ACTUAL file path into the file picker
            print(f"\n[INFO] Preparing to paste file path...")
            if not self.paste_file_path_in_picker(str(input_file), app_name):
                print("[WARNING] File path pasting may have failed")

            time.sleep(0.5)

            # Step 10: Configure checkboxes based on mode
            results = self._apply_click_mode(click_mode)

            # Step 11: Show final states
            if results:
                self.print_checkbox_states()

            # Step 12: Start protection
            print("\n[INFO] Starting protection process...")
            time.sleep(0.3)
            if not self.click_protect_application():
                print("[ERROR] Failed to click PROTECT THE APPLICATION button")
                self.cleanup_on_failure(str(input_file))
                return False

            print("[INFO] Protection process initiated!")
            print("[INFO] Waiting for packing to complete...")
            time.sleep(5)

            # Step 13: Wait for completion
            protected_file = self.wait_for_protection_complete(
                str(input_file), timeout=120
            )

            if protected_file:
                # Step 14: Clean up .asmg files in the INPUT directory
                self.cleanup_asmg_files(input_file.parent)

                # Step 15: Move to output directory (if specified)
                final_path = self.move_protected_file_to_output(
                    protected_file, output_dir
                )

                if final_path:
                    print(f"\n" + "=" * 60)
                    print("PROTECTION COMPLETE")
                    print("=" * 60)
                    print(f"  Input:  {input_file}")
                    print(f"  Output: {final_path}")
                    print("=" * 60)

                # Close application after success
                self.close_application()
                print("\n[SUCCESS] Automation complete!")
                return True
            else:
                # TIMEOUT - cleanup and close
                print("[ERROR] Protection process timed out!")
                self.cleanup_on_failure(str(input_file))
                return False

        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")
            import traceback

            traceback.print_exc()

            # Cleanup on any exception
            if input_file:
                self.cleanup_on_failure(str(input_file))
            else:
                self.close_application()

            return False

    def _apply_click_mode(self, click_mode):
        """Apply checkbox configuration based on click_mode"""
        if click_mode == "all":
            print("\n[INFO] Setting ALL checkboxes to CHECKED...")
            return self.set_all_checked()
        elif click_mode == "none":
            print("\n[INFO] Skipping checkbox configuration (mode: none)")
            return {}
        elif isinstance(click_mode, dict):
            print(f"\n[INFO] Applying custom configuration...")
            return self.set_checkbox_configuration(click_mode)
        elif isinstance(click_mode, list):
            print(f"\n[INFO] Setting selected checkboxes to CHECKED: {click_mode}")
            config = {self.NAME_MAP.get(item, item): True for item in click_mode}
            return self.set_checkbox_configuration(config)
        else:
            print(f"\n[WARNING] Unknown click_mode: {click_mode}")
            return {}


def main():
    """Entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="ASM Guard GUI Automation Wrapper with State-Aware Checkbox Control",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python asm_guard_wrapper.py
  python asm_guard_wrapper.py --check max_compression flood_mode
  python asm_guard_wrapper.py --uncheck junk_cpp junk_partitions
  python asm_guard_wrapper.py --check max_compression --uncheck junk_cpp
  python asm_guard_wrapper.py --no-click
  python asm_guard_wrapper.py --show-defaults
  python asm_guard_wrapper.py --file-path "C:\\path\\to\\your\\file.exe"

Available checkbox names:
  - max_compression, junk_cpp, junk_partitions, flood_mode, different_types
        """,
    )

    checkbox_choices = list(AsmGuardWrapper.NAME_MAP.keys())

    parser.add_argument(
        "--check",
        nargs="+",
        choices=checkbox_choices,
        help="Set these checkboxes to CHECKED",
    )
    parser.add_argument(
        "--uncheck",
        nargs="+",
        choices=checkbox_choices,
        help="Set these checkboxes to UNCHECKED",
    )
    parser.add_argument(
        "--no-click",
        action="store_true",
        help="Launch app but do not modify any checkboxes",
    )
    parser.add_argument(
        "--show-defaults",
        action="store_true",
        help="Show default checkbox states and exit",
    )
    parser.add_argument(
        "--file-path", type=str, default=None, help="Full path to the file to process"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory to copy the protected file to (if not specified, stays in place)",
    )

    args = parser.parse_args()

    # Show defaults and exit
    if args.show_defaults:
        print("\n" + "=" * 60)
        print("DEFAULT CHECKBOX STATES (when app first opens)")
        print("=" * 60)
        for name, state in AsmGuardWrapper.DEFAULT_CHECKBOX_STATES.items():
            print(f"  {name:40s} {'☑ CHECKED' if state else '☐ UNCHECKED'}")
        print("=" * 60)
        return 0

    # Determine click mode
    if args.no_click:
        click_mode = "none"
    elif args.check or args.uncheck:
        config = {}
        if args.check:
            for short_name in args.check:
                config[AsmGuardWrapper.NAME_MAP[short_name]] = True
        if args.uncheck:
            for short_name in args.uncheck:
                config[AsmGuardWrapper.NAME_MAP[short_name]] = False
        click_mode = config
    else:
        click_mode = "all"

    # Determine paths
    script_dir = Path(__file__).parent
    main_dir = script_dir.parent
    yaml_path = main_dir / "manifest" / "packer_corpus.yaml"

    print(f"Script directory: {script_dir}")
    print(f"Main directory: {main_dir}")
    print(f"YAML path: {yaml_path}")
    print(
        f"Configuration mode: {click_mode if not isinstance(click_mode, dict) else f'CUSTOM ({len(click_mode)} settings)'}"
    )
    if args.output_dir:
        print(f"Output directory: {args.output_dir}")

    if not yaml_path.exists():
        print(f"\n[ERROR] YAML file not found at: {yaml_path}")
        return 1

    wrapper = AsmGuardWrapper(yaml_path, main_dir)
    success = wrapper.run(
        click_mode=click_mode, file_path=args.file_path, output_dir=args.output_dir
    )

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
