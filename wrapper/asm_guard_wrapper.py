"""
ASM Guard GUI Automation Wrapper - Part 1
Opens the asm_guard application and prints window dimensions
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
    def __init__(self, yaml_path, main_dir):
        """
        Initialize the wrapper

        Args:
            yaml_path: Path to packer_corpus.yaml
            main_dir: Main directory containing packers folder
        """
        self.yaml_path = yaml_path
        self.main_dir = Path(main_dir)
        self.packer_info = None
        self.process = None
        self.window = None

        # Track checkbox states (True = checked, False = unchecked)
        # Initialize with known default states when app opens
        self.checkbox_states = {
            "maximum_instruction_compression": False,
            "add_junk_cpp_functions": True,
            "add_junk_partitions": True,
            "enhanced_flood_mode": False,
            "add_different_types": False,
        }

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

    # Add these methods to your AsmGuardWrapper class:

    def extract_app_name(self, file_path):
        """
        Extract application name from file path

        Args:
            file_path: Full path like "C:\\...\\Air Explorer_5.9.0_Machine_X86_nullsoft_en-US.exe"

        Returns:
            str: Application name (e.g., "Air Explorer_5.9.0_Machine_X86_nullsoft_en-US.exe")
        """
        return Path(file_path).name

    def get_output_path(self, input_file_path, output_suffix="_packed"):
        """
        Generate output path in main_dir/wrapper/

        Args:
            input_file_path: Full path to input file
            output_suffix: Suffix to add before extension (default: "_packed")

        Returns:
            Path: Output path like main_dir/wrapper/AppName_packed.exe
        """
        app_name = self.extract_app_name(input_file_path)
        name_parts = Path(app_name)

        # Create output filename: original_name + suffix + extension
        output_name = f"{name_parts.stem}{output_suffix}{name_parts.suffix}"

        # Output directory is main_dir/wrapper/
        output_dir = self.main_dir / "wrapper"
        output_dir.mkdir(parents=True, exist_ok=True)

        return output_dir / output_name

    def get_output_directory(self):
        """
        Get the wrapper output directory

        Returns:
            Path: main_dir/wrapper/
        """
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
        """
        Find the asm_guard window by process ID

        Args:
            timeout: Maximum seconds to wait for window
        """
        print("\n[INFO] Searching for asm_guard window by process...")

        start_time = time.time()

        exclude_patterns = [
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

        while time.time() - start_time < timeout:
            try:

                def enum_windows_callback(hwnd, results):
                    if win32gui.IsWindowVisible(hwnd):
                        title = win32gui.GetWindowText(hwnd)
                        if not title:
                            return True

                        _, window_pid = win32process.GetWindowThreadProcessId(hwnd)

                        if window_pid == self.process.pid:
                            results.append((hwnd, title))

                    return True

                windows = []
                win32gui.EnumWindows(enum_windows_callback, windows)

                for _, title in windows:
                    title_lower = title.lower()
                    if any(pattern in title_lower for pattern in exclude_patterns):
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

    def get_window_dimensions(self):
        """
        Get and print window dimensions (both absolute and client area)
        """
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

        try:
            hwnd = win32gui.FindWindow(None, self.window.title)

            # Get client rectangle
            client_rect = win32gui.GetClientRect(hwnd)
            client_left, client_top, client_width, client_height = client_rect

            # Get window rectangle
            window_rect = win32gui.GetWindowRect(hwnd)
            win_left, win_top, win_right, win_bottom = window_rect

            # Calculate client area screen coordinates
            client_point = win32gui.ClientToScreen(hwnd, (0, 0))

            print("\n[CLIENT AREA] (actual usable space, excludes borders)")
            print(f"  Width:  {client_width}")
            print(f"  Height: {client_height}")
            print(f"  Screen Position: {client_point}")

            # Calculate title bar and border sizes
            title_bar_height = client_point[1] - win_top
            border_width = client_point[0] - win_left

            print("\n[CHROME SIZES]")
            print(f"  Title bar height: {title_bar_height}px")
            print(f"  Border width:     {border_width}px")

        except Exception as e:
            print(f"\n[WARNING] Could not get client area details: {e}")

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
        """
        Click at a position specified as percentage of window dimensions

        Args:
            x_percent: X position as percentage (0.0 to 1.0)
            y_percent: Y position as percentage (0.0 to 1.0)
            description: Description of what we're clicking
            track_state: Checkbox state key to update after click (optional)
        """
        if not self.window:
            print("[ERROR] No window found")
            return False

        try:
            import pyautogui

            self.window.activate()
            time.sleep(0.2)

            hwnd = win32gui.FindWindow(None, self.window.title)
            client_rect = win32gui.GetClientRect(hwnd)
            _, _, client_width, client_height = client_rect
            client_point = win32gui.ClientToScreen(hwnd, (0, 0))

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
        """
        Get the current tracked state of a checkbox

        Args:
            checkbox_name: Name of checkbox

        Returns:
            bool: True if checked, False if unchecked, None if unknown
        """
        return self.checkbox_states.get(checkbox_name)

    def print_checkbox_states(self):
        """Print current state of all checkboxes"""
        print("\n" + "=" * 60)
        print("CURRENT CHECKBOX STATES")
        print("=" * 60)
        for name, state in self.checkbox_states.items():
            state_str = "☑ CHECKED" if state else "☐ UNCHECKED"
            print(f"  {name:40s} {state_str}")
        print("=" * 60)

    # ========== CHECKBOX CLICK METHODS ==========

    def toggle_maximum_instruction_compression(self):
        """Toggle 'Maximum instruction compression' checkbox"""
        return self.click_at_percent(
            x_percent=0.08,
            y_percent=0.18,
            description="Maximum instruction compression",
            track_state="maximum_instruction_compression",
        )

    def toggle_add_junk_cpp_functions(self):
        """Toggle 'Add junk C/C++ functions' checkbox"""
        return self.click_at_percent(
            x_percent=0.08,
            y_percent=0.23,
            description="Add junk C/C++ functions",
            track_state="add_junk_cpp_functions",
        )

    def toggle_add_junk_partitions(self):
        """Toggle 'Add junk partitions' checkbox"""
        return self.click_at_percent(
            x_percent=0.08,
            y_percent=0.28,
            description="Add junk partitions",
            track_state="add_junk_partitions",
        )

    def toggle_enhanced_flood_mode(self):
        """Toggle 'Enhanced flood mode' checkbox"""
        return self.click_at_percent(
            x_percent=0.08,
            y_percent=0.33,
            description="Enhanced flood mode",
            track_state="enhanced_flood_mode",
        )

    def toggle_add_different_types(self):
        """Toggle 'Add different types' checkbox"""
        return self.click_at_percent(
            x_percent=0.08,
            y_percent=0.38,
            description="Add different types",
            track_state="add_different_types",
        )

    def click_folder_finder(self):
        return self.click_at_percent(
            x_percent=0.08,
            y_percent=0.05,
            description="FILE",
            track_state="FILE",
        )

    def find_file_picker_window(self, timeout=5):
        """
        Find the Windows Explorer/File Picker window that opens after clicking folder finder

        Args:
            timeout: Maximum seconds to wait for the file picker window

        Returns:
            PyGetWindow window object or None
        """
        print("\n[INFO] Searching for file picker window...")
        start_time = time.time()

        # Common file picker window titles
        picker_patterns = [
            "Open file or project",
            "Open",
            "Browse",
            "Select File",
            "Choose File",
        ]

        while time.time() - start_time < timeout:
            try:
                all_windows = gw.getAllTitles()

                for title in all_windows:
                    if not title:
                        continue

                    # Check if any pattern matches
                    for pattern in picker_patterns:
                        if pattern.lower() in title.lower():
                            print(f"[SUCCESS] Found file picker: '{title}'")
                            window = gw.getWindowsWithTitle(title)[0]
                            return window

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
            app_name: Just the filename to paste in the File name field

        Returns:
            bool: True if successful
        """
        try:
            import pyautogui

            # Wait briefly for file picker to appear
            time.sleep(0.5)

            # Find the file picker window
            picker_window = self.find_file_picker_window()

            if not picker_window:
                print("[ERROR] Could not find file picker window")
                return False

            # Activate the file picker window
            print(f"\n[INFO] Activating file picker window: '{picker_window.title}'")
            picker_window.activate()
            time.sleep(0.3)

            # Step 1: Navigate to the directory using Ctrl+L (address bar)
            directory_path = str(Path(file_path).parent)
            print(f"[INFO] Navigating to directory: {directory_path}")

            pyautogui.hotkey("ctrl", "l")
            time.sleep(0.2)
            pyautogui.hotkey("ctrl", "a")
            time.sleep(0.1)
            pyautogui.write(directory_path, interval=0.01)
            time.sleep(0.2)
            pyautogui.press("enter")
            time.sleep(0.5)  # Wait for directory to load

            # Step 2: Click on the "File name:" field (or use Alt+N shortcut)
            print(f"[INFO] Focusing file name field...")
            pyautogui.hotkey(
                "alt", "n"
            )  # Alt+N focuses "File name:" field in Windows dialogs
            time.sleep(0.2)

            # Step 3: Clear and type the app name
            pyautogui.hotkey("ctrl", "a")
            time.sleep(0.1)
            print(f"[INFO] Typing filename: {app_name}")
            pyautogui.write(app_name, interval=0.01)
            time.sleep(0.3)

            # Step 4: Click the Open button
            print("[INFO] Clicking the Open button...")
            hwnd = win32gui.FindWindow(None, picker_window.title)
            client_rect = win32gui.GetClientRect(hwnd)
            _, _, client_width, client_height = client_rect
            client_point = win32gui.ClientToScreen(hwnd, (0, 0))

            open_button_x = client_point[0] + int(client_width * 0.85)
            open_button_y = client_point[1] + int(client_height * 0.97)

            pyautogui.click(open_button_x, open_button_y)
            time.sleep(0.5)

            print("[SUCCESS] Directory navigated and filename entered")
            return True

        except Exception as e:
            print(f"[ERROR] Failed to paste file path: {e}")
            return False

    def click_open_button_in_picker(self):
        """
        Alternative method: Click the Open button in the file picker dialog
        Uses relative positioning from the picker window

        Returns:
            bool: True if successful
        """
        try:
            import pyautogui

            picker_window = self.find_file_picker_window()

            if not picker_window:
                print("[ERROR] Could not find file picker window")
                return False

            picker_window.activate()
            time.sleep(0.2)

            # Get file picker window dimensions
            hwnd = win32gui.FindWindow(None, picker_window.title)
            client_rect = win32gui.GetClientRect(hwnd)
            _, _, client_width, client_height = client_rect
            client_point = win32gui.ClientToScreen(hwnd, (0, 0))

            # Open button is typically at bottom right
            # Approximate position: 85% from left, 93% from top
            open_button_x = client_point[0] + int(client_width * 0.85)
            open_button_y = client_point[1] + int(client_height * 0.95)

            print(f"[INFO] Clicking Open button at ({open_button_x}, {open_button_y})")
            pyautogui.click(open_button_x, open_button_y)
            time.sleep(0.3)

            print("[SUCCESS] Open button clicked")
            return True

        except Exception as e:
            print(f"[ERROR] Failed to click Open button: {e}")
            return False

    # Add this method to your AsmGuardWrapper class:

    def click_protect_application(self):
        """
        Click the 'PROTECT THE APPLICATION' button to start the packing process

        Returns:
            bool: True if successful
        """
        return self.click_at_percent(
            x_percent=0.22,  # Button is roughly 22% from left
            y_percent=0.50,  # Roughly 77% down from top
            description="PROTECT THE APPLICATION",
        )

    # ========== STATE-AWARE METHODS ==========
    def ensure_checkbox_state(self, checkbox_name, desired_state):
        """
        Ensure a checkbox is in the desired state (checked or unchecked)

        Args:
            checkbox_name: Name of the checkbox
            desired_state: True for checked, False for unchecked

        Returns:
            bool: True if successful, False otherwise
        """
        current_state = self.checkbox_states.get(checkbox_name)

        if current_state is None:
            print(f"[ERROR] Unknown checkbox: {checkbox_name}")
            return False

        # If already in desired state, don't click
        if current_state == desired_state:
            state_str = "CHECKED" if desired_state else "UNCHECKED"
            print(f"[INFO] {checkbox_name} already {state_str}, skipping")
            return True

        # Need to toggle to reach desired state
        toggle_methods = {
            "maximum_instruction_compression": self.toggle_maximum_instruction_compression,
            "add_junk_cpp_functions": self.toggle_add_junk_cpp_functions,
            "add_junk_partitions": self.toggle_add_junk_partitions,
            "enhanced_flood_mode": self.toggle_enhanced_flood_mode,
            "add_different_types": self.toggle_add_different_types,
        }

        if checkbox_name in toggle_methods:
            return toggle_methods[checkbox_name]()

        return False

    def ensure_checked(self, checkbox_name):
        """Ensure a checkbox is checked"""
        return self.ensure_checkbox_state(checkbox_name, True)

    def ensure_unchecked(self, checkbox_name):
        """Ensure a checkbox is unchecked"""
        return self.ensure_checkbox_state(checkbox_name, False)

    def set_checkbox_configuration(self, config):
        """
        Set multiple checkboxes to specific states

        Args:
            config: Dictionary mapping checkbox names to desired states
                   Example: {'maximum_instruction_compression': True,
                            'add_junk_cpp_functions': False}

        Returns:
            dict: Results of each operation
        """
        print("\n" + "=" * 60)
        print(f"CONFIGURING CHECKBOXES ({len(config)} items)")
        print("=" * 60)

        results = {}
        for checkbox_name, desired_state in config.items():
            results[checkbox_name] = self.ensure_checkbox_state(
                checkbox_name, desired_state
            )

        # Summary
        print("\n" + "=" * 60)
        print("CONFIGURATION SUMMARY")
        print("=" * 60)
        successful = sum(1 for v in results.values() if v)
        total = len(results)

        for name, status in results.items():
            status_str = "✓ SUCCESS" if status else "✗ FAILED"
            desired_state = config[name]
            state_str = "CHECKED" if desired_state else "UNCHECKED"
            print(f"  {name:40s} → {state_str:10s} {status_str}")

        print(f"\n  Total: {successful}/{total} successful")
        print("=" * 60)

        return results

    # ========== LEGACY METHODS (for backward compatibility) ==========

    def click_maximum_instruction_compression(self):
        """DEPRECATED: Use toggle_maximum_instruction_compression() or ensure_checked()"""
        return self.toggle_maximum_instruction_compression()

    def click_add_junk_cpp_functions(self):
        """DEPRECATED: Use toggle_add_junk_cpp_functions() or ensure_checked()"""
        return self.toggle_add_junk_cpp_functions()

    def click_add_junk_partitions(self):
        """DEPRECATED: Use toggle_add_junk_partitions() or ensure_checked()"""
        return self.toggle_add_junk_partitions()

    def click_enhanced_flood_mode(self):
        """DEPRECATED: Use toggle_enhanced_flood_mode() or ensure_checked()"""
        return self.toggle_enhanced_flood_mode()

    def click_add_different_types(self):
        """DEPRECATED: Use toggle_add_different_types() or ensure_checked()"""
        return self.toggle_add_different_types()

    def click_all_checkboxes(self):
        """
        DEPRECATED: Use set_all_checked() or set_checkbox_configuration() instead

        Toggle all available checkboxes in the Loader tab (state-unaware)

        Returns:
            dict: Status of each checkbox click
        """
        print("\n[WARNING] click_all_checkboxes() is deprecated and state-unaware")
        print(
            "[INFO] Consider using set_all_checked() or set_checkbox_configuration() instead"
        )

        print("\n" + "=" * 60)
        print("TOGGLING ALL CHECKBOXES")
        print("=" * 60)

        results = {
            "maximum_instruction_compression": self.toggle_maximum_instruction_compression(),
            "add_junk_cpp_functions": self.toggle_add_junk_cpp_functions(),
            "add_junk_partitions": self.toggle_add_junk_partitions(),
            "enhanced_flood_mode": self.toggle_enhanced_flood_mode(),
            "add_different_types": self.toggle_add_different_types(),
        }

        # Summary
        print("\n" + "=" * 60)
        print("CHECKBOX TOGGLE SUMMARY")
        print("=" * 60)
        successful = sum(1 for v in results.values() if v)
        total = len(results)

        for name, status in results.items():
            status_str = "✓ SUCCESS" if status else "✗ FAILED"
            state = self.checkbox_states[name]
            state_str = "☑ CHECKED" if state else "☐ UNCHECKED"
            print(f"  {name:40s} {state_str:12s} {status_str}")

        print(f"\n  Total: {successful}/{total} successful")
        print("=" * 60)

        return results

    def set_all_checked(self):
        """Ensure all checkboxes are checked"""
        config = {name: True for name in self.checkbox_states.keys()}
        return self.set_checkbox_configuration(config)

    def set_all_unchecked(self):
        """Ensure all checkboxes are unchecked"""
        config = {name: False for name in self.checkbox_states.keys()}
        return self.set_checkbox_configuration(config)

    def click_selected_checkboxes(self, checkboxes):
        """
        DEPRECATED: Use set_checkbox_configuration() instead

        Toggle only selected checkboxes (state-unaware)

        Args:
            checkboxes: List of checkbox names to click
                       Valid names: 'max_compression', 'junk_cpp', 'junk_partitions',
                                   'flood_mode', 'different_types'

        Returns:
            dict: Status of each requested checkbox click
        """
        print("\n[WARNING] click_selected_checkboxes() is deprecated and state-unaware")
        print("[INFO] Consider using set_checkbox_configuration() instead")

        # Map short names to full names
        name_map = {
            "max_compression": "maximum_instruction_compression",
            "junk_cpp": "add_junk_cpp_functions",
            "junk_partitions": "add_junk_partitions",
            "flood_mode": "enhanced_flood_mode",
            "different_types": "add_different_types",
        }

        toggle_methods = {
            "max_compression": self.toggle_maximum_instruction_compression,
            "junk_cpp": self.toggle_add_junk_cpp_functions,
            "junk_partitions": self.toggle_add_junk_partitions,
            "flood_mode": self.toggle_enhanced_flood_mode,
            "different_types": self.toggle_add_different_types,
        }

        print("\n" + "=" * 60)
        print(f"TOGGLING SELECTED CHECKBOXES ({len(checkboxes)} items)")
        print("=" * 60)

        results = {}
        for checkbox_name in checkboxes:
            if checkbox_name in toggle_methods:
                results[checkbox_name] = toggle_methods[checkbox_name]()
            else:
                print(f"\n[WARNING] Unknown checkbox: {checkbox_name}")
                results[checkbox_name] = False

        return results

    def move_protected_file_to_output(self, protected_file_path):
        """
        Move the protected file to main_dir/wrapper/
        """
        import shutil

        if not protected_file_path:
            return None

        source = Path(protected_file_path)
        if not source.exists():
            print(f"[ERROR] Protected file not found: {source}")
            return None

        output_dir = self.get_output_directory()
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

    def run(self, click_mode="all", file_path=None):
        """
        Main execution flow

        Args:
            click_mode: 'all', 'none', or dict with desired checkbox states
            file_path: Path to paste in the file picker (optional)
        """
        print("\n" + "=" * 60)
        print("ASM GUARD WRAPPER - Checkbox Automation")
        print("=" * 60)

        # Step 1: Load configuration
        if not self.load_packer_info():
            return False

        # Step 2: Launch application
        if not self.launch_application():
            return False

        # Step 3: Find window
        if not self.find_window():
            print("[ERROR] Could not find window within timeout")
            return False

        # Step 4: Wait for window to fully load and expand
        print("\n[INFO] Waiting for window to fully load...")
        time.sleep(2)  # Give the window time to expand to full size

        # Refresh window info to get updated dimensions
        try:
            self.window = gw.getWindowsWithTitle(self.window.title)[0]
        except:
            pass

        # Step 5: Get dimensions
        dimensions = self.get_window_dimensions()

        # Step 6: Show initial checkbox states
        print("\n" + "=" * 60)
        print("INITIAL CHECKBOX STATES (defaults when app opens)")
        print("=" * 60)
        for name, state in self.checkbox_states.items():
            state_str = "☑ CHECKED" if state else "☐ UNCHECKED"
            print(f"  {name:40s} {state_str}")
        print("=" * 60)

        # Step 6.5: Click the file/folder finder BEFORE configuring checkboxes
        print("\n[INFO] Clicking file finder...")
        if not self.click_folder_finder():
            print("[WARNING] File finder click may have failed")

        # Step 6.6: Paste file path in the opened file picker
        if file_path is None:
            file_path = r"C:\Users\bkoro\projects\automated-packing\corpus\wrapper\Air Explorer_5.9.0_Machine_X86_nullsoft_en-US.exe"

        app_name = self.extract_app_name(file_path)
        output_path = self.get_output_path(file_path)

        print(f"\n[INFO] Input file: {app_name}")
        print(f"[INFO] Output will be saved to: {output_path}")

        print(f"\n[INFO] Preparing to paste file path...")
        if not self.paste_file_path_in_picker(output_path, app_name):
            print("[WARNING] File path pasting may have failed")
            # Alternative: If Enter key doesn't work, you can try:
            # self.click_open_button_in_picker()

        time.sleep(0.5)  # Brief pause after submitting file

        # Step 7: Configure checkboxes based on mode
        if click_mode == "all":
            print("\n[INFO] Setting ALL checkboxes to CHECKED...")
            results = self.set_all_checked()
        elif click_mode == "none":
            print("\n[INFO] Skipping checkbox configuration (mode: none)")
            results = {}
        elif isinstance(click_mode, dict):
            print(f"\n[INFO] Applying custom configuration...")
            results = self.set_checkbox_configuration(click_mode)
        elif isinstance(click_mode, list):
            print(f"\n[INFO] DEPRECATED: List-based mode, use dict instead")
            print(f"[INFO] Setting selected checkboxes to CHECKED: {click_mode}")
            # Convert list to dict (all True)
            name_map = {
                "max_compression": "maximum_instruction_compression",
                "junk_cpp": "add_junk_cpp_functions",
                "junk_partitions": "add_junk_partitions",
                "flood_mode": "enhanced_flood_mode",
                "different_types": "add_different_types",
            }
            config = {name_map.get(item, item): True for item in click_mode}
            results = self.set_checkbox_configuration(config)
        else:
            print(f"\n[WARNING] Unknown click_mode: {click_mode}")
            results = {}

        # Step 8: Show final states
        if results:
            self.print_checkbox_states()

        print("\n[INFO] Starting protection process...")
        time.sleep(0.3)  # Brief pause before clicking
        if not self.click_protect_application():
            print("[ERROR] Failed to click PROTECT THE APPLICATION button")
            return False

        print("[INFO] Protection process initiated!")
        print("[INFO] Waiting for packing to complete...")

        time.sleep(5)  #

        # Step 10: Wait for protection to complete
        protected_file = self.wait_for_protection_complete(file_path, timeout=120)

        if protected_file:
            # Step 11: Move to output directory
            final_path = self.move_protected_file_to_output(protected_file)

            if final_path:
                print(f"\n" + "=" * 60)
                print("PROTECTION COMPLETE")
                print("=" * 60)
                print(f"  Input:  {app_name}")
                print(f"  Output: {final_path}")
                print("=" * 60)
        else:
            print("[ERROR] Protection process may have failed")
            return False

        print("\n[SUCCESS] Automation complete!")

        # Close the application
        if self.process:
            self.process.terminate()
            print("[INFO] Application closed")

        return True

    def is_file_locked(self, file_path):
        """
        Check if a file is locked (still being written to)

        Args:
            file_path: Path to check

        Returns:
            bool: True if locked/in-use, False if available
        """
        import os

        try:
            # Try to open the file with exclusive access
            with open(file_path, "r+b") as f:
                # Try to get exclusive lock (Windows)
                import msvcrt

                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            return False  # File is NOT locked
        except (IOError, OSError, PermissionError):
            return True  # File IS locked

    def wait_for_protection_complete(
        self, input_file_path, timeout=120, check_interval=2
    ):
        """
        Wait for the protection process to complete by monitoring for the output file

        Args:
            input_file_path: Path to the input file
            timeout: Maximum seconds to wait (default: 120)
            check_interval: Seconds between checks (default: 2)

        Returns:
            str: Path to the protected file if successful, None if timeout
        """
        input_path = Path(input_file_path)

        # ASM Guard saves as: originalname_protected.exe in the same directory
        protected_name = f"{input_path.stem}_protected{input_path.suffix}"
        protected_path = input_path.parent / protected_name

        print(f"\n[INFO] Waiting for protection to complete...")
        print(f"[INFO] Watching for: {protected_path}")

        start_time = time.time()

        while time.time() - start_time < timeout:
            elapsed = int(time.time() - start_time)

            if protected_path.exists():
                current_size = protected_path.stat().st_size

                # Check if file is still being written to
                if self.is_file_locked(protected_path):
                    print(f"  [{elapsed}s] Writing... {current_size:,} bytes")
                else:
                    # File exists and is not locked - it's complete!
                    print(f"\n[SUCCESS] Protection complete! ({elapsed}s)")
                    print(f"[INFO] Output file: {protected_path}")
                    print(f"[INFO] File size: {current_size:,} bytes")
                    return str(protected_path)
            else:
                print(f"  [{elapsed}s] Processing...", end="\r")

            time.sleep(check_interval)

        print(f"\n[ERROR] Timeout after {timeout}s waiting for protected file")
        return None


def main():
    """Entry point"""
    import argparse

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="ASM Guard GUI Automation Wrapper with State-Aware Checkbox Control",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Set all checkboxes to CHECKED (default)
  python asm_guard_wrapper.py
  
  # Set specific checkboxes to CHECKED (unchecks pre-checked ones not listed)
  python asm_guard_wrapper.py --check max_compression flood_mode
  
  # Set specific checkboxes to UNCHECKED
  python asm_guard_wrapper.py --uncheck junk_cpp junk_partitions
  
  # Mixed configuration
  python asm_guard_wrapper.py --check max_compression --uncheck junk_cpp
  
  # Don't modify any checkboxes (use defaults)
  python asm_guard_wrapper.py --no-click
  
  # Show current states only
  python asm_guard_wrapper.py --show-defaults
  
  # Specify custom file path
  python asm_guard_wrapper.py --file-path "C:\\path\\to\\your\\file.exe"
  
  # Full example with custom file and checkbox config
  python asm_guard_wrapper.py --file-path "C:\\custom\\file.exe" --check max_compression

Available checkbox names:
  - max_compression      : Maximum instruction compression (default: UNCHECKED)
  - junk_cpp            : Add junk C/C++ functions (default: CHECKED)
  - junk_partitions     : Add junk partitions (default: CHECKED)
  - flood_mode          : Enhanced flood mode (default: UNCHECKED)
  - different_types     : Add different types (default: UNCHECKED)
  
Note: junk_cpp and junk_partitions come PRE-CHECKED when the app opens.
      By default, uses: C:\\Users\\bkoro\\projects\\automated-packing\\corpus\\wrapper\\Air Explorer_5.9.0_Machine_X86_nullsoft_en-US.exe
        """,
    )

    parser.add_argument(
        "--check",
        nargs="+",
        choices=[
            "max_compression",
            "junk_cpp",
            "junk_partitions",
            "flood_mode",
            "different_types",
        ],
        help="Set these checkboxes to CHECKED",
    )

    parser.add_argument(
        "--uncheck",
        nargs="+",
        choices=[
            "max_compression",
            "junk_cpp",
            "junk_partitions",
            "flood_mode",
            "different_types",
        ],
        help="Set these checkboxes to UNCHECKED",
    )

    parser.add_argument(
        "--no-click",
        action="store_true",
        help="Launch app but do not modify any checkboxes (use defaults)",
    )

    parser.add_argument(
        "--show-defaults",
        action="store_true",
        help="Show default checkbox states and exit",
    )

    parser.add_argument(
        "--file-path",
        type=str,
        default=None,
        help="Full path to the file to paste in the file picker (default: Air Explorer example)",
    )

    args = parser.parse_args()

    # Show defaults and exit
    if args.show_defaults:
        print("\n" + "=" * 60)
        print("DEFAULT CHECKBOX STATES (when app first opens)")
        print("=" * 60)
        defaults = {
            "maximum_instruction_compression": False,
            "add_junk_cpp_functions": True,
            "add_junk_partitions": True,
            "enhanced_flood_mode": False,
            "add_different_types": False,
        }
        for name, state in defaults.items():
            state_str = "☑ CHECKED" if state else "☐ UNCHECKED"
            print(f"  {name:40s} {state_str}")
        print("=" * 60)
        return 0

    # Map short names to full names
    name_map = {
        "max_compression": "maximum_instruction_compression",
        "junk_cpp": "add_junk_cpp_functions",
        "junk_partitions": "add_junk_partitions",
        "flood_mode": "enhanced_flood_mode",
        "different_types": "add_different_types",
    }

    # Determine click mode
    if args.no_click:
        click_mode = "none"
    elif args.check or args.uncheck:
        # Build configuration dict
        config = {}

        if args.check:
            for short_name in args.check:
                full_name = name_map[short_name]
                config[full_name] = True

        if args.uncheck:
            for short_name in args.uncheck:
                full_name = name_map[short_name]
                config[full_name] = False

        click_mode = config
    else:
        # Default: set all to checked
        click_mode = "all"

    # Determine paths
    script_dir = Path(__file__).parent
    main_dir = script_dir.parent  # Go up one level to main directory
    yaml_path = main_dir / "manifest" / "packer_corpus.yaml"

    print(f"Script directory: {script_dir}")
    print(f"Main directory: {main_dir}")
    print(f"YAML path: {yaml_path}")
    if isinstance(click_mode, dict):
        print(f"Configuration mode: CUSTOM ({len(click_mode)} settings)")
    else:
        print(f"Configuration mode: {click_mode}")

    if not yaml_path.exists():
        print(f"\n[ERROR] YAML file not found at: {yaml_path}")
        print("[INFO] Please ensure packer_corpus.yaml is in the manifest/ directory")
        return 1

    # Create wrapper and run
    wrapper = AsmGuardWrapper(yaml_path, main_dir)
    success = wrapper.run(click_mode=click_mode, file_path=args.file_path)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
