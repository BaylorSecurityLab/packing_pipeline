"""
ASM Guard GUI Automation Wrapper - Using Base GUI Wrapper
"""

import sys
import time
from pathlib import Path
from base_gui import BaseGUI


class AsmGuard(BaseGUI):
    """
    Wrapper for ASM Guard GUI automation using the BaseGUIWrapper.

    This implementation provides:
    - Checkbox state management
    - Protection process automation
    - File cleanup (*.asmg files)
    - State-aware checkbox configuration
    """

    # ASM Guard specific checkbox defaults
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

    def __init__(self, yaml_path, main_dir):
        """Initialize ASM Guard wrapper with checkbox states"""
        super().__init__(yaml_path, main_dir)
        self.checkbox_states = self.DEFAULT_CHECKBOX_STATES.copy()

    def get_packer_name(self):
        """Return the packer name for YAML lookup"""
        return "asm_guard"

    # ========== CHECKBOX MANAGEMENT ==========

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

    def toggle_checkbox(self, checkbox_name):
        """
        Toggle any checkbox by name.

        Args:
            checkbox_name: Full checkbox name (e.g., 'maximum_instruction_compression')
                          or short name (e.g., 'max_compression')

        Returns:
            bool: True if successful
        """
        # Resolve short name to full name if needed
        full_name = self.NAME_MAP.get(checkbox_name, checkbox_name)

        if full_name not in self.CHECKBOX_POSITIONS:
            print(f"[ERROR] Unknown checkbox: {checkbox_name}")
            return False

        x_percent, y_percent = self.CHECKBOX_POSITIONS[full_name]
        description = full_name.replace("_", " ").title()

        # Use custom click logic for checkbox state tracking
        return self._click_checkbox(x_percent, y_percent, description, full_name)

    def _click_checkbox(self, x_percent, y_percent, description, checkbox_name):
        """
        Click a checkbox and track its state.

        Args:
            x_percent: X position as percentage
            y_percent: Y position as percentage
            description: Description of the checkbox
            checkbox_name: Name of the checkbox for state tracking

        Returns:
            bool: True if successful
        """
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

            print(f"\n[ACTION] Clicking: {description}")
            print(f"  Position: {x_percent * 100:.1f}% x, {y_percent * 100:.1f}% y")
            print(f"  Client area: {client_width}x{client_height}")
            print(f"  Absolute coords: ({abs_x}, {abs_y})")

            old_state = self.checkbox_states[checkbox_name]
            print(f"  Current state: {'☑ CHECKED' if old_state else '☐ UNCHECKED'}")

            pyautogui.click(abs_x, abs_y)
            time.sleep(0.1)

            # Toggle state
            self.checkbox_states[checkbox_name] = not self.checkbox_states[
                checkbox_name
            ]
            new_state = self.checkbox_states[checkbox_name]
            print(f"  New state: {'☑ CHECKED' if new_state else '☐ UNCHECKED'}")

            print("[+] Click successful")
            return True

        except Exception as e:
            print(f"[ERROR] Click failed: {e}")
            return False

    def ensure_checkbox_state(self, checkbox_name, desired_state):
        """
        Ensure a checkbox is in the desired state.

        Args:
            checkbox_name: Checkbox name (short or full)
            desired_state: True for checked, False for unchecked

        Returns:
            bool: True if successful
        """
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
        """
        Set multiple checkboxes to specific states.

        Args:
            config: Dict mapping checkbox names to desired states

        Returns:
            dict: Results of configuration
        """
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

    # ========== UI INTERACTION METHODS ==========

    def click_folder_finder(self):
        """Click the file finder button"""
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

    # ========== PROTECTION PROCESS METHODS ==========
    def cleanup_asmg_files(self, directory):
        """
        Delete .asmg files created by ASM Guard.

        Args:
            directory: Directory to clean up

        Returns:
            list: List of deleted file paths
        """
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
        Clean up after a failed or timed out protection attempt.

        Args:
            input_file_path: Path to the input file
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

    # ========== MAIN EXECUTION ==========

    def run(self, click_mode="all", file_path=None, output_dir=None):
        """
        Main execution flow for ASM Guard automation.

        Args:
            click_mode: 'all', 'none', or dict with desired checkbox states
            file_path: Path to the input file
            output_dir: Directory to copy final output to (optional)

        Returns:
            bool: True if successful
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
                import pygetwindow as gw

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
            protected_file = self.wait_for_protection_complete(str(input_file))

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

    def wait_for_protection_complete(self, input_file_path, check_interval=15):
        """
        Wait for the protection process to complete with stability verification.
        Targets the '{stem}_protected{suffix}' file naming convention.
        """
        timeout = self.EXTRA_LONG_TIMEOUT
        input_path = Path(input_file_path)

        # Define the expected output path
        protected_name = f"{input_path.stem}_protected{input_path.suffix}"
        protected_path = input_path.parent / protected_name

        # Stability settings
        required_stable_checks = 5
        stable_count = 0
        check_interval = self.LONG_TIMEOUT

        print("\n[INFO] Waiting for protection to complete...")
        print(f"[INFO] Watching for: {protected_path}")
        print(
            f"[INFO] Stability Requirement: {required_stable_checks} consecutive unlocked checks"
        )
        print(f"[INFO] Interval: {check_interval}s | Timeout: {timeout}s")

        start_time = time.time()

        # Initial buffer to let the packer start creating the new file
        time.sleep(10)

        while time.time() - start_time < timeout:
            elapsed = int(time.time() - start_time)

            if protected_path.exists():
                current_size = protected_path.stat().st_size

                if self.is_file_locked(str(protected_path)):
                    # File is still being written to; reset counter
                    if stable_count > 0:
                        print(
                            f"  [{elapsed}s] Lock reappeared! Resetting stability counter."
                        )

                    stable_count = 0
                    print(f"  [{elapsed}s] Writing... {current_size:,} bytes")
                else:
                    # File is unlocked; increment stability counter
                    stable_count += 1
                    print(
                        f"  [{elapsed}s] File unlocked. Verification {stable_count}/{required_stable_checks}..."
                    )

                    if stable_count >= required_stable_checks:
                        print(
                            f"\n[SUCCESS] Protection complete and verified stable! ({elapsed}s)"
                        )
                        print(f"[INFO] Output file: {protected_path}")
                        print(f"[INFO] Final size: {current_size:,} bytes")
                        return str(protected_path)
            else:
                # File hasn't been created yet
                print(
                    f"  [{elapsed}s] Processing (waiting for file creation)...",
                    end="\r",
                )
                stable_count = 0

            time.sleep(check_interval)

        # Timeout reached
        print(f"\n[ERROR] Timeout after {timeout}s waiting for stable protected file")
        return None


def main():
    """Entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="ASM Guard GUI Automation Wrapper with State-Aware Checkbox Control",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python asm_guard.py
  python asm_guard.py --check max_compression flood_mode
  python asm_guard.py --uncheck junk_cpp junk_partitions
  python asm_guard.py --check max_compression --uncheck junk_cpp
  python asm_guard.py --no-click
  python asm_guard.py --show-defaults
  python asm_guard.py --file-path "C:\\path\\to\\your\\file.exe"

Available checkbox names:
  - max_compression, junk_cpp, junk_partitions, flood_mode, different_types
        """,
    )

    checkbox_choices = list(AsmGuard.NAME_MAP.keys())

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
        for name, state in AsmGuard.DEFAULT_CHECKBOX_STATES.items():
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
                config[AsmGuard.NAME_MAP[short_name]] = True
        if args.uncheck:
            for short_name in args.uncheck:
                config[AsmGuard.NAME_MAP[short_name]] = False
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

    wrapper = AsmGuard(yaml_path, main_dir)
    success = wrapper.run(
        click_mode=click_mode, file_path=args.file_path, output_dir=args.output_dir
    )

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
