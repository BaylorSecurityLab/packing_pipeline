"""
GUI Wrapper Runner
Scans benign_sources/x86 directory and runs appropriate GUI packers on compatible files
"""

import sys
from pathlib import Path
from typing import List, Dict, Optional, Any
import argparse

# Import the wrapper (adjust import path as needed)
from asm_guard_wrapper import AsmGuardWrapper


# Dictionary defining which file extensions each packer supports
# Default is ["*"] meaning all files
PACKER_FILE_SUPPORT: Dict[str, List[str]] = {
    "asm_guard": [".exe"],
    # Add more packers here as you implement them
    # "themida": [".exe", ".dll"],
    # "upx": [".exe", ".dll", ".sys"],
    # "vmprotect": [".exe", ".dll"],
    # "enigma": [".exe"],
    # "obsidium": [".exe", ".dll"],
    # "pecompact": [".exe", ".dll", ".scr", ".ocx"],
    # "mpress": ["*"],  # * means all files
}

# Packer-specific option mappings
# Each packer has its own set of options with short names -> full names
PACKER_OPTIONS: Dict[str, Dict[str, str]] = {
    "asm_guard": {
        "max_compression": "maximum_instruction_compression",
        "junk_cpp": "add_junk_cpp_functions",
        "junk_partitions": "add_junk_partitions",
        "flood_mode": "enhanced_flood_mode",
        "different_types": "add_different_types",
    },
    # Add more packers here:
    # "themida": {
    #     "vm_level": "virtualization_level",
    #     "anti_debug": "anti_debugging",
    #     "compress": "compression_enabled",
    # },
    # "vmprotect": {
    #     "mutation": "code_mutation",
    #     "virtualize": "virtualization",
    #     "ultra": "ultra_mode",
    # },
}

# Default checkbox/option states when packer opens (for state-aware toggling)
PACKER_DEFAULT_STATES: Dict[str, Dict[str, bool]] = {
    "asm_guard": {
        "maximum_instruction_compression": False,
        "add_junk_cpp_functions": True,
        "add_junk_partitions": True,
        "enhanced_flood_mode": False,
        "add_different_types": False,
    },
    # "themida": {
    #     "virtualization_level": False,
    #     "anti_debugging": True,
    #     "compression_enabled": True,
    # },
}

# Default packer to use
DEFAULT_PACKER = "asm_guard"


class GUIWrapperRunner:
    def __init__(self, source_dir: str, main_dir: str, yaml_path: str):
        """
        Initialize the GUI Wrapper Runner

        Args:
            source_dir: Directory containing files to pack (e.g., benign_sources/x86)
            main_dir: Main project directory
            yaml_path: Path to packer_corpus.yaml
        """
        self.source_dir = Path(source_dir)
        self.main_dir = Path(main_dir)
        self.yaml_path = Path(yaml_path)

        # Validate paths
        if not self.source_dir.exists():
            raise FileNotFoundError(f"Source directory not found: {self.source_dir}")
        if not self.yaml_path.exists():
            raise FileNotFoundError(f"YAML file not found: {self.yaml_path}")

    def get_supported_extensions(self, packer_name: str) -> List[str]:
        """
        Get list of supported file extensions for a packer

        Args:
            packer_name: Name of the packer

        Returns:
            List of extensions (e.g., ['.exe', '.dll']) or ['*'] for all
        """
        return PACKER_FILE_SUPPORT.get(packer_name, ["*"])

    def get_packer_options(self, packer_name: str) -> Dict[str, str]:
        """
        Get option name mappings for a packer

        Args:
            packer_name: Name of the packer

        Returns:
            Dict mapping short names to full names
        """
        return PACKER_OPTIONS.get(packer_name, {})

    def get_packer_defaults(self, packer_name: str) -> Dict[str, bool]:
        """
        Get default option states for a packer

        Args:
            packer_name: Name of the packer

        Returns:
            Dict mapping option names to default states
        """
        return PACKER_DEFAULT_STATES.get(packer_name, {})

    def is_file_supported(self, file_path: Path, packer_name: str) -> bool:
        """
        Check if a file is supported by the specified packer

        Args:
            file_path: Path to the file
            packer_name: Name of the packer

        Returns:
            bool: True if supported
        """
        supported = self.get_supported_extensions(packer_name)

        # "*" means all files are supported
        if "*" in supported:
            return True

        return file_path.suffix.lower() in [ext.lower() for ext in supported]

    def scan_source_directory(
        self, packer_name: str = DEFAULT_PACKER, recursive: bool = False
    ) -> List[Path]:
        """
        Scan source directory for files compatible with the specified packer

        Args:
            packer_name: Name of the packer to filter by
            recursive: Whether to scan subdirectories

        Returns:
            List of compatible file paths
        """
        print(f"\n[INFO] Scanning directory: {self.source_dir}")
        print(f"[INFO] Packer: {packer_name}")
        print(
            f"[INFO] Supported extensions: {self.get_supported_extensions(packer_name)}"
        )

        if recursive:
            all_files = list(self.source_dir.rglob("*"))
        else:
            all_files = list(self.source_dir.glob("*"))

        # Filter to only files (not directories)
        all_files = [f for f in all_files if f.is_file()]

        # Filter by supported extensions
        compatible_files = [
            f for f in all_files if self.is_file_supported(f, packer_name)
        ]

        print(f"[INFO] Total files found: {len(all_files)}")
        print(f"[INFO] Compatible files: {len(compatible_files)}")

        return compatible_files

    def build_packer_config(
        self,
        packer_name: str,
        check_options: Optional[List[str]] = None,
        uncheck_options: Optional[List[str]] = None,
    ) -> Optional[Dict[str, bool]]:
        """
        Build configuration dict for a packer from check/uncheck lists

        Args:
            packer_name: Name of the packer
            check_options: List of option short names to enable
            uncheck_options: List of option short names to disable

        Returns:
            Configuration dict or None if no options specified
        """
        if not check_options and not uncheck_options:
            return None

        name_map = self.get_packer_options(packer_name)
        if not name_map:
            print(f"[WARNING] No options defined for packer: {packer_name}")
            return None

        config = {}

        if check_options:
            for short_name in check_options:
                if short_name in name_map:
                    config[name_map[short_name]] = True
                else:
                    print(f"[WARNING] Unknown option '{short_name}' for {packer_name}")

        if uncheck_options:
            for short_name in uncheck_options:
                if short_name in name_map:
                    config[name_map[short_name]] = False
                else:
                    print(f"[WARNING] Unknown option '{short_name}' for {packer_name}")

        return config if config else None

    def run_asm_guard(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
    ) -> bool:
        """
        Run ASM Guard wrapper on a single file

        Args:
            file_path: Path to the file to pack
            packer_config: Optional checkbox configuration dict

        Returns:
            bool: True if successful
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = AsmGuardWrapper(str(self.yaml_path), str(self.main_dir))

            # Determine click mode
            if packer_config:
                click_mode = packer_config
            else:
                click_mode = "all"

            success = wrapper.run(click_mode=click_mode, file_path=str(file_path))
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            return False

    def run_packer(
        self,
        packer_name: str,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
    ) -> bool:
        """
        Run the specified packer on a file

        Args:
            packer_name: Name of the packer
            file_path: Path to the file
            packer_config: Packer-specific configuration

        Returns:
            bool: True if successful
        """
        packer_methods = {
            "asm_guard": self.run_asm_guard,
            # Add more packers here:
            # "themida": self.run_themida,
            # "vmprotect": self.run_vmprotect,
        }

        if packer_name not in packer_methods:
            print(f"[ERROR] Unknown packer: {packer_name}")
            print(f"[INFO] Available packers: {list(packer_methods.keys())}")
            return False

        return packer_methods[packer_name](file_path, packer_config=packer_config)

    def run_batch(
        self,
        packer_name: str = DEFAULT_PACKER,
        packer_config: Optional[Dict[str, bool]] = None,
        recursive: bool = False,
        dry_run: bool = False,
        limit: Optional[int] = None,
    ) -> Dict[str, bool]:
        """
        Run packer on all compatible files in the source directory

        Args:
            packer_name: Name of the packer to use
            packer_config: Packer-specific configuration
            recursive: Whether to scan subdirectories
            dry_run: If True, only list files without processing
            limit: Maximum number of files to process (None = all)

        Returns:
            Dict mapping filename to success status
        """
        # Get compatible files
        files = self.scan_source_directory(packer_name, recursive)

        if limit:
            files = files[:limit]
            print(f"[INFO] Limited to first {limit} files")

        if not files:
            print("[WARNING] No compatible files found!")
            return {}

        # Print file list
        print(f"\n{'=' * 60}")
        print(f"FILES TO PROCESS ({len(files)} files)")
        print(f"{'=' * 60}")
        for i, f in enumerate(files, 1):
            print(f"  {i:3d}. {f.name}")

        if dry_run:
            print("\n[DRY RUN] No files will be processed")
            return {f.name: None for f in files}

        # Process each file
        results = {}
        for i, file_path in enumerate(files, 1):
            print(f"\n[PROGRESS] Processing file {i}/{len(files)}")

            success = self.run_packer(
                packer_name,
                file_path,
                packer_config=packer_config,
            )
            results[file_path.name] = success

            # Brief pause between files
            if i < len(files):
                import time

                print("[INFO] Pausing before next file...")
                time.sleep(2)

        # Print summary
        self.print_summary(results)

        return results

    def print_summary(self, results: Dict[str, bool]):
        """Print processing summary"""
        print(f"\n{'=' * 60}")
        print("BATCH PROCESSING SUMMARY")
        print(f"{'=' * 60}")

        successful = sum(1 for v in results.values() if v is True)
        failed = sum(1 for v in results.values() if v is False)
        skipped = sum(1 for v in results.values() if v is None)
        total = len(results)

        for filename, status in results.items():
            if status is True:
                status_str = "✓ SUCCESS"
            elif status is False:
                status_str = "✗ FAILED"
            else:
                status_str = "○ SKIPPED"
            print(f"  {status_str}  {filename}")

        print(f"\n  Total:      {total}")
        print(f"  Successful: {successful}")
        print(f"  Failed:     {failed}")
        if skipped:
            print(f"  Skipped:    {skipped}")
        print(f"{'=' * 60}")


def build_packer_argparser(packer_name: str, parser: argparse.ArgumentParser):
    """
    Add packer-specific arguments to the parser

    Args:
        packer_name: Name of the packer
        parser: ArgumentParser to add arguments to
    """
    options = PACKER_OPTIONS.get(packer_name, {})
    defaults = PACKER_DEFAULT_STATES.get(packer_name, {})

    if not options:
        return

    option_choices = list(options.keys())

    parser.add_argument(
        "--check",
        nargs="+",
        choices=option_choices,
        metavar="OPTION",
        help=f"Set these options to ENABLED. Choices: {', '.join(option_choices)}",
    )

    parser.add_argument(
        "--uncheck",
        nargs="+",
        choices=option_choices,
        metavar="OPTION",
        help=f"Set these options to DISABLED. Choices: {', '.join(option_choices)}",
    )


def print_packer_info(packer_name: str):
    """Print detailed info about a packer's options"""
    print(f"\n{'=' * 60}")
    print(f"PACKER: {packer_name}")
    print(f"{'=' * 60}")

    extensions = PACKER_FILE_SUPPORT.get(packer_name, ["*"])
    ext_str = ", ".join(extensions) if extensions != ["*"] else "ALL FILES"
    print(f"\nSupported file types: {ext_str}")

    options = PACKER_OPTIONS.get(packer_name, {})
    defaults = PACKER_DEFAULT_STATES.get(packer_name, {})

    if options:
        print(f"\nAvailable options:")
        for short_name, full_name in options.items():
            default_state = defaults.get(full_name, False)
            state_str = "CHECKED" if default_state else "UNCHECKED"
            print(f"  {short_name:20s} -> {full_name}")
            print(f"  {'':20s}    Default: {state_str}")
    else:
        print("\nNo configurable options defined.")

    print(f"{'=' * 60}")


def main():
    parser = argparse.ArgumentParser(
        description="GUI Wrapper Runner - Batch process files with GUI packers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process all compatible files in x86 directory with ASM Guard
  python gui_wrapper_runner.py
  
  # Dry run - list files without processing
  python gui_wrapper_runner.py --dry-run
  
  # Process only first 5 files
  python gui_wrapper_runner.py --limit 5
  
  # Process single file
  python gui_wrapper_runner.py --file "C:\\path\\to\\file.exe"
  
  # Use custom options (packer-specific)
  python gui_wrapper_runner.py --check max_compression --uncheck junk_cpp
  
  # Scan subdirectories recursively
  python gui_wrapper_runner.py --recursive
  
  # Show info about a specific packer
  python gui_wrapper_runner.py --packer-info asm_guard

  # List all available packers
  python gui_wrapper_runner.py --list-packers
        """,
    )

    parser.add_argument(
        "--packer",
        type=str,
        default=DEFAULT_PACKER,
        choices=list(PACKER_FILE_SUPPORT.keys()),
        help=f"Packer to use (default: {DEFAULT_PACKER})",
    )

    parser.add_argument(
        "--source-dir",
        type=str,
        default="../benign_sources/x86",
        help="Source directory containing files",
    )

    parser.add_argument(
        "--file",
        type=str,
        default=None,
        help="Process a single file instead of batch",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List files without processing",
    )

    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Scan subdirectories recursively",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of files to process",
    )

    parser.add_argument(
        "--list-packers",
        action="store_true",
        help="List available packers and their supported file types",
    )

    parser.add_argument(
        "--packer-info",
        type=str,
        metavar="PACKER",
        help="Show detailed info about a specific packer's options",
    )

    # Add packer-specific options for default packer
    # (In a more advanced version, this could be dynamic based on --packer)
    build_packer_argparser(DEFAULT_PACKER, parser)

    args = parser.parse_args()

    # List packers and exit
    if args.list_packers:
        print("\n" + "=" * 60)
        print("AVAILABLE PACKERS AND SUPPORTED FILE TYPES")
        print("=" * 60)
        for packer, extensions in PACKER_FILE_SUPPORT.items():
            ext_str = ", ".join(extensions) if extensions != ["*"] else "ALL FILES"
            print(f"  {packer:20s} : {ext_str}")
        print("=" * 60)
        print("\nUse --packer-info <name> for detailed options")
        return 0

    # Show packer info and exit
    if args.packer_info:
        if args.packer_info not in PACKER_FILE_SUPPORT:
            print(f"[ERROR] Unknown packer: {args.packer_info}")
            print(f"[INFO] Available: {list(PACKER_FILE_SUPPORT.keys())}")
            return 1
        print_packer_info(args.packer_info)
        return 0

    # Determine paths
    script_dir = Path(__file__).parent
    main_dir = script_dir.parent  # Go up one level to main directory

    # Source directory
    if args.source_dir:
        source_dir = Path(args.source_dir)
    else:
        source_dir = script_dir.parent / "benign_sources" / "x86"

    yaml_path = main_dir / "manifest" / "packer_corpus.yaml"

    print(f"Script directory: {script_dir}")
    print(f"Main directory: {main_dir}")
    print(f"Source directory: {source_dir}")
    print(f"YAML path: {yaml_path}")

    try:
        runner = GUIWrapperRunner(
            source_dir=str(source_dir),
            main_dir=str(main_dir),
            yaml_path=str(yaml_path),
        )

        # Build packer-specific config from args
        packer_config = runner.build_packer_config(
            args.packer,
            check_options=args.check,
            uncheck_options=args.uncheck,
        )

        # Single file mode
        if args.file:
            file_path = Path(args.file)
            if not file_path.exists():
                print(f"[ERROR] File not found: {file_path}")
                return 1

            success = runner.run_packer(
                args.packer,
                file_path,
                packer_config=packer_config,
            )
            return 0 if success else 1

        # Batch mode
        results = runner.run_batch(
            packer_name=args.packer,
            packer_config=packer_config,
            recursive=args.recursive,
            dry_run=args.dry_run,
            limit=args.limit,
        )

        # Return non-zero if any failed
        if any(v is False for v in results.values()):
            return 1
        return 0

    except FileNotFoundError as e:
        print(f"[ERROR] {e}")
        return 1
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
