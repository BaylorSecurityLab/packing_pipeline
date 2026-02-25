"""
GUI Wrapper Runner
Scans benign_sources/x86 directory and runs appropriate GUI packers on compatible files
"""

import sys
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Set
import argparse

from asm_guard import AsmGuard
from acprotect import ACProtect
from alienyze import Alienyze
from mew import Mew
from packman import Packman
from rlpack import RLPack
from ped import PEDiminisher
from shrinker import Shrinker
from telock import Telock
from upx_scrambler import UpxScrambler
from wupack import WinUpack

PACKER_FILE_SUPPORT: Dict[str, List[str]] = {
    "asm_guard": [".exe"],
    "acprotect": [".exe"],
    "alienyze": [".exe"],
    "mew": [".exe"],
    "packman": [".exe"],
    "rlpack": [".exe"],
    "pe_diminisher": [".exe"],
    "shrinker": [".exe"],
    "telock": [".exe"],
    "upx_scrambler": [".exe"],
    "winupack": [".exe"],
}

PACKER_OPTIONS: Dict[str, Dict[str, str]] = {
    "asm_guard": {
        "max_compression": "maximum_instruction_compression",
        "junk_cpp": "add_junk_cpp_functions",
        "junk_partitions": "add_junk_partitions",
        "flood_mode": "enhanced_flood_mode",
        "different_types": "add_different_types",
    },
}


PACKER_DEFAULT_STATES: Dict[str, Dict[str, bool]] = {
    "asm_guard": {
        "maximum_instruction_compression": False,
        "add_junk_cpp_functions": True,
        "add_junk_partitions": True,
        "enhanced_flood_mode": False,
        "add_different_types": False,
    },
    "acprotect": {},
    "alienyze": {},
    "mew": {},
    "packman": {},
    "rlpack": {},
    "pe_diminisher": {},
    "shrinker": {},
    "telock": {},
    "upx_scrambler": {},
    "winupack": {},
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
        self.source_dir = Path(source_dir).resolve()
        self.main_dir = Path(main_dir).resolve()
        self.yaml_path = Path(yaml_path).resolve()

        # Validate paths
        if not self.source_dir.exists():
            raise FileNotFoundError(f"Source directory not found: {self.source_dir}")
        if not self.yaml_path.exists():
            raise FileNotFoundError(f"YAML file not found: {self.yaml_path}")

    def get_supported_extensions(self, packer_name: str) -> List[str]:
        """Get list of supported file extensions for a packer"""
        return PACKER_FILE_SUPPORT.get(packer_name, ["*"])

    def get_packer_options(self, packer_name: str) -> Dict[str, str]:
        """Get option name mappings for a packer"""
        return PACKER_OPTIONS.get(packer_name, {})

    def get_packer_defaults(self, packer_name: str) -> Dict[str, bool]:
        """Get default option states for a packer"""
        return PACKER_DEFAULT_STATES.get(packer_name, {})

    def get_output_directory(self, packer_name: str) -> Path:
        """
        Get the output directory for a packer's packed files

        Args:
            packer_name: Name of the packer

        Returns:
            Path: Output directory (e.g., main_dir/packed_sources/asm_guard)
        """
        output_dir = self.main_dir / "packed_sources" / packer_name
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    def get_temp_directory(self, output_dir: Path) -> Path:
        """
        Get the temp directory inside the output directory for working copies

        Args:
            output_dir: The output directory

        Returns:
            Path: Temp directory (e.g., output_dir/temp)
        """
        temp_dir = output_dir / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        return temp_dir

    def copy_to_temp(self, file_path: Path, output_dir: Path) -> Path:
        """
        Copy input file to temp directory inside output directory

        Args:
            file_path: Path to the original input file
            output_dir: The output directory

        Returns:
            Path: Path to the copied file in temp directory
        """
        temp_dir = self.get_temp_directory(output_dir)
        temp_file = temp_dir / file_path.name

        print(f"[INFO] Copying input file to temp directory...")
        print(f"[INFO]   Source: {file_path}")
        print(f"[INFO]   Dest:   {temp_file}")

        shutil.copy2(file_path, temp_file)
        return temp_file

    def is_file_supported(self, file_path: Path, packer_name: str) -> bool:
        """Check if a file is supported by the specified packer"""
        supported = self.get_supported_extensions(packer_name)

        # "*" means all files are supported
        if "*" in supported:
            return True

        return file_path.suffix.lower() in [ext.lower() for ext in supported]

    # ========== DIRECTORY SNAPSHOT & CLEANUP ==========

    def snapshot_directory(self, directory: Path, recursive: bool = False) -> Set[Path]:
        """
        Take a snapshot of all files in a directory

        Args:
            directory: Directory to snapshot
            recursive: Whether to include subdirectories

        Returns:
            Set of absolute file paths
        """
        directory = Path(directory).resolve()

        if recursive:
            files = set(f.resolve() for f in directory.rglob("*") if f.is_file())
        else:
            files = set(f.resolve() for f in directory.glob("*") if f.is_file())

        print(f"[SNAPSHOT] Captured {len(files)} files in {directory}")
        return files

    # ========== SCANNING & PACKING ==========

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
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run ASM Guard wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = AsmGuard(str(self.yaml_path), str(self.main_dir))

            # Determine click mode - default to "all" (check all boxes)
            click_mode = packer_config if packer_config else "all"

            # Use packer-specific output directory if not specified
            if output_dir is None:
                output_dir = self.get_output_directory("asm_guard")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=click_mode,
                file_path=str(file_path.resolve()),  # Always use absolute path
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_acprotect(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run ACProtect wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = ACProtect(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("acprotect")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_alienyze(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Alienyze wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = Alienyze(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("alienyze")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_mew(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run MEW wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = Mew(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("mew")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_packman(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Packman wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = Packman(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("packman")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_rlpack(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run RLPack wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = RLPack(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("rlpack")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_pe_diminisher(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run PE Diminisher wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = PEDiminisher(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("pe_diminisher")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_shrinker(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run shrinker wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = Shrinker(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("shrinker")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_telock(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run tElock wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = Telock(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("telock")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_upx_scrambler(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run UPX Scrambler wrapper on a single file.
        The wrapper handles UPX pre-packing internally via packer_runner.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = UpxScrambler(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("upx_scrambler")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_winupack(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run WinUpack wrapper on a single file.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = WinUpack(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("winupack")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_packer(
        self,
        packer_name: str,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run the specified packer on a file

        The input file is first copied to a temp directory inside the output
        directory, and the packer operates on that copy.
        """
        packer_methods = {
            "asm_guard": self.run_asm_guard,
            "acprotect": self.run_acprotect,
            "alienyze": self.run_alienyze,
            "mew": self.run_mew,
            "packman": self.run_packman,
            "rlpack": self.run_rlpack,
            "pe_diminisher": self.run_pe_diminisher,
            "shrinker": self.run_shrinker,
            "telock": self.run_telock,
            "upx_scrambler": self.run_upx_scrambler,
            "winupack": self.run_winupack,
        }

        if packer_name not in packer_methods:
            print(f"[ERROR] Unknown packer: {packer_name}")
            print(f"[INFO] Available packers: {list(packer_methods.keys())}")
            return False

        if output_dir is None:
            output_dir = self.get_output_directory(packer_name)

        # Copy input file to temp directory inside output directory
        temp_file = self.copy_to_temp(file_path, output_dir)

        return packer_methods[packer_name](
            temp_file,  # Use the temp copy instead of the original
            packer_config=packer_config,
            output_dir=output_dir,
        )

    def is_already_packed(self, file_path: Path, packer_name: str) -> bool:
        """
        Check if a file has already been packed (output exists in packed_sources)
        Uses fuzzy matching - checks if any file contains the original stem
        """
        output_dir = self.get_output_directory(packer_name)
        stem = file_path.stem.lower()

        # Check if any file in output_dir contains the original filename stem
        for existing_file in output_dir.glob("*"):
            if existing_file.is_file() and stem in existing_file.stem.lower():
                return True
        return False

    def run_batch(
        self,
        packer_name: str = DEFAULT_PACKER,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
        recursive: bool = False,
        dry_run: bool = False,
        limit: Optional[int] = None,
        skip_existing: bool = True,
    ) -> Dict[str, bool]:
        """
        Run packer on all compatible files in the source directory

        Args:
            packer_name: Name of the packer to use
            packer_config: Packer-specific configuration
            output_dir: Directory to save packed files (if None, uses default)
            recursive: Whether to scan subdirectories
            dry_run: If True, only list files without processing
            limit: Maximum number of files to process (None = all)
            skip_existing: If True, skip files that are already packed

        Returns:
            Dict mapping filename to success status
        """
        # Get compatible files
        files = self.scan_source_directory(packer_name, recursive)

        if not files:
            print("[WARNING] No compatible files found!")
            return {}

        # Use packer-specific output directory if not specified
        if output_dir is None:
            output_dir = self.get_output_directory(packer_name)

        # Filter out already packed files
        if skip_existing:
            files_to_process = []
            skipped_files = []

            for f in files:
                if self.is_already_packed(f, packer_name):
                    skipped_files.append(f)
                else:
                    files_to_process.append(f)

            if skipped_files:
                print(f"\n[INFO] Skipping {len(skipped_files)} already packed files:")
                for f in skipped_files[:10]:
                    print(f"  - {f.name}")
                if len(skipped_files) > 10:
                    print(f"  ... and {len(skipped_files) - 10} more")

            files = files_to_process

        if limit:
            files = files[:limit]
            print(f"[INFO] Limited to first {limit} files")

        if not files:
            print("[INFO] All files already packed! Nothing to do.")
            return {}

        # Print file list
        print(f"\n{'=' * 60}")
        print(f"FILES TO PROCESS ({len(files)} files)")
        print(f"{'=' * 60}")
        print(f"[INFO] Output directory: {output_dir}")
        for i, f in enumerate(files, 1):
            print(f"  {i:3d}. {f.name}")

        if dry_run:
            print("\n[DRY RUN] No files will be processed")
            return {f.name: None for f in files}

        # ========== SNAPSHOT SOURCE DIRECTORY BEFORE PROCESSING ==========
        print("\n[INFO] Taking snapshot of source directory before processing...")
        original_files = self.snapshot_directory(self.source_dir, recursive=recursive)

        # Process each file
        results = {}
        for i, file_path in enumerate(files, 1):
            print(f"\n[PROGRESS] Processing file {i}/{len(files)}")

            success = self.run_packer(
                packer_name,
                file_path,
                packer_config=packer_config,
                output_dir=output_dir,
            )
            results[file_path.name] = success

            # Brief pause between files
            if i < len(files):
                import time

                print("[INFO] Pausing before next file...")
                time.sleep(2)

        # ========== DELETE TEMP DIRECTORY ==========
        temp_dir = self.get_temp_directory(output_dir)
        if temp_dir.exists():
            import shutil

            shutil.rmtree(temp_dir, ignore_errors=True)
            print(f"[INFO] Deleted temp directory: {temp_dir}")

        # Print summary
        self.print_summary(results, skipped_files if skip_existing else [])

        return results

    def print_summary(self, results: Dict[str, bool], skipped_files: List[Path] = None):
        """Print processing summary"""
        print(f"\n{'=' * 60}")
        print("BATCH PROCESSING SUMMARY")
        print(f"{'=' * 60}")

        successful = sum(1 for v in results.values() if v is True)
        failed = sum(1 for v in results.values() if v is False)
        dry_run_skipped = sum(1 for v in results.values() if v is None)
        already_packed = len(skipped_files) if skipped_files else 0
        total = len(results) + already_packed

        for filename, status in results.items():
            if status is True:
                status_str = "✓ SUCCESS"
            elif status is False:
                status_str = "✗ FAILED"
            else:
                status_str = "○ DRY RUN"
            print(f"  {status_str}  {filename}")

        # List skipped (already packed) files
        if skipped_files:
            print("\n  SKIPPED (already packed):")
            for f in skipped_files:
                print(f"    ○ {f.name}")

        # List failed files explicitly
        failed_files = [name for name, status in results.items() if status is False]
        if failed_files:
            print("\n  FAILED FILES:")
            for name in failed_files:
                print(f"    ✗ {name}")

        print(f"\n  Total:         {total}")
        print(f"  Successful:    {successful}")
        print(f"  Failed:        {failed}")
        print(f"  Already packed:{already_packed}")
        if dry_run_skipped:
            print(f"  Dry run:       {dry_run_skipped}")
        print(f"{'=' * 60}")


def build_packer_argparser(packer_name: str, parser: argparse.ArgumentParser):
    """Add packer-specific arguments to the parser"""
    options = PACKER_OPTIONS.get(packer_name, {})

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
        print("\nAvailable options:")
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
  # Output goes to ../packed_sources/asm_guard/
  python gui_wrapper_runner.py
  
  # Dry run - list files without processing
  python gui_wrapper_runner.py --dry-run
  
  # Process only first 5 files
  python gui_wrapper_runner.py --limit 5
  
  # Process single file
  python gui_wrapper_runner.py --file "C:\\path\\to\\file.exe"
  
  # Use custom options (packer-specific)
  python gui_wrapper_runner.py --check max_compression --uncheck junk_cpp
  
  # Specify custom output directory
  python gui_wrapper_runner.py --output-dir "C:\\custom\\output"
  
  # Scan subdirectories recursively
  python gui_wrapper_runner.py --recursive
  
  # Show info about a specific packer
  python gui_wrapper_runner.py --packer-info asm_guard

  # List all available packers
  python gui_wrapper_runner.py --list-packers
  
  # Re-process all files (don't skip existing)
  python gui_wrapper_runner.py --no-skip
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
        "--output-dir",
        type=str,
        default=None,
        help="Directory to save packed files (default: ../packed_sources/<packer>/)",
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

    parser.add_argument(
        "--no-skip",
        action="store_true",
        help="Process all files even if already packed",
    )

    # Add packer-specific options for default packer
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
        print("\nUse --packer-info <n> for detailed options")
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
    script_dir = Path(__file__).parent.resolve()
    main_dir = script_dir.parent

    # Source directory - always resolve to absolute
    source_dir = (
        Path(args.source_dir).resolve()
        if Path(args.source_dir).is_absolute()
        else (script_dir / args.source_dir).resolve()
    )

    # Output directory (if specified via CLI)
    output_dir = Path(args.output_dir).resolve() if args.output_dir else None

    yaml_path = main_dir / "manifest" / "packer_corpus.yaml"

    print(f"Script directory: {script_dir}")
    print(f"Main directory: {main_dir}")
    print(f"Source directory: {source_dir}")
    print(f"YAML path: {yaml_path}")
    if output_dir:
        print(f"Output directory (CLI): {output_dir}")
    else:
        print(f"Output directory: ../packed_sources/{args.packer}/ (default)")

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
            file_path = Path(args.file).resolve()
            if not file_path.exists():
                print(f"[ERROR] File not found: {file_path}")
                return 1

            # Snapshot before single file
            original_files = runner.snapshot_directory(file_path.parent)

            success = runner.run_packer(
                args.packer,
                file_path,
                packer_config=packer_config,
                output_dir=output_dir,
            )

            # Cleanup after single file
            runner.cleanup_new_files(file_path.parent, original_files)

            return 0 if success else 1

        # Batch mode
        results = runner.run_batch(
            packer_name=args.packer,
            packer_config=packer_config,
            output_dir=output_dir,
            recursive=args.recursive,
            dry_run=args.dry_run,
            limit=args.limit,
            skip_existing=not args.no_skip,
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
