"""
GUI Wrapper Runner
Scans benign_sources/x86 directory and runs appropriate GUI packers on compatible files
"""

import sys
import os
import re
import shutil
import time
import threading
import queue
from pathlib import Path
from typing import List, Dict, Optional, Set
import argparse
import yaml
from tqdm import tqdm

# Reuse the packer_runner filename sanitizer (spaces -> underscores, non-ASCII
# -> hashed) so GUI packers never receive a name with spaces/unicode they choke
# on. packer_runner lives in ../utils.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "utils"))
from packer_runner import sanitize_filename


# Set on Ctrl+C so worker threads stop pulling new packers from the queue.
# In-flight workers are daemon threads, so they die when the process exits.
_ABORT = threading.Event()


# Global verbosity flag. When False (default) we only show progress bars,
# per-packer failures, and the final report; the wrappers' verbose [INFO]
# chatter is routed to per-sample log files. When True everything prints to
# the console (interleaved under parallelism — intended for debugging).
VERBOSE = False

# The real stdout, captured before the thread-local router is installed. tqdm
# bars, result lines, and the final report are written here so they stay clean
# regardless of any per-thread stdout redirection.
_REAL_STDOUT = sys.stdout

# Force UTF-8 with replacement so progress bars / box-drawing chars / check marks
# never crash with UnicodeEncodeError on a legacy cp1252 Windows console.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def vlog(msg):
    """Print only when --verbose is set (uses tqdm.write so bars stay intact)."""
    if VERBOSE:
        tqdm.write(msg, file=_REAL_STDOUT)


class _StdoutRouter:
    """Thread-aware stdout proxy.

    Each worker thread can redirect *its own* prints to a per-task file via
    set_target(); the main thread (and any thread without a target) keeps
    writing to the real stdout. This lets the noisy wrappers log to files while
    the progress bars and report stay readable on the console, without the
    threads clobbering each other's output.
    """

    def __init__(self, real):
        self._real = real
        self._local = threading.local()

    def set_target(self, fileobj):
        self._local.target = fileobj

    def reset(self):
        self._local.target = None

    def _stream(self):
        return getattr(self._local, "target", None) or self._real

    def write(self, s):
        self._stream().write(s)

    def flush(self):
        self._stream().flush()

    def isatty(self):
        return self._real.isatty()

from fsg import FSG
from asm_guard import AsmGuard
from alienyze_protector import AlienyzeProtector
from mew import Mew
from packman import Packman
from rlpack import RLPack
from ped import PEDiminisher
from shrinker import Shrinker
from upx_scrambler import (
    UpxScrambler304,
    UpxScrambler306,
    UpxScramblerRC1,
    UpxScramblerRC103,
    UpxScramblerRC105,
    UpxScramblerRC1b10,
)
from jdpack import JDPack
from npack import NPack
from nspack import NSpack
from wupack import WinUpack
from yoda_crypter import YodaCrypter
from yoda_crypter_v12 import YodaCrypterV12
from yoda_protector_v10 import YodaProtectorV10
from yoda_protector_v1012 import YodaProtectorV1012
from yoda_protector_v102 import YodaProtectorV102
from yoda_protector_v1032 import YodaProtectorV1032
from yoda_protector_v1033 import YodaProtectorV1033
from acprotect import ACProtect
from telock import Telock
from pelock import PELock
from armadillo import Armadillo
from pecompact import PECompact
from themida_gui import ThemidaGUI
from obsidium_v1880_gui import ObsidiumV1880GUI
from obsidium_v152_gui import ObsidiumV152GUI
from xpa_v143_gui import XPAV143GUI
from zprotect_gui import ZProtectGUI

PACKER_FILE_SUPPORT: Dict[str, List[str]] = {
    "npack_v1.1": [".exe"],
    "nspack_v3.7": [".exe"],
    "jdpack_v1.00": [".exe"],
    "fsg_v1.0": [".exe"],
    "asm_guard": [".exe"],
    "alienyze_protector": [".exe"],
    "mew": [".exe"],
    "packman": [".exe"],
    "rlpack": [".exe"],
    "pe_diminisher": [".exe"],
    "shrinker_v3.4_demo": [".exe"],
    "upx_scrambler": [".exe"],
    "upx_scrambler_306": [".exe"],
    "upx_scrambler_rc1": [".exe"],
    "upx_scrambler_rc103": [".exe"],
    "upx_scrambler_rc105": [".exe"],
    "upx_scrambler_rc1b10": [".exe"],
    "winupack": [".exe"],
    "yoda_crypter_v1.3": [".exe"],
    "yoda_crypter_v1.2": [".exe"],
    "yoda_protector_v1.0": [".exe"],
    "yoda_protector_v1.01.2": [".exe"],
    "yoda_protector_v1.02": [".exe"],
    "yoda_protector_v1.03.2": [".exe"],
    "yoda_protector_v1.03.3": [".exe"],
    "acprotect_std": [".exe"],
    "telock_v0.98": [".exe"],
    "pelock_v2.40": [".exe"],
    "armadillo": [".exe"],
    "pecompact_v1.84": [".exe"],
    "themida_v3.2.4.34": [".exe"],
    "obsidium_v1.8.8": [".exe"],
    "obsidium_v1.5.2": [".exe"],
    "xpa_v1.43": [".exe"],
    "zprotect": [".exe"],
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
    "npack_v1.1": {},
    "nspack_v3.7": {},
    "jdpack_v1.00": {},
    "fsg_v1.0": {},
    "alienyze_protector": {},
    "mew": {},
    "packman": {},
    "rlpack": {},
    "pe_diminisher": {},
    "shrinker_v3.4_demo": {},
    "upx_scrambler": {},
    "upx_scrambler_306": {},
    "upx_scrambler_rc1": {},
    "upx_scrambler_rc103": {},
    "upx_scrambler_rc105": {},
    "upx_scrambler_rc1b10": {},
    "winupack": {},
    "yoda_crypter_v1.3": {},
    "yoda_crypter_v1.2": {},
    "yoda_protector_v1.0": {},
    "yoda_protector_v1.01.2": {},
    "yoda_protector_v1.02": {},
    "yoda_protector_v1.03.2": {},
    "yoda_protector_v1.03.3": {},
    "acprotect_std": {},
    "telock_v0.98": {},
    "pelock_v2.40": {},
    "armadillo": {},
    "pecompact_v1.84": {},
    "themida_v3.2.4.34": {},
    "obsidium_v1.8.8": {},
    "obsidium_v1.5.2": {},
    "xpa_v1.43": {},
    "zprotect": {},
}

# Default packer to use
DEFAULT_PACKER = "all"


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

        # Load YAML config for version lookups
        with open(self.yaml_path, "r") as f:
            self._config = yaml.safe_load(f)
        self._version_map = {}
        for defn in self._config.get("definitions", []):
            name = defn.get("packer_name", "").lower()
            version = defn.get("version", "unknown")
            self._version_map[name] = version

        # Per-packer stats collected for the final report (used in 'all' mode).
        self.report_rows: List[Dict] = []

    def _record_report_row(
        self,
        packer_name: str,
        packed: int,
        skipped: int,
        failed: int,
        total: int,
        note: str = "",
    ):
        """Append one packer's stats to the aggregated final report."""
        self.report_rows.append(
            {
                "packer": packer_name,
                "packed": packed,
                "skipped": skipped,
                "failed": failed,
                "total": total,
                "note": note,
            }
        )

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
            Path: Output directory (e.g., main_dir/packed_sources/asm_guard_2.9.4)
        """
        version = self._version_map.get(packer_name.lower(), "unknown")
        # Sanitize version for filesystem (replace spaces, parens, etc.)
        safe_version = re.sub(r'[^\w\.\-]', '_', version).strip('_')
        dir_name = f"{packer_name}_{safe_version}"
        output_dir = self.main_dir / "packed_sources" / dir_name
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
        # Sanitize the working-copy name: many GUI packers reject spaces /
        # non-ASCII in the path, surfacing as "invalid name" errors. The packed
        # output then inherits this safe name.
        temp_file = temp_dir / sanitize_filename(file_path.name)

        print("[INFO] Copying input file to temp directory...")
        print(f"[INFO]   Source: {file_path}")
        print(f"[INFO]   Dest:   {temp_file}")

        try:
            shutil.copy2(file_path, temp_file)
        except OSError as e:
            if e.winerror in (32, 1224):
                # WinError 1224: file has a user-mapped section open (memory-mapped by OS).
                # WinError 32: sharing violation (file locked by another process).
                # Fall back to raw binary copy which bypasses this restriction.
                print(f"[WARNING] shutil.copy2 blocked (WinError {e.winerror}); using raw binary copy.")
                with open(file_path, "rb") as src, open(temp_file, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                shutil.copystat(file_path, temp_file)
            else:
                raise

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
        self, packer_name: str = "asm_guard", recursive: bool = False
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

    def run_npack(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run nPack wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = NPack(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("npack_v1.1")

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

    def run_nspack(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run NSpack wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = NSpack(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("nspack_v3.7")

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

    def run_jdpack(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run JDPack wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = JDPack(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("jdpack_v1.00")

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

    def run_fsg(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run FSG wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = FSG(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("fsg_v1.0")

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

    def run_alienyze_protector(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Alienyze Protector wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = AlienyzeProtector(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("alienyze_protector")

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
                output_dir = self.get_output_directory("shrinker_v3.4_demo")

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
            wrapper = UpxScrambler304(str(self.yaml_path), str(self.main_dir))

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

    def run_upx_scrambler_306(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """Run UPX Scrambler 3.06 wrapper on a single file."""
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = UpxScrambler306(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("upx_scrambler_306")

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

    def run_upx_scrambler_rc1(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """Run UPX Scrambler RC1 wrapper on a single file."""
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = UpxScramblerRC1(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("upx_scrambler_rc1")

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

    def run_upx_scrambler_rc103(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """Run UPX Scrambler RC1.03 wrapper on a single file."""
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = UpxScramblerRC103(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("upx_scrambler_rc103")

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

    def run_upx_scrambler_rc105(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """Run UPX Scrambler RC1.05 wrapper on a single file."""
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = UpxScramblerRC105(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("upx_scrambler_rc105")

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

    def run_upx_scrambler_rc1b10(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """Run UPX Scrambler RC1b10 wrapper on a single file."""
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = UpxScramblerRC1b10(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("upx_scrambler_rc1b10")

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

    def run_yoda_crypter(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Yoda's Crypter wrapper on a single file.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = YodaCrypter(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("yoda_crypter_v1.3")

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

    def run_yoda_crypter_v12(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Yoda's Crypter v1.2 wrapper on a single file.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = YodaCrypterV12(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("yoda_crypter_v1.2")

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

    def run_yoda_protector_v10(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Yoda's Protector v1.0 wrapper on a single file.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = YodaProtectorV10(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("yoda_protector_v1.0")

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

    def run_yoda_protector_v1012(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Yoda's Protector v1.01.2 wrapper on a single file.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = YodaProtectorV1012(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("yoda_protector_v1.01.2")

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

    def run_yoda_protector_v102(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Yoda's Protector v1.02 wrapper on a single file.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = YodaProtectorV102(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("yoda_protector_v1.02")

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

    def run_yoda_protector_v1032(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Yoda's Protector v1.03.2 wrapper on a single file.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = YodaProtectorV1032(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("yoda_protector_v1.03.2")

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

    def run_yoda_protector_v1033(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Yoda's Protector v1.03.3 wrapper on a single file.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = YodaProtectorV1033(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("yoda_protector_v1.03.3")

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
        Run Telock wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = Telock(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("telock_v0.98")

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
                output_dir = self.get_output_directory("acprotect_std")

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

    def run_pelock(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run PELock wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = PELock(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("pelock_v2.40")

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

    def run_armadillo(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Armadillo wrapper - launch, wait 60 seconds, close.
        Armadillo is GUI-only; no CLI scripting is possible.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = Armadillo(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("armadillo")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode="none",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def run_pecompact(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run PECompact wrapper - launch, wait 60 seconds, close.
        PECompact is GUI-only; no CLI scripting is possible.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = PECompact(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("pecompact_v1.84")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode="none",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def run_themida(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Themida wrapper - launch, wait 60 seconds, close.
        Themida is GUI-only; no CLI scripting is possible.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = ThemidaGUI(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("themida_v3.2.4.34")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode="none",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def run_obsidium_v1880(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """Run Obsidium v1.8.8 GUI wrapper (stub)."""
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = ObsidiumV1880GUI(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("obsidium_v1.8.8")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode="none",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def run_obsidium_v152(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """Run Obsidium v1.5.2 GUI wrapper (stub)."""
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = ObsidiumV152GUI(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("obsidium_v1.5.2")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode="none",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def run_xpa_v143(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """Run XPA v1.43 GUI wrapper."""
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = XPAV143GUI(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("xpa_v1.43")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def run_zprotect(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """Run ZProtect v1.4.2.0 GUI wrapper."""
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = ZProtectGUI(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("zprotect")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
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
            "npack_v1.1": self.run_npack,
            "nspack_v3.7": self.run_nspack,
            "jdpack_v1.00": self.run_jdpack,
            "fsg_v1.0": self.run_fsg,
            "asm_guard": self.run_asm_guard,
            "alienyze_protector": self.run_alienyze_protector,
            "mew": self.run_mew,
            "packman": self.run_packman,
            "rlpack": self.run_rlpack,
            "pe_diminisher": self.run_pe_diminisher,
            "shrinker_v3.4_demo": self.run_shrinker,
            "upx_scrambler": self.run_upx_scrambler,
            "upx_scrambler_306": self.run_upx_scrambler_306,
            "upx_scrambler_rc1": self.run_upx_scrambler_rc1,
            "upx_scrambler_rc103": self.run_upx_scrambler_rc103,
            "upx_scrambler_rc105": self.run_upx_scrambler_rc105,
            "upx_scrambler_rc1b10": self.run_upx_scrambler_rc1b10,
            "winupack": self.run_winupack,
            "yoda_crypter_v1.3": self.run_yoda_crypter,
            "yoda_crypter_v1.2": self.run_yoda_crypter_v12,
            "yoda_protector_v1.0": self.run_yoda_protector_v10,
            "yoda_protector_v1.01.2": self.run_yoda_protector_v1012,
            "yoda_protector_v1.02": self.run_yoda_protector_v102,
            "yoda_protector_v1.03.2": self.run_yoda_protector_v1032,
            "yoda_protector_v1.03.3": self.run_yoda_protector_v1033,
            "acprotect_std": self.run_acprotect,
            "telock_v0.98": self.run_telock,
            "pelock_v2.40": self.run_pelock,
            "armadillo": self.run_armadillo,
            "pecompact_v1.84": self.run_pecompact,
            "themida_v3.2.4.34": self.run_themida,
            "obsidium_v1.8.8": self.run_obsidium_v1880,
            "obsidium_v1.5.2": self.run_obsidium_v152,
            "xpa_v1.43": self.run_xpa_v143,
            "zprotect": self.run_zprotect,
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
        Uses fuzzy matching - checks if any file contains the sanitized stem.

        Matching is done on the *sanitized* stem because that is the name the
        packed output now carries (see copy_to_temp); the raw stem (with spaces)
        would never substring-match the underscored output name.
        """
        output_dir = self.get_output_directory(packer_name)

        # Normalize spaces->underscores on both sides so this also matches
        # outputs from older runs that were saved with the raw (spaced) name.
        def _norm(s: str) -> str:
            return s.lower().replace(" ", "_")

        stem = _norm(Path(sanitize_filename(file_path.name)).stem)

        for existing_file in output_dir.glob("*"):
            if existing_file.is_file() and stem in _norm(existing_file.stem):
                return True
        return False

    def run_batch(
        self,
        packer_name: str = "asm_guard",
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
            self._record_report_row(
                packer_name, 0, 0, 0, 0, note="no compatible files"
            )
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
            already = len(skipped_files) if skip_existing else 0
            self._record_report_row(
                packer_name, 0, already, 0, already, note="all already packed"
            )
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
            self._record_report_row(
                packer_name, 0, 0, 0, len(files), note="dry run"
            )
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

        # Record aggregated stats for the final report (used in 'all' mode).
        successful = sum(1 for v in results.values() if v is True)
        failed = sum(1 for v in results.values() if v is False)
        already = len(skipped_files) if skip_existing else 0
        self._record_report_row(
            packer_name,
            packed=successful,
            skipped=already,
            failed=failed,
            total=successful + failed + already,
        )

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

    # ========== PARALLEL ORCHESTRATION ==========

    def gather_samples(self, recursive: bool = False) -> List[Path]:
        """Return the list of .exe samples in the source directory (sorted)."""
        globber = self.source_dir.rglob("*") if recursive else self.source_dir.glob("*")
        return sorted(
            f for f in globber if f.is_file() and f.suffix.lower() == ".exe"
        )

    def _run_one(self, packer_name: str, sample_path: Path):
        """Worker: run one packer on one sample.

        In non-verbose mode this thread's stdout is routed to a per-sample log
        file under the packer's output dir, so the wrappers' chatter doesn't
        flood the console or interleave with other workers. Returns
        (success, log_path | None).
        """
        output_dir = self.get_output_directory(packer_name)

        # Verbose: let wrapper output go straight to the console (interleaved).
        if VERBOSE or not isinstance(sys.stdout, _StdoutRouter):
            try:
                return self.run_packer(packer_name, sample_path, output_dir=output_dir), None
            except Exception as e:
                tqdm.write(f"[x] {packer_name} / {sample_path.name}: {e}", file=_REAL_STDOUT)
                return False, None

        # Non-verbose: route this worker's stdout to a per-sample log file.
        log_dir = output_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"{sample_path.stem}.log"

        router = sys.stdout
        log_file = open(log_path, "w", encoding="utf-8", errors="replace")
        try:
            router.set_target(log_file)
            return self.run_packer(packer_name, sample_path, output_dir=output_dir), log_path
        except Exception as e:
            print(f"[ERROR] Worker exception: {e}")  # captured to log_file
            return False, log_path
        finally:
            router.reset()
            log_file.close()

    def run_parallel(
        self,
        packers: List[str],
        workers: int = 4,
        recursive: bool = False,
        dry_run: bool = False,
        limit: Optional[int] = None,
        skip_existing: bool = True,
        samples: Optional[List[Path]] = None,
    ) -> bool:
        """Run multiple packers across samples, parallel across DIFFERENT packers.

        Iterates samples outermost (one at a time); for each sample it fans the
        supported packers out across a thread pool. The global input lock in
        base_gui serializes each packer's launch+click phase while their long
        file-watch phases overlap. Each packer writes to its own output dir, so
        there are no output collisions.

        Returns True if any packer failed on any sample.
        """
        if samples is None:
            samples = self.gather_samples(recursive=recursive)
            if limit:
                samples = samples[:limit]

        if not samples:
            print("[WARNING] No .exe samples found to process.")
            return False

        # Per-packer running totals across all samples.
        agg = {p: {"packed": 0, "skipped": 0, "failed": 0} for p in packers}
        any_failed = False

        stats_lock = threading.Lock()
        interrupted = False

        sample_bar = tqdm(
            samples,
            total=len(samples),
            unit="sample",
            desc="Samples",
            position=0,
            leave=True,
            file=_REAL_STDOUT,
        )
        try:
            for sample in sample_bar:
                sample_bar.set_postfix_str(sample.name[:30])

                # Which packers actually have work to do for this sample.
                todo = []
                for p in packers:
                    if not self.is_file_supported(sample, p):
                        continue
                    if skip_existing and self.is_already_packed(sample, p):
                        agg[p]["skipped"] += 1
                        continue
                    todo.append(p)

                if not todo:
                    continue

                if dry_run:
                    for p in todo:
                        tqdm.write(f"[DRY RUN] {sample.name} -> {p}", file=_REAL_STDOUT)
                    continue

                # Fan the supported packers out across daemon worker threads
                # pulling from a shared queue. Daemon threads are key for Ctrl+C:
                # the main thread's join() is interruptible, and the workers (some
                # sitting in 500s GUI-watch sleeps) die instantly when the process
                # exits instead of blocking shutdown.
                work = queue.Queue()
                for p in todo:
                    work.put(p)

                with tqdm(
                    total=len(todo),
                    unit="packer",
                    desc=f"  └─ {sample.name[:24]}",
                    position=1,
                    leave=False,
                    file=_REAL_STDOUT,
                ) as pbar:

                    def _worker():
                        while not _ABORT.is_set():
                            try:
                                p = work.get_nowait()
                            except queue.Empty:
                                return
                            try:
                                success, log_path = self._run_one(p, sample)
                            except Exception as e:
                                success, log_path = False, None
                                tqdm.write(
                                    f"[x] {p} / {sample.name}: {e}",
                                    file=_REAL_STDOUT,
                                )
                            with stats_lock:
                                if success:
                                    agg[p]["packed"] += 1
                                else:
                                    agg[p]["failed"] += 1
                                    msg = f"[-] {p} / {sample.name}: failed"
                                    if log_path:
                                        msg += f"  (log: {log_path})"
                                    tqdm.write(msg, file=_REAL_STDOUT)
                                pbar.set_postfix_str(p)
                                pbar.update(1)

                    pool = [
                        threading.Thread(
                            target=_worker, name=f"pack-{i}", daemon=True
                        )
                        for i in range(min(workers, len(todo)))
                    ]
                    for t in pool:
                        t.start()
                    # Poll-join so a pending Ctrl+C reaches the main thread
                    # promptly. A bare join() blocks in C and delays delivery of
                    # the KeyboardInterrupt until the (possibly 500s) worker ends.
                    while any(t.is_alive() for t in pool):
                        for t in pool:
                            t.join(0.2)
        except KeyboardInterrupt:
            interrupted = True
            _ABORT.set()
            tqdm.write(
                "\n[!] Interrupted — stopping. In-flight packer windows may "
                "remain open; close them manually.",
                file=_REAL_STDOUT,
            )
        finally:
            sample_bar.close()

        # Clean each packer's temp dir (working copies accumulate across
        # samples). Skip when interrupted — daemon workers may still be writing.
        if not interrupted:
            for p in packers:
                try:
                    temp_dir = self.get_temp_directory(self.get_output_directory(p))
                    if temp_dir.exists():
                        shutil.rmtree(temp_dir, ignore_errors=True)
                except Exception:
                    pass

        # Build the aggregated report rows (reuses print_final_report).
        self.report_rows = []
        for p in packers:
            a = agg[p]
            total = a["packed"] + a["failed"] + a["skipped"]
            if dry_run:
                note = "dry run"
            elif total == 0:
                note = "no samples"
            else:
                note = ""
            self._record_report_row(
                p, a["packed"], a["skipped"], a["failed"], total, note=note
            )

        any_failed = any(a["failed"] > 0 for a in agg.values())
        return any_failed or interrupted


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


def print_final_report(rows, report_dir: Path):
    """Print an aggregated summary after an 'all' run and write it to a file.

    The report is written to <report_dir>/gui_packing_report.txt and overwritten
    on every run. Mirrors the packer_runner final report.
    """
    executed = [r for r in rows if not r.get("note")]
    not_run = [r for r in rows if r.get("note")]

    lines = []
    lines.append("=" * 72)
    lines.append("FINAL GUI PACKING REPORT")
    lines.append("=" * 72)

    if not executed and not not_run:
        lines.append("No GUI packing was performed (no packers ran).")
        lines.append("=" * 72)
    else:
        if executed:
            name_w = max(max(len(r["packer"]) for r in executed), len("Packer"))

            header = (
                f"{'Packer':<{name_w}}  "
                f"{'Packed':>6}  {'Skipped':>7}  {'Failed':>6}  {'Total':>6}"
            )
            lines.append(header)
            lines.append("-" * len(header))

            tot_packed = tot_skipped = tot_failed = tot_total = 0
            for r in executed:
                lines.append(
                    f"{r['packer']:<{name_w}}  "
                    f"{r['packed']:>6}  {r['skipped']:>7}  "
                    f"{r['failed']:>6}  {r['total']:>6}"
                )
                tot_packed += r["packed"]
                tot_skipped += r["skipped"]
                tot_failed += r["failed"]
                tot_total += r["total"]

            lines.append("-" * len(header))
            lines.append(
                f"{'TOTALS':<{name_w}}  "
                f"{tot_packed:>6}  {tot_skipped:>7}  "
                f"{tot_failed:>6}  {tot_total:>6}"
            )

            # Surface packers that produced nothing new but had failures.
            problem_packers = [
                r for r in executed if r["failed"] > 0 and r["packed"] == 0
            ]
            if problem_packers:
                lines.append("")
                lines.append("[!] Packers that packed 0 files and had failures:")
                for r in problem_packers:
                    lines.append(
                        f"    - {r['packer']}: {r['failed']} failed of {r['total']}"
                    )
        else:
            lines.append("No packers produced output.")

        # Packers that never ran (no compatible files, all already packed, dry run).
        if not_run:
            lines.append("")
            lines.append(f"[i] Packers not run ({len(not_run)}):")
            for r in not_run:
                lines.append(f"    - {r['packer']}: {r['note']}")

        lines.append("=" * 72)

    report_text = "\n".join(lines)
    print("\n" + report_text)

    # Persist to packed_sources, overwriting any previous report.
    try:
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "gui_packing_report.txt"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_text + "\n")
        print(f"\n[*] Report written to: {report_path}")
    except Exception as e:
        print(f"[!] Warning: could not write report file: {e}")


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
        nargs="+",
        default=[DEFAULT_PACKER],
        choices=list(PACKER_FILE_SUPPORT.keys()) + ["all"],
        metavar="PACKER",
        help=(
            f"One or more packers to run (default: {DEFAULT_PACKER}), or 'all' "
            "for every GUI packer. Multiple packers (or 'all') run in parallel "
            "across DIFFERENT packers per sample; a single packer runs sequentially."
        ),
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Parallel workers (different packers run concurrently per sample). "
        "Default: 4. Only applies when running 2+ packers or 'all'.",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print all wrapper output to the console. Without it: only progress "
        "bars, failures, and the final report (wrapper logs go to per-sample files).",
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

    # Resolve verbosity and install the thread-local stdout router so worker
    # threads can redirect their (noisy) output to per-sample log files.
    global VERBOSE
    VERBOSE = args.verbose
    if not isinstance(sys.stdout, _StdoutRouter):
        sys.stdout = _StdoutRouter(_REAL_STDOUT)

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

    # Resolve the requested packers: 'all' expands to every packer; otherwise
    # use the given list (de-duplicated, order preserved).
    if "all" in args.packer:
        packers = list(PACKER_FILE_SUPPORT.keys())
    else:
        packers = list(dict.fromkeys(args.packer))
    parallel = len(packers) > 1

    vlog(f"Script directory: {script_dir}")
    vlog(f"Main directory: {main_dir}")
    vlog(f"Source directory: {source_dir}")
    vlog(f"YAML path: {yaml_path}")
    if parallel:
        print(
            f"[*] Running {len(packers)} packers "
            f"(parallel across packers, {args.workers} workers): "
            f"{', '.join(packers)}"
        )
    elif output_dir:
        vlog(f"Output directory (CLI): {output_dir}")
    else:
        vlog(f"Output directory: ../packed_sources/{packers[0]}/ (default)")

    try:
        runner = GUIWrapperRunner(
            source_dir=str(source_dir),
            main_dir=str(main_dir),
            yaml_path=str(yaml_path),
        )

        # Packer-specific --check/--uncheck options only apply to single-packer
        # runs; in parallel mode every packer uses its defaults.
        packer_config = None
        if not parallel:
            packer_config = runner.build_packer_config(
                packers[0],
                check_options=getattr(args, "check", None),
                uncheck_options=getattr(args, "uncheck", None),
            )

        # ----- Single file -----
        if args.file:
            file_path = Path(args.file).resolve()
            if not file_path.exists():
                print(f"[ERROR] File not found: {file_path}")
                return 1

            if parallel:
                # Multiple packers on one sample — parallel across packers.
                any_failed = runner.run_parallel(
                    packers,
                    workers=args.workers,
                    dry_run=args.dry_run,
                    skip_existing=not args.no_skip,
                    samples=[file_path],
                )
                print_final_report(runner.report_rows, main_dir / "packed_sources")
                return 1 if any_failed else 0

            success = runner.run_packer(
                packers[0],
                file_path,
                packer_config=packer_config,
                output_dir=output_dir,
            )
            return 0 if success else 1

        # ----- Batch -----
        if parallel:
            any_failed = runner.run_parallel(
                packers,
                workers=args.workers,
                recursive=args.recursive,
                dry_run=args.dry_run,
                limit=args.limit,
                skip_existing=not args.no_skip,
            )
            print_final_report(runner.report_rows, main_dir / "packed_sources")
            return 1 if any_failed else 0

        # Single-packer batch — sequential (same-packer concurrency is unsafe).
        results = runner.run_batch(
            packer_name=packers[0],
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

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user — exiting.", file=_REAL_STDOUT)
        return 130
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
