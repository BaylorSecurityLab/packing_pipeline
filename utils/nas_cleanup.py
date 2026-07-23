"""Cleanup pass for packed_sources/.

Two contamination classes are addressed:

1. **Cross-packer duplicates** -- the same byte-identical file under two or
   more ``<packer>_<version>`` directories. Two real packers cannot emit
   the same bytes, so any duplicate that crosses packer dirs is an
   unpacked original that leaked into the corpus.
2. **Pass-throughs** -- a packed file whose SHA-256 equals an input file
   under ``benign_sources/x86/``. The packer returned the input bytes
   unchanged (or trivially wrapped them).

This script is read-only for ``inventory`` and ``report``; ``quarantine``
moves flagged files into ``packed_sources/_quarantine/`` preserving their
relative paths and never deletes in place.

Run:

    uv run python utils/nas_cleanup.py inventory
    uv run python utils/nas_cleanup.py report
    uv run python utils/nas_cleanup.py quarantine
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import logging
import os
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

try:
    from tqdm import tqdm
except ImportError:  # tqdm is a runtime dep, but degrade gracefully for tests
    def tqdm(iterable=None, **_kw):
        return iterable if iterable is not None else iter([])
from typing import Iterable, Iterator

# Allow direct-script launch (`python utils/nas_cleanup.py`).
try:
    from .binary_info import get_sha256
except ImportError:
    from binary_info import get_sha256


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
_log = logging.getLogger("nas_cleanup")


def _setup_logging(log_path: Path) -> None:
    """Attach a single append-mode FileHandler to the module logger.

    Console output remains the caller's responsibility (``print()``);
    this log captures machine-parseable run history.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if not any(isinstance(h, logging.FileHandler) and
               Path(getattr(h, "baseFilename", "")) == log_path
               for h in _log.handlers):
        handler = logging.FileHandler(log_path, mode="a", encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        handler.setLevel(logging.DEBUG)
        _log.addHandler(handler)
    _log.setLevel(logging.DEBUG)


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent

PACKED_ROOT_DEFAULT = PROJECT_ROOT / "packed_sources"
BENIGN_DIR_DEFAULT = PROJECT_ROOT / "benign_sources" / "x86"


def _resolve_paths(packed_root: Path) -> dict[str, Path]:
    """Compute output paths under ``<packed_root>/_audit`` and
    ``<packed_root>/_quarantine`` so a fixture run never collides with
    the real corpus."""
    audit_dir = packed_root / "_audit"
    quarantine_dir = packed_root / "_quarantine"
    return {
        "audit_dir": audit_dir,
        "quarantine_dir": quarantine_dir,
        "inventory_path": audit_dir / "nas_inventory.jsonl",
        "inventory_state_path": audit_dir / "inventory.state.json",
        "log_path": audit_dir / "nas_cleanup.log",
        "flags_path": audit_dir / "nas_cleanup_flags.jsonl",
        "report_path": audit_dir / "nas_cleanup_report.md",
        "quarantine_manifest": quarantine_dir / "quarantine_manifest.jsonl",
    }


# Backwards-compat defaults derived from the default packed root.
_DEFAULT = _resolve_paths(PACKED_ROOT_DEFAULT)
AUDIT_DIR = _DEFAULT["audit_dir"]
QUARANTINE_DIR = _DEFAULT["quarantine_dir"]
INVENTORY_PATH = _DEFAULT["inventory_path"]
INVENTORY_STATE_PATH = _DEFAULT["inventory_state_path"]
LOG_PATH = _DEFAULT["log_path"]
FLAGS_PATH = _DEFAULT["flags_path"]
REPORT_PATH = _DEFAULT["report_path"]
QUARANTINE_MANIFEST = _DEFAULT["quarantine_manifest"]


# ---------------------------------------------------------------------------
# Inventory state (resume)
# ---------------------------------------------------------------------------
class InventoryState:
    """Persistent ``{path: {sha256, size, mtime_ns}}`` map.

    Resuming an interrupted ``inventory`` run reuses a file's cached SHA
    when its ``size`` and ``mtime_ns`` still match -- saving the
    minutes-long rehash of the ~30k-file corpus.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._data: dict[str, dict] = {}
        if path.exists():
            try:
                with path.open(encoding="utf-8") as f:
                    self._data = json.load(f)
            except (OSError, json.JSONDecodeError):
                self._data = {}

    def get_if_fresh(self, rel_path: str, size: int, mtime_ns: int) -> str | None:
        """Return the cached SHA when size + mtime_ns match, else ``None``."""
        row = self._data.get(rel_path)
        if row is None:
            return None
        if int(row.get("size", -1)) != size:
            return None
        if int(row.get("mtime_ns", -1)) != mtime_ns:
            return None
        return row.get("sha256")

    def set(self, rel_path: str, sha256: str, size: int, mtime_ns: int) -> None:
        self._data[rel_path] = {
            "sha256": sha256,
            "size": size,
            "mtime_ns": mtime_ns,
        }

    def save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        try:
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, sort_keys=True)
            os.replace(tmp, self._path)
        except OSError:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise

    def __len__(self) -> int:
        return len(self._data)

# Directories never scanned -- mirrors ShaGate's exclusion list.
EXCLUDED_DIRS = frozenset({
    ".qsyncclient",
    "_temp_build",
    "_audit",
    "_quarantine",
    "_diag",
    "temp",
})


@dataclass(frozen=True)
class InventoryRecord:
    path: str  # POSIX-style relative to PACKED_ROOT
    sha256: str
    size: int
    packer_dir: str  # first path component (may be "" for root-level files)


@dataclass(frozen=True)
class FlagRecord:
    path: str
    sha256: str
    size: int
    packer_dir: str
    reasons: tuple[str, ...]  # ("DUP_ACROSS_PACKERS", "PASSTHROUGH", ...)
    other_packers: tuple[str, ...]  # other packer_dirs sharing this SHA
    matching_benign: tuple[str, ...]  # benign_sources paths sharing this SHA


def iter_packed_executables(packed_root: Path) -> Iterator[Path]:
    """Yield every .exe under packed_root, excluding build/audit dirs."""
    for root, dirs, files in os.walk(packed_root, followlinks=False):
        dirs[:] = sorted(
            d for d in dirs if d.lower() not in EXCLUDED_DIRS
        )
        for fname in sorted(files):
            if not fname.lower().endswith(".exe"):
                continue
            yield Path(root) / fname


def _hash_one(path: Path) -> tuple[Path, int, str, int] | None:
    try:
        st = path.stat()
        size = st.st_size
        mtime_ns = st.st_mtime_ns
        sha = get_sha256(path)
        return (path, size, sha, mtime_ns)
    except OSError:
        return None


def create_inventory(
    packed_root: Path,
    inventory_path: Path,
    *,
    workers: int = 8,
    state: InventoryState | None = None,
) -> list[InventoryRecord]:
    """Walk packed_root, hash every .exe, write inventory_path atomically.

    When ``state`` is supplied, files whose ``size`` + ``mtime_ns`` match
    a cached row reuse the cached SHA (resume after interruption).
    Newly-hashed or freshly-modified files update the state in-place and
    the state is saved on the way out.
    """
    inventory_path.parent.mkdir(parents=True, exist_ok=True)
    _log.info("inventory start  root=%s workers=%d", packed_root, workers)

    paths = list(iter_packed_executables(packed_root))

    # First pass: collect (path, size, mtime_ns) and split into "use cache"
    # vs "needs hash" buckets without hashing yet.
    to_hash: list[Path] = []
    preliminary: list[tuple[Path, int, int, str | None]] = []
    for p in tqdm(paths, desc="scanning", unit="file", leave=False):
        try:
            st = p.stat()
        except OSError:
            _log.warning("stat failed  path=%s", p)
            continue
        rel = p.relative_to(packed_root).as_posix() if p.is_absolute() else str(p)
        cached_sha = (
            state.get_if_fresh(rel, st.st_size, st.st_mtime_ns)
            if state is not None
            else None
        )
        preliminary.append((p, st.st_size, st.st_mtime_ns, cached_sha))
        if cached_sha is None:
            to_hash.append(p)

    _log.info(
        "inventory plan  total=%d  cache_hits=%d  to_hash=%d",
        len(preliminary), len(preliminary) - len(to_hash), len(to_hash),
    )

    hashed: dict[Path, str] = {}
    if to_hash:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(_hash_one, p): p for p in to_hash}
            with tqdm(
                total=len(to_hash),
                desc="hashing",
                unit="file",
                leave=False,
            ) as bar:
                for fut in as_completed(futs):
                    r = fut.result()
                    if r is not None:
                        path, _size, sha, _mtime = r
                        hashed[path] = sha
                    bar.update(1)
    else:
        # Nothing to hash -- print a one-liner so the user knows the cache hit.
        print(f"[*] All {len(preliminary)} file(s) up to date (cache hit).")

    # Compose records and update state with anything we hashed fresh.
    records: list[InventoryRecord] = []
    for path, size, mtime_ns, cached_sha in sorted(
        preliminary, key=lambda t: str(t[0])
    ):
        sha = cached_sha if cached_sha is not None else hashed.get(path)
        if sha is None:
            _log.warning("hash failed  path=%s", path)
            continue
        if state is not None and cached_sha is None:
            rel = path.relative_to(packed_root).as_posix()
            state.set(rel, sha, size, mtime_ns)
        try:
            rel = path.relative_to(packed_root).as_posix()
        except ValueError:
            rel = str(path)
        packer_dir = rel.split("/", 1)[0] if "/" in rel else ""
        records.append(InventoryRecord(
            path=rel,
            sha256=sha,
            size=size,
            packer_dir=packer_dir,
        ))

    tmp = inventory_path.with_suffix(inventory_path.suffix + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps({
                    "path": r.path,
                    "sha256": r.sha256,
                    "size": r.size,
                    "packer_dir": r.packer_dir,
                }, ensure_ascii=False) + "\n")
        os.replace(tmp, inventory_path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise

    if state is not None:
        try:
            state.save()
        except OSError as e:
            _log.error("state save failed: %s", e)
            raise

    _log.info(
        "inventory done  records=%d  total_bytes=%d",
        len(records), sum(r.size for r in records),
    )
    return records


def load_inventory(inventory_path: Path) -> list[InventoryRecord]:
    if not inventory_path.exists():
        return []
    records: list[InventoryRecord] = []
    with inventory_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            records.append(InventoryRecord(
                path=row.get("path", ""),
                sha256=row.get("sha256", ""),
                size=int(row.get("size", -1)),
                packer_dir=row.get("packer_dir", ""),
            ))
    return records


def load_flags(flags_path: Path) -> list[FlagRecord]:
    if not flags_path.exists():
        return []
    out: list[FlagRecord] = []
    with flags_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            out.append(FlagRecord(
                path=row.get("path", ""),
                sha256=row.get("sha256", ""),
                size=int(row.get("size", -1)),
                packer_dir=row.get("packer_dir", ""),
                reasons=tuple(row.get("reasons", [])),
                other_packers=tuple(row.get("other_packers", [])),
                matching_benign=tuple(row.get("matching_benign", [])),
            ))
    return out


def compute_needs_repacking(
    records: list[InventoryRecord],
    flags: list[FlagRecord],
    min_unflagged: int = 2,
) -> list[dict]:
    """For each packer_dir, compute how many samples remain once flagged
    files are removed. A dir with fewer than ``min_unflagged`` genuine
    (unflagged) samples "needs re-packing".

    This mirrors the guard in ``quarantine`` but is READ-ONLY -- it moves
    nothing, so it's safe to run any time to check corpus health.

    Returns a list of dicts sorted by unflagged count (neediest first).
    """
    total_per_dir: dict[str, int] = {}
    for r in records:
        d = r.packer_dir or "(root)"
        total_per_dir[d] = total_per_dir.get(d, 0) + 1

    flagged_per_dir: dict[str, int] = {}
    flagged_paths = {fl.path for fl in flags}
    for r in records:
        d = r.packer_dir or "(root)"
        if r.path in flagged_paths:
            flagged_per_dir[d] = flagged_per_dir.get(d, 0) + 1

    rows: list[dict] = []
    for d, total in total_per_dir.items():
        flagged = flagged_per_dir.get(d, 0)
        unflagged = total - flagged
        rows.append({
            "packer_dir": d,
            "total": total,
            "flagged": flagged,
            "unflagged": unflagged,
            "needs_repacking": unflagged < min_unflagged,
        })
    rows.sort(key=lambda r: (not r["needs_repacking"], r["unflagged"], r["packer_dir"]))
    return rows


def _read_inventory_sha_from_report(report_path: Path) -> str | None:
    """Pull ``inventory_sha256`` out of the report's HTML-comment metadata.

    The report embeds ``<!-- metadata ... inventory_sha256: <sha> ... -->``
    near the top; quarantine uses this to refuse stale data.
    """
    if not report_path.exists():
        return None
    try:
        text = report_path.read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("inventory_sha256:"):
            return line.split(":", 1)[1].strip()
    return None


def hash_benign_inputs(benign_dir: Path) -> dict[str, list[str]]:
    """Return ``{sha256: [relative paths]}`` for every .exe under benign_dir."""
    out: dict[str, list[str]] = {}
    if not benign_dir.exists():
        return out
    candidates = [
        p for p in sorted(benign_dir.iterdir())
        if p.is_file() and p.name.lower().endswith(".exe")
    ]
    for path in tqdm(candidates, desc="benign", unit="file", leave=False):
        try:
            sha = get_sha256(path)
        except OSError:
            continue
        out.setdefault(sha, []).append(path.name)
    return out


def build_flags(
    records: list[InventoryRecord],
    benign_paths_by_sha: dict[str, list[str]],
) -> tuple[list[FlagRecord], dict]:
    """Group records by SHA, classify defect 1 (cross-packer dup) and
    defect 2 (pass-through), return flagged records plus aggregate counts.
    """
    by_sha: dict[str, list[InventoryRecord]] = {}
    for r in records:
        by_sha.setdefault(r.sha256, []).append(r)

    flags: list[FlagRecord] = []
    seen_paths: set[str] = set()

    cross_dup_sha_count = 0
    cross_dup_file_count = 0
    passthrough_sha_count = 0
    passthrough_file_count = 0

    for sha, group in sorted(by_sha.items()):
        packer_dirs = {r.packer_dir for r in group if r.packer_dir}
        is_dup = len(packer_dirs) >= 2
        is_passthrough = sha in benign_paths_by_sha
        if not (is_dup or is_passthrough):
            continue

        if is_dup:
            cross_dup_sha_count += 1
        if is_passthrough:
            passthrough_sha_count += 1

        for r in group:
            if r.path in seen_paths:
                continue
            seen_paths.add(r.path)
            reasons: list[str] = []
            other_packers: list[str] = []
            matching_benign: list[str] = []
            if is_dup:
                reasons.append("DUP_ACROSS_PACKERS")
                cross_dup_file_count += 1
                other_packers = sorted(packer_dirs - {r.packer_dir})
            if is_passthrough:
                reasons.append("PASSTHROUGH")
                passthrough_file_count += 1
                matching_benign = list(benign_paths_by_sha[sha])
            flags.append(FlagRecord(
                path=r.path,
                sha256=r.sha256,
                size=r.size,
                packer_dir=r.packer_dir,
                reasons=tuple(reasons),
                other_packers=tuple(other_packers),
                matching_benign=tuple(matching_benign),
            ))

    counts = {
        "total_files": len(records),
        "distinct_shas": len(by_sha),
        "cross_dup_sha_count": cross_dup_sha_count,
        "cross_dup_file_count": cross_dup_file_count,
        "passthrough_sha_count": passthrough_sha_count,
        "passthrough_file_count": passthrough_file_count,
        "flagged_file_count": len(flags),
    }
    return flags, counts


def write_flags_jsonl(flags: list[FlagRecord], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as f:
            for fl in flags:
                f.write(json.dumps({
                    "path": fl.path,
                    "sha256": fl.sha256,
                    "size": fl.size,
                    "packer_dir": fl.packer_dir,
                    "reasons": list(fl.reasons),
                    "other_packers": list(fl.other_packers),
                    "matching_benign": list(fl.matching_benign),
                }, ensure_ascii=False) + "\n")
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def write_markdown_report(
    flags: list[FlagRecord],
    counts: dict,
    inventory_path: Path,
    flags_path: Path,
    report_path: Path,
    inventory_sha: str,
) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    # Per-packer breakdown.
    per_dir: dict[str, dict[str, int]] = {}
    for fl in flags:
        d = fl.packer_dir or "(root)"
        per_dir.setdefault(d, {"flagged": 0, "dup": 0, "passthrough": 0})
        per_dir[d]["flagged"] += 1
        if "DUP_ACROSS_PACKERS" in fl.reasons:
            per_dir[d]["dup"] += 1
        if "PASSTHROUGH" in fl.reasons:
            per_dir[d]["passthrough"] += 1

    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    lines: list[str] = []
    lines.append("# packed_sources/ cleanup report")
    lines.append("")
    lines.append(f"_Generated: {now}_")
    lines.append("")
    lines.append("<!-- metadata")
    lines.append(f"inventory: {inventory_path.as_posix()}")
    lines.append(f"inventory_sha256: {inventory_sha}")
    lines.append(f"flags: {flags_path.as_posix()}")
    lines.append("-->")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Inventory: `{inventory_path.as_posix()}`")
    lines.append(f"- Inventory SHA-256: `{inventory_sha}`")
    lines.append(f"- Total output files: **{counts['total_files']}**")
    lines.append(f"- Distinct SHAs: **{counts['distinct_shas']}**")
    lines.append(
        f"- Cross-packer duplicate SHAs: **{counts['cross_dup_sha_count']}** "
        f"({counts['cross_dup_file_count']} files)"
    )
    lines.append(
        f"- Pass-through SHAs: **{counts['passthrough_sha_count']}** "
        f"({counts['passthrough_file_count']} files)"
    )
    lines.append(f"- Flagged files (union): **{counts['flagged_file_count']}**")
    lines.append("")
    lines.append("## Per-packer breakdown")
    lines.append("")
    lines.append("| Packer dir | Flagged | Cross-packer dup | Pass-through |")
    lines.append("|---|---:|---:|---:|")
    for d in sorted(per_dir.keys()):
        row = per_dir[d]
        lines.append(
            f"| `{d}` | {row['flagged']} | {row['dup']} | {row['passthrough']} |"
        )
    lines.append("")
    lines.append("## Flagged files")
    lines.append("")
    lines.append("| Path | SHA-256 (prefix) | Size | Reasons | Other packers | Benign match |")
    lines.append("|---|---|---:|---|---|---|")
    for fl in flags:
        reasons = "|".join(fl.reasons)
        others = ",".join(fl.other_packers) or "-"
        benign = ",".join(fl.matching_benign) or "-"
        lines.append(
            f"| `{fl.path}` | `{fl.sha256[:16]}` | {fl.size} | {reasons} | "
            f"{others} | {benign} |"
        )
    lines.append("")

    tmp = report_path.with_suffix(report_path.suffix + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(tmp, report_path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def cmd_inventory(args: argparse.Namespace) -> int:
    packed_root = Path(args.packed_root).resolve()
    paths = _resolve_paths(packed_root)
    if not packed_root.exists():
        print(f"[!] Packed root not found: {packed_root}", file=sys.stderr)
        return 2
    _setup_logging(paths["log_path"])
    _log.info("=== inventory subcommand ===")
    state = InventoryState(paths["inventory_state_path"])
    if len(state):
        print(f"[*] Resuming with {len(state)} cached file(s) from state")
        _log.info("resume  state_entries=%d", len(state))
    print(f"[*] Inventorying {packed_root} (workers={args.workers}) ...")
    records = create_inventory(
        packed_root, paths["inventory_path"],
        workers=args.workers, state=state,
    )
    print(f"[+] Wrote {len(records)} record(s) to {paths['inventory_path']}")
    print(f"    Total bytes: {sum(r.size for r in records):,}")
    print(f"[+] State file: {paths['inventory_state_path']}  ({len(state)} entries)")
    print(f"[+] Log:        {paths['log_path']}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    packed_root = Path(args.packed_root).resolve()
    benign_dir = Path(args.benign_dir).resolve()
    paths = _resolve_paths(packed_root)
    inventory_path = paths["inventory_path"]
    if not inventory_path.exists():
        print(f"[!] Inventory not found: {inventory_path}", file=sys.stderr)
        print("    Run: uv run python utils/nas_cleanup.py inventory")
        return 2
    _setup_logging(paths["log_path"])
    _log.info("=== report subcommand ===")
    records = load_inventory(inventory_path)
    if not records:
        print(f"[!] Inventory is empty: {inventory_path}", file=sys.stderr)
        return 2

    print(f"[*] Loaded {len(records)} record(s) from inventory")
    print(f"[*] Hashing benign inputs under {benign_dir} ...")
    benign = hash_benign_inputs(benign_dir)
    print(f"    {len(benign)} distinct benign SHA(s)")
    _log.info("benign  files=%d  distinct_shas=%d", sum(len(v) for v in benign.values()), len(benign))

    flags, counts = build_flags(records, benign)
    write_flags_jsonl(flags, paths["flags_path"])
    inventory_sha = _file_sha256(inventory_path)
    write_markdown_report(
        flags, counts,
        inventory_path, paths["flags_path"], paths["report_path"],
        inventory_sha,
    )

    _log.info(
        "report  total=%d  cross_dup_sha=%d  passthrough_sha=%d  flagged=%d",
        counts["total_files"],
        counts["cross_dup_sha_count"],
        counts["passthrough_sha_count"],
        counts["flagged_file_count"],
    )

    print(f"[+] Flags JSONL: {paths['flags_path']}  ({len(flags)} record(s))")
    print(f"[+] Markdown report: {paths['report_path']}")
    print(
        f"    cross-packer dups: {counts['cross_dup_file_count']} file(s) "
        f"across {counts['cross_dup_sha_count']} SHA(s); "
        f"pass-throughs: {counts['passthrough_file_count']} file(s); "
        f"union: {counts['flagged_file_count']}"
    )

    # Read-only "needs re-packing" analysis: which packer dirs would drop
    # below 2 genuine (unflagged) samples if the flagged files were removed.
    repack = compute_needs_repacking(records, flags)
    needy = [r for r in repack if r["needs_repacking"]]
    repack_path = paths["audit_dir"] / "needs_repacking.txt"
    with repack_path.open("w", encoding="utf-8") as f:
        f.write(f"{'packer_dir':<45} {'total':>6} {'flagged':>8} {'unflagged':>10} {'status':>16}\n")
        for r in repack:
            status = "NEEDS RE-PACKING" if r["needs_repacking"] else "ok"
            f.write(
                f"{r['packer_dir']:<45} {r['total']:>6} {r['flagged']:>8} "
                f"{r['unflagged']:>10} {status:>16}\n"
            )
    print(f"[+] Repack status:   {repack_path}")
    if needy:
        print(f"\n[!] {len(needy)} packer dir(s) NEED RE-PACKING "
              f"(< 2 unflagged samples):")
        for r in needy:
            print(f"    - {r['packer_dir']:<40} "
                  f"unflagged={r['unflagged']}  (total={r['total']}, flagged={r['flagged']})")
    else:
        print("\n[+] No packer dirs need re-packing (all have >= 2 unflagged samples).")
    return 0


def cmd_lookup(args: argparse.Namespace) -> int:
    """Query the cache without touching the corpus.

    Three modes:
      --path REL_PATH  find a single record in nas_inventory.jsonl
      --sha  HASH      find every path sharing the given sha256
      --input NAME     look up a benign_sources/x86 filename and report
                       which packer_dirs contain that sha (i.e. which
                       packers succeeded / produced a pass-through for
                       that input)
    """
    packed_root = Path(args.packed_root).resolve()
    paths = _resolve_paths(packed_root)
    inventory_path = paths["inventory_path"]
    if not inventory_path.exists():
        print(f"[!] Inventory not found: {inventory_path}", file=sys.stderr)
        print("    Run: uv run python utils/nas_cleanup.py inventory", file=sys.stderr)
        return 2
    records = load_inventory(inventory_path)

    if args.path:
        target = args.path.replace("\\", "/").lstrip("./")
        hits = [r for r in records if r.path == target]
        if not hits:
            print(f"[!] Not found in inventory: {target}", file=sys.stderr)
            return 1
        for r in hits:
            print(f"path       {r.path}")
            print(f"  sha256   {r.sha256}")
            print(f"  size     {r.size:,}")
            print(f"  packer   {r.packer_dir}")
        # Also list other packer_dirs sharing the same sha (cross-packer view).
        if hits:
            same_sha = sorted({
                r.packer_dir for r in records
                if r.sha256 == hits[0].sha256 and r.packer_dir != hits[0].packer_dir
            })
            if same_sha:
                print(f"  also in  {', '.join(same_sha)}")
        return 0

    if args.sha:
        sha = args.sha.lower()
        hits = [r for r in records if r.sha256 == sha]
        if not hits:
            print(f"[!] No inventory record matches sha: {sha}", file=sys.stderr)
            return 1
        for r in sorted(hits, key=lambda x: x.path):
            print(f"{r.packer_dir:<40}  {r.path}  ({r.size:,} B)")
        print(f"\nTotal: {len(hits)} record(s)")
        return 0

    if args.input:
        # Find the sha of the named benign input (filename match).
        benign_dir = Path(args.benign_dir).resolve()
        candidate = None
        if benign_dir.exists():
            for p in benign_dir.iterdir():
                if p.is_file() and p.name == args.input:
                    candidate = p
                    break
        if candidate is None:
            print(f"[!] Benign input not found: {args.input}", file=sys.stderr)
            return 1
        try:
            sha = get_sha256(candidate)
        except OSError as e:
            print(f"[!] Could not hash {candidate}: {e}", file=sys.stderr)
            return 2
        print(f"input      {candidate.name}")
        print(f"  path     {candidate}")
        print(f"  sha256   {sha}")
        hits = sorted(
            [r for r in records if r.sha256 == sha],
            key=lambda x: x.packer_dir,
        )
        if not hits:
            print(f"  No packed corpus file has this sha (input never leaked in).")
            return 0
        for r in hits:
            mark = " <-- pass-through" if r.packer_dir else ""
            print(f"  {r.packer_dir:<40}  {r.path}  ({r.size:,} B){mark}")
        print(f"\nTotal: {len(hits)} corpus file(s) match this input's sha")
        return 0

    print("[!] Pass one of --path, --sha, or --input.", file=sys.stderr)
    return 2


def cmd_delete_passthroughs(args: argparse.Namespace) -> int:
    """Delete quarantined files.

    By default only deletes rows whose reasons include ``PASSTHROUGH``
    (packer returned the input unchanged). With ``--all``, every row in
    the quarantine manifest is deleted -- used after a deliberate
    operator decision to purge the entire quarantine.

    A pass-through is a packed file whose SHA-256 equals an input under
    ``benign_sources/x86/``. Cross-packer duplicates that did NOT match
    a benign input are kept by default (genuine ambiguity).
    """
    packed_root = Path(args.packed_root).resolve()
    paths = _resolve_paths(packed_root)
    quarantine_dir = paths["quarantine_dir"]
    manifest = paths["quarantine_manifest"]
    _setup_logging(paths["log_path"])
    _log.info("=== delete-passthroughs subcommand (all=%s) ===", args.all)

    if not manifest.exists():
        print(f"[!] Quarantine manifest not found: {manifest}", file=sys.stderr)
        print("    Run: uv run python utils/nas_cleanup.py quarantine", file=sys.stderr)
        return 2

    rows: list[dict] = []
    with manifest.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    kept: list[dict] = []
    deleted = 0
    missing = 0
    failed = 0
    for row in rows:
        reasons = row.get("reasons", [])
        if not args.all and "PASSTHROUGH" not in reasons:
            kept.append(row)
            continue
        target = quarantine_dir / row["original_path"]
        if not target.exists():
            kept.append(row)
            missing += 1
            continue
        try:
            target.unlink()
            deleted += 1
            _log.info(
                "delete  reason=%s path=%s sha=%s",
                "|".join(reasons),
                row.get("original_path"), row.get("sha256"),
            )
        except OSError as e:
            failed += 1
            kept.append(row)
            print(f"[!] Failed to delete {target}: {e}", file=sys.stderr)

    tmp = manifest.with_suffix(manifest.suffix + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as f:
            for row in kept:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        os.replace(tmp, manifest)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise

    mode = "ALL" if args.all else "PASSTHROUGH only"
    print(
        f"[+] Mode: {mode}  deleted={deleted}  kept={len(kept)}  "
        f"missing={missing}  failed={failed}"
    )
    print(f"[+] Manifest: {manifest}")
    print(f"[+] Log:      {paths['log_path']}")
    _log.info(
        "delete-passthroughs  mode=%s  deleted=%d  kept=%d  missing=%d  failed=%d",
        mode, deleted, len(kept), missing, failed,
    )
    return 0


def cmd_quarantine(args: argparse.Namespace) -> int:
    """Move flagged files into ``<packed_root>/_quarantine/`` preserving
    relative paths. Idempotent. Refuses to act on a packer_dir that would
    drop below 2 unflagged files (those surface as ``needs re-packing``).
    """
    packed_root = Path(args.packed_root).resolve()
    paths = _resolve_paths(packed_root)
    inventory_path = paths["inventory_path"]
    flags_path = paths["flags_path"]
    quarantine_dir = paths["quarantine_dir"]
    quarantine_manifest = paths["quarantine_manifest"]

    if not inventory_path.exists():
        print(f"[!] Inventory not found: {inventory_path}", file=sys.stderr)
        print("    Run: uv run python utils/nas_cleanup.py inventory")
        return 2
    if not flags_path.exists():
        print(f"[!] Flags JSONL not found: {flags_path}", file=sys.stderr)
        print("    Run: uv run python utils/nas_cleanup.py report")
        return 2
    _setup_logging(paths["log_path"])
    _log.info("=== quarantine subcommand ===")

    records = load_inventory(inventory_path)
    if not records:
        print(f"[!] Inventory is empty: {inventory_path}", file=sys.stderr)
        return 2

    flags = load_flags(flags_path)
    if not flags:
        print(f"[!] No flagged rows in {flags_path}", file=sys.stderr)
        return 0

    # Validate that the inventory on disk matches what the report was built
    # from -- prevents operating on stale data.
    expected_inventory_sha = _read_inventory_sha_from_report(paths["report_path"])
    if expected_inventory_sha is not None:
        actual_inventory_sha = _file_sha256(inventory_path)
        if expected_inventory_sha != actual_inventory_sha:
            print(
                f"[!] Inventory has changed since the report was generated.",
                file=sys.stderr,
            )
            print(
                f"    report expects inventory_sha256={expected_inventory_sha}",
                file=sys.stderr,
            )
            print(
                f"    on-disk inventory_sha256 ={actual_inventory_sha}",
                file=sys.stderr,
            )
            print("    Re-run: inventory -> report -> quarantine", file=sys.stderr)
            return 2

    # Per-packer totals from the full inventory.
    total_per_dir: dict[str, int] = {}
    for r in records:
        d = r.packer_dir or "(root)"
        total_per_dir[d] = total_per_dir.get(d, 0) + 1

    # Flagged rows per packer_dir.
    flagged_per_dir: dict[str, int] = {}
    for fl in flags:
        d = fl.packer_dir or "(root)"
        flagged_per_dir[d] = flagged_per_dir.get(d, 0) + 1

    # Decide which packer_dirs are allowed to release files. A dir is
    # blocked when quarantining its flagged files would leave it with
    # fewer than --min-unflagged genuine samples. Pass --min-unflagged 0
    # to disable the guard entirely (dirs may empty out; repack afterward).
    min_unflagged = getattr(args, "min_unflagged", 2)
    allowed_dirs: set[str] = set()
    blocked_dirs: dict[str, int] = {}
    for d, total in total_per_dir.items():
        flagged = flagged_per_dir.get(d, 0)
        unflagged = total - flagged
        if unflagged < min_unflagged:
            blocked_dirs[d] = unflagged
        else:
            allowed_dirs.add(d)

    quarantine_dir.mkdir(parents=True, exist_ok=True)
    quarantine_manifest.parent.mkdir(parents=True, exist_ok=True)

    # Load already-quarantined keys so re-runs are no-ops.
    existing_keys: set[tuple[str, str]] = set()
    if quarantine_manifest.exists():
        with quarantine_manifest.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                existing_keys.add((row.get("original_path", ""), row.get("sha256", "")))

    moved = 0
    already = 0
    skipped_blocked = 0
    failed = 0
    manifest_f = quarantine_manifest.open("a", encoding="utf-8")
    try:
        for fl in tqdm(flags, desc="quarantine", unit="file", leave=False):
            d = fl.packer_dir or "(root)"
            if d not in allowed_dirs:
                skipped_blocked += 1
                continue
            src = packed_root / fl.path
            dst = quarantine_dir / fl.path
            key = (fl.path, fl.sha256)
            if key in existing_keys:
                # Already quarantined by a previous run -- skip.
                if not src.exists() and dst.exists():
                    already += 1
                    continue
            if not src.exists():
                # Source already gone (manual delete, prior quarantine, etc.).
                if dst.exists():
                    already += 1
                else:
                    failed += 1
                    print(
                        f"[!] Source missing and destination absent: {fl.path}",
                        file=sys.stderr,
                    )
                continue
            try:
                cur_sha = get_sha256(src)
            except OSError as e:
                failed += 1
                print(f"[!] Hash failed for {fl.path}: {e}", file=sys.stderr)
                continue
            if cur_sha != fl.sha256:
                failed += 1
                print(
                    f"[!] SHA changed since report; refusing to move {fl.path}",
                    file=sys.stderr,
                )
                continue
            if dst.exists():
                failed += 1
                print(
                    f"[!] Destination already exists; refusing to overwrite "
                    f"{dst}",
                    file=sys.stderr,
                )
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.move(str(src), str(dst))
            except OSError as e:
                failed += 1
                print(f"[!] Move failed for {fl.path}: {e}", file=sys.stderr)
                continue
            manifest_f.write(json.dumps({
                "original_path": fl.path,
                "sha256": fl.sha256,
                "size": fl.size,
                "packer_dir": fl.packer_dir,
                "reasons": list(fl.reasons),
            }, ensure_ascii=False) + "\n")
            manifest_f.flush()
            existing_keys.add(key)
            moved += 1
    finally:
        manifest_f.close()

    print(f"[+] Quarantined: {moved} moved, {already} already, "
          f"{skipped_blocked} blocked (needs re-packing), {failed} failed")
    if blocked_dirs:
        print(f"[!] Packer dirs that would drop below {min_unflagged} unflagged "
              f"sample(s) (flagged files NOT moved; use --min-unflagged 0 to "
              f"force):")
        for d in sorted(blocked_dirs):
            print(f"    - {d}: would have {blocked_dirs[d]} unflagged left")
    print(f"[+] Manifest: {quarantine_manifest}")
    print(f"[+] Log:      {paths['log_path']}")
    _log.info(
        "quarantine  moved=%d  already=%d  blocked=%d  failed=%d",
        moved, already, skipped_blocked, failed,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Cleanup pass for packed_sources/ (inventory, report, quarantine).",
    )
    parser.add_argument(
        "--packed-root",
        type=str,
        default=str(PACKED_ROOT_DEFAULT),
        help=f"Root packed output directory (default: {PACKED_ROOT_DEFAULT})",
    )
    parser.add_argument(
        "--benign-dir",
        type=str,
        default=str(BENIGN_DIR_DEFAULT),
        help=f"Benign sources x86 directory (default: {BENIGN_DIR_DEFAULT})",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_inv = sub.add_parser("inventory", help="Walk packed_sources/ and write a SHA-256 inventory.")
    p_inv.add_argument("--workers", type=int, default=8, help="Hash workers (default 8).")
    p_inv.set_defaults(func=cmd_inventory)

    p_rep = sub.add_parser("report", help="Analyse the inventory and emit flagged files + report.")
    p_rep.set_defaults(func=cmd_report)

    p_qua = sub.add_parser("quarantine", help="Move flagged files into _quarantine/.")
    p_qua.add_argument(
        "--min-unflagged",
        type=int,
        default=2,
        metavar="N",
        help="Refuse to quarantine a packer dir's flagged files if it would "
        "leave fewer than N genuine samples (default 2). Use 0 to force "
        "(dirs may empty out; repack afterward).",
    )
    p_qua.set_defaults(func=cmd_quarantine)

    p_del = sub.add_parser(
        "delete-passthroughs",
        help="Delete quarantined files (PASSTHROUGH by default; --all to purge everything).",
    )
    p_del.add_argument(
        "--all",
        action="store_true",
        help="Delete every row in the quarantine manifest, not just PASSTHROUGH.",
    )
    p_del.set_defaults(func=cmd_delete_passthroughs)

    p_lookup = sub.add_parser(
        "lookup",
        help="Query the inventory cache by path, sha, or benign-input name.",
    )
    lookup_mode = p_lookup.add_mutually_exclusive_group(required=True)
    lookup_mode.add_argument("--path", help="Find a single record by relative path.")
    lookup_mode.add_argument("--sha", help="Find every record with the given sha256.")
    lookup_mode.add_argument(
        "--input",
        help="Find a benign_sources/x86 file by name and list corpus matches.",
    )
    p_lookup.set_defaults(func=cmd_lookup)

    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())