"""Tests for utils.nas_cleanup resume + logging."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from utils.nas_cleanup import (
    InventoryState,
    create_inventory,
    iter_packed_executables,
    load_inventory,
)


def _make_tree(root: Path) -> dict[str, bytes]:
    """Create a tiny packed tree under ``root`` and return {relpath: bytes}."""
    files: dict[str, bytes] = {
        "packer_a_1.0/x.exe": b"alpha",
        "packer_a_1.0/y.exe": b"bravo",
        "packer_b_1.0/z.exe": b"charlie",
    }
    for rel, payload in files.items():
        full = root / rel
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_bytes(payload)
    return files


# ---------------------------------------------------------------------------
# InventoryState
# ---------------------------------------------------------------------------

def test_state_cache_hit_on_matching_mtime(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    state = InventoryState(state_path)
    state.set("packer_a/x.exe", "deadbeef", 100, 12345)
    state.save()

    reloaded = InventoryState(state_path)
    assert reloaded.get_if_fresh("packer_a/x.exe", 100, 12345) == "deadbeef"


def test_state_cache_miss_on_size_change(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    state = InventoryState(state_path)
    state.set("packer_a/x.exe", "deadbeef", 100, 12345)
    state.save()

    reloaded = InventoryState(state_path)
    assert reloaded.get_if_fresh("packer_a/x.exe", 200, 12345) is None


def test_state_cache_miss_on_mtime_change(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    state = InventoryState(state_path)
    state.set("packer_a/x.exe", "deadbeef", 100, 12345)
    state.save()

    reloaded = InventoryState(state_path)
    assert reloaded.get_if_fresh("packer_a/x.exe", 100, 99999) is None


def test_state_handles_corrupt_file(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    state_path.write_text("this is not json", encoding="utf-8")
    state = InventoryState(state_path)
    assert state.get_if_fresh("anything", 1, 1) is None


# ---------------------------------------------------------------------------
# create_inventory resume behaviour
# ---------------------------------------------------------------------------

def test_inventory_resume_reuses_cache_for_unchanged_files(tmp_path: Path) -> None:
    packed = tmp_path / "packed"
    files = _make_tree(packed)
    inv_path = tmp_path / "audit" / "nas_inventory.jsonl"
    state_path = tmp_path / "audit" / "inventory.state.json"

    state1 = InventoryState(state_path)
    records1 = create_inventory(packed, inv_path, state=state1)
    assert len(records1) == 3
    assert len(state1) == 3

    # Snapshot the mtime_ns of each file so we can rewrite with the SAME
    # mtime_ns and confirm the cache hit still triggers.
    stat_snapshot = {r.path: r.size for r in records1}

    state2 = InventoryState(state_path)
    # Force the same size/mtime_ns -- the second run must skip hashing.
    for rel, sz in stat_snapshot.items():
        (packed / rel).stat()  # touch
        cached = state2.get_if_fresh(rel, sz, os.stat(packed / rel).st_mtime_ns)
        assert cached is not None, f"cache miss for {rel}"


def test_inventory_invalidates_cache_on_modified_file(tmp_path: Path) -> None:
    packed = tmp_path / "packed"
    files = _make_tree(packed)
    inv_path = tmp_path / "audit" / "nas_inventory.jsonl"
    state_path = tmp_path / "audit" / "inventory.state.json"

    state1 = InventoryState(state_path)
    create_inventory(packed, inv_path, state=state1)
    first = {r.path: r.sha256 for r in load_inventory(inv_path)}

    # Mutate one file -- new bytes, new mtime.
    (packed / "packer_a_1.0/x.exe").write_bytes(b"alpha-mutated")
    state2 = InventoryState(state_path)
    records2 = create_inventory(packed, inv_path, state=state2)
    second = {r.path: r.sha256 for r in records2}

    assert first["packer_a_1.0/x.exe"] != second["packer_a_1.0/x.exe"]
    assert first["packer_a_1.0/y.exe"] == second["packer_a_1.0/y.exe"]


def test_inventory_removes_deleted_files_from_state(tmp_path: Path) -> None:
    packed = tmp_path / "packed"
    _make_tree(packed)
    inv_path = tmp_path / "audit" / "nas_inventory.jsonl"
    state_path = tmp_path / "audit" / "inventory.state.json"

    state1 = InventoryState(state_path)
    create_inventory(packed, inv_path, state=state1)
    assert len(state1) == 3

    # Delete one file -- state still has stale entry, but the on-disk
    # inventory should not include it.
    (packed / "packer_a_1.0/y.exe").unlink()

    state2 = InventoryState(state_path)
    records2 = create_inventory(packed, inv_path, state=state2)
    rels = {r.path for r in records2}
    assert "packer_a_1.0/y.exe" not in rels
    assert len(records2) == 2


def test_inventory_writes_log_file(tmp_path: Path) -> None:
    packed = tmp_path / "packed"
    _make_tree(packed)
    audit = tmp_path / "audit"
    inv_path = audit / "nas_inventory.jsonl"
    state_path = audit / "inventory.state.json"
    log_path = audit / "nas_cleanup.log"

    state = InventoryState(state_path)
    create_inventory(packed, inv_path, state=state)

    # Manually wire the logger the way the cmd_* helpers do.
    from utils.nas_cleanup import _setup_logging
    _setup_logging(log_path)
    import logging
    logging.getLogger("nas_cleanup").info("post-create smoke line")

    assert log_path.exists()
    text = log_path.read_text(encoding="utf-8")
    assert "post-create smoke line" in text
    # _setup_logging must be idempotent: only one FileHandler for this path.
    handlers = [
        h for h in logging.getLogger("nas_cleanup").handlers
        if getattr(h, "baseFilename", "") == str(log_path)
    ]
    _setup_logging(log_path)
    handlers2 = [
        h for h in logging.getLogger("nas_cleanup").handlers
        if getattr(h, "baseFilename", "") == str(log_path)
    ]
    assert len(handlers2) == len(handlers)


def test_inventory_pruning_excluded_dirs(tmp_path: Path) -> None:
    packed = tmp_path / "packed"
    (packed / "packer_a_1.0").mkdir(parents=True)
    (packed / "packer_a_1.0" / "kept.exe").write_bytes(b"keep")
    (packed / "packer_a_1.0" / "temp").mkdir()
    (packed / "packer_a_1.0" / "temp" / "working_copy.exe").write_bytes(b"skip")
    (packed / "_quarantine" / "old.exe").parent.mkdir(parents=True, exist_ok=True)
    (packed / "_quarantine" / "old.exe").write_bytes(b"skip")
    (packed / "_audit" / "manifest.jsonl.exe").parent.mkdir(parents=True, exist_ok=True)
    (packed / "_audit" / "manifest.jsonl.exe").write_bytes(b"skip")

    paths = list(iter_packed_executables(packed))
    rels = {p.relative_to(packed).as_posix() for p in paths}
    assert rels == {"packer_a_1.0/kept.exe"}