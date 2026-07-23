"""Tests for utils.sha_gate.

Run with:  uv run pytest
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from utils.sha_gate import ShaGate


def _write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def _make_gate(tmp_path: Path, *, packed_root: Path | None = None) -> ShaGate:
    return ShaGate(
        packed_root=packed_root or (tmp_path / "packed"),
        audit_dir=tmp_path / "audit",
        pipeline="test",
    )


def _read_manifest(gate: ShaGate) -> list[dict]:
    path = gate._manifest_path
    if not path.exists():
        return []
    rows: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


# ---------------------------------------------------------------------------
# 1. Direct pass-through (sha_out == sha_in)
# ---------------------------------------------------------------------------

def test_rejects_output_equal_to_its_input(tmp_path: Path) -> None:
    in_file = tmp_path / "in" / "a.exe"
    out_file = tmp_path / "out" / "a_packed.exe"
    _write_bytes(in_file, b"same-bytes")
    _write_bytes(out_file, b"same-bytes")

    gate = _make_gate(tmp_path)

    result = gate.verify_pack(
        input_path=in_file,
        output_path=out_file,
        packer_dir="packer_a_1.0",
        app="a.exe",
    )

    assert result.accepted is False
    assert result.code == "PACK_FAILED_PASSTHROUGH"
    assert result.message.startswith("PACK_FAILED_PASSTHROUGH packer=packer_a_1.0")
    assert "sha=" in result.message
    assert not out_file.exists()

    rows = _read_manifest(gate)
    assert len(rows) == 1
    assert rows[0]["status"] == "rejected"
    assert rows[0]["code"] == "PACK_FAILED_PASSTHROUGH"
    assert rows[0]["packer_dir"] == "packer_a_1.0"


# ---------------------------------------------------------------------------
# 2. Output equals another batch input
# ---------------------------------------------------------------------------

def test_rejects_output_matching_another_batch_input(tmp_path: Path) -> None:
    in_a = tmp_path / "in" / "a.exe"
    in_b = tmp_path / "in" / "b.exe"
    out_file = tmp_path / "out" / "a_packed.exe"
    _write_bytes(in_a, b"input-a")
    _write_bytes(in_b, b"input-b")
    _write_bytes(out_file, b"input-b")  # packer returned the other input's bytes

    gate = _make_gate(tmp_path)
    gate.prime_inputs([in_a, in_b])

    result = gate.verify_pack(
        input_path=in_a,
        output_path=out_file,
        packer_dir="packer_a_1.0",
        app="a.exe",
    )

    assert result.accepted is False
    assert result.code == "PACK_OUTPUT_MATCHES_OTHER_INPUT"
    assert result.output_sha256 == result.input_sha256 or result.output_sha256 is not None
    assert not out_file.exists()

    rows = _read_manifest(gate)
    assert any(r["code"] == "PACK_OUTPUT_MATCHES_OTHER_INPUT" for r in rows)


# ---------------------------------------------------------------------------
# 3. Cross-packer duplicate
# ---------------------------------------------------------------------------

def test_rejects_sha_published_by_different_packer(tmp_path: Path) -> None:
    in_a = tmp_path / "in" / "a.exe"
    in_b = tmp_path / "in" / "b.exe"
    out_a = tmp_path / "packed" / "packer_a_1.0" / "a.exe"
    out_b = tmp_path / "packed" / "packer_b_1.0" / "b.exe"
    _write_bytes(in_a, b"input-a")
    _write_bytes(in_b, b"input-b")
    _write_bytes(out_a, b"packed-a-bytes")
    # Note: out_b is NOT pre-created; the gate must be allowed to index
    # out_a first, then reject the cross-packer duplicate.

    gate = _make_gate(tmp_path)
    gate.add_input(in_a)

    first = gate.verify_pack(
        input_path=in_a,
        output_path=out_a,
        packer_dir="packer_a_1.0",
        app="a.exe",
    )
    assert first.accepted is True, first.message
    assert out_a.exists()

    # Now produce out_b with the same SHA under a different packer dir.
    _write_bytes(out_b, b"packed-a-bytes")
    gate.add_input(in_b)
    second = gate.verify_pack(
        input_path=in_b,
        output_path=out_b,
        packer_dir="packer_b_1.0",
        app="b.exe",
    )
    assert second.accepted is False
    assert second.code == "PACK_DUP_ACROSS_PACKERS"
    assert "existing_packers=packer_a_1.0" in second.message
    assert not out_b.exists()
    # The first accepted artifact must remain.
    assert out_a.exists()


# ---------------------------------------------------------------------------
# 4. Happy path: distinct inputs + distinct outputs + distinct packers
# ---------------------------------------------------------------------------

def test_accepts_distinct_outputs_and_writes_manifest(tmp_path: Path) -> None:
    in_a = tmp_path / "in" / "a.exe"
    in_b = tmp_path / "in" / "b.exe"
    out_a = tmp_path / "packed" / "packer_a_1.0" / "a.exe"
    out_b = tmp_path / "packed" / "packer_b_1.0" / "b.exe"
    _write_bytes(in_a, b"input-a")
    _write_bytes(in_b, b"input-b")
    _write_bytes(out_a, b"packed-a-unique")
    _write_bytes(out_b, b"packed-b-unique")

    gate = _make_gate(tmp_path)
    gate.add_input(in_a)
    gate.add_input(in_b)

    r1 = gate.verify_pack(
        input_path=in_a, output_path=out_a,
        packer_dir="packer_a_1.0", app="a.exe",
    )
    r2 = gate.verify_pack(
        input_path=in_b, output_path=out_b,
        packer_dir="packer_b_1.0", app="b.exe",
    )

    assert r1.accepted is True
    assert r2.accepted is True
    assert out_a.exists()
    assert out_b.exists()

    rows = _read_manifest(gate)
    accepted = [r for r in rows if r["status"] == "published"]
    assert len(accepted) == 2
    assert {r["packer_dir"] for r in accepted} == {"packer_a_1.0", "packer_b_1.0"}
    assert {r["app"] for r in accepted} == {"a.exe", "b.exe"}
    assert all(r["pipeline"] == "test" for r in accepted)


# ---------------------------------------------------------------------------
# 5. Same-packer duplicate is allowed; cache reconciles preexisting outputs
# ---------------------------------------------------------------------------

def test_reconciles_preexisting_output_index_without_same_packer_false_positive(tmp_path: Path) -> None:
    packed_root = tmp_path / "packed"
    pre_existing = packed_root / "packer_a_1.0" / "presh.exe"
    _write_bytes(pre_existing, b"preshared-bytes")

    # Construct the gate: reconciliation should index the preexisting output.
    gate1 = ShaGate(
        packed_root=packed_root,
        audit_dir=tmp_path / "audit",
        pipeline="test",
    )

    # Same packer_dir + same SHA must be accepted (re-run of an existing file).
    new_in_same_dir = tmp_path / "in" / "c.exe"
    new_out_same_dir = packed_root / "packer_a_1.0" / "c.exe"
    _write_bytes(new_in_same_dir, b"input-c")
    _write_bytes(new_out_same_dir, b"preshared-bytes")  # same SHA, same packer
    gate1.add_input(new_in_same_dir)

    r_same = gate1.verify_pack(
        input_path=new_in_same_dir,
        output_path=new_out_same_dir,
        packer_dir="packer_a_1.0",
        app="c.exe",
    )
    assert r_same.accepted is True, r_same.message

    # Different packer_dir + same SHA must be rejected.
    new_in_other = tmp_path / "in" / "d.exe"
    new_out_other = packed_root / "packer_b_1.0" / "d.exe"
    _write_bytes(new_in_other, b"input-d")
    _write_bytes(new_out_other, b"preshared-bytes")  # same SHA, different packer
    gate1.add_input(new_in_other)

    r_other = gate1.verify_pack(
        input_path=new_in_other,
        output_path=new_out_other,
        packer_dir="packer_b_1.0",
        app="d.exe",
    )
    assert r_other.accepted is False
    assert r_other.code == "PACK_DUP_ACROSS_PACKERS"
    assert "existing_packers=packer_a_1.0" in r_other.message

    # A second gate constructed from the same audit dir must keep the
    # same published state (cache round-trip).
    gate2 = ShaGate(
        packed_root=packed_root,
        audit_dir=tmp_path / "audit",
        pipeline="test",
    )
    in_e = tmp_path / "in" / "e.exe"
    out_e = packed_root / "packer_b_1.0" / "e.exe"
    _write_bytes(in_e, b"input-e")
    _write_bytes(out_e, b"preshared-bytes")
    gate2.add_input(in_e)
    r2 = gate2.verify_pack(
        input_path=in_e,
        output_path=out_e,
        packer_dir="packer_b_1.0",
        app="e.exe",
    )
    assert r2.accepted is False
    assert r2.code == "PACK_DUP_ACROSS_PACKERS"


# ---------------------------------------------------------------------------
# 6. Excluded directories must not enter the published index
# ---------------------------------------------------------------------------

def test_reconciliation_excludes_temp_and_audit_dirs(tmp_path: Path) -> None:
    packed_root = tmp_path / "packed"
    keep = packed_root / "packer_a_1.0" / "good.exe"
    skip_dirs = {
        "temp": packed_root / "packer_a_1.0" / "temp" / "working_copy.exe",
        "_temp_build": packed_root / "packer_a_1.0" / "_temp_build" / "staged.exe",
        "_audit": packed_root / "_audit" / "manifest.jsonl.exe",
        "_quarantine": packed_root / "_quarantine" / "old.exe",
        "_diag": packed_root / "_diag" / "scratch.exe",
        ".qsyncclient": packed_root / ".qsyncclient" / "lock.exe",
    }
    _write_bytes(keep, b"keep-me")
    for p in skip_dirs.values():
        _write_bytes(p, b"do-not-index")

    gate = ShaGate(packed_root=packed_root, audit_dir=tmp_path / "audit", pipeline="test")

    keep_key = str(keep)
    assert keep_key in gate._published_index
    for skip_path in skip_dirs.values():
        assert str(skip_path) not in gate._published_index, f"should skip {skip_path}"


# ---------------------------------------------------------------------------
# 7. PACK_SHA_GATE_ERROR on hash failure (missing input file)
# ---------------------------------------------------------------------------

def test_returns_gate_error_on_missing_input(tmp_path: Path) -> None:
    out_file = tmp_path / "out" / "a.exe"
    _write_bytes(out_file, b"any")

    gate = _make_gate(tmp_path)
    result = gate.verify_pack(
        input_path=tmp_path / "in" / "does_not_exist.exe",
        output_path=out_file,
        packer_dir="packer_a_1.0",
        app="a.exe",
    )
    assert result.accepted is False
    assert result.code == "PACK_SHA_GATE_ERROR"
    assert "PACK_SHA_GATE_ERROR" in result.message


# ---------------------------------------------------------------------------
# 8. Optional debug log
# ---------------------------------------------------------------------------

def test_debug_log_records_accept_and_reject(tmp_path: Path) -> None:
    in_a = tmp_path / "in" / "a.exe"
    in_b = tmp_path / "in" / "b.exe"
    out_a = tmp_path / "packed" / "packer_a_1.0" / "a.exe"
    out_b = tmp_path / "packed" / "packer_b_1.0" / "b.exe"
    _write_bytes(in_a, b"input-a")
    _write_bytes(in_b, b"input-b")
    _write_bytes(out_a, b"packed-a-unique")
    _write_bytes(out_b, b"input-b")  # same as in_b -> pass-through

    gate = ShaGate(
        packed_root=tmp_path / "packed",
        audit_dir=tmp_path / "audit",
        pipeline="test",
        log_debug=True,
    )
    # Register ONLY the input that is actually being packed, so the gate
    # classifies a matching output as PACK_FAILED_PASSTHROUGH (direct)
    # rather than PACK_OUTPUT_MATCHES_OTHER_INPUT.
    gate.add_input(in_b)

    r1 = gate.verify_pack(
        input_path=in_a, output_path=out_a,
        packer_dir="packer_a_1.0", app="a.exe",
    )
    r2 = gate.verify_pack(
        input_path=in_b, output_path=out_b,
        packer_dir="packer_b_1.0", app="b.exe",
    )
    assert r1.accepted is True
    assert r2.accepted is False
    assert r2.code == "PACK_FAILED_PASSTHROUGH"

    log_path = tmp_path / "audit" / "gate.log"
    assert log_path.exists()
    text = log_path.read_text(encoding="utf-8")
    assert "ACCEPT packer=packer_a_1.0 app=a.exe" in text
    assert "REJECT code=PACK_FAILED_PASSTHROUGH packer=packer_b_1.0 app=b.exe" in text


def test_debug_log_disabled_by_default(tmp_path: Path) -> None:
    in_a = tmp_path / "in" / "a.exe"
    out_a = tmp_path / "packed" / "packer_a_1.0" / "a.exe"
    _write_bytes(in_a, b"input-a")
    _write_bytes(out_a, b"packed-a-unique")

    gate = ShaGate(
        packed_root=tmp_path / "packed",
        audit_dir=tmp_path / "audit",
        pipeline="test",
    )
    gate.add_input(in_a)
    gate.verify_pack(
        input_path=in_a, output_path=out_a,
        packer_dir="packer_a_1.0", app="a.exe",
    )

    log_path = tmp_path / "audit" / "gate.log"
    assert not log_path.exists()


def test_enable_debug_log_is_idempotent(tmp_path: Path) -> None:
    packed = tmp_path / "packed"
    audit = tmp_path / "audit"
    audit.mkdir(parents=True)
    gate = ShaGate(packed_root=packed, audit_dir=audit, pipeline="test")
    gate._enable_debug_log()
    handler_count_1 = sum(
        1 for h in _gate_logger().handlers
        if getattr(h, "baseFilename", "") == str(audit / "gate.log")
    )
    gate._enable_debug_log()
    handler_count_2 = sum(
        1 for h in _gate_logger().handlers
        if getattr(h, "baseFilename", "") == str(audit / "gate.log")
    )
    assert handler_count_1 == handler_count_2 == 1


def _gate_logger():
    import logging
    return logging.getLogger("sha_gate")