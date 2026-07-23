"""Regression test: pack_single_file must tolerate the shorter args tuple
built by wrapper/upx_scrambler.py (which does not pass sha_gate /
packer_dir_name). A short tuple must degrade to "no gate", never raise
ValueError -- that regression silently failed all 4 upx_scrambler variants.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# packer_runner.py lives in utils/ and imports sibling modules by bare name.
_UTILS = Path(__file__).resolve().parent.parent / "utils"
if str(_UTILS) not in sys.path:
    sys.path.insert(0, str(_UTILS))

import packer_runner as pr  # noqa: E402


def _args(n: int, tmp: Path):
    """Build an args tuple of length n pointing at a missing source so the
    call returns cleanly (False, msg) without needing a real packer."""
    base = [
        str(tmp / "missing_src.exe"),   # src_path
        str(tmp),                        # output_dir
        str(tmp / "nobin.exe"),          # packer_bin
        "{bin} {in} {out}",             # cmd_template
        0,                               # max_size_kb
        5,                               # timeout
        "explicit",                      # output_behavior
        [],                              # dependencies
        {},                              # config
        "",                              # project_file
        "upx",                           # packer_name (11th, required)
        None,                            # sha_gate (12th, optional)
        "upx",                           # packer_dir_name (13th, optional)
    ]
    return tuple(base[:n])


def test_thirteen_field_tuple_does_not_raise(tmp_path: Path):
    ok, msg = pr.pack_single_file(_args(13, tmp_path))
    assert ok is False  # missing source -> clean failure, not a crash


def test_eleven_field_tuple_degrades_to_no_gate(tmp_path: Path):
    # The upx_scrambler intermediate historically passed a short tuple.
    ok, msg = pr.pack_single_file(_args(11, tmp_path))
    assert ok is False
    assert "unpack" not in msg.lower()  # never a ValueError text


def test_ten_field_tuple_still_rejected(tmp_path: Path):
    # Fewer than the 11 genuinely-required fields must still fail loudly
    # (packer_name is not optional).
    with pytest.raises(ValueError):
        pr.pack_single_file(_args(10, tmp_path))
