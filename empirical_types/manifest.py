from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterator

import yaml


def load_conditions(path: Path) -> dict[str, dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return {case["id"]: case for case in data.get("test_cases", [])}


def condition_id(case: dict) -> str:
    identity = {
        "packer_family": case["packer_family"],
        "version": str(case["version"]),
        "architecture": case.get("supported_output_arch"),
        "test_case": case["id"],
        "cli_template": case.get("cli_template"),
    }
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[
        :12
    ]
    return f"{case['id'].lower()}-{digest}"


def inventory(
    root: Path,
    manifest_path: Path,
    original_root: Path | None = None,
    case_id_override: str | None = None,
) -> Iterator[dict]:
    cases = load_conditions(manifest_path)
    for sample in sorted(root.rglob("*.exe")):
        try:
            case_id = case_id_override or sample.parent.name
            case = cases[case_id]
        except KeyError:
            continue
        original = original_root / "x86" / sample.name if original_root else None
        packed_sha256 = hashlib.sha256(sample.read_bytes()).hexdigest()
        sample_id = hashlib.sha256(
            (packed_sha256 + "\0" + str(sample.resolve())).encode()
        ).hexdigest()
        yield {
            "sample_id": sample_id,
            "packed_sha256": packed_sha256,
            "packed_path": str(sample.resolve()),
            "original_path": str(original.resolve())
            if original and original.exists()
            else None,
            "configuration_id": condition_id(case),
            "test_case_id": case_id,
            "packer_family": case["packer_family"],
            "packer_name": case["packer_name"],
            "packer_version": str(case["version"]),
            "architecture": case.get("supported_output_arch"),
            "command_label": case.get("command_label"),
            "cli_template": case.get("cli_template"),
        }
