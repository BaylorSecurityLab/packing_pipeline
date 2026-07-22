from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


def _normalize_type(value: str | None) -> str | None:
    if not value:
        return None
    normalized = value.strip().upper().replace(" ", "_").replace("-", "_")
    return normalized if normalized.startswith("TYPE_") else None


def sample_identity(row: dict) -> str:
    return row.get("packed_sha256") or row["sample_id"]


def repetition_identity(row: dict) -> str:
    repetition = row.get("repetition")
    if repetition is not None:
        return f"rep:{repetition}"
    return f"run:{row.get('run_directory') or row['sample_id']}"


def dynamic_validation(run_dir: Path) -> dict:
    run_path = run_dir / "run.json"
    sample_path = run_dir / "sample.json"
    run = json.loads(run_path.read_text(encoding="utf-8")) if run_path.exists() else {}
    sample = (
        json.loads(sample_path.read_text(encoding="utf-8"))
        if sample_path.exists()
        else {}
    )
    wall_seconds = None
    if run.get("started_at") and run.get("finished_at"):
        try:
            wall_seconds = (
                datetime.fromisoformat(run["finished_at"])
                - datetime.fromisoformat(run["started_at"])
            ).total_seconds()
        except ValueError:
            pass
    return_code = run.get("return_code")
    return {
        "sample_id": sample.get("sample_id", run_dir.name),
        "packed_sha256": sample.get("packed_sha256"),
        "packer_family": sample.get("packer_family"),
        "packer_version": sample.get("packer_version"),
        "test_case_id": sample.get("test_case_id"),
        "configuration_id": sample.get("configuration_id"),
        "original_path": sample.get("original_path"),
        "repetition": sample.get("repetition"),
        "retry_for_dynamic_gate": bool(sample.get("retry_for_dynamic_gate")),
        "retry_mode": sample.get("retry_mode"),
        "run_directory": str(run_dir),
        "backend_return_code": return_code,
        "started_at": run.get("started_at"),
        "finished_at": run.get("finished_at"),
        "wall_seconds": wall_seconds,
        "target_event_counts": {},
        "target_events": 0,
        "dynamically_validated": False,
        "dynamic_failure_reason": (
            None if return_code == 0 else "backend_nonzero_return"
        ),
    }
