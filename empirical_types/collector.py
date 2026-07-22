from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .model import Classification, Evidence, UNRESOLVED


DEFAULT_PLUGINS = ("procmon", "apimon", "exmon", "memdump", "filetracer")
BACKEND_FAILURE_MARKERS = (
    "cannot open libxc handle",
    "privileged command interface",
    "process exited with exit code 1",
    "failed to restore vm",
    "device model did not start",
    "failed to find an available port",
)


def _is_backend_failure(stderr: str) -> bool:
    lowered = stderr.lower()
    return any(marker in lowered for marker in BACKEND_FAILURE_MARKERS)


def _write_json(path: Path, data: dict) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def collect_drakrun(
    record: dict,
    output_root: Path,
    timeout: int,
    drakrun: str,
    dry_run: bool = False,
    repetition: int | None = None,
) -> Classification:
    """Run broad DRAKVUF collection. Deep Type evidence is deliberately unresolved.

    DRAKVUF artifacts are retained for later fusion with a normalized write/exec
    trace. The stock plugins do not prove instruction-to-write relationships.
    """
    run_dir = output_root / record["sample_id"]
    if repetition is not None:
        run_dir = run_dir / f"rep_{repetition:03d}"
    result_path = run_dir / "classification.json"
    if result_path.exists():
        try:
            data = json.loads(result_path.read_text(encoding="utf-8"))
            evidence_values = {
                key: data[key]
                for key in Evidence.__dataclass_fields__
                if key in data
            }
            e = Evidence(**evidence_values)
            if e.sample_id != record["sample_id"]:
                raise ValueError("cached classification belongs to another sample")
            if (
                e.termination == "backend_failure"
                or data["complexity_type"] == UNRESOLVED["backend_failure"]
            ):
                raise ValueError("retry transient backend failure")
            return Classification(
                data["complexity_type"], data["confidence"], e, data["rule"]
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            result_path.unlink(missing_ok=True)
    run_dir.mkdir(parents=True, exist_ok=True)
    run_record = {**record, "repetition": repetition}
    _write_json(run_dir / "sample.json", run_record)
    analysis_dir = run_dir / "drakrun"
    if analysis_dir.exists():
        shutil.rmtree(analysis_dir)
    command = [
        drakrun,
        "analyze",
        "--sample",
        record["packed_path"],
        "--output-dir",
        str(analysis_dir),
        "--timeout",
        str(timeout),
        "--net-disable",
        "--no-screenshotter",
        "--no-post-restore",
    ]
    for plugin in DEFAULT_PLUGINS:
        command.extend(("--plugin", plugin))
    if os.geteuid() != 0 and os.environ.get("PACKER_DRAKRUN_SUDO") == "1":
        command = ["sudo", "-n", *command]
    metadata = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "command": command,
        "backend": "drakrun",
    }
    if dry_run:
        metadata["dry_run"] = True
        return Classification(
            UNRESOLVED["trace_loss"],
            1.0,
            Evidence(record["sample_id"], trace_complete=False),
            "dry run",
        )
    termination = "completed"
    try:
        completed = subprocess.run(
            command, check=False, timeout=timeout + 120, capture_output=True, text=True
        )
        metadata["attempt_count"] = 1
        metadata["attempts"] = [
            {
                "return_code": completed.returncode,
                "stderr_tail": completed.stderr[-2000:],
            }
        ]
        recovery = os.environ.get("PACKER_DRAKRUN_RECOVERY")
        if completed.returncode != 0 and _is_backend_failure(completed.stderr) and recovery:
            recovery_command = [recovery]
            if os.geteuid() != 0:
                recovery_command = ["sudo", "-n", *recovery_command]
            recovered = subprocess.run(
                recovery_command,
                check=False,
                timeout=60,
                capture_output=True,
                text=True,
            )
            metadata["backend_recovery_return_code"] = recovered.returncode
            metadata["backend_recovery_stderr_tail"] = recovered.stderr[-2000:]
            if recovered.returncode == 0:
                if analysis_dir.exists():
                    shutil.rmtree(analysis_dir)
                completed = subprocess.run(
                    command,
                    check=False,
                    timeout=timeout + 120,
                    capture_output=True,
                    text=True,
                )
                metadata["attempt_count"] = 2
                metadata["attempts"].append(
                    {
                        "return_code": completed.returncode,
                        "stderr_tail": completed.stderr[-2000:],
                    }
                )
        if completed.returncode != 0:
            termination = "crash"
            metadata["stderr_tail"] = completed.stderr[-4000:]
            if _is_backend_failure(completed.stderr):
                termination = "backend_failure"
        metadata["return_code"] = completed.returncode
    except subprocess.TimeoutExpired:
        termination = "timeout"
        metadata["return_code"] = None
    metadata["finished_at"] = datetime.now(timezone.utc).isoformat()
    _write_json(run_dir / "run.json", metadata)
    evidence = Evidence(
        record["sample_id"],
        termination=termination,
        trace_complete=False,
        original_match_available=bool(record.get("original_path")),
        notes=[
            "Stock DRAKVUF evidence lacks exact basic-block write/execute provenance"
        ],
    )
    if termination == "timeout":
        result = Classification(
            UNRESOLVED["timeout"], 1.0, evidence, "execution timed out"
        )
    elif termination == "backend_failure":
        result = Classification(
            UNRESOLVED["backend_failure"],
            1.0,
            evidence,
            "DRAKVUF/Xen backend failed before sample execution",
        )
    elif termination == "crash":
        result = Classification(
            UNRESOLVED["crash"], 1.0, evidence, "drakrun returned non-zero"
        )
    else:
        result = Classification(
            UNRESOLVED["trace_loss"], 1.0, evidence, "deep trace not yet fused"
        )
    _write_json(result_path, result.to_dict())
    return result


def find_drakrun(explicit: str | None) -> str:
    candidates = [explicit, shutil.which("drakrun"), "/opt/pydrakvuf/.venv/bin/drakrun"]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise FileNotFoundError("drakrun not found; pass --drakrun")
