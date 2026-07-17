from __future__ import annotations

import json
from pathlib import Path

from .audit import audit_matrix
from .collector import collect_drakrun, find_drakrun
from .finalize import finalize_labels
from .nas import stage_retry_matrix
from .verify import verify_artifacts


def finish_matrix(
    plan: Path,
    runs: Path,
    retry_destination: Path,
    output_directory: Path,
    manifest_output: Path,
    minimum_repetitions: int = 3,
    minimum_distinct_samples: int = 2,
    timeout: int = 10,
    max_retry_batches: int = 7,
    drakrun_path: str | None = None,
) -> dict:
    """Exhaust retry candidates, finalize all formats, and verify provenance."""
    output_directory.mkdir(parents=True, exist_ok=True)
    drakrun = find_drakrun(drakrun_path)
    final_retry_report = None
    retry_runs = 0
    retry_batches = 0

    for round_number in range(1, max_retry_batches + 2):
        inventory_path = output_directory / f"retry_inventory.{round_number:02d}.jsonl"
        report_path = output_directory / f"retry_report.{round_number:02d}.json"
        report = stage_retry_matrix(
            plan,
            runs,
            retry_destination,
            inventory_path,
            minimum_repetitions,
            minimum_distinct_samples,
        )
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        if report["conditions_not_ready"]:
            raise RuntimeError(
                f"primary matrix is incomplete for {report['conditions_not_ready']} conditions"
            )
        if report["staged_samples"] == 0:
            final_retry_report = report
            break
        if round_number > max_retry_batches:
            raise RuntimeError(
                f"retry candidates remain after {max_retry_batches} batches"
            )
        retry_batches += 1
        records = [
            json.loads(line)
            for line in inventory_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        for record in records:
            repetitions = record.get("retry_repetitions") or range(
                1, minimum_repetitions + 1
            )
            for repetition in repetitions:
                collect_drakrun(
                    record,
                    runs,
                    timeout,
                    drakrun,
                    repetition=repetition,
                )
                retry_runs += 1
    if final_retry_report is None:
        raise RuntimeError("retry workflow ended without a final exhaustion report")

    final_retry_path = output_directory / "retry_report.final.json"
    final_retry_path.write_text(
        json.dumps(final_retry_report, indent=2) + "\n", encoding="utf-8"
    )
    audit_path = output_directory / "audit.final.json"
    audit = audit_matrix(
        plan, runs, minimum_repetitions, minimum_distinct_samples
    )
    audit_path.write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8")

    labels_json = output_directory / "labels.json"
    labels_csv = output_directory / "labels.csv"
    finalize_labels(
        plan,
        runs,
        minimum_repetitions,
        minimum_distinct_samples,
        labels_json,
        manifest_output,
        labels_csv,
    )
    verification_path = output_directory / "verification.json"
    verification = verify_artifacts(
        plan,
        audit_path,
        labels_json,
        manifest_output,
        labels_csv,
        retry_report_path=final_retry_path,
        require_retry_accounting=True,
    )
    verification_path.write_text(
        json.dumps(verification, indent=2) + "\n", encoding="utf-8"
    )
    if not verification["valid"]:
        raise RuntimeError(
            f"final artifact verification failed: {verification['errors'][:3]}"
        )
    return {
        "retry_batches": retry_batches,
        "retry_runs": retry_runs,
        "dynamic_gate_complete_conditions": audit[
            "dynamic_gate_complete_conditions"
        ],
        "exhausted_below_dynamic_gate": verification[
            "exhausted_below_dynamic_gate"
        ],
        "condition_count": verification["condition_count"],
        "verification": str(verification_path),
        "manifest": str(manifest_output),
    }
