from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from statistics import mean, median

from .provisional import dynamic_validation, repetition_identity, sample_identity


def audit_matrix(
    plan_path: Path,
    runs: Path,
    minimum_repetitions: int = 3,
    minimum_distinct_samples: int = 2,
) -> dict:
    if minimum_repetitions < 1 or minimum_distinct_samples < 1:
        raise ValueError("minimum repetitions and distinct samples must be positive")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    expected_configuration_ids = {
        condition["configuration_id"] for condition in plan["conditions"]
    }
    by_configuration: dict[str, list[dict]] = defaultdict(list)
    parse_errors = []
    seen_run_identities: dict[tuple[str, str, str], Path] = {}
    for run_path in runs.rglob("run.json"):
        try:
            row = dynamic_validation(run_path.parent)
            configuration_id = row.get("configuration_id")
            if configuration_id not in expected_configuration_ids:
                parse_errors.append(
                    {
                        "run": str(run_path),
                        "error": f"unknown configuration_id {configuration_id!r}",
                    }
                )
                continue
            run_identity = (
                configuration_id,
                sample_identity(row),
                repetition_identity(row),
            )
            if run_identity in seen_run_identities:
                parse_errors.append(
                    {
                        "run": str(run_path),
                        "error": (
                            "duplicate configuration/sample/repetition identity; "
                            f"first seen at {seen_run_identities[run_identity]}"
                        ),
                    }
                )
                continue
            seen_run_identities[run_identity] = run_path
            by_configuration[configuration_id].append(row)
        except Exception as error:
            parse_errors.append({"run": str(run_path), "error": repr(error)})

    conditions = []
    for planned in plan["conditions"]:
        members = by_configuration.get(planned["configuration_id"], [])
        completed_repetitions: dict[str, set[str]] = defaultdict(set)
        validated_repetitions: dict[str, set[str]] = defaultdict(set)
        for row in members:
            identity = sample_identity(row)
            repetition = repetition_identity(row)
            completed_repetitions[identity].add(repetition)
            if row["dynamically_validated"]:
                validated_repetitions[identity].add(repetition)
        completed_samples = sum(
            len(repetitions) >= minimum_repetitions
            for repetitions in completed_repetitions.values()
        )
        validated_samples = sum(
            len(repetitions) >= minimum_repetitions
            for repetitions in validated_repetitions.values()
        )
        execution_gate = completed_samples >= minimum_distinct_samples
        dynamic_gate = validated_samples >= minimum_distinct_samples
        if planned["status"] != "planned":
            status = planned["status"]
        elif len(planned.get("samples", [])) < minimum_distinct_samples:
            status = "insufficient_source_samples"
        elif dynamic_gate:
            status = "complete"
        elif execution_gate:
            status = "needs_retry"
        elif members:
            status = "pending_repetitions"
        else:
            status = "pending_not_started"
        failures = Counter(
            row["dynamic_failure_reason"]
            for row in members
            if row["dynamic_failure_reason"]
        )
        retry_runs = [row for row in members if row["retry_for_dynamic_gate"]]
        conditions.append(
            {
                "configuration_id": planned["configuration_id"],
                "packer_family": planned["packer_family"],
                "packer_version": planned["packer_version"],
                "test_case_id": planned["test_case_id"],
                "condition_source": planned["source"],
                "nas_status": planned["status"],
                "available_nas_samples": planned["available_samples"],
                "selected_samples": len(planned.get("samples", [])),
                "alternate_samples": len(planned.get("alternate_samples", [])),
                "completed_runs": len(members),
                "completed_distinct_samples": len(completed_repetitions),
                "completed_qualifying_samples": completed_samples,
                "validated_runs": sum(
                    row["dynamically_validated"] for row in members
                ),
                "retry_runs": len(retry_runs),
                "in_place_validation_runs": sum(
                    row.get("retry_mode") == "in_place_validation"
                    for row in retry_runs
                ),
                "alternate_payload_runs": sum(
                    row.get("retry_mode") == "alternate_payload"
                    for row in retry_runs
                ),
                "validated_distinct_samples": len(validated_repetitions),
                "validated_qualifying_samples": validated_samples,
                "qualifying_distinct_samples": validated_samples,
                "execution_gate_met": execution_gate,
                "dynamic_gate_met": dynamic_gate,
                "failure_reasons": dict(failures),
                "status": status,
            }
        )

    planned_count = sum(row["nas_status"] == "planned" for row in conditions)
    status_distribution = Counter(row["status"] for row in conditions)
    executions = [row for members in by_configuration.values() for row in members]
    durations = sorted(
        row["wall_seconds"]
        for row in executions
        if row.get("wall_seconds") is not None
    )
    starts = []
    finishes = []
    for row in executions:
        try:
            if row.get("started_at"):
                starts.append(datetime.fromisoformat(row["started_at"]))
            if row.get("finished_at"):
                finishes.append(datetime.fromisoformat(row["finished_at"]))
        except ValueError:
            continue
    observed_period_seconds = (
        (max(finishes) - min(starts)).total_seconds() if starts and finishes else None
    )
    runs_per_hour = (
        len(executions) / (observed_period_seconds / 3600)
        if observed_period_seconds and observed_period_seconds > 0
        else None
    )
    p95_index = max(0, int(len(durations) * 0.95) - 1) if durations else None
    return {
        "schema_version": 1,
        "minimum_repetitions_per_sample": minimum_repetitions,
        "minimum_distinct_samples": minimum_distinct_samples,
        "minimum_runs_per_populated_condition": (
            minimum_repetitions * minimum_distinct_samples
        ),
        "condition_count": len(conditions),
        "populated_condition_count": planned_count,
        "empty_condition_count": len(conditions) - planned_count,
        "expected_primary_run_count": (
            planned_count * minimum_repetitions * minimum_distinct_samples
        ),
        "observed_run_count": sum(row["completed_runs"] for row in conditions),
        "validated_run_count": sum(row["validated_runs"] for row in conditions),
        "retry_run_count": sum(row["retry_runs"] for row in conditions),
        "in_place_validation_run_count": sum(
            row["in_place_validation_runs"] for row in conditions
        ),
        "alternate_payload_run_count": sum(
            row["alternate_payload_runs"] for row in conditions
        ),
        "timing": {
            "observed_period_seconds": observed_period_seconds,
            "runs_per_hour": round(runs_per_hour, 3) if runs_per_hour else None,
            "estimated_total_hours": round(
                (
                    planned_count
                    * minimum_repetitions
                    * minimum_distinct_samples
                )
                / runs_per_hour,
                3,
            )
            if runs_per_hour
            else None,
            "run_wall_seconds_min": round(min(durations), 3) if durations else None,
            "run_wall_seconds_median": round(median(durations), 3)
            if durations
            else None,
            "run_wall_seconds_mean": round(mean(durations), 3) if durations else None,
            "run_wall_seconds_p95": round(durations[p95_index], 3)
            if p95_index is not None
            else None,
            "run_wall_seconds_max": round(max(durations), 3) if durations else None,
        },
        "dynamic_gate_complete_conditions": sum(
            row["dynamic_gate_met"] for row in conditions
        ),
        "status_distribution": dict(status_distribution),
        "parse_errors": parse_errors,
        "conditions": conditions,
    }
