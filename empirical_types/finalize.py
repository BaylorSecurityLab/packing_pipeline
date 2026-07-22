from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import yaml

from .provisional import (
    dynamic_validation,
    repetition_identity,
    sample_identity,
)


EXACT_TYPE_PATTERN = re.compile(
    r"^(?:TYPE_(?:I|II|III|IV)|TYPE_(?:V|VI)-[PFBG])$"
)


def _resolved_classification(run_dir: Path, expected_sample_id: str) -> str | None:
    path = run_dir / "classification.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    value = data.get("complexity_type")
    if not isinstance(value, str) or not EXACT_TYPE_PATTERN.fullmatch(value):
        return None
    if data.get("sample_id") != expected_sample_id:
        return None
    if data.get("termination") != "completed":
        return None
    if data.get("trace_complete") is not True:
        return None
    if data.get("taxonomy_basis") == "paper_runtime_heuristic":
        return value
    if data.get("original_match_available") is not True:
        return None
    coverage = data.get("union_code_coverage")
    if not isinstance(coverage, (int, float)) or coverage < 0.05:
        return None
    return value


def finalize_labels(
    plan_path: Path,
    runs: Path,
    minimum_repetitions: int,
    minimum_distinct_samples: int,
    output_json: Path,
    output_yaml: Path,
    output_csv: Path | None = None,
) -> list[dict]:
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    executions = []
    for run_path in runs.rglob("run.json"):
        row = dynamic_validation(run_path.parent)
        row["resolved_classification"] = _resolved_classification(
            run_path.parent, row["sample_id"]
        )
        executions.append(row)
    by_configuration = defaultdict(list)
    for row in executions:
        by_configuration[row["configuration_id"]].append(row)

    conditions = []
    for planned in plan["conditions"]:
        members = by_configuration.get(planned["configuration_id"], [])
        validated = [row for row in members if row["dynamically_validated"]]
        exact = [
            row["resolved_classification"]
            for row in members
            if row["resolved_classification"]
        ]
        exact_counts = Counter(exact)
        original_mapped_samples = {
            sample_identity(row) for row in members if row.get("original_path")
        }
        target_event_totals = Counter()
        for row in validated:
            target_event_totals.update(row.get("target_event_counts", {}))
        retry_runs = [row for row in members if row["retry_for_dynamic_gate"]]
        distinct_validated = len({sample_identity(row) for row in validated})
        validated_by_sample: dict[str, set[str]] = defaultdict(set)
        for row in validated:
            validated_by_sample[sample_identity(row)].add(repetition_identity(row))
        qualifying_samples = {
            sample_id for sample_id, repetitions in validated_by_sample.items()
            if len(repetitions) >= minimum_repetitions
        }
        meets_dynamic_gate = len(qualifying_samples) >= minimum_distinct_samples
        label = None
        status = None
        confidence = 0.0
        evidence_level = None
        exact_by_sample: dict[str, dict[str, set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )
        for row in members:
            if row["resolved_classification"]:
                exact_by_sample[sample_identity(row)][repetition_identity(row)].add(
                    row["resolved_classification"]
                )
        exact_qualifying_samples = {
            sample_id: next(iter(all_values))
            for sample_id, repetitions in exact_by_sample.items()
            if len(repetitions) >= minimum_repetitions
            and all(len(values) == 1 for values in repetitions.values())
            and len(
                all_values := {
                    value for values in repetitions.values() for value in values
                }
            )
            == 1
        }
        exact_consensus = set(exact_qualifying_samples.values())
        if (
            len(exact_qualifying_samples) >= minimum_distinct_samples
            and len(exact_consensus) == 1
        ):
            label = next(iter(exact_consensus))
            status = "empirical_exact_trace_consensus"
            confidence = 0.95
            evidence_level = "A_exact_layer_frame_trace"
        conditions.append(
            {
                "packer_family": planned["packer_family"],
                "packer_version": planned["packer_version"],
                "configuration_id": planned["configuration_id"],
                "test_case_id": planned["test_case_id"],
                "condition_source": planned["source"],
                "nas_status": planned["status"],
                "available_nas_samples": planned["available_samples"],
                "minimum_repetitions_per_sample": minimum_repetitions,
                "minimum_distinct_samples": minimum_distinct_samples,
                "minimum_total_validated_runs": (
                    minimum_repetitions * minimum_distinct_samples
                ),
                "completed_runs": len(members),
                "validated_runs": len(validated),
                "retry_runs": len(retry_runs),
                "in_place_validation_runs": sum(
                    row.get("retry_mode") == "in_place_validation"
                    for row in retry_runs
                ),
                "alternate_payload_runs": sum(
                    row.get("retry_mode") == "alternate_payload"
                    for row in retry_runs
                ),
                "validated_distinct_samples": distinct_validated,
                "qualifying_distinct_samples": len(qualifying_samples),
                "validated_target_events": sum(
                    row.get("target_events", 0) for row in validated
                ),
                "target_event_totals": dict(target_event_totals),
                "original_mapped_distinct_samples": len(original_mapped_samples),
                "exact_trace_resolved_runs": len(exact),
                "exact_trace_distribution": dict(exact_counts),
                "dynamic_failure_reasons": dict(
                    Counter(
                        row["dynamic_failure_reason"]
                        for row in members
                        if row["dynamic_failure_reason"]
                    )
                ),
                "label": label,
                "label_status": status,
                "confidence": confidence,
                "paper_evidence_level": evidence_level,
                "executions": members,
            }
        )

    label_status_distribution = Counter(row["label_status"] for row in conditions)
    label_distribution = Counter(row["label"] for row in conditions)
    nas_status_distribution = Counter(row["nas_status"] for row in conditions)
    dynamic_gate_complete_conditions = sum(
        row["qualifying_distinct_samples"] >= minimum_distinct_samples
        for row in conditions
    )
    retry_run_count = sum(row["retry_runs"] for row in conditions)
    in_place_validation_run_count = sum(
        row["in_place_validation_runs"] for row in conditions
    )
    alternate_payload_run_count = sum(
        row["alternate_payload_runs"] for row in conditions
    )
    summary = {
        "schema_version": 1,
        "taxonomy": "Ugarte et al. Type I-VI",
        "minimum_repetitions_per_sample": minimum_repetitions,
        "minimum_distinct_samples": minimum_distinct_samples,
        "condition_count": len(conditions),
        "label_status_distribution": dict(label_status_distribution),
        "label_distribution": dict(label_distribution),
        "nas_status_distribution": dict(nas_status_distribution),
        "dynamic_gate_complete_conditions": dynamic_gate_complete_conditions,
        "retry_run_count": retry_run_count,
        "in_place_validation_run_count": in_place_validation_run_count,
        "alternate_payload_run_count": alternate_payload_run_count,
        "conditions": conditions,
    }
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    compact = []
    for condition in conditions:
        compact.append(
            {key: value for key, value in condition.items() if key != "executions"}
        )
    output_yaml.parent.mkdir(parents=True, exist_ok=True)
    output_yaml.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "taxonomy": "Ugarte et al. Type I-VI",
                "warning": (
                    "Only empirical_exact_trace_consensus is an exact paper-faithful "
                    "measurement; conditions without it remain explicitly unresolved."
                ),
                "minimum_repetitions_per_sample": minimum_repetitions,
                "minimum_distinct_samples": minimum_distinct_samples,
                "condition_count": len(conditions),
                "label_status_distribution": dict(label_status_distribution),
                "label_distribution": dict(label_distribution),
                "nas_status_distribution": dict(nas_status_distribution),
                "dynamic_gate_complete_conditions": dynamic_gate_complete_conditions,
                "retry_run_count": retry_run_count,
                "in_place_validation_run_count": in_place_validation_run_count,
                "alternate_payload_run_count": alternate_payload_run_count,
                "conditions": compact,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    if output_csv:
        output_csv.parent.mkdir(parents=True, exist_ok=True)
        fields = [
            "packer_family",
            "packer_version",
            "test_case_id",
            "configuration_id",
            "condition_source",
            "nas_status",
            "available_nas_samples",
            "completed_runs",
            "validated_runs",
            "retry_runs",
            "in_place_validation_runs",
            "alternate_payload_runs",
            "validated_distinct_samples",
            "qualifying_distinct_samples",
            "validated_target_events",
            "target_event_totals",
            "original_mapped_distinct_samples",
            "exact_trace_resolved_runs",
            "label",
            "label_status",
            "confidence",
            "paper_evidence_level",
            "dynamic_failure_reasons",
            "exact_trace_distribution",
        ]
        with output_csv.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for condition in conditions:
                row = {key: condition.get(key) for key in fields}
                row["dynamic_failure_reasons"] = json.dumps(
                    row["dynamic_failure_reasons"], sort_keys=True
                )
                row["target_event_totals"] = json.dumps(
                    row["target_event_totals"], sort_keys=True
                )
                row["exact_trace_distribution"] = json.dumps(
                    row["exact_trace_distribution"], sort_keys=True
                )
                writer.writerow(row)
    return conditions
