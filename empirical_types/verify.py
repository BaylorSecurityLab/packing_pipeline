from __future__ import annotations

import csv
import json
import re
from collections import Counter
from pathlib import Path

import yaml

from .provisional import _normalize_type


LABEL_PATTERN = re.compile(
    r"^(?:TYPE_(?:I|II|III|IV)|TYPE_(?:V|VI)-[PFBG]|"
    r"(?:PROVISIONAL_|HYPOTHESIS_ONLY_)TYPE_(?:I|II|III|IV|V|VI))$"
)
BASE_TYPE_PATTERN = re.compile(r"TYPE_(VI|IV|III|II|V|I)(?:$|-[PFBG])")


def _type_group_conflicts(
    rows: list[dict], group_fields: tuple[str, ...]
) -> dict[tuple[str, ...], set[str]]:
    grouped: dict[tuple[str, ...], set[str]] = {}
    for row in rows:
        group = tuple(str(row.get(field, "")) for field in group_fields)
        if not all(group):
            continue
        match = BASE_TYPE_PATTERN.search(str(row.get("label", "")))
        if match:
            grouped.setdefault(group, set()).add(f"TYPE_{match.group(1)}")
    return {group: values for group, values in grouped.items() if len(values) > 1}


def verify_artifacts(
    plan_path: Path,
    audit_path: Path,
    labels_json_path: Path,
    labels_yaml_path: Path,
    labels_csv_path: Path,
    require_all_populated_dynamic: bool = False,
    retry_report_path: Path | None = None,
    require_retry_accounting: bool = False,
) -> dict:
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    labels_json = json.loads(labels_json_path.read_text(encoding="utf-8"))
    labels_yaml = yaml.safe_load(labels_yaml_path.read_text(encoding="utf-8"))
    with labels_csv_path.open(newline="", encoding="utf-8") as handle:
        labels_csv = list(csv.DictReader(handle))
    retry_report = (
        json.loads(retry_report_path.read_text(encoding="utf-8"))
        if retry_report_path
        else None
    )

    errors = []
    warnings = []

    def indexed(rows: list[dict], source: str) -> dict[str, dict]:
        result = {}
        for row in rows:
            configuration_id = row.get("configuration_id")
            if not configuration_id:
                errors.append(f"{source}: condition without configuration_id")
                continue
            if configuration_id in result:
                errors.append(f"{source}: duplicate condition {configuration_id}")
            result[configuration_id] = row
        return result

    plan_by_id = indexed(plan["conditions"], "plan")
    audit_by_id = indexed(audit["conditions"], "audit")
    json_by_id = indexed(labels_json["conditions"], "labels_json")
    yaml_by_id = indexed(labels_yaml["conditions"], "labels_yaml")
    csv_by_id = indexed(labels_csv, "labels_csv")
    expected_ids = set(plan_by_id)

    for document, source in (
        (labels_json, "labels_json"),
        (labels_yaml, "labels_yaml"),
    ):
        rows = document["conditions"]
        expected_summary = {
            "condition_count": len(rows),
            "label_status_distribution": dict(
                Counter(row.get("label_status") for row in rows)
            ),
            "label_distribution": dict(Counter(row.get("label") for row in rows)),
            "nas_status_distribution": dict(
                Counter(row.get("nas_status") for row in rows)
            ),
        }
        for field, expected in expected_summary.items():
            if document.get(field) != expected:
                errors.append(f"{source}: stale or missing {field}")
        expected_design = {
            "schema_version": 1,
            "taxonomy": "Ugarte et al. Type I-VI",
            "minimum_repetitions_per_sample": audit.get(
                "minimum_repetitions_per_sample"
            ),
            "minimum_distinct_samples": audit.get("minimum_distinct_samples"),
            "dynamic_gate_complete_conditions": audit.get(
                "dynamic_gate_complete_conditions"
            ),
            "retry_run_count": audit.get("retry_run_count"),
            "in_place_validation_run_count": audit.get(
                "in_place_validation_run_count"
            ),
            "alternate_payload_run_count": audit.get(
                "alternate_payload_run_count"
            ),
        }
        for field, expected in expected_design.items():
            if field in {
                "retry_run_count",
                "in_place_validation_run_count",
                "alternate_payload_run_count",
            } and expected is None:
                continue
            if expected is None or document.get(field) != expected:
                errors.append(f"{source}: missing or inconsistent {field}")
    for source, rows in (
        ("audit", audit_by_id),
        ("labels_json", json_by_id),
        ("labels_yaml", yaml_by_id),
        ("labels_csv", csv_by_id),
    ):
        missing = sorted(expected_ids - set(rows))
        extra = sorted(set(rows) - expected_ids)
        if missing:
            errors.append(f"{source}: missing {len(missing)} conditions: {missing[:5]}")
        if extra:
            errors.append(f"{source}: extra {len(extra)} conditions: {extra[:5]}")

    for group_fields, description in (
        (("packer_family", "packer_version"), "family/version"),
        (("packer_family",), "family"),
    ):
        for group, values in _type_group_conflicts(
            list(json_by_id.values()), group_fields
        ).items():
            errors.append(
                f"{description} {'/'.join(group)} spans multiple types: "
                f"{sorted(values)}"
            )

    below_dynamic = []
    for configuration_id, planned in plan_by_id.items():
        label = json_by_id.get(configuration_id, {})
        audited = audit_by_id.get(configuration_id, {})
        yaml_label = yaml_by_id.get(configuration_id, {})
        csv_label = csv_by_id.get(configuration_id, {})
        value = label.get("label")
        if not value:
            errors.append(f"{configuration_id}: null label")
            continue
        if not LABEL_PATTERN.fullmatch(value):
            errors.append(f"{configuration_id}: malformed label {value!r}")
        if yaml_label.get("label") != value or csv_label.get("label") != value:
            errors.append(f"{configuration_id}: label differs across JSON/YAML/CSV")
        if label.get("nas_status") != planned.get("status"):
            errors.append(f"{configuration_id}: JSON label NAS status differs from plan")
        if audited.get("nas_status") != planned.get("status"):
            errors.append(f"{configuration_id}: audit NAS status differs from plan")
        identity_fields = (
            ("packer_family", "packer_family"),
            ("packer_version", "packer_version"),
            ("test_case_id", "test_case_id"),
            ("source", "condition_source"),
            ("available_samples", "available_nas_samples"),
        )
        for plan_field, label_field in identity_fields:
            if plan_field not in planned:
                continue
            expected = planned.get(plan_field)
            if label.get(label_field) != expected:
                errors.append(
                    f"{configuration_id}: {label_field} differs from plan"
                )
            if yaml_label.get(label_field) != expected:
                errors.append(
                    f"{configuration_id}: {label_field} differs in YAML"
                )
            expected_csv = "" if expected is None else str(expected)
            if csv_label.get(label_field) != expected_csv:
                errors.append(
                    f"{configuration_id}: {label_field} differs in CSV"
                )
        if "type_hypothesis" in planned:
            expected_hypothesis = _normalize_type(planned.get("type_hypothesis"))
            for source, observed in (
                ("JSON", label.get("taxonomy_hypothesis")),
                ("YAML", yaml_label.get("taxonomy_hypothesis")),
                ("CSV", csv_label.get("taxonomy_hypothesis")),
            ):
                if observed != expected_hypothesis:
                    errors.append(
                        f"{configuration_id}: taxonomy hypothesis differs in {source}"
                    )
        status = label.get("label_status")
        if (
            yaml_label.get("label_status") != status
            or csv_label.get("label_status") != status
        ):
            errors.append(
                f"{configuration_id}: label status differs across JSON/YAML/CSV"
            )
        for field in (
            "completed_runs",
            "validated_runs",
            "retry_runs",
            "in_place_validation_runs",
            "alternate_payload_runs",
            "validated_distinct_samples",
            "qualifying_distinct_samples",
        ):
            if field not in label:
                continue
            if label[field] != audited.get(field):
                errors.append(f"{configuration_id}: {field} differs from audit")
            if yaml_label.get(field) != label[field]:
                errors.append(f"{configuration_id}: {field} differs in YAML")
            if csv_label.get(field) != str(label[field]):
                errors.append(f"{configuration_id}: {field} differs in CSV")
        for field in (
            "validated_target_events",
            "original_mapped_distinct_samples",
            "exact_trace_resolved_runs",
        ):
            if field not in label:
                continue
            if yaml_label.get(field) != label[field]:
                errors.append(f"{configuration_id}: {field} differs in YAML")
            if csv_label.get(field) != str(label[field]):
                errors.append(f"{configuration_id}: {field} differs in CSV")
        if "target_event_totals" in label:
            if yaml_label.get("target_event_totals") != label["target_event_totals"]:
                errors.append(
                    f"{configuration_id}: target_event_totals differs in YAML"
                )
            try:
                csv_target_events = json.loads(
                    csv_label.get("target_event_totals", "")
                )
            except json.JSONDecodeError:
                csv_target_events = None
            if csv_target_events != label["target_event_totals"]:
                errors.append(
                    f"{configuration_id}: target_event_totals differs in CSV"
                )
        if status == "empirical_exact_trace_consensus":
            if value.startswith(("PROVISIONAL_", "HYPOTHESIS_ONLY_")):
                errors.append(f"{configuration_id}: exact status has prefixed label")
        elif status == "provisional_stack_cross_check":
            if not value.startswith("PROVISIONAL_"):
                errors.append(f"{configuration_id}: provisional status lacks prefix")
        elif status == "pending_dynamic_evidence":
            if not value.startswith("HYPOTHESIS_ONLY_"):
                errors.append(f"{configuration_id}: pending status lacks hypothesis prefix")
        else:
            errors.append(f"{configuration_id}: unknown label status {status!r}")
        if planned.get("status") == "planned" and not audited.get("dynamic_gate_met"):
            below_dynamic.append(configuration_id)
    if below_dynamic:
        message = f"{len(below_dynamic)} populated conditions remain below the dynamic gate"
        if require_all_populated_dynamic:
            errors.append(message)
        else:
            warnings.append(message)
    exhausted_below_dynamic = 0
    if retry_report is not None:
        retry_by_id = {
            row["configuration_id"]: row for row in retry_report.get("shortfalls", [])
        }
        for configuration_id in below_dynamic:
            retry = retry_by_id.get(configuration_id)
            exhausted = bool(
                retry
                and retry.get("retry_samples_staged") == 0
                and retry.get("unused_alternates_remaining") == 0
            )
            if exhausted:
                exhausted_below_dynamic += 1
            elif require_retry_accounting:
                errors.append(
                    f"{configuration_id}: below dynamic gate without exhausted alternates"
                )
        if require_retry_accounting and retry_report.get("conditions_not_ready"):
            errors.append(
                f"retry report has {retry_report['conditions_not_ready']} primary conditions not ready"
            )
    elif require_retry_accounting and below_dynamic:
        errors.append("retry accounting required but no retry report was supplied")
    if audit.get("parse_errors"):
        errors.append(f"audit contains {len(audit['parse_errors'])} parse errors")

    return {
        "schema_version": 1,
        "valid": not errors,
        "condition_count": len(expected_ids),
        "populated_condition_count": sum(
            row.get("status") == "planned" for row in plan_by_id.values()
        ),
        "dynamic_gate_complete_conditions": audit.get(
            "dynamic_gate_complete_conditions"
        ),
        "populated_below_dynamic_gate": len(below_dynamic),
        "exhausted_below_dynamic_gate": exhausted_below_dynamic,
        "errors": errors,
        "warnings": warnings,
    }
