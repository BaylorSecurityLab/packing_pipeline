import csv
import json
import tempfile
import unittest
from pathlib import Path

import yaml

from empirical_types.verify import (
    LABEL_PATTERN,
    _type_group_conflicts,
    verify_artifacts,
)


class VerifyTests(unittest.TestCase):
    def test_detects_type_spans_within_packer_group(self):
        rows = [
            {
                "packer_family": "p",
                "packer_version": "1",
                "label": "PROVISIONAL_TYPE_I",
            },
            {
                "packer_family": "p",
                "packer_version": "1",
                "label": "HYPOTHESIS_ONLY_TYPE_III",
            },
        ]
        conflicts = _type_group_conflicts(
            rows, ("packer_family", "packer_version")
        )
        self.assertEqual(conflicts, {("p", "1"): {"TYPE_I", "TYPE_III"}})

    def test_exact_granularity_suffix_is_limited_to_types_v_and_vi(self):
        self.assertIsNotNone(LABEL_PATTERN.fullmatch("TYPE_I"))
        self.assertIsNotNone(LABEL_PATTERN.fullmatch("TYPE_V-P"))
        self.assertIsNotNone(LABEL_PATTERN.fullmatch("PROVISIONAL_TYPE_V"))
        self.assertIsNone(LABEL_PATTERN.fullmatch("TYPE_I-P"))
        self.assertIsNone(LABEL_PATTERN.fullmatch("TYPE_V"))
        self.assertIsNone(LABEL_PATTERN.fullmatch("PROVISIONAL_TYPE_I-P"))

    def test_retry_accounting_requires_exhausted_alternates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            condition = {
                "configuration_id": "c",
                "status": "planned",
            }
            label = {
                "configuration_id": "c",
                "nas_status": "planned",
                "label": "HYPOTHESIS_ONLY_TYPE_I",
                "label_status": "pending_dynamic_evidence",
            }
            audit_condition = {
                "configuration_id": "c",
                "nas_status": "planned",
                "dynamic_gate_met": False,
            }
            plan = root / "plan.json"
            audit = root / "audit.json"
            labels_json = root / "labels.json"
            labels_yaml = root / "labels.yaml"
            labels_csv = root / "labels.csv"
            retry = root / "retry.json"
            plan.write_text(json.dumps({"conditions": [condition]}), encoding="utf-8")
            audit.write_text(
                json.dumps(
                    {
                        "minimum_repetitions_per_sample": 3,
                        "minimum_distinct_samples": 2,
                        "dynamic_gate_complete_conditions": 0,
                        "parse_errors": [],
                        "conditions": [audit_condition],
                    }
                ),
                encoding="utf-8",
            )
            labels_json.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "taxonomy": "Ugarte et al. Type I-VI",
                        "minimum_repetitions_per_sample": 3,
                        "minimum_distinct_samples": 2,
                        "dynamic_gate_complete_conditions": 0,
                        "condition_count": 1,
                        "label_status_distribution": {
                            "pending_dynamic_evidence": 1
                        },
                        "label_distribution": {"HYPOTHESIS_ONLY_TYPE_I": 1},
                        "nas_status_distribution": {"planned": 1},
                        "conditions": [label],
                    }
                ),
                encoding="utf-8",
            )
            labels_yaml.write_text(
                yaml.safe_dump(
                    {
                        "schema_version": 1,
                        "taxonomy": "Ugarte et al. Type I-VI",
                        "minimum_repetitions_per_sample": 3,
                        "minimum_distinct_samples": 2,
                        "dynamic_gate_complete_conditions": 0,
                        "condition_count": 1,
                        "label_status_distribution": {
                            "pending_dynamic_evidence": 1
                        },
                        "label_distribution": {"HYPOTHESIS_ONLY_TYPE_I": 1},
                        "nas_status_distribution": {"planned": 1},
                        "conditions": [label],
                    }
                ),
                encoding="utf-8",
            )
            with labels_csv.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=label.keys())
                writer.writeheader()
                writer.writerow(label)
            retry.write_text(
                json.dumps(
                    {
                        "conditions_not_ready": 0,
                        "shortfalls": [
                            {
                                "configuration_id": "c",
                                "retry_samples_staged": 0,
                                "unused_alternates_remaining": 0,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = verify_artifacts(
                plan,
                audit,
                labels_json,
                labels_yaml,
                labels_csv,
                retry_report_path=retry,
                require_retry_accounting=True,
            )
            self.assertTrue(result["valid"])
            self.assertEqual(result["exhausted_below_dynamic_gate"], 1)

    def test_consistent_hypothesis_only_artifacts_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            condition = {
                "configuration_id": "c",
                "packer_family": "p",
                "packer_version": "1",
                "test_case_id": None,
                "source": "gui_family_version",
                "status": "missing_on_nas",
                "available_samples": 0,
            }
            label = {
                "configuration_id": "c",
                "packer_family": "p",
                "packer_version": "1",
                "test_case_id": None,
                "condition_source": "gui_family_version",
                "nas_status": "missing_on_nas",
                "available_nas_samples": 0,
                "taxonomy_hypothesis": None,
                "label": "HYPOTHESIS_ONLY_TYPE_I",
                "label_status": "pending_dynamic_evidence",
            }
            audit = {
                "minimum_repetitions_per_sample": 3,
                "minimum_distinct_samples": 2,
                "dynamic_gate_complete_conditions": 0,
                "parse_errors": [],
                "conditions": [
                    {
                        "configuration_id": "c",
                        "nas_status": "missing_on_nas",
                        "dynamic_gate_met": False,
                    }
                ],
            }
            paths = {
                name: root / name
                for name in ("plan.json", "audit.json", "labels.json", "labels.yaml", "labels.csv")
            }
            paths["plan.json"].write_text(
                json.dumps({"conditions": [condition]}), encoding="utf-8"
            )
            paths["audit.json"].write_text(json.dumps(audit), encoding="utf-8")
            paths["labels.json"].write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "taxonomy": "Ugarte et al. Type I-VI",
                        "minimum_repetitions_per_sample": 3,
                        "minimum_distinct_samples": 2,
                        "dynamic_gate_complete_conditions": 0,
                        "condition_count": 1,
                        "label_status_distribution": {
                            "pending_dynamic_evidence": 1
                        },
                        "label_distribution": {"HYPOTHESIS_ONLY_TYPE_I": 1},
                        "nas_status_distribution": {"missing_on_nas": 1},
                        "conditions": [label],
                    }
                ),
                encoding="utf-8",
            )
            paths["labels.yaml"].write_text(
                yaml.safe_dump(
                    {
                        "schema_version": 1,
                        "taxonomy": "Ugarte et al. Type I-VI",
                        "minimum_repetitions_per_sample": 3,
                        "minimum_distinct_samples": 2,
                        "dynamic_gate_complete_conditions": 0,
                        "condition_count": 1,
                        "label_status_distribution": {
                            "pending_dynamic_evidence": 1
                        },
                        "label_distribution": {"HYPOTHESIS_ONLY_TYPE_I": 1},
                        "nas_status_distribution": {"missing_on_nas": 1},
                        "conditions": [label],
                    }
                ),
                encoding="utf-8",
            )
            with paths["labels.csv"].open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=label.keys())
                writer.writeheader()
                writer.writerow(label)
            result = verify_artifacts(
                paths["plan.json"],
                paths["audit.json"],
                paths["labels.json"],
                paths["labels.yaml"],
                paths["labels.csv"],
            )
            self.assertTrue(result["valid"])
            self.assertEqual(result["condition_count"], 1)
            stale = json.loads(paths["labels.json"].read_text())
            stale["condition_count"] = 2
            paths["labels.json"].write_text(json.dumps(stale), encoding="utf-8")
            result = verify_artifacts(
                paths["plan.json"],
                paths["audit.json"],
                paths["labels.json"],
                paths["labels.yaml"],
                paths["labels.csv"],
            )
            self.assertFalse(result["valid"])
            self.assertIn(
                "labels_json: stale or missing condition_count", result["errors"]
            )


if __name__ == "__main__":
    unittest.main()
