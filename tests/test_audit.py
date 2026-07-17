import json
import tempfile
import unittest
from pathlib import Path

from empirical_types.audit import audit_matrix


class AuditTests(unittest.TestCase):
    def test_rejects_unknown_and_duplicate_run_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "plan.json"
            plan.write_text(
                json.dumps(
                    {
                        "conditions": [
                            {
                                "configuration_id": "c",
                                "packer_family": "p",
                                "packer_version": "1",
                                "test_case_id": "CASE",
                                "source": "yaml_test_case",
                                "status": "planned",
                                "available_samples": 2,
                                "samples": [{}, {}],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            records = (
                ("first", "c", "same-content", 1),
                ("duplicate", "c", "same-content", 1),
                ("orphan", "unknown", "other-content", 1),
            )
            for directory_name, configuration_id, packed_sha256, repetition in records:
                run = root / "runs" / directory_name
                run.mkdir(parents=True)
                (run / "run.json").write_text('{"return_code":1}', encoding="utf-8")
                (run / "sample.json").write_text(
                    json.dumps(
                        {
                            "sample_id": directory_name,
                            "packed_sha256": packed_sha256,
                            "configuration_id": configuration_id,
                            "repetition": repetition,
                            "retry_for_dynamic_gate": directory_name == "first",
                            "retry_mode": (
                                "alternate_payload"
                                if directory_name == "first"
                                else None
                            ),
                        }
                    ),
                    encoding="utf-8",
                )
            result = audit_matrix(plan, root / "runs")
            self.assertEqual(result["observed_run_count"], 1)
            self.assertEqual(result["retry_run_count"], 1)
            self.assertEqual(result["alternate_payload_run_count"], 1)
            self.assertEqual(len(result["parse_errors"]), 2)
            self.assertTrue(
                any("duplicate" in row["error"] for row in result["parse_errors"])
            )
            self.assertTrue(
                any(
                    "unknown configuration_id" in row["error"]
                    for row in result["parse_errors"]
                )
            )

    def test_preserves_missing_nas_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "plan.json"
            plan.write_text(
                json.dumps(
                    {
                        "conditions": [
                            {
                                "configuration_id": "missing",
                                "packer_family": "p",
                                "packer_version": "1",
                                "test_case_id": None,
                                "source": "gui_family_version",
                                "status": "missing_on_nas",
                                "available_samples": 0,
                                "samples": [],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            result = audit_matrix(plan, root / "runs")
            self.assertEqual(result["conditions"][0]["status"], "missing_on_nas")

    def test_distinguishes_completed_execution_from_dynamic_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "plan.json"
            plan.write_text(
                json.dumps(
                    {
                        "conditions": [
                            {
                                "configuration_id": "c",
                                "packer_family": "p",
                                "packer_version": "1",
                                "test_case_id": "CASE",
                                "source": "yaml_test_case",
                                "status": "planned",
                                "available_samples": 2,
                                "samples": [{}, {}],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            for sample in ("a", "b"):
                for repetition in range(1, 4):
                    run = root / "runs" / sample / f"rep_{repetition:03d}"
                    drakrun = run / "drakrun"
                    drakrun.mkdir(parents=True)
                    (run / "run.json").write_text(
                        '{"return_code":0,'
                        '"started_at":"2026-01-01T00:00:00+00:00",'
                        '"finished_at":"2026-01-01T00:00:10+00:00"}',
                        encoding="utf-8",
                    )
                    (run / "sample.json").write_text(
                        json.dumps(
                            {"sample_id": sample, "configuration_id": "c"}
                        ),
                        encoding="utf-8",
                    )
                    (drakrun / "metadata.json").write_text("{}", encoding="utf-8")
                    (drakrun / "inject.log").write_text(
                        '{"Status":"Error","ErrorCode":740}\n', encoding="utf-8"
                    )
            result = audit_matrix(plan, root / "runs")
            condition = result["conditions"][0]
            self.assertTrue(condition["execution_gate_met"])
            self.assertFalse(condition["dynamic_gate_met"])
            self.assertEqual(condition["status"], "needs_retry")
            self.assertEqual(
                condition["failure_reasons"], {"sample_requires_elevation": 6}
            )
            self.assertEqual(result["timing"]["run_wall_seconds_median"], 10.0)


if __name__ == "__main__":
    unittest.main()
