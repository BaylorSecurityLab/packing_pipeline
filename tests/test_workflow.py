import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from empirical_types.workflow import finish_matrix


class WorkflowTests(unittest.TestCase):
    def test_honors_targeted_retry_repetition_list(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "plan.json"
            plan.write_text('{"conditions":[]}', encoding="utf-8")
            calls = 0

            def stage_retries(
                _plan, _runs, _destination, inventory, _repetitions, _samples
            ):
                nonlocal calls
                calls += 1
                if calls == 1:
                    inventory.write_text(
                        json.dumps(
                            {
                                "sample_id": "sample",
                                "packed_path": "/tmp/sample.exe",
                                "retry_repetitions": [4],
                            }
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    return {
                        "staged_samples": 1,
                        "conditions_not_ready": 0,
                        "shortfalls": [],
                    }
                inventory.write_text("", encoding="utf-8")
                return {
                    "staged_samples": 0,
                    "conditions_not_ready": 0,
                    "shortfalls": [],
                }

            audit = {"dynamic_gate_complete_conditions": 0, "conditions": []}
            verification = {
                "valid": True,
                "exhausted_below_dynamic_gate": 0,
                "condition_count": 0,
            }
            with (
                patch("empirical_types.workflow.find_drakrun", return_value="drakrun"),
                patch(
                    "empirical_types.workflow.stage_retry_matrix",
                    side_effect=stage_retries,
                ),
                patch("empirical_types.workflow.collect_drakrun") as collect,
                patch("empirical_types.workflow.audit_matrix", return_value=audit),
                patch("empirical_types.workflow.finalize_labels"),
                patch(
                    "empirical_types.workflow.verify_artifacts",
                    return_value=verification,
                ),
            ):
                result = finish_matrix(
                    plan,
                    root / "runs",
                    root / "retries",
                    root / "output",
                    root / "manifest.yaml",
                )
            self.assertEqual(result["retry_runs"], 1)
            collect.assert_called_once()
            self.assertEqual(collect.call_args.kwargs["repetition"], 4)

    def test_no_retry_finalization_writes_verified_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "plan.json"
            plan.write_text(
                json.dumps(
                    {
                        "conditions": [
                            {
                                "packer_family": "fsg",
                                "packer_version": "1.0",
                                "configuration_id": "gui-fsg",
                                "test_case_id": None,
                                "source": "gui_family_version",
                                "status": "missing_on_nas",
                                "available_samples": 0,
                                "type_hypothesis": "Type I",
                                "samples": [],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            final_retry = {
                "staged_samples": 0,
                "conditions_below_gate": 0,
                "conditions_not_ready": 0,
                "retryable_conditions": 0,
                "exhausted_conditions": 0,
                "conditions_without_enough_alternates": 0,
                "shortfalls": [],
            }
            manifest = root / "manifest.yaml"
            with (
                patch("empirical_types.workflow.find_drakrun", return_value="drakrun"),
                patch(
                    "empirical_types.workflow.stage_retry_matrix",
                    return_value=final_retry,
                ),
            ):
                result = finish_matrix(
                    plan,
                    root / "runs",
                    root / "retries",
                    root / "output",
                    manifest,
                )
            self.assertEqual(result["condition_count"], 1)
            self.assertTrue(manifest.exists())
            verification = json.loads(
                (root / "output" / "verification.json").read_text()
            )
            self.assertTrue(verification["valid"])


if __name__ == "__main__":
    unittest.main()
