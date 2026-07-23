import json
import tempfile
import unittest
from pathlib import Path

from empirical_types.provisional import (
    _normalize_type,
    dynamic_validation,
    repetition_identity,
    sample_identity,
)


class ProvisionalHelperTests(unittest.TestCase):
    def test_normalize_type(self):
        self.assertEqual(_normalize_type("Type V"), "TYPE_V")
        self.assertEqual(_normalize_type("type-iv"), "TYPE_IV")
        self.assertIsNone(_normalize_type("nonsense"))
        self.assertIsNone(_normalize_type(None))

    def test_sample_identity_prefers_content_hash(self):
        self.assertEqual(
            sample_identity({"packed_sha256": "abc", "sample_id": "s"}), "abc"
        )
        self.assertEqual(sample_identity({"sample_id": "s"}), "s")

    def test_repetition_identity(self):
        self.assertEqual(repetition_identity({"repetition": 3}), "rep:3")
        self.assertEqual(
            repetition_identity({"run_directory": "/r", "sample_id": "s"}), "run:/r"
        )

    def test_reads_run_and_sample_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            (run / "run.json").write_text('{"return_code": 0}', encoding="utf-8")
            (run / "sample.json").write_text(
                json.dumps(
                    {
                        "sample_id": "s",
                        "packed_sha256": "sha",
                        "configuration_id": "c",
                        "repetition": 2,
                        "retry_for_dynamic_gate": True,
                        "retry_mode": "in_place_validation",
                    }
                ),
                encoding="utf-8",
            )
            row = dynamic_validation(run)
            self.assertEqual(row["sample_id"], "s")
            self.assertEqual(row["packed_sha256"], "sha")
            self.assertEqual(row["configuration_id"], "c")
            self.assertEqual(row["repetition"], 2)
            self.assertTrue(row["retry_for_dynamic_gate"])
            self.assertEqual(row["retry_mode"], "in_place_validation")
            self.assertEqual(row["backend_return_code"], 0)
            self.assertFalse(row["dynamically_validated"])
            self.assertIsNone(row["dynamic_failure_reason"])

    def test_flags_backend_nonzero_return(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            (run / "run.json").write_text('{"return_code": 1}', encoding="utf-8")
            (run / "sample.json").write_text(
                '{"sample_id": "s", "configuration_id": "c"}', encoding="utf-8"
            )
            row = dynamic_validation(run)
            self.assertEqual(row["dynamic_failure_reason"], "backend_nonzero_return")


if __name__ == "__main__":
    unittest.main()
