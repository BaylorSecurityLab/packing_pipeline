import json
import tempfile
import unittest
from pathlib import Path

from empirical_types.provisional import auto_label, dynamic_validation


class ProvisionalLabelTests(unittest.TestCase):
    def test_validates_events_from_target_child_process(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            drakrun = run / "drakrun"
            drakrun.mkdir()
            (run / "run.json").write_text('{"return_code":0}', encoding="utf-8")
            (run / "sample.json").write_text(
                '{"sample_id":"s","configuration_id":"c",'
                '"retry_for_dynamic_gate":true,'
                '"retry_mode":"in_place_validation"}',
                encoding="utf-8",
            )
            (drakrun / "metadata.json").write_text("{}", encoding="utf-8")
            (drakrun / "inject.log").write_text(
                '{"Status":"Success","InjectedPid":7}\n', encoding="utf-8"
            )
            (drakrun / "process_tree.json").write_text(
                '[{"pid":7,"children":['
                '{"pid":8,"procname":"child.exe","children":[]},'
                '{"pid":9,"procname":"C:\\\\Windows\\\\conhost.exe","children":[]}'
                "]}]",
                encoding="utf-8",
            )
            (drakrun / "apimon.log").write_text(
                '{"PID":8,"Method":"ChildEvent"}\n', encoding="utf-8"
            )
            result = dynamic_validation(run)
            self.assertTrue(result["dynamically_validated"])
            self.assertEqual(result["target_process_pids"], [7, 8])
            self.assertEqual(
                result["paper_proxy_features"]["target_descendant_processes"], 1
            )
            self.assertTrue(result["retry_for_dynamic_gate"])
            self.assertEqual(result["retry_mode"], "in_place_validation")

    def test_reports_elevation_required_injection_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            drakrun = run / "drakrun"
            drakrun.mkdir()
            (run / "run.json").write_text('{"return_code":0}', encoding="utf-8")
            (run / "sample.json").write_text(
                '{"sample_id":"s","configuration_id":"c"}', encoding="utf-8"
            )
            (drakrun / "metadata.json").write_text("{}", encoding="utf-8")
            (drakrun / "inject.log").write_text(
                '{"Status":"Error","ErrorCode":740}\n', encoding="utf-8"
            )
            result = dynamic_validation(run)
            self.assertFalse(result["dynamically_validated"])
            self.assertEqual(
                result["dynamic_failure_reason"], "sample_requires_elevation"
            )

    def test_requires_n_dynamic_validations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.yaml"
            manifest.write_text(
                "test_cases:\n"
                "  - id: CASE_1\n"
                "    packer_family: p\n"
                "    version: '1'\n"
                "    type_hypothesis: Type I\n",
                encoding="utf-8",
            )
            for index in range(2):
                for repetition in range(1, 3):
                    run = root / "runs" / f"s{index}" / f"rep_{repetition:03d}"
                    drakrun = run / "drakrun"
                    drakrun.mkdir(parents=True)
                    (run / "run.json").write_text(
                        '{"return_code": 0}', encoding="utf-8"
                    )
                    (run / "sample.json").write_text(
                        json.dumps(
                            {
                                "sample_id": f"s{index}",
                                "packer_family": "p",
                                "packer_version": "1",
                                "configuration_id": "c",
                                "test_case_id": "CASE_1",
                                "repetition": repetition,
                            }
                        ),
                        encoding="utf-8",
                    )
                    (drakrun / "metadata.json").write_text("{}", encoding="utf-8")
                    (drakrun / "process_tree.json").write_text("{}", encoding="utf-8")
                    (drakrun / "inject.log").write_text(
                        '{"Status":"Success","InjectedPid":7}\n', encoding="utf-8"
                    )
                    (drakrun / "apimon.log").write_text(
                        '{"PID":7,"Method":"X"}\n', encoding="utf-8"
                    )
            output = root / "labels.json"
            conditions = auto_label(root / "runs", manifest, 2, output)
            self.assertEqual(conditions[0]["auto_label"], "PROVISIONAL_TYPE_I")
            self.assertTrue(conditions[0]["eligible"])


if __name__ == "__main__":
    unittest.main()
