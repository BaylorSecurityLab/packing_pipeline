import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from empirical_types.nas import stage_retry_matrix


class RetryPlanningTests(unittest.TestCase):
    def test_resumes_partially_completed_retry_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "plan.json"
            plan.write_text(
                json.dumps(
                    {
                        "server": "nas",
                        "share": "samples",
                        "conditions": [
                            {
                                "packer_family": "p",
                                "packer_version": "1",
                                "configuration_id": "c",
                                "test_case_id": "CASE",
                                "source": "yaml_test_case",
                                "status": "planned",
                                "type_hypothesis": "Type I",
                                "alternate_samples": [
                                    {
                                        "remote_path": "//nas/new.exe",
                                        "filename": "new.exe",
                                        "size": 2048,
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            def write_run(sample: str, repetition: int, valid: bool, retry: bool = False):
                run = root / "runs" / sample / f"rep_{repetition:03d}"
                drakrun = run / "drakrun"
                drakrun.mkdir(parents=True)
                (run / "run.json").write_text('{"return_code":0}', encoding="utf-8")
                (run / "sample.json").write_text(
                    json.dumps(
                        {
                            "sample_id": sample,
                            "packed_sha256": f"hash-{sample}",
                            "packed_path": f"/tmp/{sample}.exe",
                            "configuration_id": "c",
                            "nas_remote_path": f"//nas/{sample}.exe",
                            "retry_for_dynamic_gate": retry,
                            "repetition": repetition,
                        }
                    ),
                    encoding="utf-8",
                )
                (drakrun / "metadata.json").write_text("{}", encoding="utf-8")
                if valid:
                    (drakrun / "inject.log").write_text(
                        '{"Status":"Success","InjectedPid":7}\n', encoding="utf-8"
                    )
                    (drakrun / "apimon.log").write_text(
                        '{"PID":7,"Method":"X"}\n', encoding="utf-8"
                    )
                else:
                    (drakrun / "inject.log").write_text(
                        '{"Status":"Error","ErrorCode":740}\n', encoding="utf-8"
                    )

            for repetition in range(1, 4):
                write_run("a", repetition, True)
                write_run("b", repetition, False)
            write_run("retry-c", 1, True, retry=True)
            inventory = root / "retry.jsonl"
            with (
                patch.dict(
                    os.environ,
                    {"PACKER_NAS_USERNAME": "u", "PACKER_NAS_PASSWORD": "p"},
                ),
                patch("smbclient.register_session"),
                patch("smbclient.open_file") as open_file,
            ):
                report = stage_retry_matrix(
                    plan, root / "runs", root / "staged", inventory, 3, 2
                )
            open_file.assert_not_called()
            self.assertEqual(report["staged_samples"], 1)
            self.assertEqual(report["shortfalls"][0]["retry_samples_resumed"], 1)
            record = json.loads(inventory.read_text().strip())
            self.assertEqual(record["sample_id"], "retry-c")
            self.assertNotIn("repetition", record)
            self.assertEqual(record["retry_repetitions"], [2, 3])
            self.assertEqual(record["retry_mode"], "resume_missing_repetitions")

    def test_retries_near_qualifying_payload_in_place_before_alternate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "plan.json"
            plan.write_text(
                json.dumps(
                    {
                        "server": "nas",
                        "share": "samples",
                        "conditions": [
                            {
                                "packer_family": "p",
                                "packer_version": "1",
                                "configuration_id": "c",
                                "test_case_id": "CASE",
                                "source": "yaml_test_case",
                                "status": "planned",
                                "type_hypothesis": "Type I",
                                "alternate_samples": [
                                    {
                                        "remote_path": "//nas/alternate.exe",
                                        "filename": "alternate.exe",
                                        "size": 2048,
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            def write_run(sample: str, repetition: int, valid: bool):
                run = root / "runs" / sample / f"rep_{repetition:03d}"
                drakrun = run / "drakrun"
                drakrun.mkdir(parents=True)
                (run / "run.json").write_text(
                    '{"return_code":0}', encoding="utf-8"
                )
                (run / "sample.json").write_text(
                    json.dumps(
                        {
                            "sample_id": sample,
                            "packed_sha256": f"hash-{sample}",
                            "packed_path": f"/tmp/{sample}.exe",
                            "configuration_id": "c",
                            "nas_remote_path": f"//nas/{sample}.exe",
                            "repetition": repetition,
                        }
                    ),
                    encoding="utf-8",
                )
                (drakrun / "metadata.json").write_text("{}", encoding="utf-8")
                if valid:
                    (drakrun / "inject.log").write_text(
                        '{"Status":"Success","InjectedPid":7}\n',
                        encoding="utf-8",
                    )
                    (drakrun / "apimon.log").write_text(
                        '{"PID":7,"Method":"X"}\n', encoding="utf-8"
                    )
                else:
                    (drakrun / "inject.log").write_text(
                        '{"Status":"Error","ErrorCode":740}\n', encoding="utf-8"
                    )

            for repetition in range(1, 4):
                write_run("a", repetition, True)
                write_run("b", repetition, repetition < 3)
            inventory = root / "retry.jsonl"
            with (
                patch.dict(
                    os.environ,
                    {"PACKER_NAS_USERNAME": "u", "PACKER_NAS_PASSWORD": "p"},
                ),
                patch("smbclient.register_session"),
                patch("smbclient.open_file") as open_file,
            ):
                report = stage_retry_matrix(
                    plan, root / "runs", root / "staged", inventory, 3, 2
                )
            open_file.assert_not_called()
            self.assertEqual(report["staged_samples"], 1)
            self.assertEqual(
                report["shortfalls"][0]["in_place_validation_retries"], 1
            )
            record = json.loads(inventory.read_text().strip())
            self.assertEqual(record["sample_id"], "b")
            self.assertEqual(record["retry_repetitions"], [4])
            self.assertEqual(record["retry_mode"], "in_place_validation")

    def test_does_not_retry_an_unfinished_primary_condition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "plan.json"
            plan.write_text(
                json.dumps(
                    {
                        "server": "nas",
                        "share": "samples",
                        "conditions": [
                            {
                                "packer_family": "p",
                                "packer_version": "1",
                                "configuration_id": "c",
                                "test_case_id": "CASE",
                                "source": "yaml_test_case",
                                "status": "planned",
                                "type_hypothesis": "Type I",
                                "alternate_samples": [
                                    {
                                        "remote_path": "//nas/samples/alternate.exe",
                                        "filename": "alternate.exe",
                                        "size": 2048,
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            inventory = root / "retry.jsonl"
            with (
                patch.dict(
                    os.environ,
                    {"PACKER_NAS_USERNAME": "u", "PACKER_NAS_PASSWORD": "p"},
                ),
                patch("smbclient.register_session"),
            ):
                report = stage_retry_matrix(
                    plan, root / "runs", root / "staged", inventory, 3, 2
                )
            self.assertEqual(report["staged_samples"], 0)
            self.assertEqual(report["conditions_not_ready"], 1)

    def test_stages_one_alternate_when_one_payload_qualifies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate_payload = b"MZ" + b"x" * 2046
            unique_payload = b"MZ" + b"y" * 2046
            plan = root / "plan.json"
            plan.write_text(
                json.dumps(
                    {
                        "server": "nas",
                        "share": "samples",
                        "conditions": [
                            {
                                "packer_family": "p",
                                "packer_version": "1",
                                "configuration_id": "c",
                                "test_case_id": "CASE",
                                "source": "yaml_test_case",
                                "status": "planned",
                                "type_hypothesis": "Type I",
                                "alternate_samples": [
                                    {
                                        "remote_path": "//nas/samples/setup.exe",
                                        "filename": "setup_machine_nullsoft.exe",
                                        "size": 2048,
                                    },
                                    {
                                        "remote_path": "//nas/samples/a.exe",
                                        "filename": "a_portable.exe",
                                        "size": 2048,
                                    },
                                    {
                                        "remote_path": "//nas/samples/b.exe",
                                        "filename": "b_portable.exe",
                                        "size": 2048,
                                    },
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            for sample in ("sample-a", "sample-b"):
                for repetition in range(1, 4):
                    run = root / "runs" / sample / f"rep_{repetition:03d}"
                    drakrun = run / "drakrun"
                    drakrun.mkdir(parents=True)
                    (run / "run.json").write_text(
                        '{"return_code": 0}', encoding="utf-8"
                    )
                    (run / "sample.json").write_text(
                        json.dumps(
                            {
                                "sample_id": sample,
                                "packed_sha256": (
                                    hashlib.sha256(duplicate_payload).hexdigest()
                                    if sample == "sample-a"
                                    else "failed-content"
                                ),
                                "configuration_id": "c",
                                "nas_remote_path": f"//nas/samples/{sample}.exe",
                            }
                        ),
                        encoding="utf-8",
                    )
                    (drakrun / "metadata.json").write_text("{}", encoding="utf-8")
                    if sample == "sample-a":
                        (drakrun / "inject.log").write_text(
                            '{"Status":"Success","InjectedPid":7}\n',
                            encoding="utf-8",
                        )
                        (drakrun / "apimon.log").write_text(
                            '{"PID":7,"Method":"X"}\n', encoding="utf-8"
                        )
                    else:
                        (drakrun / "inject.log").write_text(
                            '{"Status":"Error","ErrorCode":740}\n',
                            encoding="utf-8",
                        )
            inventory = root / "retry.jsonl"
            with (
                patch.dict(
                    os.environ,
                    {"PACKER_NAS_USERNAME": "u", "PACKER_NAS_PASSWORD": "p"},
                ),
                patch("smbclient.register_session"),
                patch(
                    "smbclient.open_file",
                    side_effect=[
                        io.BytesIO(duplicate_payload),
                        io.BytesIO(unique_payload),
                    ],
                ),
            ):
                report = stage_retry_matrix(
                    plan, root / "runs", root / "staged", inventory, 3, 2
                )
            self.assertEqual(report["staged_samples"], 1)
            self.assertEqual(report["retryable_conditions"], 1)
            self.assertEqual(report["exhausted_conditions"], 0)
            records = [json.loads(line) for line in inventory.read_text().splitlines()]
            self.assertEqual(len(records), 1)
            self.assertEqual(
                records[0]["nas_remote_path"], "//nas/samples/b.exe"
            )
            self.assertEqual(records[0]["retry_mode"], "alternate_payload")
            self.assertEqual(
                report["shortfalls"][0]["duplicate_alternates_skipped"], 1
            )


if __name__ == "__main__":
    unittest.main()
