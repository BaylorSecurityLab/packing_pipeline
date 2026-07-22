import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from empirical_types.collector import collect_drakrun


class CollectorTests(unittest.TestCase):
    def test_cached_backend_failure_is_rerun(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = {
                "sample_id": "sample",
                "packed_path": str(root / "sample.exe"),
                "configuration_id": "condition",
            }
            run = root / "runs" / "sample" / "rep_001"
            run.mkdir(parents=True)
            cached = {
                "sample_id": "sample",
                "complexity_type": "UNRESOLVED_BACKEND_FAILURE",
                "confidence": 1.0,
                "rule": "DRAKVUF/Xen backend failed before sample execution",
                "termination": "backend_failure",
                "trace_complete": False,
                "original_match_available": False,
            }
            (run / "classification.json").write_text(
                json.dumps(cached), encoding="utf-8"
            )
            completed = SimpleNamespace(returncode=0, stderr="", stdout="")
            with patch(
                "empirical_types.collector.subprocess.run", return_value=completed
            ) as rerun:
                result = collect_drakrun(
                    record, root / "runs", 10, "drakrun", repetition=1
                )
            rerun.assert_called_once()
            self.assertEqual(result.complexity_type, "UNRESOLVED_TRACE_LOSS")

    def test_restore_failure_is_classified_as_backend_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = {
                "sample_id": "sample",
                "packed_path": str(root / "sample.exe"),
                "configuration_id": "condition",
            }
            completed = SimpleNamespace(
                returncode=1,
                stderr="RuntimeError: Failed to restore VM vm-1",
                stdout="",
            )
            with patch(
                "empirical_types.collector.subprocess.run", return_value=completed
            ):
                result = collect_drakrun(
                    record, root / "runs", 10, "drakrun", repetition=1
                )
            self.assertEqual(result.complexity_type, "UNRESOLVED_BACKEND_FAILURE")
            self.assertEqual(result.evidence.termination, "backend_failure")

    def test_restore_failure_runs_bounded_recovery_and_retries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = {
                "sample_id": "sample",
                "packed_path": str(root / "sample.exe"),
                "configuration_id": "condition",
            }
            restore_failure = SimpleNamespace(
                returncode=1,
                stderr="device model did not start",
                stdout="",
            )
            recovered = SimpleNamespace(returncode=0, stderr="", stdout="")
            success = SimpleNamespace(returncode=0, stderr="", stdout="")
            analysis_dir = root / "runs/sample/rep_001/drakrun"
            invocations = []

            def execute(command, **kwargs):
                invocations.append(command)
                if len(invocations) == 1:
                    analysis_dir.mkdir(parents=True)
                    (analysis_dir / "partial.log").write_text(
                        "partial", encoding="utf-8"
                    )
                    return restore_failure
                if len(invocations) == 2:
                    return recovered
                self.assertFalse(analysis_dir.exists())
                return success

            with (
                patch.dict(
                    os.environ,
                    {"PACKER_DRAKRUN_RECOVERY": "/usr/local/sbin/recover"},
                ),
                patch("empirical_types.collector.os.geteuid", return_value=1000),
                patch(
                    "empirical_types.collector.subprocess.run",
                    side_effect=execute,
                ) as execute,
            ):
                result = collect_drakrun(
                    record, root / "runs", 10, "drakrun", repetition=1
                )
            self.assertEqual(execute.call_count, 3)
            self.assertEqual(
                execute.call_args_list[1].args[0],
                ["sudo", "-n", "/usr/local/sbin/recover"],
            )
            self.assertEqual(result.complexity_type, "UNRESOLVED_TRACE_LOSS")
            metadata = json.loads((root / "runs/sample/rep_001/run.json").read_text())
            self.assertEqual(metadata["attempt_count"], 2)
            self.assertEqual(metadata["backend_recovery_return_code"], 0)
            self.assertEqual(
                [attempt["return_code"] for attempt in metadata["attempts"]],
                [1, 0],
            )

    def test_explicit_sudo_mode_prefixes_drakrun_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = {
                "sample_id": "sample",
                "packed_path": str(root / "sample.exe"),
                "configuration_id": "condition",
            }
            completed = SimpleNamespace(returncode=0, stderr="", stdout="")
            with (
                patch.dict(os.environ, {"PACKER_DRAKRUN_SUDO": "1"}),
                patch("empirical_types.collector.os.geteuid", return_value=1000),
                patch(
                    "empirical_types.collector.subprocess.run",
                    return_value=completed,
                ) as execute,
            ):
                collect_drakrun(record, root / "runs", 10, "drakrun", repetition=1)
            command = execute.call_args.args[0]
            self.assertEqual(command[:3], ["sudo", "-n", "drakrun"])

    def test_legacy_cached_result_uses_defaults_without_rerun(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = {
                "sample_id": "sample",
                "packed_path": str(root / "sample.exe"),
                "configuration_id": "condition",
            }
            run = root / "runs" / "sample" / "rep_001"
            run.mkdir(parents=True)
            legacy = {
                "sample_id": "sample",
                "complexity_type": "UNRESOLVED_TRACE_LOSS",
                "confidence": 1.0,
                "rule": "deep trace not yet fused",
                "termination": "completed",
                "trace_complete": False,
                "original_match_available": False,
            }
            (run / "classification.json").write_text(
                json.dumps(legacy), encoding="utf-8"
            )
            with patch("empirical_types.collector.subprocess.run") as rerun:
                result = collect_drakrun(
                    record, root / "runs", 10, "drakrun", repetition=1
                )
            rerun.assert_not_called()
            self.assertIsNone(result.evidence.original_multiframe_ratio)

    def test_corrupt_cached_result_is_rerun_with_atomic_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = {
                "sample_id": "sample",
                "packed_path": str(root / "sample.exe"),
                "configuration_id": "condition",
            }
            run = root / "runs" / "sample" / "rep_001"
            stale = run / "drakrun"
            stale.mkdir(parents=True)
            (stale / "partial.log").write_text("partial", encoding="utf-8")
            (run / "classification.json").write_text("{", encoding="utf-8")
            completed = SimpleNamespace(returncode=0, stderr="", stdout="")
            with patch("empirical_types.collector.subprocess.run", return_value=completed):
                result = collect_drakrun(
                    record, root / "runs", 10, "drakrun", repetition=1
                )
            self.assertEqual(result.complexity_type, "UNRESOLVED_TRACE_LOSS")
            self.assertFalse(stale.exists())
            self.assertFalse(any(run.glob("*.tmp")))
            cached = json.loads((run / "classification.json").read_text())
            self.assertEqual(cached["sample_id"], "sample")
            with patch("empirical_types.collector.subprocess.run") as rerun:
                collect_drakrun(record, root / "runs", 10, "drakrun", repetition=1)
            rerun.assert_not_called()


if __name__ == "__main__":
    unittest.main()
