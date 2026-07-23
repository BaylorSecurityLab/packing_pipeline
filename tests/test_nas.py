import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from empirical_types.nas import plan_matrix


class NasPlanningTests(unittest.TestCase):
    @staticmethod
    def _entry(name, is_directory):
        entry = Mock()
        entry.name = name
        entry.is_dir.return_value = is_directory
        return entry

    def test_includes_gui_definition_when_nas_has_no_files(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.yaml"
            manifest.write_text(
                "definitions:\n"
                "  - packer_family: fsg\n"
                "    packer_name: fsg_v1.0\n"
                "    version: '1.0'\n"
                "    tags: [GUI, Compressor]\n"
                "    type_hypothesis: Type I\n"
                "test_cases: []\n",
                encoding="utf-8",
            )
            with (
                patch.dict(
                    os.environ,
                    {"PACKER_NAS_USERNAME": "u", "PACKER_NAS_PASSWORD": "p"},
                ),
                patch("smbclient.register_session"),
                patch("smbclient.scandir", return_value=[]),
            ):
                plan = plan_matrix("nas", "samples", "root", manifest, 2)
            self.assertEqual(len(plan["conditions"]), 1)
            condition = plan["conditions"][0]
            self.assertEqual(condition["packer_family"], "fsg")
            self.assertEqual(condition["status"], "missing_on_nas")
            self.assertEqual(condition["samples"], [])

    def test_gui_directory_with_only_logs_is_empty_not_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.yaml"
            manifest.write_text(
                "definitions:\n"
                "  - packer_family: fsg\n"
                "    packer_name: fsg_v1.0\n"
                "    version: '1.0'\n"
                "    tags: [GUI, Compressor]\n"
                "    type_hypothesis: Type I\n"
                "test_cases: []\n",
                encoding="utf-8",
            )
            packer = self._entry("fsg_v1.0_1.0", True)
            logs = self._entry("logs", True)

            def scan(path):
                if path == "//nas/samples/root":
                    return [packer]
                if path == "//nas/samples/root/fsg_v1.0_1.0":
                    return [logs]
                raise AssertionError(f"unexpected SMB path: {path}")

            with (
                patch.dict(
                    os.environ,
                    {"PACKER_NAS_USERNAME": "u", "PACKER_NAS_PASSWORD": "p"},
                ),
                patch("smbclient.register_session"),
                patch("smbclient.scandir", side_effect=scan),
            ):
                plan = plan_matrix("nas", "samples", "root", manifest, 2)
            condition = plan["conditions"][0]
            self.assertEqual(condition["status"], "empty_on_nas")
            self.assertEqual(condition["nas_packer_directory"], "fsg_v1.0_1.0")
            self.assertEqual(condition["available_samples"], 0)


if __name__ == "__main__":
    unittest.main()
