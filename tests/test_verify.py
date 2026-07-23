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

if __name__ == "__main__":
    unittest.main()
