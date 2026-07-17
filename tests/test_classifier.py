import json
import tempfile
import unittest
from pathlib import Path

from empirical_types.classifier import classify
from empirical_types.model import Evidence
from empirical_types.trace import analyze_jsonl


class ClassifierTests(unittest.TestCase):
    def evidence(self, **changes):
        base = dict(
            sample_id="x",
            layers=2,
            original_code_frames=1,
            maximum_simultaneous_code_coverage=1.0,
            union_code_coverage=1.0,
            tail_transition=True,
        )
        base.update(changes)
        return Evidence(**base)

    def test_single_process_cert_rejects_cross_process_trace(self):
        # A normal single-process trace still classifies under a single-process
        # certification.
        self.assertEqual(
            classify(self.evidence(cross_process_certified=False)).complexity_type,
            "TYPE_I",
        )
        # But if the same trace shows cross-process activity, the single-process
        # certification must refuse to label it.
        self.assertEqual(
            classify(
                self.evidence(
                    cross_process_activity=True, cross_process_certified=False
                )
            ).complexity_type,
            "UNRESOLVED_UNCERTIFIED_CROSS_PROCESS",
        )
        # A fully-certified backend labels the cross-process trace normally.
        self.assertEqual(
            classify(
                self.evidence(
                    cross_process_activity=True, cross_process_certified=True
                )
            ).complexity_type,
            "TYPE_I",
        )

    def test_paper_hierarchy(self):
        self.assertEqual(classify(self.evidence()).complexity_type, "TYPE_I")
        self.assertEqual(classify(self.evidence(layers=4)).complexity_type, "TYPE_II")
        self.assertEqual(
            classify(self.evidence(layers=4, backward_transitions=1)).complexity_type,
            "TYPE_III",
        )
        self.assertEqual(
            classify(
                self.evidence(tail_transition=False, interleaved=True)
            ).complexity_type,
            "TYPE_IV",
        )
        self.assertEqual(
            classify(
                self.evidence(tail_transition=False, interleaved=False)
            ).complexity_type,
            "UNRESOLVED_INSUFFICIENT_COVERAGE",
        )
        self.assertEqual(
            classify(
                self.evidence(
                    tail_transition=False,
                    interleaved=True,
                    original_code_frames=3,
                    original_multiframe_ratio=1.0,
                    maximum_simultaneous_code_coverage=1.0,
                    frame_sizes=[4096, 4096],
                )
            ).complexity_type,
            "TYPE_V-P",
        )
        self.assertEqual(
            classify(
                self.evidence(
                    tail_transition=False,
                    interleaved=True,
                    original_code_frames=3,
                    original_multiframe_ratio=1.0,
                    maximum_simultaneous_code_coverage=0.4,
                    repacked_original_bytes=2,
                    frame_sizes=[10, 12],
                    frame_basic_blocks=[1, 1],
                )
            ).complexity_type,
            "TYPE_VI-B",
        )
        self.assertEqual(
            classify(
                self.evidence(
                    tail_transition=False,
                    interleaved=True,
                    original_code_frames=3,
                    original_multiframe_ratio=1.0,
                    maximum_simultaneous_code_coverage=0.4,
                )
            ).complexity_type,
            "TYPE_V-F",
        )
        self.assertEqual(
            classify(
                self.evidence(
                    tail_transition=False,
                    interleaved=True,
                    original_code_frames=3,
                    original_multiframe_ratio=1.0,
                    maximum_simultaneous_code_coverage=0.4,
                    frame_sizes=[64, 96],
                    frame_basic_blocks=[2, 2],
                    frame_function_aligned=[True, True],
                )
            ).complexity_type,
            "TYPE_V-F",
        )
        self.assertEqual(
            classify(
                self.evidence(
                    tail_transition=False,
                    interleaved=False,
                    original_code_frames=3,
                    original_multiframe_ratio=1.0,
                    maximum_simultaneous_code_coverage=0.4,
                )
            ).complexity_type,
            "UNRESOLVED_INSUFFICIENT_COVERAGE",
        )

    def test_does_not_force_missing_trace(self):
        result = classify(self.evidence(trace_complete=False))
        self.assertEqual(result.complexity_type, "UNRESOLVED_TRACE_LOSS")

    def test_normalized_trace(self):
        events = [
            {
                "event": "exec",
                "pid": 1,
                "tid": 1,
                "address": "0x1000",
                "size": 2,
                "original": False,
            },
            {"event": "write", "pid": 1, "tid": 1, "address": "0x2000", "size": 2},
            {
                "event": "exec",
                "pid": 1,
                "tid": 1,
                "address": "0x2000",
                "size": 2,
                "original": True,
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            path.write_text(
                "".join(json.dumps(e) + "\n" for e in events), encoding="utf-8"
            )
            evidence = analyze_jsonl(path, "sample", 2)
        self.assertEqual(evidence.layers, 2)
        self.assertEqual(evidence.original_code_frames, 1)
        self.assertTrue(evidence.tail_transition)
        self.assertEqual(classify(evidence).complexity_type, "TYPE_I")

    def test_system_library_execution_does_not_create_interleaving(self):
        events = [
            {"event": "exec", "pid": 1, "tid": 1, "address": "0x1000"},
            {"event": "write", "pid": 1, "tid": 1, "address": "0x2000"},
            {
                "event": "exec",
                "pid": 1,
                "tid": 1,
                "address": "0x2000",
                "original": True,
            },
            {
                "event": "exec",
                "pid": 1,
                "tid": 1,
                "address": "0x70000000",
                "role": "system",
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            path.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            evidence = analyze_jsonl(path, "sample", 1)
        self.assertTrue(evidence.tail_transition)
        self.assertFalse(evidence.interleaved)
        self.assertEqual(classify(evidence).complexity_type, "TYPE_I")

    def test_thread_switch_is_not_a_layer_transition(self):
        events = [
            {"event": "exec", "pid": 1, "tid": 1, "address": "0x1000"},
            {"event": "exec", "pid": 1, "tid": 2, "address": "0x3000"},
            {"event": "write", "pid": 1, "tid": 2, "address": "0x2000"},
            {"event": "exec", "pid": 1, "tid": 2, "address": "0x2000"},
            {"event": "exec", "pid": 1, "tid": 1, "address": "0x1000"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            path.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            evidence = analyze_jsonl(path, "sample", 1)
        self.assertEqual(evidence.forward_transitions, 1)
        self.assertEqual(evidence.backward_transitions, 0)

    def test_trace_distinguishes_incremental_and_shifting_frames(self):
        incremental = [
            {"event": "exec", "pid": 1, "tid": 1, "address": "0x1000"},
            {
                "event": "write",
                "pid": 1,
                "tid": 1,
                "address": "0x2000",
                "size": 4096,
                "original": True,
            },
            {
                "event": "exec",
                "pid": 1,
                "tid": 1,
                "address": "0x2000",
                "original": True,
            },
            {"event": "exec", "pid": 1, "tid": 1, "address": "0x1000"},
            {
                "event": "write",
                "pid": 1,
                "tid": 1,
                "address": "0x3000",
                "size": 4096,
                "original": True,
            },
            {
                "event": "exec",
                "pid": 1,
                "tid": 1,
                "address": "0x3000",
                "original": True,
            },
        ]
        shifting = incremental[:4] + [
            {
                "event": "write",
                "pid": 1,
                "tid": 1,
                "address": "0x2000",
                "size": 4096,
            }
        ] + incremental[4:]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            incremental_path = root / "incremental.jsonl"
            shifting_path = root / "shifting.jsonl"
            incremental_path.write_text(
                "".join(json.dumps(event) + "\n" for event in incremental),
                encoding="utf-8",
            )
            shifting_path.write_text(
                "".join(json.dumps(event) + "\n" for event in shifting),
                encoding="utf-8",
            )
            incremental_evidence = analyze_jsonl(incremental_path, "i", 8192)
            shifting_evidence = analyze_jsonl(shifting_path, "s", 8192)
        self.assertEqual(classify(incremental_evidence).complexity_type, "TYPE_V-P")
        self.assertEqual(classify(shifting_evidence).complexity_type, "TYPE_VI-P")

    def test_granularity_excludes_non_original_scratch_writes(self):
        events = []
        for index, original_address in enumerate((0x2000, 0x4000)):
            events.extend(
                [
                    {"event": "exec", "pid": 1, "tid": 1, "address": "0x1000"},
                    {
                        "event": "write",
                        "pid": 1,
                        "tid": 1,
                        "address": "0x8000",
                        "size": 4080,
                    },
                    {
                        "event": "write",
                        "pid": 1,
                        "tid": 1,
                        "address": original_address,
                        "size": 16,
                        "original": True,
                        "original_rva": index * 16,
                    },
                    {
                        "event": "exec",
                        "pid": 1,
                        "tid": 1,
                        "address": original_address,
                        "size": 16,
                        "original": True,
                        "original_rva": index * 16,
                    },
                ]
            )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            path.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            evidence = analyze_jsonl(path, "sample", 32)
        self.assertEqual(evidence.frame_sizes, [16, 16])
        self.assertEqual(classify(evidence).complexity_type, "TYPE_V-B")
        for event in events:
            if event.get("event") == "exec" and event.get("original"):
                event["frame_function_aligned"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            path.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            function_evidence = analyze_jsonl(path, "sample", 32)
        self.assertEqual(function_evidence.frame_function_aligned, [True, True])
        # The paper's reported suffixes are P/B/G. Function-sized frames are
        # included in the paper's function (F) category unless their average
        # is one basic block.
        self.assertEqual(classify(function_evidence).complexity_type, "TYPE_V-B")

    def test_original_rva_tracks_reused_decode_buffer(self):
        events = [
            {"event": "exec", "pid": 1, "tid": 1, "address": "0x1000"},
            {
                "event": "write",
                "pid": 1,
                "tid": 1,
                "address": "0x2000",
                "size": 4096,
                "original": True,
                "original_rva": "0x1000",
            },
            {
                "event": "exec",
                "pid": 1,
                "tid": 1,
                "address": "0x2000",
                "original": True,
                "original_rva": "0x1000",
            },
            {"event": "exec", "pid": 1, "tid": 1, "address": "0x1000"},
            {
                "event": "write",
                "pid": 1,
                "tid": 1,
                "address": "0x2000",
                "size": 4096,
                "original": True,
                "original_rva": "0x3000",
            },
            {
                "event": "exec",
                "pid": 1,
                "tid": 1,
                "address": "0x2000",
                "original": True,
                "original_rva": "0x3000",
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            path.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            evidence = analyze_jsonl(path, "sample", 8192)
        self.assertEqual(evidence.union_code_coverage, 1.0)
        self.assertEqual(evidence.maximum_simultaneous_code_coverage, 0.5)
        self.assertEqual(evidence.repacked_original_bytes, 1)
        self.assertEqual(classify(evidence).complexity_type, "TYPE_VI-P")

    def test_lower_writer_does_not_reduce_destination_layer_frame(self):
        events = [
            {"event": "exec", "pid": 1, "tid": 1, "address": "0x1000"},
            {
                "event": "write",
                "pid": 1,
                "tid": 1,
                "address": "0x2000",
                "original": True,
                "original_rva": "0x1000",
            },
            {
                "event": "exec",
                "pid": 1,
                "tid": 1,
                "address": "0x2000",
                "original": True,
                "original_rva": "0x1000",
            },
            {
                "event": "write",
                "pid": 1,
                "tid": 1,
                "address": "0x2000",
                "original": True,
                "original_rva": "0x2000",
            },
            {
                "event": "exec",
                "pid": 1,
                "tid": 1,
                "address": "0x2000",
                "original": True,
                "original_rva": "0x2000",
            },
            {
                "event": "write",
                "pid": 1,
                "tid": 1,
                "address": "0x2000",
                "source_layer": 0,
                "original": True,
                "original_rva": "0x3000",
            },
            {
                "event": "exec",
                "pid": 1,
                "tid": 1,
                "address": "0x2000",
                "original": True,
                "original_rva": "0x3000",
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            path.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            evidence = analyze_jsonl(path, "sample", 3)
        self.assertEqual(evidence.layers, 3)
        self.assertEqual(evidence.original_code_frames, 3)

    def test_unmap_repacks_original_code_in_its_actual_layer(self):
        events = [
            {"event": "exec", "pid": 1, "tid": 1, "address": "0x1000"},
            {
                "event": "write",
                "pid": 1,
                "tid": 1,
                "address": "0x2000",
                "original": True,
                "original_rva": "0x1000",
            },
            {
                "event": "exec",
                "pid": 1,
                "tid": 1,
                "address": "0x2000",
                "original": True,
                "original_rva": "0x1000",
            },
            {
                "event": "unmap",
                "pid": 1,
                "tid": 1,
                "address": "0x2000",
                "source_layer": 9,
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            path.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            evidence = analyze_jsonl(path, "sample", 1)
        self.assertEqual(evidence.repacked_original_bytes, 1)
        self.assertEqual(evidence.maximum_simultaneous_code_coverage, 1.0)


if __name__ == "__main__":
    unittest.main()
