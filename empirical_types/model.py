from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


UNRESOLVED = {
    "timeout": "UNRESOLVED_TIMEOUT",
    "crash": "UNRESOLVED_CRASH",
    "no_original_code": "UNRESOLVED_NO_ORIGINAL_CODE",
    "insufficient_coverage": "UNRESOLVED_INSUFFICIENT_COVERAGE",
    "trace_loss": "UNRESOLVED_TRACE_LOSS",
    "backend_failure": "UNRESOLVED_BACKEND_FAILURE",
}


@dataclass
class Evidence:
    sample_id: str
    taxonomy_basis: str = "original_binary_match"
    termination: str = "completed"
    trace_complete: bool = True
    original_match_available: bool = True
    layers: int = 0
    processes: int = 0
    threads: int = 0
    forward_transitions: int = 0
    backward_transitions: int = 0
    original_code_frames: int = 0
    original_multiframe_ratio: float | None = None
    maximum_simultaneous_code_coverage: float = 0.0
    union_code_coverage: float = 0.0
    repacked_original_bytes: int = 0
    tail_transition: bool = False
    interleaved: bool = False
    frame_sizes: list[int] = field(default_factory=list)
    frame_basic_blocks: list[int] = field(default_factory=list)
    frame_function_aligned: list[bool] = field(default_factory=list)
    candidate_code_bytes: int = 0
    candidate_multiframe_bytes: int = 0
    all_code_flagged_packer: bool = False
    linear_transition_model: bool | None = None
    packer_to_application_transitions: int = 0
    application_to_packer_transitions: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Classification:
    complexity_type: str
    confidence: float
    evidence: Evidence
    rule: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "complexity_type": self.complexity_type,
            "confidence": self.confidence,
            "rule": self.rule,
            **self.evidence.to_dict(),
        }
