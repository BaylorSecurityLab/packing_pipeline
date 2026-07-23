"""protection_class -- an axis ORTHOGONAL to the Ugarte Type I-VI scale.

Ugarte et al. (SoK: Deep Packer Inspection, IEEE S&P 2015) place virtualization-
based protectors OUTSIDE the Type I-VI taxonomy: they "do not recover the original
code by overwriting a region of memory," so a write->execute (W->X) oracle cannot
assign them a Type.  When our oracle reports no unpacking (layers < 2 -> UNRESOLVED)
this module reads the already-recorded trace and reports the MECHANICAL reason the
oracle was blind -- WITHOUT re-tracing.

Design note (empirically grounded, see docs/methodology_limit_literature.md).  An
earlier version tried to label `virtualized` directly from dispatcher-frequency and
block out-degree.  Both were falsified against real samples: zprotect (a genuine VM
protector) looks LESS dispatcher-like than kkrunchy (a demoscene compressor).  The
literature is explicit that distinguishing a VM interpreter from a heavy
decompression/crypto loop requires VM-structural signals -- VM entry/exit context
save-restore bursts (Xu 2018, VMHunt) or virtual-PC recovery (Sharif 2009,
Rotalume) -- which our basic-block/write trace does not carry.  So this axis reports
only what the trace can support, and flags a NON-authoritative `high_reexec` hint
(possible virtualization OR heavy compression) rather than asserting virtualization.

  unpacking_observed  W->X resolved a layered unpack (a Type_* label exists).
  mapped_execution    the sample executed, but (nearly) all execution came from
                      mapped file/section memory -- the W->X-blind mechanism
                      (section/view-mapped loading, in-file VM code, or pre-entry
                      decryption all surface this way; the trace cannot separate
                      them further).
  no_execution        the sample loaded but never executed a single block (dud /
                      launch failure / possible anti-analysis bail-out).
  inconclusive        the sample executed from a mix of mapped and written memory
                      yet reached no consensus, or the recording failed; no
                      mechanical verdict is drawable.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

MAPPED_HI = 0.95
REEXEC_HINT = 25.0
DISPATCH_TOP_K = 8


@dataclass
class ProtectionSignals:
    total_exec: int = 0
    unique_blocks: int = 0
    mapped_exec: int = 0
    writes: int = 0
    exec_pages: int = 0
    write_exec_overlap_pages: int = 0
    dispatcher_share: float = 0.0
    exec_per_unique: float = 0.0
    mapped_exec_ratio: float = 0.0
    sample_started: bool = False
    high_reexec: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_exec": self.total_exec,
            "unique_blocks": self.unique_blocks,
            "mapped_exec_ratio": round(self.mapped_exec_ratio, 4),
            "dispatcher_share": round(self.dispatcher_share, 4),
            "exec_per_unique": round(self.exec_per_unique, 2),
            "writes": self.writes,
            "write_exec_overlap_pages": self.write_exec_overlap_pages,
            "sample_started": self.sample_started,
            "high_reexec": self.high_reexec,
            "notes": self.notes,
        }


def measure(trace_path: Path) -> ProtectionSignals:
    """Single pass over a trace.jsonl, extracting the protection signals."""
    freq: dict[int, int] = {}
    exec_pages: set[int] = set()
    write_pages: set[int] = set()
    sig = ProtectionSignals()
    if not Path(trace_path).exists():
        sig.notes.append("trace_absent")
        return sig
    with open(trace_path) as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            kind = event.get("event")
            if kind == "sample_start":
                sig.sample_started = True
            elif kind == "exec":
                sig.total_exec += 1
                address = event.get("address", 0)
                freq[address] = freq.get(address, 0) + 1
                exec_pages.add(address >> 12)
                if event.get("file_id") is not None:
                    sig.mapped_exec += 1
            elif kind == "write":
                sig.writes += 1
                write_pages.add(event.get("address", 0) >> 12)
    sig.unique_blocks = len(freq)
    sig.exec_pages = len(exec_pages)
    sig.write_exec_overlap_pages = len(exec_pages & write_pages)
    if sig.total_exec:
        top = sorted(freq.values(), reverse=True)[:DISPATCH_TOP_K]
        sig.dispatcher_share = sum(top) / sig.total_exec
        sig.mapped_exec_ratio = sig.mapped_exec / sig.total_exec
    if sig.unique_blocks:
        sig.exec_per_unique = sig.total_exec / sig.unique_blocks
    sig.high_reexec = sig.exec_per_unique >= REEXEC_HINT and sig.total_exec >= 500_000
    return sig


def classify_protection(
    signals: ProtectionSignals, resolved_type: str | None = None,
    recording_failed: bool = False,
) -> tuple[str, float]:
    """Assign a protection_class by precedence.  Returns (class, confidence).

    resolved_type: a Type_* label from the W->X oracle, if the sample resolved.
    recording_failed: the trace itself is unusable (trace loss / absent).  A mere
    host timeout is NOT a recording failure -- a run that executed millions of
    blocks then hit the timeout is still mechanically analysable, so timeouts are
    classified on their execution, not discarded.
    """
    if resolved_type and resolved_type.startswith("TYPE_"):
        return "unpacking_observed", 1.0
    if recording_failed:
        return "inconclusive", 1.0
    if signals.total_exec == 0 or not signals.sample_started:
        return "no_execution", 1.0
    if signals.mapped_exec_ratio >= MAPPED_HI:
        return "mapped_execution", 0.8
    return "inconclusive", 0.6


def analyze(
    trace_path: Path, resolved_type: str | None = None,
    recording_failed: bool = False,
) -> dict:
    signals = measure(trace_path)
    if "trace_absent" in signals.notes:
        recording_failed = True
    protection_class, confidence = classify_protection(
        signals, resolved_type, recording_failed
    )
    return {
        "protection_class": protection_class,
        "confidence": confidence,
        "resolved_type": resolved_type,
        "signals": signals.to_dict(),
    }
