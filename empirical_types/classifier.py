from __future__ import annotations

from .model import Classification, Evidence, UNRESOLVED


def _granularity(e: Evidence) -> str:
    if not e.frame_sizes:
        return "F"
    page_like = sum(s >= 4096 and s % 4096 == 0 for s in e.frame_sizes)
    if page_like > len(e.frame_sizes) / 2:
        return "P"
    if e.frame_basic_blocks and sum(e.frame_basic_blocks) / len(e.frame_basic_blocks) == 1:
        return "B"
    # Figure 1 names this middle category Function (F).  Section III-E
    # explains that the automated fallback also includes irregular generic
    # blocks/functionality-sized frames in this category.
    return "F"


def _classify_paper_runtime(e: Evidence) -> Classification:
    """Section III-E decision procedure, including the Type-III fallback."""
    if e.all_code_flagged_packer:
        return Classification(
            "TYPE_III",
            1.0,
            e,
            "paper fallback: all executed code was conservatively flagged as packer code",
        )

    linear = bool(e.linear_transition_model)
    if e.tail_transition:
        if linear and e.layers == 2:
            return Classification(
                "TYPE_I", 1.0, e, "one unpacking layer followed by a tail transition"
            )
        if linear and e.layers > 2:
            return Classification(
                "TYPE_II", 1.0, e, "multiple sequential layers and a tail transition"
            )
        return Classification(
            "TYPE_III", 1.0, e, "cyclic layer topology followed by a tail transition"
        )

    multi_frame = (
        e.original_multiframe_ratio is not None
        and e.original_multiframe_ratio > 0.5
    )
    if multi_frame:
        suffix = _granularity(e)
        if e.repacked_original_bytes:
            return Classification(
                f"TYPE_VI-{suffix}",
                1.0,
                e,
                "a majority of candidate application code is multi-frame and repacked",
            )
        return Classification(
            f"TYPE_V-{suffix}",
            1.0,
            e,
            "a majority of candidate application code is unpacked incrementally",
        )
    return Classification(
        "TYPE_IV",
        1.0,
        e,
        "packer and candidate application code are interleaved without majority multi-frame code",
    )


def classify(e: Evidence) -> Classification:
    """Apply the decision hierarchy from Ugarte et al. without forced labels."""
    if e.termination == "timeout":
        return Classification(UNRESOLVED["timeout"], 1.0, e, "execution timed out")
    if e.termination == "crash":
        return Classification(UNRESOLVED["crash"], 1.0, e, "sample crashed")
    if e.termination == "backend_failure":
        return Classification(
            "UNRESOLVED_BACKEND_FAILURE", 1.0, e, "analysis backend failed"
        )
    if not e.trace_complete:
        return Classification(
            UNRESOLVED["trace_loss"], 1.0, e, "required trace events are missing"
        )
    if e.cross_process_activity and not e.cross_process_certified:
        # The sample created/enrolled/wrote into another process, but the backend
        # was only certified for the single-process channel set.  Refuse to label
        # rather than risk a Type derived from a trace whose cross-process
        # behavior this backend may not have fully observed.
        return Classification(
            UNRESOLVED["uncertified_cross_process"],
            1.0,
            e,
            "cross-process activity observed under a single-process-only backend "
            "certification",
        )
    if e.taxonomy_basis == "paper_runtime_heuristic":
        if e.layers == 0:
            return Classification(
                UNRESOLVED["trace_loss"],
                1.0,
                e,
                "paper trace contains no executed basic blocks",
            )
        return _classify_paper_runtime(e)
    if not e.original_match_available:
        return Classification(
            UNRESOLVED["trace_loss"], 1.0, e, "no original-binary mapping"
        )
    if e.union_code_coverage == 0:
        return Classification(
            UNRESOLVED["no_original_code"], 1.0, e, "original code was not observed"
        )
    if e.union_code_coverage < 0.05:
        return Classification(
            UNRESOLVED["insufficient_coverage"],
            0.9,
            e,
            "less than 5% original-code coverage",
        )

    linear = e.backward_transitions == 0
    if e.tail_transition and not e.interleaved:
        if e.layers <= 2 and linear:
            return Classification(
                "TYPE_I", 0.95, e, "single unpacking layer and tail transition"
            )
        if linear:
            return Classification(
                "TYPE_II", 0.95, e, "multiple sequential layers and tail transition"
            )
        return Classification("TYPE_III", 0.95, e, "cyclic layers and tail transition")

    full_visible = e.maximum_simultaneous_code_coverage >= 0.95
    multi_frame = e.original_code_frames > 1 and (
        e.original_multiframe_ratio is None or e.original_multiframe_ratio > 0.5
    )
    if e.interleaved and multi_frame:
        suffix = _granularity(e)
        if e.repacked_original_bytes:
            return Classification(
                f"TYPE_VI-{suffix}", 0.95, e, "multi-frame original code with repacking"
            )
        return Classification(
            f"TYPE_V-{suffix}", 0.95, e, "incremental multi-frame original code"
        )
    if e.interleaved and full_visible:
        return Classification(
            "TYPE_IV", 0.9, e, "interleaved execution with full code visibility"
        )
    return Classification(
        UNRESOLVED["insufficient_coverage"],
        0.75,
        e,
        "evidence lacks required interleaving or does not distinguish Type IV from V",
    )
