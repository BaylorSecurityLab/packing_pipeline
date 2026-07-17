# Full-Matrix Scope — what "label all packer types, paper-faithful" actually requires

Goal (restated): produce **explicit** Ugarte et al. *SoK: Deep Packer Inspection*
Type I–VI labels for every corpus condition, measured exactly from runtime
write→execute behavior — **no approximation**, no DRAKVUF-only or YAML-hypothesis
labels. This is the standard fixed in `docs/empirical_type_collection.md` and the
eligibility invariant in `docs/empirical_type_handoff.md`.

Last grounded from `empirical_results/full_matrix/plan.livecheck.json` and
`manifest/empirical_types.yaml` on 2026-07-17.

## Current deliverable state (honest)

`manifest/empirical_types.yaml` today holds **zero** exact
(`empirical_exact_trace_consensus`) labels. Every row is provisional or
hypothesis-only:

- `provisional_stack_cross_check`: 226 (DRAKVUF stack cross-check — explicitly
  NOT a paper label)
- `pending_dynamic_evidence`: 29 (empty on NAS)

So none of the 255 conditions currently meets the goal. The pipeline, classifier,
and backend are built; the measurements are not produced.

## The corpus to label

- **255 conditions**, **44 families**, **111 family/version pairs**.
- **226 populated** (2 selected payloads each → **452 payloads**), **29 empty**.
- Type-hypothesis spread (starting guesses, not labels): Type I 183, V 21,
  Type III 20, IV 18, II 13.
- Dominated by **UPX** (134 conditions / 50 versions) plus a long tail of one- or
  two-condition families.
- Planned exact executions at current population: **226 × 2 payloads × 3 reps =
  1,356**. If the 29 empties are filled: **1,530**.

## Three hard prerequisites (all currently unmet)

### P1 — A validated exact backend  ⛔ BLOCKED (the critical path)

No Type I–VI output is accepted until the current QEMU/plugin/profile identity
passes `ops/qemu/validate_fixture_trace.py` with zero errors and a
`ops/qemu/backend_validation.json` stamp exists. As of fixture run 024 the
validator returns **9 errors**: the guest hit the 30-minute maximum stalled at
the first child-process spawn, so the file-I/O, unmap-identity, cross-process
`NtWriteVirtualMemory`, shared-RAM-alias, and remote-write channels never fired.

The reordered fixture (committed) recovers the 4 no-child channels once staged
and rerun. The **3 genuinely cross-process channels require solving child-process
spawn+trace throughput** — the unsolved core problem (step 2 of the plan).
Until P1 is green, **every one of the 1,356 runs would return
`UNRESOLVED_TRACE_LOSS` by construction** — running the matrix first is wasted.

### P2 — Sample availability: NAS access + regenerate 29 empty conditions

**Status (2026-07-17): NAS access now CONFIRMED WORKING.** Credentials are never
stored in-repo; staging reads `PACKER_NAS_USERNAME` / `PACKER_NAS_PASSWORD` from
the environment (kept in the gitignored `.env`; template in `.env.example`).
`//10.100.99.29/samples/benign_packed` has 116 family/version entries.
Spot-checked populated families are well-stocked and stageable (petite 533,
mpress 614, beroexepacker 972, molebox 679 executables). So the 226 populated
conditions (452 payloads) can be staged once P1 is green.

- A credentialed live recursive audit (2026-07-17,
  `empirical_results/full_matrix/nas-credentialed-audit.json`) **re-confirms the
  29 empty conditions are genuinely empty** — their testcase directories exist
  but contain zero executables; kkrunchy `_003_NEW` is empty while `_001/_002`
  hold 83/73, and 6 of 7 pezor testcases are empty while `002_self_inject_32`
  holds 67. Not a layout/credential mismatch — the samples were never generated.
- The 29 empty conditions have **no qualifying executable on the NAS**:
  - amber (13), pezor (6 of 7), hxor_packer (4), hyperion (2), alushpacker (1),
    fsg (1, GUI), simpledpack (1), kkrunchy `_NEW` (1).
- The declared packer binary/wrapper for 28 of these exists in-repo, but this
  Debian tracing host has **no Wine and no WSL**, and `utils/packer_runner.py`
  is Windows-oriented (PEzor explicitly needs WSL). So regeneration must run in
  the **original Windows/WSL generator environment** (or a prepared packing VM),
  producing exactly 2 valid payloads per empty condition. Do NOT substitute a
  different testcase — that would break provenance.

### P3 — Compute budget

Fixture run 024 alone consumed a full **host hour** and did not finish one
program. Real packer traces under this instrumentation are the same order:
conservatively **~15–60 host-minutes each**, and any packer that spawns a child
(common) hits the same P1 wall. 1,356 runs × ~30 min ≈ **~680 host-hours ≈ 28
days** of continuous single-host runtime — and this 3.8 GiB host already forced
the guest down to 3 GiB and into swap (run 018). Realistically this needs a
**dedicated, larger tracing host** (ideally several in parallel), not this box.

## Critical path (do NOT reorder)

1. **P1**: solve child-process spawn throughput → stage reordered fixture →
   rerun → `validate_fixture_trace.py` green → write `backend_validation.json`.
2. **Pilot**: trace the existing UPX sample, `analyze_paper_jsonl`, require
   `paper_label_eligible=true`. Proves one real exact label end-to-end.
3. **P2**: obtain NAS creds; regenerate the 29 empties on a Windows/WSL host.
4. **P3**: stage + run the 2×3 matrix on adequate hardware, repairing
   backend-caused unresolved traces, until every populated condition meets the
   dynamic gate or exhausts its alternates.
5. **Finalize/verify**: `finalize` → `manifest/empirical_types.yaml` +
   `verify --require-retry-accounting`. Only then are labels
   `empirical_exact_trace_consensus`.

## What the user must provide (nothing here is synthesizable in-session)

- **NAS credentials** (env vars, per session).
- **A Windows/WSL packing host** to regenerate the 29 empty conditions.
- **A dedicated tracing host** (more RAM than 3.8 GiB; ideally parallel) and the
  **wall-clock budget** (~weeks) for ~1,356 hour-scale runs.
- A decision on the 29 empties: regenerate, or explicitly ship them as
  `pending_dynamic_evidence` (unresolved) rather than fabricated measurements.

## Bottom line

The pipeline is complete and green (66 tests, ruff clean); the measurements are
entirely gated on **P1** (one unsolved performance problem — the next work item)
and then on **P2/P3 external resources**. No exact label can be produced before
P1 is green, so the immediate engineering focus is child-process tracing
throughput.
