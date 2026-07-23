# Empirical Type I–VI collection

The `type` values formerly stored in `manifest/packer_corpus.yaml` were qualitative
hypotheses. They are not ground truth. They are now named `type_hypothesis` and
`type_hypothesis_rationale`; measured classifications are written per sample under
`empirical_results/`.

The exact classifier follows Ugarte et al., *SoK: Deep Packer Inspection* (paper
included in this directory): layers and transitions separate Types I–III; the
paper's 10-page runtime heuristic separates packer and candidate application code;
multiple candidate-code frames identify Type V; and rewriting already-executed
candidate code identifies Type VI. Missing evidence is an `UNRESOLVED_*` result,
never an inferred Type.

Granularity suffixes are exactly those in Figure 1 of the paper: `P` (page), `F`
(function), and `B` (basic block or instruction). Section III-E's automated
procedure assigns irregular generic/functionality-sized frames to the middle `F`
category because they are neither page multiples nor an average of one basic block
per frame.

## 1. Stage or mount the samples

Credentials are never stored in this repository. To copy the NAS tree locally:

```bash
export PACKER_NAS_USERNAME='...'
read -rsp 'NAS password: ' PACKER_NAS_PASSWORD; export PACKER_NAS_PASSWORD
uv run packer-types stage-nas --destination /data/packer-samples
unset PACKER_NAS_PASSWORD
```

Use `--remote benign_packed/PACKER/TEST_CASE --limit 1` for a one-file pilot.

If the share is already mounted, skip staging.

## 2. Build the paired inventory

The directory layout is expected to match the generator:
`<packer_version>/<TEST_CASE_ID>/<original-filename>.exe`.

```bash
uv run packer-types inventory /data/packer-samples \
  --original-root /data/benign_sources \
  --output empirical_results/inventory.jsonl
```

Each record includes hashes, family, version, architecture, test case, CLI template,
and a stable configuration ID.

## 4. Upstream-QEMU paper-faithful tracing

The installed PANDA/QEMU build is not used because it crashes with the
paper's two-vCPU topology. The exact backend is the pinned upstream-QEMU TCG
plugin under `ops/qemu/`. It records one globally ordered stream of executed
basic blocks and every successful store from both guest CPUs. The Windows guest
launcher creates the sample suspended, emits its root PID, and resumes it; the
trace begins at the packed PE entry point.

The QEMU source carries a reproducible patch that exposes a stable RAMBlock byte
identity. This connects writes and executions through virtual aliases and shared
sections, including mappings that cross pages. Kernel offsets and syscall RVAs
are generated from the guest's exact PDB profile rather than generic Windows
version guesses.

Every run has a metadata sidecar listing required observation channels. The
classifier will return `UNRESOLVED_TRACE_LOSS` unless basic-block execution,
same/remote-process writes, shared sections, mapped-file/disk communication, and
unmap/free events are all declared complete.

## 5. Classify a normalized paper trace

The deep backend emits timestamp-ordered JSON Lines. Required records are:

```json
{"event":"write","pid":1,"tid":4,"address":"0x401000","size":16}
{"event":"exec","pid":1,"tid":4,"address":"0x401000","size":5}
```

For cross-process writes, `pid` is the writer and `target_pid` is the destination.
Memory deallocation is represented by `invalidate`, `unmap`, or `free` and is treated
as overwriting visible code, following the paper. Shadow byte state and new-frame
bits are maintained separately for every process/layer.
System-library instructions should be excluded by the trace normalizer or emitted as
`{"event":"exec", ..., "role":"system"}`; they are not packer/application
interleaving. External `packer` or `original` role labels are deliberately ignored
by the paper classifier.

Then run:

```bash
uv run packer-types classify-paper-trace trace.jsonl --sample-id SHA256 \
  --meta trace.meta.json \
  --output empirical_results/runs/SHA256/classification.json
uv run packer-types report empirical_results/runs
```

Only traces with every paper-required observation channel can yield Type I–VI.

## Full matrix, audit, and retries

The corpus-wide workflow selects two payloads for every YAML test case. GUI-only
packers are grouped by family/version because they have no test-case directory:

```bash
uv run packer-types plan-nas --samples-per-condition 2 \
  --output empirical_results/full_matrix/plan.json
uv run packer-types stage-plan empirical_results/full_matrix/plan.json \
  --destination /tmp/packer-full-matrix \
  --inventory empirical_results/full_matrix/inventory.jsonl
uv run packer-types collect empirical_results/full_matrix/inventory.jsonl \
  --repetitions 3 --output /tmp/packer-full-runs
uv run packer-types audit empirical_results/full_matrix/plan.json \
  /tmp/packer-full-runs -n 3 --minimum-distinct-samples 2 \
  --output empirical_results/full_matrix/audit.json
```

After the primary batch, stage unused alternates only for conditions below the
dynamic gate, then run each retry payload three times. Retry selection prefers
portable applications over installers that commonly require UAC interaction:

If an otherwise usable payload already has two validated repetitions, the automated
workflow first makes at most two additional in-place attempts (`rep_004` and
`rep_005`). This recovers transient VM/injection failures without changing the
payload. Persistent failures then fall back to a distinct alternate, which receives
the full three-repetition treatment. The default seven-batch ceiling covers both
in-place attempts plus all five retained alternates before exhaustion is reported.

```bash
uv run packer-types stage-retries empirical_results/full_matrix/plan.json \
  /tmp/packer-full-runs --destination /tmp/packer-full-retries \
  --inventory empirical_results/full_matrix/retry_inventory.jsonl \
  --report empirical_results/full_matrix/retry_report.json
uv run packer-types collect empirical_results/full_matrix/retry_inventory.jsonl \
  --repetitions 3 --output /tmp/packer-full-runs
```

Repeat the retry/audit pair until every populated condition meets the gate or its
alternates are exhausted. Produce the provenance-preserving complete labels with:

```bash
uv run packer-types finalize empirical_results/full_matrix/plan.json \
  /tmp/packer-full-runs -n 3 --minimum-distinct-samples 2 \
  --output empirical_results/full_matrix/labels.json \
  --yaml-output manifest/empirical_types.yaml \
  --csv-output empirical_results/full_matrix/labels.csv
uv run packer-types verify empirical_results/full_matrix/plan.json \
  empirical_results/full_matrix/audit.json \
  empirical_results/full_matrix/labels.json \
  manifest/empirical_types.yaml \
  empirical_results/full_matrix/labels.csv \
  --retry-report empirical_results/full_matrix/retry_report.final.json \
  --require-retry-accounting \
  --output empirical_results/full_matrix/verification.json
```

An `empirical_exact_trace_consensus` label requires eligible exact traces from both
payloads. Empty NAS conditions and exhausted failures remain explicitly
unresolved rather than being silently presented as empirical measurements.
Every condition row also reports `original_mapped_distinct_samples` and
`exact_trace_resolved_runs`, making the missing exact-trace prerequisites visible
in JSON, YAML, and CSV rather than only in the methodology narrative. It also
includes `validated_target_events` and per-plugin `target_event_totals`, so the
runtime evidence supporting a provisional gate is directly inspectable.
The verifier requires identical condition IDs, labels, provenance statuses, and
run counts across the plan, audit, JSON, YAML, and CSV artifacts. Add
`--require-all-populated-dynamic` when no exhausted failure is being retained.
When failures remain, run `stage-retries` one final time after the last retry batch;
its zero-staged report proves which conditions exhausted every retained alternate.

After the primary 3x2 matrix completes, the retry/finalize/verify loop can be run as
one resumable command (NAS credentials still come only from the environment):

```bash
uv run packer-types finish-matrix empirical_results/full_matrix/plan.json \
  /tmp/packer-full-runs --retry-destination /tmp/packer-full-retries \
  --output-directory empirical_results/full_matrix \
  --manifest-output manifest/empirical_types.yaml -n 3
```
