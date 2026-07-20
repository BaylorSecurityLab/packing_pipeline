# Prompt for the sync-system / auto-packing-pipeline Claude agent

Copy everything below the line and give it to the agent running on the sample-sync
host (the machine with write access to the NAS `samples` share and to the
auto-packing pipeline source).

---

You are working on the host that owns the packed-sample corpus: it has write access
to the SMB share `//10.100.99.29/samples` (use the credentials already in this
host's environment/config — do NOT hardcode them) and to the **auto-packing
pipeline** source that produces `benign_packed/`. Your job has two parts:
(1) purge bad samples that are already on the NAS, and (2) add a hash check to the
packing pipeline so bad samples can never be produced again.

## Background — the two defects we found

The corpus lives at `//10.100.99.29/samples/benign_packed/<packer_family_version>/`.
Each dir is supposed to contain apps packed by that one packer+version. A downstream
empirical type-labeler discovered two kinds of contamination:

1. **Unpacked-original duplicates.** The identical file appears in multiple packer
   dirs. Concrete proof: `ansi2knr_unxutils_X86_portable_en-US.exe` has
   `sha256 = 00129a0e7483c75f…` and that exact file is byte-identical in both
   `alienyze_protector_1.4/` and `amber_v2.0_2.0/`. Two different packers cannot
   emit byte-identical output, so these are original (never-packed) binaries that
   got mixed in. Whole suites are affected — the UnxUtils tools and various
   `*_portable_*` apps recur as originals across dozens of dirs (we measured
   25–50 duplicate originals in some dirs: upx, upack, pecompact, obsidium, the
   upx_scrambler variants, etc.).

2. **Pass-through / silently-failed packs.** A file is unique to its packer dir
   (so it is NOT a cross-dir duplicate) yet is not actually packed — running it
   executes entirely from mapped PE sections with no runtime unpacking, i.e. the
   "packed" output is functionally the original. Example we hit:
   `amber_v2.0_2.0/…/IconViewer_…exe` and `Bitwarden_…nullsoft…exe` — unique hashes,
   ~0.9–1.2 MB, but zero write-then-execute at runtime. These are packs that
   failed open (the packer returned the input unchanged or nearly so).

Both defects make the file look like a packed sample while behaving like an
unpacked one, which corrupts any analysis that assumes the dir's contents are
genuinely packed by that packer.

## Part 1 — Purge bad samples already on the NAS

Work in **dry-run first**. Produce a report, get it reviewed, and only then delete.
Prefer **quarantine (move) over hard-delete** for the first pass: move offending
files to `//10.100.99.29/samples/_quarantine/<original_relative_path>` and write a
manifest, so nothing is irreversibly lost until a human confirms.

Steps:

1. **Enumerate + hash.** Walk every `.exe` under `benign_packed/**` and compute its
   sha256 and size. Cache results (this is large — stream files, don't hold them in
   memory; skip/note any file over, say, 200 MB unless needed). Write a
   `nas_inventory.jsonl` of `{path, sha256, size, packer_dir}`.

2. **Flag cross-dir duplicates (defect 1).** Group by sha256. Any sha256 that
   appears under **two or more different `<packer_family_version>` dirs** is an
   unpacked original (or an otherwise mis-filed shared file). Flag **all** copies.
   (A sha appearing multiple times within a *single* packer dir is fine — that is
   just the same app in different test cases.)

3. **Flag pass-throughs (defect 2), if you can access the original inputs.** If the
   pipeline keeps the pre-pack originals (a `benign_unpacked/` or build cache),
   compute their shas and flag any `benign_packed/**` file whose sha256 equals its
   original input's sha256 — that pack did nothing. If originals are not available
   here, skip this in Part 1 and rely on Part 2 to stop future pass-throughs; also
   emit the list of "unique but suspicious" candidates (small size delta vs a
   same-named file, or names matching known originals) for a human to spot-check.

4. **Report.** Emit `nas_cleanup_report.md`: counts per packer dir, total bytes
   reclaimed, and the full flagged list. Do NOT delete yet.

5. **Quarantine on approval.** After the report is approved, MOVE flagged files to
   `_quarantine/` preserving relative paths, and write `quarantine_manifest.jsonl`
   (`{original_path, sha256, reason}`). After a retention period a human can purge
   `_quarantine/`. Never delete a dir that would leave a packer with < 2 genuine
   samples without explicitly flagging that packer as "needs re-packing."

Safety rules: never touch anything outside `benign_packed/`; never delete the base
guest images or non-`.exe` assets; log every move with its sha; make the whole run
idempotent (re-running re-uses the inventory and skips already-quarantined files).

## Part 2 — Add a hash check to the auto-packing pipeline

Find the packing pipeline source on this host (the code that takes an original
`input.exe`, runs a packer, and writes the result into `benign_packed/<packer>/`).
Add a **post-pack verification gate** that runs for every produced sample, before it
is published to the NAS:

1. **Reject pass-throughs.** Compute `sha_in = sha256(original_input)` and
   `sha_out = sha256(packed_output)`. If `sha_out == sha_in`, the pack failed open —
   **fail the job**, do not publish, log
   `PACK_FAILED_PASSTHROUGH packer=<..> app=<..> sha=<..>`.

2. **Reject "packed == original bytes" more robustly.** Also fail if the packer's
   exit code is non-zero, if `sha_out` equals **any** known original-input sha
   (maintain a set of input shas for the batch), or — optional but recommended — if
   a quick static signal shows no packing occurred (e.g. entry section still the
   original `.text`, no high-entropy/compressed section, import table unchanged).

3. **Enforce cross-packer uniqueness.** Maintain a running set of published output
   shas for the batch. If a new `sha_out` collides with an output already published
   under a **different** packer dir, fail the job (that means an original leaked in,
   or two packers produced identical bytes — both are bugs). Emit
   `PACK_DUP_ACROSS_PACKERS`.

4. **Record provenance.** For every published sample, write a sidecar (or a central
   `manifest.jsonl`) with `{packer_family, packer_version, app, input_sha256,
   output_sha256, packer_exit_code, verified: true}` so future consumers can trust
   the corpus and re-run these checks.

5. **Tests.** Add a unit/integration test that feeds the pipeline a file the packer
   is known to no-op on and asserts the gate rejects it (sha_out == sha_in →
   job fails, nothing published).

Deliverables: the pipeline diff implementing the gate + tests, `nas_cleanup_report.md`,
and (after approval) the quarantine manifest. Keep all destructive NAS actions behind
dry-run + quarantine until a human approves the report.
