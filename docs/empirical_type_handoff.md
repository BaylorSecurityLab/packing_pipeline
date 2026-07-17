# Empirical Type Collection — Live Handoff

Last updated: 2026-07-16 11:14 CDT (US/Central)

This is the authoritative continuation record for the paper-faithful Type I–VI
collection. Update this file whenever a milestone, runtime process, blocker, or
accepted-label count changes. Do not put NAS or sudo passwords in this file.

## Final objective

Produce paper-faithful empirical Deep Packer Inspection labels for every usable
YAML condition using:

- 2 distinct packed payloads per family/version/testcase;
- 3 executions per payload (`n=3`), or 6 executions per populated condition;
- GUI packers grouped by family/version without a testcase;
- one Type I–VI result (with V/VI granularity suffix) or an explicit unresolved
  reason per execution;
- investigation and rerun of every unresolved trace caused by the backend;
- per-condition distributions without forcing repeated executions to agree;
- a cross-check of at least 20 executions per family/version where the corpus
  supplies enough samples/conditions.

Do not accept DRAKVUF-only or qualitative/YAML-hypothesis labels as empirical
types. DRAKVUF may remain a diagnostic/orchestration source only.

## RESUME AFTER RAM INCREASE (2026-07-17)

The VM is being resized from 3.8 GiB/2 vCPU to more RAM (target >= 8 GiB, ideally
12-16) so the 3-4 GiB Windows guest runs without swap thrash — the wall that
blocked certification. After reboot, resume here:

1. `free -m` — confirm the OS now sees the new RAM (a reboot is needed; hotplug
   to 16 GiB is unreliable). Also confirm `nproc`.
2. Everything is committed on branch `feature/empirical-type-backend`. Build
   artifacts are gitignored; rebuild if missing:
   `ops/qemu/build_plugin.sh`, `ops/panda/build_guest_launcher.sh`,
   `ops/qemu/build_validation_fixture.sh`.
3. The fixture image copy `empirical_results/qemu_runtime/windows10-qemu-fixture.qcow2`
   already has the single-process fixture (`2797e32e…`), the idle-override
   launcher (`a5ff3b14…`), `idle_ms.txt=900000`, and `single_process.txt` staged.
   Re-stage if needed: `sudo ops/qemu/stage_fixture_launcher.sh` (SINGLE_PROCESS=1).
4. Run the single-process certification at 3G or 4G now that RAM allows it:
   `run_trace.py … --guest-memory 4G --host-timeout 1200`, then
   `validate_fixture_trace.py --single-process … <trace> ops/qemu/backend_validation.json`.
   It was 2 unmap-events from passing; with a stable (non-thrash) guest speed the
   detection races that plagued 2 GiB should not recur (029/031 reached
   sample_start reliably at 3 GiB when it booted).
5. On a clean stamp, run a real packed pilot (existing UPX sample) through
   `classify-paper-trace` requiring `paper_label_eligible=true`, then scale via the
   plan/collect/finalize pipeline. NAS creds are in the gitignored `.env`.

NOTE: a fable code-review of the session's paper_trace.c changes (context-cache,
fast-reject, root_asid, eager discovery) was in flight to check whether the 2 GiB
nondeterminism is a plugin bug (which would persist at higher RAM) rather than
pure timing; check its findings before the first post-resize run.

Supervisor (fable) guidance folded in:
- DONE (host-independent): cross-process guardrail. The analyzer now positively
  detects a process-creation/injection attempt (enrolled descendant, post-cutoff
  candidate via `descendant_debug` after_cutoff, or any cross-process write) and
  `classify()` hard-fails it to `UNRESOLVED_UNCERTIFIED_CROSS_PROCESS` under a
  single-process-only stamp. So a single-process stamp can never silently label a
  cross-process packer. Every accepted label must record the stamp mode.
- TODO before the pilot (host-independent, recommended): add a HARDWARE-fault
  raise + VEH recovery step to the single-process fixture (e.g. guard-page or
  access-violation caught by a vectored handler, in-process, no child). The
  fixture only exercised the software `RtlRaiseException` path; the processor
  fault-vector path has only a bare-metal `#UD` smoke, yet real Type III/VI
  packers use access violations / int3 / guard pages. Cheapest high-value close.
- Post-resize ORDER: re-baseline (rebuild + full gate + hashes) -> boot sanity at
  3-4 GiB (confirm no thrash, deterministic sample_start; abandon the 2 GiB
  operating point, don't chase its nondeterminism) -> single-process cert + stamp
  -> ALSO attempt one FULL cross-process fixture run (the CreateProcess wall was
  plausibly thrash-amplified; one hour is cheap and if it certifies the scoping
  question evaporates) -> pilot ONE real UPX sample (require
  paper_label_eligible=true, sanity-check the Type I verdict + analyzer memory)
  -> complete ONE condition end-to-end (2 payloads x n=3 -> finalize -> verify)
  -> only then scale to the ~134 single-process conditions.
- Watch: the 2-guest-minute idle boundary under 50-100x slowdown can truncate a
  real unpacking mid-flight and still look "normal" -> scrutinize stop reasons in
  the pilot, prefer all-processes-exit evidence; benchmark analyzer per-byte-state
  memory on a large trace before the full matrix.

## Hard current checkpoint

- Accepted paper-eligible labels: **0**.
- YAML conditions: **255**.
- Live NAS planner matches: **226 populated, 29 exact testcase/configuration
  directories empty**.
- Planned executions at current population: **1,356** (`226 * 2 * 3`).
- Planned executions if all 255 conditions become populated: **1,530**.
- Project tests at the last completed gate: **65 passed**.
- Lint at the last completed gate: **clean**.
- QEMU marker smoke: **passed**.
- Dedicated eligible/rejected buffered-write smoke: **passed** with two exact
  retained stores in address/instruction order and zero overflow.
- Backend validation stamp: **not yet produced**; the eligibility gate remains
  closed.

## Why this backend

- Installed PANDA crashes with the required two-vCPU Windows guest.
- DRAKVUF page/VMI events do not provide the complete successful-store to
  basic-block ordering needed by the paper.
- The selected backend is pinned upstream QEMU/TCG revision
  `eca2c16212ef9dcb0871de39bb9d1c2efebe76be`, two vCPUs, 3 GiB, and machine
  `pc-i440fx-5.2`.
- `ops/qemu/qemu-ram-identity.patch` adds comparable stable RAM identities for
  executed instructions, memory stores, and pre-unmap guest physical pages.
- The patch has been checked in both directions: it applies to a clean pinned
  worktree and reverses cleanly from the current patched source.

## Current live runtime state

Fixture run 022 started at 11:15:20 CDT and was closed through HMP `quit` at
11:34 CDT after it stopped making trace progress. It is a preserved,
diagnostic-only run. It reached the recovered exception handler and emitted a
final sequence-64,320 summary with 44,229 executions and 19,955 writes, but it
did not finish the fixture or emit a stop marker. The summary records 14
physical-mapping failures, zero exception dispatch/recovery events, zero
virtual-memory-write events, and zero file-I/O events. No label or
backend-validation stamp is accepted from this run. Both its disposable
overlay and the clean base pass `qemu-img check` after closure.

The branchless memory buffer exposed an API-lifetime defect in the first real
Windows run: `qemu_plugin_get_hwaddr()` is being invoked when buffered callbacks
are drained after the translated block, whereas QEMU only guarantees its TLB
lookup during the dynamic memory callback. QEMU emitted `invalid use of
qemu_plugin_get_hwaddr` warnings. Ordering and virtual store addresses remain
diagnostically useful, but the physical/RAM identity channel is not eligible.
This is now repaired: each retained user store is resolved through the
still-current vCPU address space at the immediate TB-exit drain (before another
TB/vCPU) and converted to the stable RAM identity. The dedicated smoke gate
proves the exact identities and rejects the old warning. The entire fixture
still must be rerun.

Run 022 also proves that this Windows build does not traverse the exported
`KiUserExceptionDispatcher` entry for the fixture's `RaiseException` path.
The apparent raw-offset candidate `0xa16c0` is the exact `__chkstk` helper
(RVA `0xa22c0`), not an exception dispatcher, and must not be relabelled as
one. The existing exception event channel therefore remains unvalidated. Trace
reconstruction showed that modern `RtlRaiseException` invoked the fixture's
vectored handler entirely in user mode, so neither `NtRaiseException` nor the
exported dispatcher was reached. The plugin now uses QEMU's synchronous
discontinuity callback for processor exceptions plus the exact,
hash/signature-bound `RtlRaiseException` entry for software-raised exceptions;
the validator requires the recovered fixture to exercise the latter.

The registry-replay verification boot completed successfully:

- Windows reached a stable desktop at 23:07 CDT;
- ACPI shutdown was requested, and QEMU explicitly reached
  `VM status: paused (shutdown)`;
- QEMU was then closed through HMP `quit`;
- `qemu-img check empirical_results/qemu_runtime/windows10-qemu-repair.qcow2`
  reported `No errors were found on the image`.

The first offline mount then reported Fast Startup hibernation metadata plus an
active NTFS cached/unclean flag and correctly refused a writable mount. The
supported `remove_hiberfile` option also refused because of the active cached
flag; no force mount or `ntfsfix` was used.

A second safe Windows boot reached the desktop. UAC secure-desktop confirmation
could not be reliably injected, so no blind elevated command was used. Instead,
the visibly verified Run command `shutdown /s /t 0 /f` performed a full
shutdown. QEMU reached `paused (shutdown)`, was closed through HMP, and
`qemu-img check` again reported no errors. A normal writable NTFS mount then
succeeded; no `force`, `recover`, or `ntfsfix` was used.

Offline fixture staging is complete and the image is currently unmounted with
NBD disconnected:

- `C:\Panda\guest_launcher.exe` SHA-256:
  `62da41cc9b3d43b535e7a1591f90d64ccb1dd5bed1332180ac306e3a586aa199`
- `C:\Panda\validation_fixture.exe` SHA-256:
  `0c289a8625bdd1807c37ab0f7ee757a68ae12bdb5e231ec6aad264e8ce341efa`
- both hashes match the current host builds;
- the only active control set is `ControlSet001` (`Select.Current=1`);
- exported `PandaPilot` values prove `Start=2` and the exact REG_EXPAND_SZ
  command targets `validation_fixture.exe 1800 - C:\Panda\status.txt`;
- exported power values prove `HiberbootEnabled=0` and
  `HibernateEnabledDefault=0`.

The exact guest `ntdll.dll` was copied to the ignored profiling artifact
`empirical_results/qemu_runtime/ntdll.dll`; SHA-256 is
`fdb2689bffabe7d2e300882ca1c3fc2fe24a998ffcbd5f48795c7d95712d1e98`.
Its `KiUserExceptionDispatcher` export RVA is `0xa0ee0` and file offset is
`0xa02e0`.

The first real instrumented fixture run failed diagnostically and is stopped:

- user unit: `packer-fixture-validation-001.service`
- QEMU PID at launch: `751370`
- base: `empirical_results/qemu_runtime/windows10-qemu-repair.qcow2`
- disposable work disk:
  `empirical_results/qemu_runtime/fixture_validation_001/work.qcow2`
- trace: `empirical_results/qemu_runtime/fixture_validation_001/trace.jsonl`
- QEMU log: `empirical_results/qemu_runtime/fixture_validation_001/qemu.log`
- metadata target:
  `empirical_results/qemu_runtime/fixture_validation_001/meta.json`

The guest booted, the service marked root PID 588, and the root PE image/entry
were learned. The first action-4 query occurred before kernel-base discovery.
The preserved final summary proves `marker_query_failures=1`, stop detail
`0x20000000`, zero exec/write events, and a valid stop marker. The launcher
therefore took its query-failure path before the sample entry point. The unit
was stopped only after this diagnosis; only the disposable overlay could be
dirty. Both the clean base and disposable qcow2 passed `qemu-img check`.

The protocol is now corrected with an explicit initialization state:

- before kernel discovery, a valid status response has `status_ready=0`;
- the launcher continues execution but does not apply idle/process decisions;
- the 30-minute maximum remains enforced during initialization;
- once traversal is possible, responses use `status_ready=1`;
- failures after that point remain fatal and increment
  `marker_query_failures`;
- summaries count `marker_query_initializing` and `marker_query_ready`;
- fixture validation requires at least one ready query and zero true failures.

`run_trace.py` now also creates a per-run HMP Unix monitor socket so a future
guest can be inspected or cleanly powered down while active. The corrected
plugin/launcher/fixture build, marker smoke, Ruff, and **57 tests** pass. The
new launcher was restaged before fixture run 002.

Fixture run 002 was started at 23:59:55 CDT after hash-verified restaging:

- user unit: `packer-fixture-validation-002.service`
- runner PID at launch: `753569` (QEMU child PID appears after startup)
- disposable directory:
  `empirical_results/qemu_runtime/fixture_validation_002/`
- live HMP socket:
  `empirical_results/qemu_runtime/fixture_validation_002/monitor.sock`

Fixture run 002 is now stopped and preserved as a diagnostic failure, not a
sample result. It learned the correct fixture image base `0x7ff77e4b0000` and
PE entry `0x7ff77e4b14d0`, then produced 170 valid initializing action-4 queries
with zero query/context/register failures, but never activated event capture.
Its summary is sequence 175 in
`empirical_results/qemu_runtime/fixture_validation_002/trace.jsonl` and proves
`marker_query_initializing=170`, `marker_query_ready=0`, `exec_events=0`, and
`saw_stop=false`. After a bounded two guest-minute observation window, an ACPI
power-down was requested; Windows did not honor it after more than one host
minute. Only the transient unit/disposable overlay was then stopped. Both the
clean base and disposable overlay pass `qemu-img check`; the base was never
writable.

The root cause was an activation cycle: kernel discovery ran only while
`active`, but `active` was set only after observing the PE entry. The plugin now
activates at the launcher's action-2 marker immediately before `ResumeThread`,
allowing kernel discovery during initialization and preserving pre-entry TLS
callbacks. Exact PE-entry observation remains separate, is emitted once as
`trace_start`, is recorded as `root_entry_seen`, and is required by the fixture
validator. The rebuilt plugin SHA-256 is
`d00c9dbdffe38a3ea67c2bdcee3fc8eb07c0103eed1d4928248fd754b98e098f`.
Fixture run 003 started at 00:18:03 CDT and is now stopped as a second preserved
diagnostic failure. Activating before resume correctly broke the prior cycle,
but immediately exposed that the remote-kernel-write predicate lacked a
destination-address check. While the root thread was temporarily attached to
PID 4 during kernel initialization, kernel-address housekeeping stores enrolled
PID 4; that recursively enrolled unrelated processes and grew the trace to
1,296,712 write events/249 MiB in seconds. No execution event or label was
accepted. The transient run was stopped to bound disk growth. Its summary is
sequence 1,296,782 in
`empirical_results/qemu_runtime/fixture_validation_003/trace.jsonl`; both its
disposable overlay and the read-only clean base pass `qemu-img check`.

The remote-kernel-write rule now additionally requires the destination virtual
address to be user space. This preserves genuine kernel-mediated
`WriteProcessMemory` writes into a target process while rejecting attached
kernel bookkeeping. The fixture validator now independently rejects any
kernel-address `write` event. The rebuilt plugin SHA-256 is
`b4ac37cf8a77d7573769467cb70f6295c984266c0596b59a8616eeb35c6a3918`.
The scoped Ruff gate, QEMU marker smoke, and full Python 3.13 suite (**59
passed**) are green.

Fixture run 004 started at 00:25:46 CDT and is now stopped as a bounded
performance diagnostic. It reached action 1/2 with root PID 1252, did not
re-enroll PID 4, emitted zero writes, and ultimately reached one ready status
query with zero failures. Its sequence-5 summary records
`filtered_kernel_write_events=195857`, `marker_query_ready=1`, and zero
exec/write events. The trace stayed below 1 KiB rather than exploding, proving
the run-003 correctness fix. However, kernel-to-kernel stores were still being
rejected only after expensive current-context and RAM-identity reconstruction,
which delayed one guest second by over one host minute.

The plugin now rejects kernel-PC/kernel-destination stores at the top of the
write callback, before context/RAM work. Kernel-to-user stores still traverse
the complete remote-write path. The rebuilt plugin SHA-256 is
`c41e4e15d0f927cfff3a93e352c7ccd5836661ce203727403a5f299d68ebbec9`;
59 tests, scoped Ruff, build, and marker smoke remain green. Fixture run 005
started at 00:34:56 CDT: unit
`packer-fixture-validation-005.service`, runner PID 759509, QEMU PID 759570,
and disposable directory
`empirical_results/qemu_runtime/fixture_validation_005/`. It reached action 2
at about 6m50s with root PID 936 and produced status queries without any invalid
writes or system-process enrollment. The early kernel-store rejection reduced
the first post-activation query from more than one host minute to about 15–20
seconds.

Run 005 then emitted a clean action-3 idle stop (`0x40000102`) before observing
the PE entry. Readiness was achieved during loader initialization, and the
launcher's idle clock incorrectly still began at process creation. This is a
termination-control failure, not a fixture/sample result. Its guest-initiated
Windows shutdown did not complete within the bounded window, so only its
transient overlay unit was stopped. The final summary (sequence 17) proves 12
ready queries, 27,367,436 early-filtered kernel stores, zero writes/events, the
idle stop, and zero query/context failures. Both overlay and clean base pass
`qemu-img check`.

The protocol is already fixed in the host build: `MarkerStatus`/`PACKER_STATUS`
now carries `sample_started=root_entry_seen`. The launcher starts/resets its
two-minute idle clock only on the first exact PE-entry observation; all-process
exit and the 30-minute maximum remain valid before entry. New hashes awaiting
offline restaging after shutdown are:

- plugin: `3773f63300ca3ef7808f0e6ffaef94e20db66b44a58f07ed904faa2e3cc842b3`
- launcher: `1c24e77472f7794d4e4393e03a6b0f4a2425fca112eb32aad3293e2ef3872520`

The plugin and launcher compile; 59 tests, scoped Ruff, and marker smoke pass.
The clean base was attached through NBD only after run 005 stopped, mounted
normally with `ntfs-3g`, and the new launcher was copied to
`C:\Panda\guest_launcher.exe`. The in-image and host SHA-256 both matched
`1c24e77472f7794d4e4393e03a6b0f4a2425fca112eb32aad3293e2ef3872520`.
The NTFS filesystem was unmounted normally, NBD was disconnected, and a final
base `qemu-img check` found no errors.

Fixture run 006 started at 00:53:29 CDT and is now stopped as a bounded
performance diagnostic. It reached action 2 at about 5m50s (root PID 2596),
produced two ready queries, did not emit the former idle stop, and had zero
invalid writes/enrollments. Its summary proves the new `sample_started` gating
prevented the run-005 termination error. However, 20,997,304 filtered
kernel-to-user stores still performed physical RAM reconstruction before their
already-decided rejection, limiting progress to about one guest second per host
minute.

The write callback now resolves current context and the retained/filtered
decision before physical identity. Only retained user stores and genuine
connected kernel-to-user remote stores reconstruct RAM spans; the exact set of
emitted events is unchanged. Plugin SHA-256 is now
`8ec0e68ae468c3b3d54d83948cb8fe30222919b790e89ae10c948d46772a4021`.
The disposable run-006 overlay and clean base pass `qemu-img check`; 59 tests,
scoped Ruff, build, and marker smoke are green. The staged launcher hash remains
`1c24e77472f7794d4e4393e03a6b0f4a2425fca112eb32aad3293e2ef3872520`.
Fixture run 007 started at 01:03:01 CDT and is now stopped as a methodological
diagnostic. It reached action 2 at 5m32s (root PID 2180), then produced 53 ready
queries, learned the correct root image, and emitted 1,769 executions plus
3,989 writes at normal TCG speed. All 1,769 executions were tagged system code;
the root PE entry had not yet executed. The analyzer skips system `exec` events
but would still consume their untagged write events, so accepting this trace
could turn Windows loader writes into artificial W->X unpacking layers. Its
sequence-5816 summary and disposable overlay are preserved; the overlay and
clean base pass `qemu-img check`.

Instrumentation and sample recording are now explicitly separate. Action 2
enables context/kernel discovery, but no execution, write, file, free, or unmap
event is emitted until the first mapped non-system root block. That block emits
`sample_start` with reason `first_non_system_execution`; it captures TLS
callbacks before `AddressOfEntryPoint` without recording the Windows loader.
Exact PE entry remains a distinct `trace_start`/`root_entry_seen` observation.
The status `sample_started` field now reflects this recording boundary. The
analyzer recognizes `sample_start` as metadata, and the fixture validator
requires both recording start and exact PE entry.

Plugin SHA-256 is now
`92f7e048c3e52e83a9e9a22b50100c16602a4cc7e401f64c9ba8ef467d787c6d`.
The staged launcher remains compatible and unchanged. Plugin build, marker
smoke, scoped Ruff, and **60 tests** pass.

Fixture run 008 started at 01:13:24 CDT and is now stopped as a bounded loader
diagnostic. It reached action 2 at 5m39s (root PID 420), learned the root image,
and produced 303 ready queries over a five-guest-minute observation window.
It emitted zero paper exec/write/file/invalidation events, zero filtered writes,
and no idle stop, proving both the system-loader exclusion and staged
`sample_started` control. The child stayed active but never executed mapped
non-system root code or the exact PE entry. Its sequence-308 summary and
disposable overlay are preserved; overlay and clean base pass `qemu-img check`.

Run 009 adds diagnostic-only `prestart_exec` records for the first 64 root user
blocks and power-of-two samples thereafter, including address, file offset,
mapping result, and system/non-system role. The analyzer ignores these records.
Summary counters separately record root/system/unmapped pre-start executions.
This will identify the exact system loop without admitting loader events to the
paper state machine. Plugin SHA-256 is
`13e47775bc0cf7bee672cd9812836321c6548741e964d82a648224a0fee59720`;
60 tests, scoped Ruff, build, and marker smoke remain green.

Fixture run 009 started at 01:33:35 CDT and completed normally at the guest's
paper 30-minute maximum (one host hour). It learned root PID 2192/image/ASID,
then observed 303,833 pre-start root blocks, all mapped to the same exact system
DLL and none unmapped/non-system. It emitted no paper events and stopped with
`0x80000102`; QEMU returned 0 and `meta.json` correctly records both host and
guest timeout. Sampled file offsets map into normal guest `ntdll.dll`
loader/export-resolution code (including the long-run offsets around file
`0x31acc`, RVA `0x326cc`), not a one-address deadlock. The actual problem is the
cost of full current-context/VAD resolution on every pre-start ntdll block.

The pre-start hot path now captures the root user ASID and PE `SizeOfImage` when
the root image is learned. Thereafter it skips root ntdll blocks with only a CR3
and image-range check, skips kernel blocks except cheap kernel-base discovery,
and starts full recording at the first instruction inside the root PE image.
This preserves TLS callbacks and avoids treating the loader as packer code.
Post-start exact tracing is unchanged. The summary now records root ASID/image
base/image size. Plugin SHA-256 is
`cbc7f4d12ca490f6558a570c2b3fbb25196e8c8e253982926ba18fcc2affbb65`;
60 tests, scoped Ruff, build, and marker smoke were green.

Fixture run 010 started at 06:07:28 CDT and is now stopped as a process-tree
identity diagnostic. The fast pre-start path worked: root PID 1808 reached its
first PE-image instruction (`__dyn_tls_init` at image RVA `0x19d0`) at sequence
44, so the former loader stall is resolved. The very next context switch
enrolled PID 1488 because its `InheritedFromUniqueProcessId` numerically equaled
1808. Disassembly and chronology prove this was impossible as a real child:
the root had executed only one 18-byte TLS block, before `main` and before any
`CreateProcessA`. PID 1488 existed before the new root and was admitted because
Windows had reused PID 1808. Its unrelated system execution accounted for
1,776 exec and 1,239 write events. No trace or label was accepted. Run 010 was
bounded at sequence 3,071; both its disposable overlay and the read-only clean
base pass `qemu-img check`.

Descendant tracking is now identity-safe and tied to the launcher's Windows
job object. The exact kernel PDB profile adds `_EPROCESS.CreateTime` (`0x468`)
and `_EPROCESS.Job` (`0x510`). The plugin binds every monitored PID to its exact
EPROCESS object, validates the source EPROCESS PID, captures the root's job and
creation time, and enrolls only newer processes in that same job. This rejects
pre-existing PID collisions while retaining all actual descendants because the
root is assigned to a non-breakaway kill-on-close job before it resumes. A
genuine connected remote-write target can still be enrolled by the exact write
evidence. Current hashes are:

- plugin: `1501868e899a9b2e2bf80c43eb74ad7b3f85f03dacfe3554844113efc8d90bcf`
- profile header: `15d47a67ff0a9bd3ee614c97ef5a3dccdb77b5501f373d6c0b8133813188db75`
- staged launcher (unchanged):
  `1c24e77472f7794d4e4393e03a6b0f4a2425fca112eb32aad3293e2ef3872520`

Plugin build, marker smoke, scoped Ruff, and all 60 tests pass after this fix.
Fixture run 011 started at 06:21:49 CDT using the new plugin: unit
`packer-fixture-validation-011.service`, runner PID 772490, QEMU PID 772501,
and directory `empirical_results/qemu_runtime/fixture_validation_011/`.

Run 011 is now stopped as a second bounded process-boundary diagnostic. It
proved the job/creation-time fix excluded run 010's pre-existing PID collision,
reached `sample_start` at sequence 101 and the exact PE entry at sequence 7,437,
and recorded the root's local generated-code execution/free. However, a
same-job system helper PID 2684 had been created by Windows during process
startup, before the first root image instruction. It was numerically a child
and correctly in the job, but it was not created by executed sample code. Its
system-only activity dominated the trace and emitted a `free` that could
incorrectly satisfy the fixture's invalidation requirement. The run was
stopped at sequence 31,768 with no stop marker and no accepted result. Both the
overlay and clean base pass `qemu-img check`.

The exact recording boundary now snapshots the greatest `_EPROCESS.CreateTime`
among all active processes immediately before `sample_start`. A job descendant
is eligible only if its creation time is later than that snapshot. This removes
console/system helpers created as part of Windows startup while retaining a
child created by the first TLS/application block or any later packer code. A
snapshot traversal failure prevents recording start, is counted as
`process_snapshot_failures`, and is a zero-required validation/eligibility
field. Current plugin SHA-256 is
`c6e32ae1242403dc882154c93162e8e6d02f95b7841b5914dd813dd20971952e`;
the profile and launcher hashes are unchanged. Plugin build, marker smoke,
scoped Ruff, and all 60 tests pass. Fixture run 012 started at 06:37 CDT: unit
`packer-fixture-validation-012.service`, runner PID 773723, QEMU PID 773736,
and directory `empirical_results/qemu_runtime/fixture_validation_012/`.
It reached root PID 1548, learned the fixture image, and emitted
`sample_start` at sequence 40. The startup helper seen in run 011 has not been
enrolled: the process list still contains only the root. At the comparable
post-start point run 011 had roughly 10,000 helper-dominated events; run 012
had roughly 1,500 root-only events. This live result confirms the creation-time
snapshot boundary is working.

Run 012 is now stopped as a bounded performance diagnostic. Its summary at
sequence 1,560 proves zero context/snapshot/mapping failures, only the root was
monitored, and the clean boundary held. It also counted 64,590,990 filtered
kernel writes while advancing only a few guest seconds after `sample_start`.
The overlay and clean base pass `qemu-img check`; no result was accepted.

The exact event set is now optimized without changing paper ordering or
retention. Full thread/process identity is cached when a user or relevant
kernel block executes. A kernel store uses the cached source thread and reads
only its current attached process; same-process kernel stores are rejected
without reconstructing the complete context, while a monitored thread attached
to another process still follows the exact remote-write path. Kernel basic
blocks now do full introspection only at the five exact syscall entry RVAs or a
pending captured return address; other kernel blocks cannot emit any tracer
event and are skipped. The plugin SHA-256 is
`42e46fdd5fcf547d1a583416e6d516df406d3c836dc941a21d2a5e9d8dcbcaf4`.
Build, marker smoke, scoped Ruff, and all 60 tests pass. The next validation run
is 013. Run 013 started at 06:53 CDT: unit
`packer-fixture-validation-013.service`, runner PID 775074, QEMU PID 775166,
and directory `empirical_results/qemu_runtime/fixture_validation_013/`.

Run 013 is now stopped as a bounded performance result. It reached root PID
2316 and clean `sample_start` at sequence 59 with only the root monitored, so
the creation cutoff remains correct. Its sequence-65 summary has zero
integrity failures but counted 14,273,481 rejected kernel writes while making
essentially no post-start guest-time progress. Caching context reduced work per
callback but cannot remove QEMU's callback invocation itself. Both overlay and
clean base pass `qemu-img check`; no result was accepted and no validation unit
is active.

Next implementation step: add exact-PDB `NtWriteVirtualMemory` entry and
successful-return tracing, analogous to the existing exact NtRead/NtWriteFile
and NtFree/NtUnmap hooks. Capture target handle/address, source buffer, requested
size, return address, and optional completed byte count at entry; on successful
return emit the target bytes plus complete target RAM identities before the
next user block and enroll the remote target by that evidence. Then do not
register generic memory callbacks for kernel instructions. User-mode stores
remain instruction-exact. This removes tens of millions of rejected callbacks
while retaining the cross-process write effect/order relevant to the paper;
do not replace it with page traps, sampling, or API-only guessed labels. Extend
the exact profile generator/header with `NtWriteVirtualMemory`, add validator
and tests for the hook/failure counters, build/smoke/test, and start run 014.

That implementation step is now complete in the host build. The exact guest
profile resolves `NtWriteVirtualMemory` to RVA `0x6d4f20`. Entry capture records
the resolved target process, address, requested size, completed-count pointer,
target directory table, kernel return address, and last application caller.
Only a successful return emits a write; the completed range must have complete
target RAM identities or the trace receives a hard failure. Remote-target
evidence is emitted even when the target was already enrolled as a job
descendant. Translation now registers memory callbacks only for user virtual
addresses; generic kernel-store callbacks are structurally disabled. The
validator requires that fact, a positive exact virtual-write event count, and
zero virtual-write failures. Current hashes are plugin
`4355cc0f440c1d76329ac0e8cc1613247c4f412e83a42748c2a0c1cb8a795cc2`
and profile header
`366e2f246ebad37b659812a2fdead594929694ee2b40b942b327cb32a02ed8de`.
Tests: 61 passing; scoped Ruff and marker smoke are green. Run 014 started at
08:19 CDT: unit `packer-fixture-validation-014.service`, runner PID 777897,
QEMU PID 777912, directory
`empirical_results/qemu_runtime/fixture_validation_014/`.

Run 014 is now stopped as a bounded translation-performance diagnostic. It
reached clean `sample_start` at sequence 76 with only root PID 1960. Its summary
proves `filtered_kernel_write_events=0`, generic kernel callbacks disabled, and
zero integrity failures, but it still made no useful post-start progress. This
isolated the remaining cost to translation-time instruction RAM-span
reconstruction for kernel blocks that can never be emitted. Both overlay and
base pass `qemu-img check`; no result was accepted.

Translation now reconstructs instruction RAM spans, scans marker bytes, and
registers store callbacks only for user virtual addresses. Kernel blocks retain
the exact execution address needed for syscall entry/return hooks but perform
none of that unused per-instruction work. Plugin hash is now
`351419d8b5cad49bf0e5ff70168ffe04961e70206cb5ddd7597f36b813a6e8df`;
61 tests, marker smoke, and scoped Ruff pass. Run 015 started at 08:29 CDT:
unit `packer-fixture-validation-015.service`, runner PID 779380, QEMU PID
779424, directory `empirical_results/qemu_runtime/fixture_validation_015/`.
Run 015 is now stopped as a pre-start callback diagnostic. It reached root PID
60, learned the exact
fixture image, and produced 40 ready status queries, but has not yet reached
`sample_start` until the stop boundary, where the summary confirmed the first
root block and two root writes. The query count paused while both vCPUs changed
kernel RIP and CR3 values (verified live through read-only HMP sampling), so it
was not a one-address deadlock. This isolated millions of pre-start user-loader
store callback invocations that returned immediately but still carried QEMU
callback cost. Both overlay and clean base pass `qemu-img check`; no result was
accepted.

The pinned QEMU plugin ABI now exports `qemu_plugin_request_tb_flush()`, which
queues a full translated-code flush at a safe CPU work boundary. Before
`sample_start`, user loader translations retain marker scanning but receive no
store callback; root-image instructions are fully instrumented so the first TLS
block and its stores remain exact. At `sample_start`, the plugin queues exactly
one flush, after which every user/system translation receives exact callbacks.
The validator requires one flush request. The QEMU patch was regenerated from
the authoritative pinned-source diff, reverses cleanly from the current source,
and dry-runs cleanly against a fresh detached worktree. Current hashes:

- QEMU: `7b8bf2b6681b6131045f600ae008c25e17474bf8e510b08039f2cfc7b2e21054`
- plugin: `880f1fd26673a14e2cdb5cb46ffa8a405befd64a640a4b14dd065a82a39a15ea`
- QEMU patch: `331fc151911f868fa7c86d0a4962a353c0c3dfaea76b0536266272992cf68a6f`

The exported symbol is present, marker smoke passes, scoped Ruff is clean, and
all 62 tests pass. Run 016 started at 08:51 CDT: unit
`packer-fixture-validation-016.service`, runner PID 782639, QEMU PID 782650,
directory `empirical_results/qemu_runtime/fixture_validation_016/`.

Run 016 is now stopped as a post-start context-cost diagnostic. Boundary-aware
translation worked: it advanced roughly 30 guest loader seconds per 30 host
seconds, reached `sample_start` at sequence 81, retained the exact first TLS
block and its two writes, and recorded exactly one TB flush request. It then
paused because every post-start user store still repeated full ETHREAD/EPROCESS
introspection. Both overlay and clean base pass `qemu-img check`; no result was
accepted.

The TB execution callback now stores the exact `ThreadContext` in a per-vCPU
slot before any instruction in that TB executes. Store callbacks reuse that
context; a guest context switch cannot occur inside a translated block. This
removes repeated kernel-structure reads without changing any store, PID, TID,
target, or ordering. A missing block context is counted separately and is a
zero-required validation field. Plugin hash is now
`daa96d2f9193f466dbf81f441bb860469c5fab568ebd3588ba0e22d2b6114054`;
QEMU and patch hashes are unchanged. Marker smoke, scoped Ruff, and all 62 tests
pass. Run 017 started at 09:06 CDT: unit
`packer-fixture-validation-017.service`, runner PID 784435, QEMU PID 784447,
directory `empirical_results/qemu_runtime/fixture_validation_017/`.

Run 017 is now closed as a bounded post-start performance diagnostic. It found
the exact root PID 1224, root image, and `sample_start` at sequence 61; retained
the first root block and its two writes; and had zero integrity failures through
that point. After the sample-boundary flush it advanced only about one guest
status query per 30 host seconds. The loaded plugin reread ETHREAD/EPROCESS
structures on every user basic block. ACPI powerdown did not complete under
that slowdown, so QEMU was closed through HMP `quit`; the disposable overlay
and clean base both pass `qemu-img check`. Its metadata records return code 0,
no host timeout, and `paper_label_eligible=false`; no result was accepted.

The exact thread context cache now persists across consecutive user-mode basic
blocks and is invalidated on **every** intervening kernel block. This is exact:
Windows cannot switch the executing thread without a syscall, interrupt,
exception, or scheduler path entering kernel mode first. Therefore the first
user block after kernel execution refreshes ETHREAD-derived PID/TID/process
identity, while subsequent user blocks reuse that immutable context. Summary
counters expose refreshes and cache hits, and the fixture validator requires
both to be positive while still requiring zero `block_context_misses`. Current
plugin SHA-256 is
`3a77f95821dac3cbb3894486cf6ac412109ed9bd93c1028f4a9000b2b354e9d2`;
QEMU and profile hashes remain unchanged. Plugin/launcher/fixture builds,
marker smoke, scoped Ruff, and all 63 tests pass. The next action is fixture
run 018 with this plugin. Run 018 started at 09:21 CDT after correcting the
transient service's working directory: unit
`packer-fixture-validation-018.service`, runner PID 787156, QEMU PID 787167,
directory `empirical_results/qemu_runtime/fixture_validation_018/`. The first
launch attempt exited before QEMU because systemd defaulted to `/home/resbears`;
it created no overlay or trace and is not an empirical execution.

Run 018 is now closed as a host-memory diagnostic before `sample_start`. It
found exact root PID 1244 and root image, then paused at query marker sequence
57 for six minutes while changing kernel RIPs in the root address space. This
occurred before the new context-cache branch could run. The 4 GiB guest on this
3.8 GiB host had pushed 3.5 GiB into swap and repeatedly killed even tiny host
inspection helpers. QEMU was closed through HMP `quit`; both overlay and clean
base pass `qemu-img check`; no result was accepted.

`run_trace.py` now makes the empirical guest-RAM condition explicit with
`--guest-memory {2G,3G,4G}` and defaults to a fixed 3 GiB for this host. The
chosen value is recorded in every run's metadata. This does not approximate a
trace channel or taxonomy rule; it is a controlled VM environment parameter,
and 3 GiB remains above the requirements of the Windows 10 fixture and target
packers while leaving host memory for exact tracing. Tests and Ruff remain
green. The next clean fixture attempt is run 019 at 3 GiB.
Run 019 started at 09:36 CDT: unit
`packer-fixture-validation-019.service`, runner PID 789350, QEMU PID 789387,
directory `empirical_results/qemu_runtime/fixture_validation_019/`, explicit
guest RAM condition `3G`.

Run 019 is now closed as a sample-boundary flush diagnostic. It reached exact
root PID 2908 and `sample_start` sequence 52 with the first block and two
writes, but made only one further query in roughly three minutes after the
queued global TB flush. QEMU was closed through HMP `quit`; overlay and base
both pass `qemu-img check`; no result was accepted.

The phase switch no longer flushes translated code. Every user instruction is
given a write callback at its **first translation from VM boot**, so code
translated before `sample_start` cannot escape later write observation. The
callback returns without recording before the exact boundary or for an
unmonitored process. It uses `QEMU_PLUGIN_CB_NO_REGS`: the callback reads no
registers and consumes the exact per-vCPU ThreadContext established by that
TB's execution callback before its first instruction. Any kernel block
invalidates the context, and the first subsequent user block refreshes it.
This removes an unnecessary full register synchronization on every store and
removes the global retranslation pause without dropping a write channel.
`tb_flush_requests` must now be zero, and the validator requires
`always_present_user_store_callbacks=true` plus positive fixture writes and
zero context misses. A proposed conditional-memory QEMU API failed marker
smoke during development and was fully removed before any Windows run; the
pinned QEMU source/patch/binary returned byte-for-byte to their previous
validated hashes. Current hashes are QEMU
`7b8bf2b6681b6131045f600ae008c25e17474bf8e510b08039f2cfc7b2e21054`,
plugin `7de8a51c560ee5ea2e5de3d0204abfc0a652beba17e1d5af8249d30a78461e32`,
and patch
`331fc151911f868fa7c86d0a4962a353c0c3dfaea76b0536266272992cf68a6f`.
The patch reverses from the live source and applies to a fresh detached pinned
worktree; marker smoke, scoped Ruff, and all 64 tests pass. Next: fixture 020.
Run 020 started at 09:59 CDT: unit
`packer-fixture-validation-020.service`, runner PID 794119, QEMU PID 794131,
directory `empirical_results/qemu_runtime/fixture_validation_020/`, guest RAM
condition `3G`.

Run 020 is now closed as an unmonitored-store-filter diagnostic. It reached
root PID 2360 and `sample_start` sequence 73 with the exact first block and two
writes. Removing the TB flush improved the immediate boundary: five ready
queries followed promptly. It then slowed because, once `sample_started` was
true, every user store in every Windows process entered the C callback before
the process-monitor filter. QEMU was closed via HMP; overlay/base pass
`qemu-img check`; no result was accepted.

The TB execution callback now clears a per-vCPU write-eligibility bit before
attribution and sets it only after exact PID/EPROCESS monitoring, physical
mapping, and non-attached-process checks succeed. The memory callback tests
that bit before locks, hash lookups, or RAM conversion. Because the TB callback
runs before its instructions and every kernel block clears/invalidate state,
this is the same exact process predicate moved to the start of the hot path,
not sampling or omission. Current plugin SHA-256 is
`7d53db2a5ef5d7a530750f1546114e35ae2b6e2958a548145c69316959fbacec`;
marker smoke, scoped Ruff, and all 64 tests pass. Next: fixture 021.
Run 021 started at 10:07 CDT: unit
`packer-fixture-validation-021.service`, runner PID 795549, QEMU PID 795562,
directory `empirical_results/qemu_runtime/fixture_validation_021/`, guest RAM
condition `3G`.
Run 021 reached exact root PID 2428, root image, and `sample_start` sequence 61.
It then advanced immediately beyond sequence 1,570 with exact exec/write pairs
and system-role evidence, proving the eligibility fast path removed the prior
boundary stall. It is still live as of 10:18 CDT while Windows performs kernel
work; unit/PIDs and directory above remain current. Do not stop it merely
because the buffered trace file is temporarily unchanged: sampled kernel RIPs
and CR3s continue changing and QEMU remains CPU-active. It subsequently flushed
through sequence 13,304: 7,364 exec events, 5,861 writes, exact PE
`trace_start`, and one successful `free` event with RAM identity. The latest
visible root-image loop is stack probing at 4 KiB decrements; this explains the
page-fault-heavy kernel intervals. As of 10:29 CDT the unit is still active,
the host timeout has not fired, and the next action is to wait for normal
completion, validate the closed JSONL, and fix every strict validator error.
At 10:32 CDT the next buffer flush reached sequence 15,411 (8,570 exec,
6,761 writes). The root thread is inside system-library process-creation code;
no child enrollment event has appeared in the closed portion yet. This is
forward progress, not a deadlock. The recovered-exception evidence is absent
from the already ordered pre-spawn portion and is therefore a likely validator
failure to investigate after the complete trace; do not weaken that channel.
The run next advanced through sequence 23,090, with ready-query markers
resuming after the long kernel interval. No child `process` event is present in
the closed trace. Run 021 was deliberately closed through HMP `quit` at about
32 host minutes because each nominal 0.5 guest-second status-query interval had
grown to roughly five host minutes. Its final visible trace contains 13,113
executions, 9,891 writes, the exact trace start, and one successful free event,
but only the root process. It is an ineligible performance diagnostic; no label
was accepted. Both the disposable overlay and clean base passed `qemu-img
check` again at 10:52 CDT.

The remaining cost is the C call made by every Windows user-mode store even
when the per-vCPU exact process predicate rejects it immediately. A new QEMU
conditional-memory callback API was prototyped so rejected stores could be
tested inline. The QEMU build and plugin compile, but marker smoke aborts in
TCG `temp_load`; generated-op evidence proves the conditional branch occurs
inside a guest instruction while that instruction still has EBB temporaries
live after the store. Spilling only the store address is insufficient because
other guest temporaries also cross the inserted branch. This current build is
therefore rejected and fixture 022 has **not** been started. Current unaccepted
development hashes are QEMU
`a60e8b8de20d9179d64d8a8b8095431c4e40197f73827108201de8037e18b62a`
and plugin
`9032bc85eb9e62f2cff7e7563d75fcfbd02a8e5331b0edc9cda32a729d6c5ff4`.
The checked-in reproduction patch remains the prior accepted
`331fc151911f868fa7c86d0a4962a353c0c3dfaea76b0536266272992cf68a6f`
and has intentionally not been regenerated for a failing design.

Next implementation direction: replace the unsafe mid-instruction branch with
branchless per-vCPU buffering of memory events, then drain the buffer at the TB
boundary. The eligibility flag controls the buffer index arithmetically, so
unmonitored stores make no C call; monitored stores retain address, meminfo,
instruction identity, and order. The drain must occur before the next vCPU/TB
event to preserve the single-TCG global event order, and any bounded-buffer
overflow must make the trace explicitly ineligible rather than lose writes.
Do not launch Windows until marker smoke, 64 tests, Ruff, reproducible-patch
checks, and a dedicated monitored/unmonitored buffer smoke all pass.

That replacement is now complete. Every translated store appends branchlessly
to a per-vCPU buffer only by arithmetically advancing its retained-event index
when the exact scoreboard predicate is true. QEMU drains each buffer
immediately after `tcg_qemu_tb_exec` returns and before another TB/vCPU runs,
including exception exits. Thus retained write callbacks keep the original
single-TCG global order, while rejected stores make no C call. A 65,536-event
per-TB bound has a sentinel slot; any overflow increments
`memory_buffer_overflows`, and the strict validator rejects the trace rather
than permitting silent loss.

The first buffer build exposed and fixed a latent QEMU scoreboard codegen bug:
`gen_plugin_u64_ptr` modified a shared constant vCPU-index temporary in place.
It now scales into a fresh EBB temporary, which is required when one memory
operation references both the buffer scoreboard and eligibility scoreboard.
The dedicated `ops/qemu/smoke_buffer.sh` test uses two vCPUs, rejects firmware
writes, and proves exactly two eligible boot-sector stores arrive with
addresses `0x7000`, `0x7002` and PCs `0x7c04`, `0x7c08`, zero overflow. Marker
smoke also passes. Full gate: **65 tests passed**, Ruff clean, plugin/launcher/
fixture builds pass, and both smokes pass.

Accepted pre-fixture development hashes as of 11:14 CDT:

- QEMU: `a9ccf585913b42e6c9f65fc091d1c56595efab73f3204c75c02a6fc2bfc09d67`
- plugin: `0466df09c04e6fc9a3e920c83980e4d7b0bc10e363df542a969dfdacfb8047d4`
- reproduction patch:
  `3fbb733166df00f04e3d1e10b92076698fe679508916e0cacda4823f0208df33`
- profile header:
  `366e2f246ebad37b659812a2fdead594929694ee2b40b942b327cb32a02ed8de`

The regenerated patch reverses cleanly from the live source and applies
cleanly to a fresh detached `eca2c162...` worktree. No Windows run has used the
new build yet. Next action is fixture 022; its validator must additionally see
`buffered_memory_callbacks_registered=true` and
`memory_buffer_overflows=0`.

Fixture run 022 is closed and preserved at
`empirical_results/qemu_runtime/fixture_validation_022/`. Its exact validator
failure list is recorded in the current-state section above; it is not an
eligible trace.

The two Windows helper build scripts now pass GNU ld
`--no-insert-timestamp`. Two consecutive rebuilds produced identical hashes.
Those exact deterministic binaries were staged offline into `C:\Panda` using
a normal `ntfs-3g` mount, verified by SHA-256 in the mounted image, unmounted
normally, and NBD was disconnected. A post-staging base `qemu-img check`
reported no errors.

Current pre-fixture-023 identities:

- QEMU: `a9ccf585913b42e6c9f65fc091d1c56595efab73f3204c75c02a6fc2bfc09d67`
- plugin: `fe81e1966cd0c5a522baa8925f888deaa7c80a41431853cdb7a30223709582ec`
- reproduction patch:
  `3fbb733166df00f04e3d1e10b92076698fe679508916e0cacda4823f0208df33`
- launcher: `62da41cc9b3d43b535e7a1591f90d64ccb1dd5bed1332180ac306e3a586aa199`
- fixture: `0c289a8625bdd1807c37ab0f7ee757a68ae12bdb5e231ec6aad264e8ce341efa`
- ntdll: `fdb2689bffabe7d2e300882ca1c3fc2fe24a998ffcbd5f48795c7d95712d1e98`
- profile header:
  `366e2f246ebad37b659812a2fdead594929694ee2b40b942b327cb32a02ed8de`

The post-repair gate is 66 tests passed, Ruff clean, both guest builds and the
plugin compile, marker smoke passes, and the buffer smoke proves two exact
virtual/physical/RAM identities with zero mapping failures and no invalid
`qemu_plugin_get_hwaddr` warning.

Fixture run 023 started after this gate but was deliberately closed through HMP
before Windows startup completed. Review found that QEMU's generic synchronous
exception callback did not expose the x86 exception vector, so it could not
distinguish an application fault from routine demand-page faults. The run is a
preserved, sequence-1 pre-start diagnostic only. Both overlay and base passed
`qemu-img check`; no label or stamp was accepted.

The pinned QEMU API now exposes `CPUState.exception_index` only within the
synchronous-exception callback. The plugin explicitly retains x86
application-fault vectors and excludes `#PF` (14), `#NM` (7), and other
transparent/non-application vectors. Each retained processor-exception event
records its exact vector. The software-raised fixture path remains independently
bound to the exact `RtlRaiseException` entry. Current rebuilt identities are:

- QEMU: `a770c651c27e8d5838ea53ab0c32586faece099c4e48d1feff006e3cd5186e7c`
- plugin: `aba906911f1a4a3d821168dd7246c935259fe38ade585c02227def57ce804cd0`
- reproduction patch:
  `218f39754a3773336d870e485d8a5385772ece4dfe479b541266370f93c7fc57`

The reproduction patch reverses cleanly from the live tree and applies cleanly
to a fresh detached `eca2c162...` worktree. Plugin/QEMU builds, 66 tests, Ruff,
marker smoke, physical-buffer smoke, and a dedicated bare-metal `#UD` smoke are
green. The latter proves exact exception index 6 and fault PC `0x7c01` through
the new API.

Fixture 024 is closed and preserved under
`empirical_results/qemu_runtime/fixture_validation_024/`. Conditions were two
vCPUs, single TCG, 3 GiB, one-hour host guard. It is NOT eligible.

Run 024 outcome (validated 2026-07-17). The run hit the paper 30-minute guest
maximum (`paper_termination_reason=maximum_30_minute_timeout`, host+guest
timeout) after the one-hour host guard. It DID capture, with zero integrity
failures, the channels that occur early in the fixture:

- `exec_events=42962`, `write_events=5522`, all mapped-file/system-role clean;
- `exception_dispatch_events=1` and `exception_recovery_events=1` — the exact
  `RtlRaiseException` software-raise path finally fired and recovered;
- `invalidation_events=2` (free), `memory_buffer_overflows=0`,
  `always_present_user_store_callbacks=true`, `buffered_memory_callbacks_registered=true`,
  and every failure counter zero.

But it never reached the fixture's cross-process portion, so
`ops/qemu/validate_fixture_trace.py` returns nine hard errors:

```
missing required file_write event
missing required file_read event
missing required unmap event
no cross-process virtual-memory write was observed
no write/execute shared-RAM alias across processes was proved
no file-write to mapped-execution provenance chain was proved
unmap did not preserve pre-invalidation RAM identity
no remote-write target process evidence was emitted
fixture did not exercise NtWriteVirtualMemory tracing
```

Root cause is the standing performance wall, not a correctness regression. Only
`exec_events=42962` root sample blocks executed across the full 30 guest-minute
budget (block_context_cache_hits=37.8M shows the guest churned ~38M user blocks
overall). The root sample is starved: it reaches its local writes and the
exception raise/recover, then stalls — almost certainly blocked in / around the
child `CreateProcess`+loader path, whose in-guest cost under full instrumentation
consumes the remaining budget before the file-I/O, `NtWriteVirtualMemory`,
shared-section, and unmap operations execute. No backend stamp was produced;
`ops/qemu/backend_validation.json` was NOT created.

The blocker is now isolated to fixture throughput past the exception step, not
to any missing channel implementation (each channel is implemented and the early
ones verified clean this run). Confirmed against `validation_fixture.c`: `main`
ran `local_self_modify` then `recovered_exception` (both captured) and then
stalled inside `shared_parent`, the first step that spawns a child process
(`CreateProcessA` + `WaitForSingleObject`). The three remaining child-spawning
channels — shared-RAM alias (`shared_parent`), cross-process
`NtWriteVirtualMemory` (`remote_parent`), and disk-drop provenance
(`disk_drop`) — never executed, and neither did `mapped_file_execute`, which
needs NO child but ran last.

Applied fix (2026-07-17): `validation_fixture.c` `main` now front-loads
`mapped_file_execute()` (file write/read, mapped-file exec, unmap-with-RAM
identity — four of the nine validator errors, none requiring a child) ahead of
the three child-spawning steps, so a child-spawn stall can no longer hide them.
Rebuilt deterministically to fixture SHA-256
`3b2a4f30b641384c3f8903f29aeb7d59b63110fcbd0a278c1e7a91ae7f7d948f`.
This is NOT yet staged into the Windows image and NOT yet run. Staging requires
the offline NBD/`ntfs-3g` procedure (see Windows recovery history); do not
host-kill a live guest. The three genuinely cross-process channels still depend
on making child-process spawn+trace fit the guest budget — the unsolved core
performance problem.

Plugin throughput optimization (2026-07-17). Run 024's summary showed 37.8M
`block_context_cache_hits` versus only 42,962 root exec events: the root spends
the 30-minute wait blocked in `WaitForSingleObject` while every OTHER Windows
process's user blocks each took the global `trace_lock` and re-ran
`update_monitored_descendant`. `block_exec` now records, per vCPU, the
root/monitored verdict computed on the context-refreshing block and, on a
subsequent cache hit (identical thread — identity only changes through a kernel
transition, which invalidates the context), rejects an unmonitored, non-root
user block BEFORE the lock and descendant bookkeeping. This is emission-exact:
the refreshing block already ran `update_monitored_descendant` with the same
context, so its enroll/monitored decision is final for the whole cache-hit run;
no root or enrolled-descendant event is dropped, and per-block write eligibility
is still cleared at the top of every block. It removes the dominant per-block
cost of unrelated background processes during the child-spawn wait. It does NOT
reduce the enrolled child's own loader cost — that remains and may still need a
descendant pre-start fast path if run 025 still stalls. Rebuilt plugin SHA-256
`2bdd85941ee40880d36fba4820a848e74bbf35661cfb932c9f319d21b99b4d4b`. Gate green:
66 tests, ruff clean, plugin builds, and marker/buffer/exception smokes all
pass. Unproven against the real multi-process Windows load until fixture 025.

Next measurement (fixture 025): stage the reordered fixture
(`3b2a4f30…`, host-side plugin needs no staging) and run with the new plugin;
read the summary for whether `mapped_file`/`file_io`/`invalidation`(unmap) and
ideally the three cross-process channels now fire before the 30-minute maximum.
Then rerun `validate_fixture_trace.py`. Staging the fixture into the critical
qcow2 is the delicate offline step; do not attempt unattended without care.

Run 025 result (2026-07-17, plugin `2bdd8594`, OLD staged fixture, clean base +
disposable overlay, 3 GiB). The throughput optimization is a large confirmed
win: exec_events 42,962 -> **170,314** (4x), write_events 5,522 -> **37,825**
(6.8x), block_context_cache_hits 37.8M -> 131.8M, all integrity/failure counters
zero, memory_buffer_overflows 0, exception dispatch+recovery 1/1. Crucially the
guest no longer hits the hard 30-minute maximum — it now terminates via the
NORMAL `two_minutes_idle` boundary (guest_idle=true, saw_stop=true, images
clean). But the validator still returns the same nine errors: file_io=0 and
virtual_memory_write=0, and no child was enrolled.

Definitive diagnosis. Only root PID 2672 appears in exec events (all 170,314). A
child WAS spawned — the trace's final events include root freeing memory in
`target_pid=1368` — but PID 1368 never produced a single monitored exec event.
The launcher's idle clock is `GetTickCount64()` GUEST wall time
(`PACKER_IDLE_MILLISECONDS=120000` = 2 guest-minutes), reset only by new
monitored execution. Because the instrumented guest advances ~50-100x slower
than native while the guest clock tracks real time, the child cannot finish
`CreateProcess`+loader and reach its shared-section payload within 2 guest-
minutes; it never runs monitored code, the root stays blocked in
`WaitForSingleObject`, and the idle timer trips. The wall is now
child-bring-up-time vs. the guest-wall idle boundary — NOT raw per-block
throughput (the child was cheap: unmonitored, fast-rejected) and NOT a channel
implementation bug (all channels remain implemented; early ones verified clean).
block_context_refreshes was 5.18M — full ETHREAD/EPROCESS reads on every first
user block after a kernel transition, including background/child processes — a
remaining cost sink worth a cheap ASID-based reject, but that touches descendant
enrollment and must not be done blind (PID/CR3-reuse risk).

Next: run 026 with zero-risk diagnostic counters (enroll attempts, job mismatch,
create-time rejects, read failures, distinct non-root ASIDs, unmonitored user
blocks) to prove WHY PID 1368 never enrolled before optimizing further.

Runs 026-028 (2026-07-17). Run 026 was a host-thrash artifact: concurrent NAS
scans on this 3.8 GiB host pushed the 3 GiB guest into swap (352 MiB free) and
crawled it to 1 exec in 15 min. Lesson: run NOTHING heavy alongside a fixture
run. Closed cleanly via HMP; host recovered to 3 GiB free.

Run 027 (clean host) counters: exec 113,499, descendant_enroll_attempts 58,077,
descendant_job_mismatch 57,948, descendant_createtime_reject 129,
descendant_read_failures 0, descendant_enrolled 0, unmonitored_block_rejects
26.3M. This REFUTED the timing hypothesis: enrollment IS attempted 58k times;
almost all fail the job check.

Run 028 added per-process `descendant_debug` records and settled it decisively.
Of 32 distinct processes evaluated (root PID 2800): every background process has
job=0 (correctly rejected); the ONLY child of the root is PID 2932 with
job==root_job (matches!) but `after_cutoff:false` — created ~51 s BEFORE
sample_start, i.e. the OS-spawned console/startup helper that run 011's
create-time cutoff exists to exclude. Correctly rejected. ZERO processes had
`after_cutoff:true`, and exec_events was only 1,731: the root STALLED right after
sample_start and never reached `CreateProcess`, so no sample-spawned child ever
existed. **The enrollment predicate (job + create-time cutoff) is CORRECT, not
the bug.**

Real blocker, now isolated to two throughput/liveness modes, NOT enrollment:
1. Progress-then-idle (025:170k, 027:113k exec): root reaches the exception but
   the guest is too slow to finish `CreateProcess` + child bring-up within the
   launcher's 2-guest-minute idle window (`GetTickCount64`,
   `PACKER_IDLE_MILLISECONDS=120000`), so the child never spawns/runs before
   idle.
2. Early stall (026:1, 028:1,731 exec): the root stops executing entirely soon
   after sample_start — a nondeterministic guest hang (026 was thrash; 028 was a
   clean host, so ~1-in-2 of clean runs stall). Extending the idle window does
   NOT help this mode; it must be tamed for reliable iteration.

Fix direction (NOT in enrollment code):
- For mode 1: the 2-minute idle is a paper rule for real samples, but the
  cross-process VALIDATION FIXTURE deliberately spawns children and blocks in
  WaitForSingleObject, so its launcher legitimately needs a longer idle window.
  This is a `guest_launcher.c` change (raise/parameterize
  `PACKER_IDLE_MILLISECONDS` for validation only) requiring the delicate offline
  staging of the launcher into the qcow2. Do NOT change the 2-min boundary for
  real packer samples.
- For mode 2: reduce guest-side cost / nondeterminism. The 5.18M context
  refreshes (full ETHREAD/EPROCESS walks, incl. background processes) are a
  plugin-only throughput target: nearly all background processes are created
  before the cutoff (run 028: every debug record `after_cutoff:false`), so a
  process confirmed created-before-cutoff can be cached as permanently
  non-descendant and skip the walk. Safe if guarded by (eprocess, create_time).
- Iterating on hour-long, nondeterministic full-fixture runs is inefficient; a
  minimal fixture that spawns a child FIRST (before local_self_modify/exception)
  would exercise enrollment in the first minutes — but also needs staging.

Both fixes implemented + validated (run 029, 2026-07-17). Plugin
`cached_current_context` (37660552) caches immutable per-thread identity keyed by
ETHREAD, re-verifying CID.PID to guard object reuse and always re-reading the
mutable attached process. Launcher `read_idle_milliseconds` (a5ff3b14) reads an
optional `C:\Panda\idle_ms.txt` (validation-only) for a longer idle window; real
samples keep the 2-min paper boundary. Staged into a COPY
`windows10-qemu-fixture.qcow2` via `ops/qemu/stage_fixture_launcher.sh` (original
base untouched, SHA-256 verified in-image, idle_ms=900000=15min).

Run 029 (both fixes, fixture copy) outcome: context_immutable_reuse
12,138,699/12,150,330 = **99.9% cache hit, no regression** (exec 169,806). The
run **no longer idle-terminated** — it ran the full 30-guest-minute maximum
(`guest_idle:false`, `maximum_30_minute_timeout`). Both fixes work as designed.
BUT descendant_enrolled=0 still: with a full 30 guest-minutes the root recovered
its exception (1/1) yet NO sample-spawned child ever ran (only root-child is the
pre-sample console helper, after_cutoff:false). Cross-process channels
(virtual_memory_write, file_io) remain 0.

**Deeper wall isolated:** child-process creation (`CreateProcess`) does not
complete under exact instrumentation even within 30 guest-minutes — beyond
idle-window or context-refresh cost. This is likely a hardware-fundamental limit
of exact byte-level tracing of a multi-process interaction on this host.

Memory-thrash insight (runs 031-032, 2026-07-17). The "nondeterministic early
stalls" (026:1, 028:1731, 031:11974 exec) are very likely HOST MEMORY THRASH, not
inherent guest nondeterminism. A 3 GiB guest on this 3.8 GiB host leaves only
tens of MiB free once the desktop + tools are counted; run 032 at 3 GiB froze at
boot (302-byte trace, no progress, 30 MiB free) while runs that "progressed"
(025/029: ~170k exec) happened to catch a momentarily-free host. Dropping the
single-process runs to `--guest-memory 2G` leaves ~1.8 GiB host headroom and
should make progress reliable. This may also mean the cross-process CreateProcess
wall was partly thrash-amplified — worth retrying cross-process at 2 GiB once
single-process is certified. RUN NOTHING heavy (NAS scans, extra QEMU)
concurrently with a fixture run.

Single-process certification path. `validation_fixture.c` gained `local_unmap()`
(anonymous PAGE_EXECUTE_READWRITE section map/write/exec/unmap, no disk, no
child); with `C:\Panda\single_process.txt` present the fixture runs
local_self_modify (free) + local_unmap (unmap) + recovered_exception then exits
cleanly (all-processes-exit stop). `validate_fixture_trace.py --single-process`
certifies exactly that set — exec, write, free, unmap (both with RAM identity),
RtlRaiseException dispatch+recovery, system-role tagging, monotonic order, zero
integrity failures — deferring the child-requiring cross-process channels. Run
031 reached only 2 errors (both unmap, because the heavy file-backed
mapped_file_execute stalled before its UnmapViewOfFile); the lightweight
local_unmap plus 2 GiB is expected to close them. On a clean stamp, write
`ops/qemu/backend_validation.json` (certification_mode=single_process); it gates
exact labels for single-process packers (UPX + Type I-III majority) only.

Runs 032-038: the host RAM ceiling is the hard wall (2026-07-17). Attempting to
run the lightweight single-process fixture surfaced a hardware trap with no
reliable operating point on this 3.8 GiB host:
- 3 GiB: reaches sample_start when it boots (029/031), but boot now reliably
  swap-thrashes to a freeze (032/033/038: trace frozen at 302 B, ~32 MiB free),
  even after dropping caches. QEMU+plugin overhead + a 3 GiB guest + desktop
  exceeds RAM at boot.
- 2.5 GiB: also thrashes at boot.
- 2 GiB: boots without thrash but the root/sample-start detection fails
  NONDETERMINISTICALLY — run 036 learned the root yet sample_start never fired;
  run 037 never learned the root at all (root_asid=0, root_image_base=0) despite
  28.6M executed blocks. Same binary, different failures per boot: a
  timing-fragile detection path the fast guest breaks in varying ways.
So the single-process certification, which reached only 2 unmap-related errors at
3 GiB (run 031), cannot be completed here because no memory size gives BOTH a
non-thrashing boot AND reliable sample_start.

Robustness fixes committed during this arc (correct regardless of host, and
needed on a larger-RAM host too): eager kernel_base discovery from activation
(bounded to 50k attempts); root_asid derived from the root process's own
directory table instead of transient attached_asid. These did not overcome the
nondeterminism on this box.

Recommendation: run the backend on a host with >= 8 GiB RAM. There, a 3-4 GiB
guest boots without thrash and runs at a stable speed, which is the regime where
sample_start reliably fired (029/031) and where the lightweight single-process
fixture should certify (it is 2 unmap-events away). Everything else — the
paper-faithful classifier/byte-state machine, NAS staging (verified working),
plan/audit/finalize/verify pipeline, single-process certification framework
(fixture flag mode + `validate_fixture_trace.py --single-process`), and the
image-staging tooling — is built, tested (66 green), and ready to run the moment
the backend has adequate RAM.

Strategic implication: the child-REQUIRING channels (shared-RAM alias,
NtWriteVirtualMemory remote write, disk-drop file_write/read) are blocked, but
the SINGLE-PROCESS channels all work cleanly and repeatedly (exec, write,
mapped-file exec, unmap/free invalidation, exact software exception
dispatch+recovery, monotonic order, zero integrity failures). The single-process
majority of the corpus (e.g. UPX = 134 of 255 conditions, most Type I-III) never
performs cross-process operations, so their exact traces are fully covered by the
validated single-process channels. A methodologically sound path — NOT a
weakening — is to certify the single-process channel set and label single-process
packers exactly, while cross-process packers stay pending until the cross-process
channels can be certified (needs a faster tracing host or a different
child-tracing strategy). This is a user decision because it reinterprets the
one-time backend validation gate.

### Windows recovery history

1. Earlier hard-stopped runs caused Automatic Repair.
2. `SrtTrail.txt` reported zero root causes; only an offline update check timed
   out. Disk and qcow2 checks passed.
3. Offline BCD inspection found the Windows loader object
   `{aa08f7d1-6d67-11f1-97b5-fe0d34f49930}` with `recoveryenabled=1`.
4. It was changed to `0`, exported again, and verified.
5. The next boot reached winload but reported `SYSTEM` hive error `0xc000014c`.
6. The hive was present but dirty (`sequence 224/223`). Its live logs were zero
   bytes. Saved logs in `C:\Panda\stale-registry-logs` had valid checksums and
   sequences `232/232` and `223/223`; both were restored to
   `Windows\System32\config`.
7. `C:\Panda\guest_launcher.exe` was temporarily renamed to
   `guest_launcher.disabled` so registry replay cannot accidentally execute an
   old configured sample.

If Windows reaches a stable login/desktop, shut it down through ACPI/Windows and
wait for `paused (shutdown)`. Then close QEMU with HMP `quit` and run `qemu-img
check`. Do not host-kill a running Windows filesystem.

## Completed implementation and evidence

- Exact byte states O/X/W/U/R and NF/frame transitions are implemented in
  `empirical_types/paper.py`.
- Execution layers use the highest prior writer layer.
- Transition model, paper 10-page application heuristic, tail/interleaving
  detection, Type III fallback, majority multi-frame test, repacking test, and
  P/B/F granularity are implemented.
- System-library executions are excluded so the last monitored caller is used.
- Remote writes, shared physical aliases, synchronous disk I/O, mapped-file
  provenance, and successful unmap/free return hooks exist in
  `ops/qemu/paper_trace.c`.
- Unmap/free semantics were corrected: invalidation changes visibility/repacking
  state and clears stale virtual/physical provenance but does not invent a new
  writer layer.
- Pre-invalidation physical pages are captured by walking the target x64 page
  tables and converting guest physical addresses to stable QEMU RAM identities.
- Secondary processes are now included in classification only when observed
  remote-write, shared-RAM, or file provenance connects them to the root.
- Store capture registers instruction callbacks only for user-mode code, so
  loader/page-fault kernel housekeeping cannot invent W->X layers. Cross-process
  `NtWriteVirtualMemory` effects are captured exactly at entry/successful return
  with the completed target range and full RAM identities; this evidence
  enrolls or links the target process.
- The guest launcher now has a status-query protocol intended to enforce the
  paper termination boundaries: all monitored processes exited, two minutes
  without monitored execution, or a 30-minute maximum.
- QEMU, plugin, launcher, validation fixture, and profile build successfully.
- The post-validator-edit gate is green: **57 tests passed**, Ruff is clean,
  all three builds succeed, and marker smoke passes.
- The same test/lint/plugin/marker gate was rerun after the kernel-store filter
  change and remains green.
- The validation gate requires generic kernel-store callbacks to be disabled,
  a positive exact `NtWriteVirtualMemory` event count, and zero hook failures.
- `analyze_paper_jsonl` now streams JSONL from disk rather than loading and
  splitting the complete trace text. Its paper byte-state semantics are
  unchanged, and the 57-test/lint gate remains green. The per-byte state maps
  still require a measured large-trace memory benchmark before the full matrix.
- The paper's distinct unrecovered-exception boundary is now implemented:
  the plugin recognizes the exact guest `KiUserExceptionDispatcher` by system
  mapping offset plus a 16-byte code signature, tracks pending exceptions per
  PID/TID using monotonic wall time, clears them only when that thread returns
  to non-system code, and exposes count/oldest age through the status query.
  The launcher terminates after two minutes of a pending exception with a
  separate stop flag/reason. The fixture raises and recovers a vectored
  exception, and the validator requires matching dispatch/recovery events and
  zero pending exceptions. These paths compile but still require the real
  fixture trace.
- `ops/qemu/validate_fixture_trace.py` verifies all required trace channels and
  generates a hash-bound validation stamp. It still critically needs a real
  Windows fixture trace.

## Immediate next work

1. **Run fixture 022** with two vCPUs/3 GiB and the clean base using the hashes
   recorded above.
2. **Run `validate_fixture_trace.py`.** It must prove local execution/writes,
   remote writes, shared RAM aliases, file write/read to mapped execution,
   system-role tagging, free/unmap with RAM identity, query markers, monotonic
   sequence, and zero summary failures. Only then create
   `ops/qemu/backend_validation.json`.
3. **Fix every fixture failure**, rebuild, rerun, and update this file. Do not
   weaken the verifier to make it pass.
4. **Run a packed pilot** (the existing UPX sample is suitable), analyze it with
   `analyze_paper_jsonl`, and require `paper_label_eligible=true`.
5. **Finish NAS reconciliation.** Preserve the live audit evidence described
   below; do not substitute samples from another testcase.
6. **Stage and execute the full 2-payload, n=3 matrix**, repairing backend-caused
   unresolved results before finalization.
7. **Produce per-execution evidence, distributions, and the >=20 execution
   family/version cross-check.**

## NAS reconciliation evidence

Artifacts:

- `empirical_results/full_matrix/plan.livecheck.json`
- `empirical_results/full_matrix/nas-empty-audit.jsonl`
- `empirical_results/full_matrix/nas-packer-audit.jsonl`
- `empirical_results/full_matrix/nas-share-roots.json`

The live, recursive, no-filter audit found:

- all 29 exact condition directories exist but contain no qualifying executable;
- kkrunchy 0.23 alpha has 83 executables in `KKRUNCHY_001_DEFAULT` and 73 in
  `KKRUNCHY_002_BEST`, but none in `KKRUNCHY_003_NEW`;
- PEzor 3.3.0 has 67 executables only in `PEZOR_002_SELF_INJECT_32`, while the
  other six expected testcases are empty;
- FSG 1.0 contains 11 logs and no executable;
- the audited amber, hxor, hyperion, alushpacker, and simpledpack version trees
  contain no executable;
- the share contains no alternate top-level archive for those families.

This is evidence about the current NAS, not permission to relabel another
testcase. If the user expects these samples, next inspect generation host/report
state or regenerate exactly two valid payloads for each empty configuration.

Local source reconciliation also proves that the declared packer binary or
wrapper exists in this checkout for all 28 empty YAML testcase conditions (the
29th is GUI FSG). The current Debian tracing host has neither Wine nor WSL,
while `utils/packer_runner.py` is Windows-oriented and PEzor explicitly invokes
WSL. Therefore `empty_on_nas` does not mean intrinsically ungeneratable; exact
regeneration must run in the original Windows/WSL generator environment or a
separately prepared packing VM. Do not silently run another testcase instead.

## Paper type decision record

Each execution gets one type or one explicit unresolved status. Repetitions may
legitimately differ and are reported as a distribution.

- Type I: one unpacking routine/layer followed by the tail transition.
- Type II: multiple strictly sequential unpacking layers and a tail transition.
- Type III: cyclic/backward topology with a tail transition, including the
  paper's conservative all-code-marked-packer fallback.
- Type IV: packer/application execution is interleaved, but candidate original
  code is not majority multi-frame.
- Type V: the majority of candidate original code is multi-frame without
  repacked candidate blocks.
- Type VI: the majority is multi-frame and candidate original code is repacked.
- Suffix P: majority frame sizes are multiples of 4 KiB.
- Suffix B: average basic blocks per frame is exactly one.
- Suffix F: the paper's remaining generic/function/functionality-sized category.

## Commands that must stay green

```bash
ops/qemu/build_plugin.sh
ops/panda/build_guest_launcher.sh
ops/qemu/build_validation_fixture.sh
ops/qemu/smoke_marker.sh
ops/qemu/smoke_buffer.sh
ops/qemu/smoke_exception.sh
uv run --with pytest python -m pytest -q
uv run ruff check empirical_types ops tests
```

Use `uv run --with pytest python -m pytest -q`, not bare recursive `pytest`, so
the checked-out QEMU source tests are not collected and the SMB dependency is
available. `pyproject.toml` also now limits discovery to `tests/`.

## Eligibility invariant

No Type I–VI output is accepted unless all are true:

- the current QEMU/plugin/profile hashes match a successful fixture stamp;
- root, start, periodic query, and stop markers are present;
- execution and successful writes are nonempty;
- all context/physical/file/mapped/invalidation/query failure counters are zero;
- asynchronous file I/O count is zero for that execution;
- the guest did not hit the 30-minute maximum or status-query failure;
- analysis completes without malformed/unknown/lost events.

Two-minute idle is a normal paper termination boundary, not automatically a
failed label, provided the trace is otherwise complete.
