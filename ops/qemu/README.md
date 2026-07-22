# Upstream QEMU paper tracer

This is the Type I–VI evidence backend.  It uses upstream QEMU TCG callbacks for executed basic
blocks and every successful memory store.  Run the analysis VM with two guest
CPUs and single-threaded TCG (`-smp 2 -accel tcg,thread=single`) so events from
both CPUs form one ordered stream, as required by the paper's transition
model.

The plugin is built against the exact Windows kernel PDB profile used by the
guest.  It refuses to substitute generic Windows offsets.

Current status: basic blocks, every successful store, physical aliases,
descendant/remote writes, shared pages, synchronous disk I/O, mapped-file
provenance, system-library roles, and successful unmap/free paths are
implemented. Asynchronous file I/O is explicitly unresolved. The labelling
gate remains closed until `validation_fixture.exe` exercises every channel in
the real Windows guest and the recovered events are independently checked. A
trace before that validation is diagnostic evidence, not a Type I–VI label.

`smoke_marker.sh` boots a 512-byte two-vCPU fixture and verifies the complete
guest-marker path in seconds. It also guards the QEMU API invariant that the
valid opaque handle for register zero (`RAX`) has a null pointer value.

The Windows guest was originally prepared by PANDA/QEMU 2.9.1. Upstream QEMU
11 no longer provides `pc-i440fx-2.9`, so the runner pins the oldest available
compatible model, `pc-i440fx-5.2`, and records it in every result.

`run_trace.py` always creates a disposable child overlay and records the exact
QEMU revision, VM topology, kernel profile, trace digest, channel capabilities,
termination state, and eligibility decision. It refuses to reuse an analysis
overlay.
