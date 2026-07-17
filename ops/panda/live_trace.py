#!/usr/bin/env python3
"""Run the Windows guest with live paper-style PANDA instrumentation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import threading

from pandare import Panda

from trace_replay import TraceWriter


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("qcow", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--meta", type=Path)
    parser.add_argument("--vnc-display", default="0.0.0.0:1")
    parser.add_argument("--control-timeout", type=int, default=600)
    parser.add_argument("--host-timeout", type=int, default=1800)
    parser.add_argument("--kernel-profile", type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)

    panda = Panda(
        arch="x86_64",
        mem="2G",
        qcow=str(args.qcow),
        os="windows",
        extra_args=[
            "-cpu",
            "qemu64",
            "-smp",
            "2",
            "-display",
            "none",
            "-vnc",
            args.vnc_display,
            "-net",
            "none",
        ],
    )
    trace = TraceWriter(
        panda,
        args.output,
        entry_hook=True,
        kernel_profile=args.kernel_profile,
    )
    host_timed_out = False

    def stop_on_host_timeout() -> None:
        nonlocal host_timed_out
        host_timed_out = True
        panda.end_analysis()

    watchdog = threading.Timer(args.host_timeout, stop_on_host_timeout)
    watchdog.daemon = True
    watchdog.start()

    @panda.cb_guest_hypercall
    def guest_hypercall(cpu):
        return trace.on_hypercall(cpu)

    @panda.cb_before_block_exec(name="trace_blocks", enabled=False)
    def before_block(cpu, tb):
        trace.on_block(cpu, tb)

    @panda.cb_virt_mem_before_write(name="trace_writes", enabled=False)
    def before_write(cpu, pc, address, size, buffer):
        del buffer
        trace.on_write(cpu, int(pc), int(address), int(size))

    try:
        panda.run()
    finally:
        watchdog.cancel()
        trace.close()

    metadata = {
        "schema_version": 1,
        "backend": "panda_live",
        "root_pid": trace.root_pid,
        "root_asid": trace.root_asid,
        "image_base": trace.image_base,
        "entrypoint": trace.entrypoint,
        "exec_events": trace.exec_events,
        "write_events": trace.write_events,
        "remote_write_events": trace.remote_write_events,
        "kernel_contexts": trace.kernel_contexts,
        "kernel_context_failures": trace.kernel_context_failures,
        "kernel_event_arm_failure": trace.kernel_event_arm_failure,
        "unmap_free_events": (
            trace.kernel_events.events if trace.kernel_events else 0
        ),
        "unresolved_process_handles": (
            trace.kernel_events.unresolved_process_handles
            if trace.kernel_events
            else 0
        ),
        "kernel_event_failures": (
            trace.kernel_events.failures if trace.kernel_events else 0
        ),
        "kernel_profile_guid_age": (
            trace.kernel.metadata.get("GUID_AGE") if trace.kernel else None
        ),
        "module_refreshes": trace.module_refreshes,
        "trace_started": trace.exec_events > 0,
        "trace_stop_marker": trace.saw_stop,
        "stop_detail": trace.stop_detail,
        "host_timed_out": host_timed_out,
        "termination": (
            "backend_failure"
            if host_timed_out
            else "timeout"
            if trace.stop_detail == 0x102
            else "crash"
            if trace.stop_detail is not None and trace.stop_detail >= 0x80000000
            else "complete"
            if trace.saw_stop
            else "backend_failure"
        ),
        "required_channels": {
            "basic_block_execution": True,
            "same_process_memory_writes": True,
            "remote_process_writes": False,
            "shared_sections": False,
            "disk_and_mapped_files": False,
            "unmap_and_free": bool(
                trace.kernel_events
                and trace.kernel_events.base is not None
                and not trace.kernel_event_arm_failure
                and not trace.kernel_events.unresolved_process_handles
                and not trace.kernel_events.failures
            ),
        },
        "paper_label_eligible": False,
        "ineligible_reason": "inter-process and unmap/free channels are not implemented yet",
    }
    meta_path = args.meta or args.output.with_suffix(".meta.json")
    meta_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2))
    return 0 if trace.exec_events and trace.saw_stop else 1


if __name__ == "__main__":
    raise SystemExit(main())
