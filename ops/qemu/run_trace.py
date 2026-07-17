#!/usr/bin/env python3
"""Run one disposable two-vCPU QEMU trace and write auditable metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def final_summary(trace: Path) -> dict | None:
    if not trace.exists():
        return None
    result = None
    with trace.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event") == "summary":
                result = event
    return result


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("base", type=Path)
    parser.add_argument("work", type=Path)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--meta", type=Path)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--monitor", type=Path)
    parser.add_argument("--host-timeout", type=int, default=3600)
    parser.add_argument(
        "--guest-memory",
        default="3G",
        help="fixed guest RAM allocation, e.g. 2G/2560M/3G (default 3G). On this "
        "3.8 GiB host, 3G risks boot-time swap thrash and 2G has shown a "
        "kernel-discovery boot quirk; 2560M is the reliable middle ground.",
    )
    parser.add_argument("--qemu", type=Path)
    parser.add_argument("--plugin", type=Path)
    parser.add_argument("--validation-stamp", type=Path)
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[2]
    qemu = args.qemu or (
        repo / "empirical_results/qemu_runtime/qemu-build/qemu-system-x86_64"
    )
    plugin = args.plugin or repo / "ops/qemu/paper_trace.so"
    validation_stamp = args.validation_stamp or (
        repo / "ops/qemu/backend_validation.json"
    )
    ntdll = repo / "empirical_results/qemu_runtime/ntdll.dll"
    qemu_img = Path("/usr/bin/qemu-img")
    meta = args.meta or args.trace.with_suffix(".meta.json")
    log = args.log or args.trace.with_suffix(".qemu.log")
    monitor = args.monitor or args.trace.with_suffix(".monitor.sock")
    for required in (args.base, qemu, plugin, qemu_img, ntdll):
        if not required.exists():
            parser.error(f"required path does not exist: {required}")
    if args.work.exists():
        parser.error(f"refusing to reuse analysis overlay: {args.work}")
    if monitor.exists():
        parser.error(f"refusing to reuse monitor socket: {monitor}")

    args.work.parent.mkdir(parents=True, exist_ok=True)
    args.trace.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [str(qemu_img), "check", str(args.base)],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            str(qemu_img),
            "create",
            "-f",
            "qcow2",
            "-F",
            "qcow2",
            "-b",
            str(args.base.resolve()),
            str(args.work),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )

    command = [
        str(qemu),
        "-name",
        "paper-trace",
        "-machine",
        "pc-i440fx-5.2",
        "-accel",
        "tcg,thread=single",
        "-cpu",
        "qemu64",
        "-m",
        args.guest_memory,
        "-smp",
        "2",
        "-rtc",
        "base=localtime",
        "-display",
        "none",
        "-monitor",
        f"unix:{monitor.resolve()},server=on,wait=off",
        "-serial",
        "none",
        "-parallel",
        "none",
        "-net",
        "none",
        "-no-reboot",
        "-drive",
        f"file={args.work},format=qcow2,if=ide,cache=writeback",
        "-plugin",
        f"{plugin.resolve()},out={args.trace.resolve()}",
    ]
    started = time.monotonic()
    host_timed_out = False
    with log.open("wb") as log_handle:
        process = subprocess.Popen(command, stdout=log_handle, stderr=log_handle)
        try:
            return_code = process.wait(timeout=args.host_timeout)
        except subprocess.TimeoutExpired:
            host_timed_out = True
            process.terminate()
            try:
                return_code = process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                process.kill()
                return_code = process.wait()
    elapsed = time.monotonic() - started
    summary = final_summary(args.trace)
    implemented_channels = {
        "basic_block_execution": True,
        "successful_memory_writes": True,
        "remote_process_writes": True,
        "shared_sections": True,
        "synchronous_disk_io": True,
        "asynchronous_disk_io": False,
        "memory_mapped_files": True,
        "unmap_and_free": True,
    }
    trace_integrity = {
        "root_marker": bool(summary and summary.get("root_pid")),
        "stop_marker": bool(summary and summary.get("saw_stop")),
        "executed_blocks": bool(summary and summary.get("exec_events", 0) > 0),
        "writes": bool(summary and summary.get("write_events", 0) > 0),
        "context": bool(summary and summary.get("context_failures") == 0),
        "block_context": bool(
            summary and summary.get("block_context_misses") == 0
        ),
        "process_snapshot": bool(
            summary and summary.get("process_snapshot_failures") == 0
        ),
        "virtual_memory_writes": bool(
            summary
            and summary.get("kernel_store_callbacks_registered") is False
            and summary.get("virtual_memory_write_failures") == 0
        ),
        "physical_mapping": bool(
            summary and summary.get("physical_mapping_failures") == 0
        ),
        "marker_registers": bool(
            summary
            and summary.get("marker_register_failures") == 0
            and summary.get("marker_query_failures") == 0
        ),
        "file_io": bool(
            summary
            and summary.get("file_io_failures") == 0
            and summary.get("asynchronous_file_io") == 0
        ),
        "mapped_files": bool(
            summary
            and summary.get("mapped_file_failures") == 0
            and summary.get("system_role_failures") == 0
        ),
        "unmap_and_free": bool(
            summary
            and summary.get("invalidation_failures") == 0
            and summary.get("unresolved_process_handles") == 0
        ),
    }
    backend_validation = None
    if validation_stamp.is_file():
        try:
            backend_validation = json.loads(
                validation_stamp.read_text(encoding="utf-8")
            )
        except (json.JSONDecodeError, OSError):
            backend_validation = None
    current_identity = {
        "qemu_sha256": sha256(qemu),
        "plugin_sha256": sha256(plugin),
        "profile_header_sha256": sha256(repo / "ops/qemu/win10_profile.h"),
        "ntdll_sha256": sha256(ntdll),
    }
    stamped_identity = (
        backend_validation.get("backend_identity", {})
        if isinstance(backend_validation, dict)
        else {}
    )
    backend_validation_complete = bool(
        backend_validation
        and backend_validation.get("validated") is True
        and all(stamped_identity.get(key) == value
                for key, value in current_identity.items())
    )
    stop_detail = int(summary.get("stop_detail", 0)) if summary else 0
    guest_timed_out = bool(stop_detail & 0x80000000)
    guest_idle = bool(stop_detail & 0x40000000)
    guest_query_failed = bool(stop_detail & 0x20000000)
    guest_unrecovered_exception = bool(stop_detail & 0x10000000)
    metadata = {
        "schema_version": 1,
        "backend": "upstream_qemu_tcg_plugin",
        "qemu_revision": "eca2c16212ef9dcb0871de39bb9d1c2efebe76be",
        "kernel_profile_guid_age": (
            summary.get("kernel_profile_guid_age") if summary else None
        ),
        "machine": "pc-i440fx-5.2",
        "guest_memory": args.guest_memory,
        "guest_vcpus": 2,
        "tcg_threads": "single",
        "global_event_order": True,
        "host_timeout_seconds": args.host_timeout,
        "monitor_socket": str(monitor.resolve()),
        "host_timed_out": host_timed_out,
        "guest_timed_out": guest_timed_out,
        "guest_idle": guest_idle,
        "guest_query_failed": guest_query_failed,
        "guest_unrecovered_exception": guest_unrecovered_exception,
        "guest_exit_code": (
            None
            if guest_timed_out
            or guest_idle
            or guest_query_failed
            or guest_unrecovered_exception
            else stop_detail
        ),
        "paper_termination_reason": (
            "maximum_30_minute_timeout" if guest_timed_out
            else "unrecovered_exception_two_minutes"
            if guest_unrecovered_exception
            else "two_minutes_idle" if guest_idle
            else "status_query_failure" if guest_query_failed
            else "all_monitored_processes_exited"
        ),
        "elapsed_seconds": elapsed,
        "qemu_return_code": return_code,
        "trace_sha256": sha256(args.trace) if args.trace.exists() else None,
        "summary": summary,
        "implemented_channels": implemented_channels,
        "trace_integrity": trace_integrity,
        "backend_validation_complete": backend_validation_complete,
        "backend_validation_stamp": (
            str(validation_stamp.resolve()) if validation_stamp.exists() else None
        ),
        "backend_identity": current_identity,
        "paper_label_eligible": (
            backend_validation_complete
            and not guest_timed_out
            and not guest_query_failed
            and all(trace_integrity.values())
        ),
        "ineligible_reason": (
            None if backend_validation_complete
            else "the exact current QEMU/plugin/profile identity has not passed "
            "the purpose-built Windows channel fixture"
        ),
    }
    meta.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2))
    return 0 if summary and summary.get("saw_stop") and not host_timed_out else 1


if __name__ == "__main__":
    raise SystemExit(main())
