#!/usr/bin/env python3
"""Replay a PANDA recording into the paper's basic-block/write event stream.

The root address space is learned from a CPUID marker executed inside the
packed child before its primary thread is resumed.  Tracing starts at the PE
entry point, so Windows loader execution is outside the taxonomy trace.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct

from pandare import Panda

from kernel_events import KernelEventTracker
from win10_introspection import WindowsKernelProfile


PACKER_MARKER_MAGIC = 0x5041434B
MARK_ROOT_PID = 1
MARK_TRACE_START = 2
MARK_TRACE_STOP = 3
USER_LIMIT_32 = 0x80000000


class TraceWriter:
    def __init__(
        self,
        panda: Panda,
        output: Path,
        diagnostic_limit: int = 0,
        entry_hook: bool = True,
        kernel_profile: Path | None = None,
    ) -> None:
        self.panda = panda
        self.handle = output.open("w", encoding="utf-8", buffering=1024 * 1024)
        self.root_pid: int | None = None
        self.root_asid: int | None = None
        self.image_base: int | None = None
        self.entrypoint: int | None = None
        self.peb: int | None = None
        self.waiting_for_entry = False
        self.active = False
        self.saw_stop = False
        self.stop_detail: int | None = None
        self.modules: dict[int, tuple[int, str]] = {}
        self.teb_threads: dict[int, int] = {}
        self.written_bytes: set[int] = set()
        self.exec_events = 0
        self.write_events = 0
        self.module_refreshes = 0
        self.preentry_blocks = 0
        self.preentry_addresses: list[int] = []
        self.diagnostic_limit = diagnostic_limit
        self.diagnostic_stopped = False
        self.entry_hook = entry_hook
        self.kernel = (
            WindowsKernelProfile(panda, kernel_profile) if kernel_profile else None
        )
        self.kernel_events = (
            KernelEventTracker(self.kernel, self.emit) if self.kernel else None
        )
        self.kernel_event_arm_failure: str | None = None
        self.kernel_contexts = 0
        self.kernel_context_failures = 0
        self.remote_write_events = 0

    def close(self) -> None:
        self.handle.close()

    def emit(self, event: dict) -> None:
        self.handle.write(json.dumps(event, separators=(",", ":")) + "\n")

    def physical(self, cpu, address: int) -> int | None:
        value = int(self.panda.virt_to_phys(cpu, address))
        if value < 0 or value == 0xFFFFFFFFFFFFFFFF:
            return None
        return value

    def read(self, cpu, address: int, size: int) -> bytes:
        return bytes(self.panda.virtual_memory_read(cpu, address, size))

    def u16(self, cpu, address: int) -> int:
        return struct.unpack("<H", self.read(cpu, address, 2))[0]

    def u32(self, cpu, address: int) -> int:
        return struct.unpack("<I", self.read(cpu, address, 4))[0]

    def unicode32(self, cpu, address: int) -> str:
        length = self.u16(cpu, address)
        buffer = self.u32(cpu, address + 4)
        if not buffer or not length or length > 32768:
            return ""
        return self.read(cpu, buffer, length).decode("utf-16-le", errors="replace")

    def thread_id(self, cpu) -> int:
        if self.kernel is not None:
            try:
                context = self.kernel.context(cpu)
                self.kernel_contexts += 1
                return context.tid
            except ValueError:
                self.kernel_context_failures += 1
        teb = int(self.panda.arch.get_reg(cpu, "FS")) & 0xFFFFFFFF
        if teb not in self.teb_threads:
            try:
                self.teb_threads[teb] = self.u32(cpu, teb + 0x24)
            except ValueError:
                self.teb_threads[teb] = 0
        return self.teb_threads[teb]

    def learn_root_asid(self, cpu) -> None:
        if self.root_pid is None:
            return
        self.root_asid = int(self.panda.current_asid(cpu))
        teb = int(self.panda.arch.get_reg(cpu, "FS")) & 0xFFFFFFFF
        self.peb = self.u32(cpu, teb + 0x30)
        self.image_base = self.u32(cpu, self.peb + 0x08)
        pe_offset = self.u32(cpu, self.image_base + 0x3C)
        if self.read(cpu, self.image_base, 2) != b"MZ":
            raise RuntimeError("root marker did not expose a valid PE image")
        if self.read(cpu, self.image_base + pe_offset, 4) != b"PE\0\0":
            raise RuntimeError("root marker PE header is invalid")
        entry_rva = self.u32(cpu, self.image_base + pe_offset + 0x28)
        self.entrypoint = self.image_base + entry_rva
        self.refresh_modules(cpu)
        if self.entry_hook:
            self.panda.hook(
                self.entrypoint,
                enabled=True,
                kernel=False,
                asid=self.root_asid,
            )(self.start_at_entry)
            self.panda.disable_callback("trace_blocks")
        print(
            f"root_pid={self.root_pid} asid=0x{self.root_asid:x} "
            f"image_base=0x{self.image_base:x} entry=0x{self.entrypoint:x}",
            flush=True,
        )

    def start_at_entry(self, cpu, tb, hook) -> None:
        hook.enabled = False
        self.waiting_for_entry = False
        self.active = True
        self.panda.enable_callback("trace_blocks")
        self.panda.enable_callback("trace_writes")
        print("trace_started_at_entrypoint", flush=True)
        self.on_block(cpu, tb)

    def refresh_modules(self, cpu) -> None:
        if not self.peb:
            return
        try:
            ldr = self.u32(cpu, self.peb + 0x0C)
            if not ldr:
                return
            head = ldr + 0x0C
            link = self.u32(cpu, head)
            seen: set[int] = set()
            while link and link != head and link not in seen and len(seen) < 1024:
                seen.add(link)
                base = self.u32(cpu, link + 0x18)
                size = self.u32(cpu, link + 0x20)
                name = self.unicode32(cpu, link + 0x24)
                if base and size:
                    self.modules[base] = (size, name)
                link = self.u32(cpu, link)
            self.module_refreshes += 1
        except ValueError:
            return

    def module_at(self, cpu, address: int) -> tuple[int, int, str] | None:
        for base, (size, name) in self.modules.items():
            if base <= address < base + size:
                return base, size, name
        self.refresh_modules(cpu)
        for base, (size, name) in self.modules.items():
            if base <= address < base + size:
                return base, size, name
        return None

    def system_code(self, cpu, address: int, size: int) -> bool:
        module = self.module_at(cpu, address)
        if module is None or module[0] == self.image_base:
            return False
        # Modified library code remains part of the unpacking trace.
        if any(byte in self.written_bytes for byte in range(address, address + size)):
            return False
        path = module[2].replace("/", "\\").lower()
        return "\\windows\\system32\\" in path or "\\windows\\syswow64\\" in path

    def on_hypercall(self, cpu) -> bool:
        env = cpu.env_ptr
        magic = int(env.regs[0]) & 0xFFFFFFFF
        if magic != PACKER_MARKER_MAGIC:
            return False
        pid = int(env.regs[3]) & 0xFFFFFFFF
        action = int(env.regs[1]) & 0xFFFFFFFF
        if action == MARK_ROOT_PID:
            self.root_pid = pid
            if self.kernel_events is not None and self.kernel_events.base is None:
                try:
                    self.kernel_events.arm(cpu)
                except ValueError as exc:
                    self.kernel_event_arm_failure = str(exc)
            # The original pilot used this marker as the start marker too.
            self.waiting_for_entry = True
            self.panda.enable_callback("trace_blocks")
        elif action == MARK_TRACE_START:
            self.waiting_for_entry = True
        elif action == MARK_TRACE_STOP:
            self.active = False
            self.saw_stop = True
            self.stop_detail = int(env.regs[2]) & 0xFFFFFFFF
            self.panda.disable_callback("trace_blocks")
            self.panda.disable_callback("trace_writes")
        return False

    def on_block(self, cpu, tb) -> None:
        address = int(tb.pc)
        if self.active and self.kernel_events is not None:
            self.kernel_events.on_block(cpu, address)
        if self.root_asid is None and self.root_pid is not None and address < USER_LIMIT_32:
            try:
                teb = int(self.panda.arch.get_reg(cpu, "FS")) & 0xFFFFFFFF
                if teb and self.u32(cpu, teb + 0x20) == self.root_pid:
                    self.learn_root_asid(cpu)
            except (RuntimeError, ValueError):
                pass
        if self.root_asid is None or int(self.panda.current_asid(cpu)) != self.root_asid:
            return
        size = int(tb.size)
        if self.waiting_for_entry and address < USER_LIMIT_32:
            self.preentry_blocks += 1
            if len(self.preentry_addresses) < 64:
                self.preentry_addresses.append(address)
            if self.diagnostic_limit and self.preentry_blocks >= self.diagnostic_limit:
                self.diagnostic_stopped = True
                self.panda.disable_callback("trace_blocks")
                print(
                    "preentry_diagnostic="
                    + json.dumps([hex(value) for value in self.preentry_addresses]),
                    flush=True,
                )
                return
        if self.waiting_for_entry and address == self.entrypoint:
            self.waiting_for_entry = False
            self.active = True
            self.panda.enable_callback("trace_writes")
            print("trace_started_at_entrypoint", flush=True)
        if not self.active or address >= USER_LIMIT_32:
            return
        tid = self.thread_id(cpu)
        if self.system_code(cpu, address, size):
            return
        event = {
            "event": "exec",
            "pid": self.root_pid,
            "tid": tid,
            "address": address,
            "size": size,
        }
        physical = self.physical(cpu, address)
        if physical is not None:
            event["physical_address"] = physical
        self.emit(event)
        self.exec_events += 1

    def on_write(self, cpu, pc: int, address: int, size: int) -> None:
        if (
            not self.active
            or self.root_asid is None
            or address >= USER_LIMIT_32
            or size <= 0
        ):
            return
        source_pid = self.root_pid
        target_pid = self.root_pid
        if self.kernel is not None:
            try:
                context = self.kernel.context(cpu)
                self.kernel_contexts += 1
            except ValueError:
                self.kernel_context_failures += 1
                return
            source_pid = context.source_pid
            target_pid = context.attached_pid
            if source_pid != self.root_pid and target_pid != self.root_pid:
                return
            tid = context.tid
        else:
            if int(self.panda.current_asid(cpu)) != self.root_asid:
                return
            tid = self.thread_id(cpu)
        event = {
            "event": "write",
            "pid": source_pid,
            "tid": tid,
            "target_pid": target_pid,
            "address": int(address),
            "size": int(size),
            "pc": int(pc),
        }
        physical = self.physical(cpu, address)
        if physical is not None:
            event["physical_address"] = physical
        self.emit(event)
        if source_pid != target_pid:
            self.remote_write_events += 1
        self.written_bytes.update(range(int(address), int(address) + int(size)))
        self.write_events += 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("recording", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--meta", type=Path)
    parser.add_argument("--preentry-diagnostic-limit", type=int, default=0)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)

    panda = Panda(
        arch="x86_64",
        mem="2G",
        os="windows",
        extra_args=["-display", "none", "-net", "none"],
    )
    trace = TraceWriter(
        panda,
        args.output,
        args.preentry_diagnostic_limit,
        entry_hook=not bool(args.preentry_diagnostic_limit),
    )

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
        panda.run_replay(str(args.recording))
    finally:
        trace.close()

    # A successfully completed replay ends at recctrl's recording boundary.
    if trace.exec_events:
        trace.saw_stop = True

    metadata = {
        "schema_version": 1,
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
        "module_refreshes": trace.module_refreshes,
        "preentry_blocks": trace.preentry_blocks,
        "preentry_addresses": trace.preentry_addresses,
        "diagnostic_stopped": trace.diagnostic_stopped,
        "trace_started": trace.exec_events > 0,
        "trace_stop_marker": trace.saw_stop,
        "stop_detail": trace.stop_detail,
        "required_channels": {
            "basic_block_execution": True,
            "same_process_memory_writes": True,
            "remote_process_writes": False,
            "shared_sections": False,
            "disk_and_mapped_files": False,
            "unmap_and_free": False,
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
