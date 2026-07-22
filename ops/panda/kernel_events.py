#!/usr/bin/env python3
"""Paper-required Windows unmap/free event tracing for the PANDA backend."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass

from win10_introspection import WindowsKernelProfile


@dataclass(frozen=True)
class _PendingInvalidation:
    return_address: int
    event: str
    pid: int
    tid: int
    target_pid: int
    address: int
    size: int


class KernelEventTracker:
    """Observe successful NtFree/NtUnmap calls using the exact kernel PDB."""

    def __init__(
        self,
        profile: WindowsKernelProfile,
        emit: Callable[[dict], None],
    ) -> None:
        self.profile = profile
        self.emit = emit
        self.base: int | None = None
        self.entries: dict[int, str] = {}
        self.pending: dict[int, list[_PendingInvalidation]] = defaultdict(list)
        self.events = 0
        self.unresolved_process_handles = 0
        self.failures = 0

    def arm(self, cpu) -> None:
        self.base = self.profile.kernel_base(cpu)
        for name in (
            "NtFreeVirtualMemory",
            "NtUnmapViewOfSection",
            "NtUnmapViewOfSectionEx",
        ):
            if name in self.profile.functions:
                self.entries[self.base + self.profile.functions[name]] = name

    @staticmethod
    def _current_process_handle(handle: int) -> bool:
        return handle & 0xFFFFFFFF in {0xFFFFFFFF, 0xFFFFFFFE}

    def _return_address(self, cpu) -> int:
        rsp = int(cpu.env_ptr.regs[4])
        return self.profile.u64(cpu, rsp)

    def _on_entry(self, cpu, name: str) -> None:
        context = self.profile.context(cpu)
        env = cpu.env_ptr
        process_handle = int(env.regs[1])
        if not self._current_process_handle(process_handle):
            # Resolving arbitrary Windows handles is required before this can
            # be declared a complete channel.  Count it instead of guessing.
            self.unresolved_process_handles += 1
            return

        if name == "NtFreeVirtualMemory":
            base_pointer = int(env.regs[2])
            size_pointer = int(env.regs[8])
            address = self.profile.u64(cpu, base_pointer)
            size = self.profile.u64(cpu, size_pointer)
            if not size:
                vad = self.profile.vad_range(cpu, context.attached_eprocess, address)
                if vad is None:
                    return
                address, end = vad
                size = end - address
            kind = "free"
        else:
            address = int(env.regs[2])
            vad = self.profile.vad_range(cpu, context.attached_eprocess, address)
            if vad is None:
                return
            address, end = vad
            size = end - address
            kind = "unmap"

        self.pending[context.tid].append(
            _PendingInvalidation(
                return_address=self._return_address(cpu),
                event=kind,
                pid=context.source_pid,
                tid=context.tid,
                target_pid=context.attached_pid,
                address=address,
                size=size,
            )
        )

    def _on_return(self, cpu, pc: int) -> None:
        context = self.profile.context(cpu)
        calls = self.pending.get(context.tid)
        if not calls:
            return
        for index in range(len(calls) - 1, -1, -1):
            call = calls[index]
            if call.return_address != pc:
                continue
            del calls[index]
            status = int(cpu.env_ptr.regs[0]) & 0xFFFFFFFF
            if status < 0x80000000:
                self.emit(
                    {
                        "event": call.event,
                        "pid": call.pid,
                        "tid": call.tid,
                        "target_pid": call.target_pid,
                        "address": call.address,
                        "size": call.size,
                    }
                )
                self.events += 1
            break

    def on_block(self, cpu, pc: int) -> None:
        if self.base is None:
            return
        try:
            name = self.entries.get(pc)
            if name is not None:
                self._on_entry(cpu, name)
            self._on_return(cpu, pc)
        except ValueError:
            self.failures += 1
