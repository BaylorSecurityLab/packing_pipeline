#!/usr/bin/env python3
"""Minimal Windows kernel introspection backed by the VM's exact PDB profile.

PANDA's bundled Windows OSI profiles stop at Windows 7.  The corpus guest is
Windows 10, so the tracer reads only the small set of kernel fields needed to
attribute writes and executions to processes and threads.  Offsets and kernel
function RVAs are loaded from the Rekall profile generated for this exact VM;
none are hard-coded to a generic Windows build.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import struct

from pandare import Panda


@dataclass(frozen=True)
class ThreadContext:
    source_pid: int
    tid: int
    source_eprocess: int
    attached_eprocess: int
    attached_pid: int
    attached_asid: int


class WindowsKernelProfile:
    def __init__(self, panda: Panda, path: Path) -> None:
        self.panda = panda
        profile = json.loads(path.read_text(encoding="utf-8"))
        self.functions: dict[str, int] = profile["$FUNCTIONS"]
        self.structs: dict[str, list] = profile["$STRUCTS"]
        self.metadata: dict = profile["$METADATA"]
        self._kpcr: int | None = None

        self.kpcr_prcb = self.offset("_KPCR", "Prcb")
        self.kprcb_current_thread = self.offset("_KPRCB", "CurrentThread")
        self.kthread_apc_state = self.offset("_KTHREAD", "ApcState")
        self.kthread_process = self.offset("_KTHREAD", "Process")
        self.kapc_process = self.offset("_KAPC_STATE", "Process")
        self.ethread_cid = self.offset("_ETHREAD", "Cid")
        self.cid_pid = self.offset("_CLIENT_ID", "UniqueProcess")
        self.cid_tid = self.offset("_CLIENT_ID", "UniqueThread")
        self.eprocess_pid = self.offset("_EPROCESS", "UniqueProcessId")
        self.eprocess_parent = self.offset(
            "_EPROCESS", "InheritedFromUniqueProcessId"
        )
        self.eprocess_links = self.offset("_EPROCESS", "ActiveProcessLinks")
        self.eprocess_vad_root = self.offset("_EPROCESS", "VadRoot")
        self.avl_root = self.offset("_RTL_AVL_TREE", "Root")
        self.vad_left = self.offset("_RTL_BALANCED_NODE", "Left")
        self.vad_right = self.offset("_RTL_BALANCED_NODE", "Right")
        self.vad_start = self.offset("_MMVAD_SHORT", "StartingVpn")
        self.vad_end = self.offset("_MMVAD_SHORT", "EndingVpn")
        self.vad_start_high = self.offset("_MMVAD_SHORT", "StartingVpnHigh")
        self.vad_end_high = self.offset("_MMVAD_SHORT", "EndingVpnHigh")
        self.kprocess_directory_table = self.offset(
            "_KPROCESS", "DirectoryTableBase"
        )
        self.kprocess_user_directory_table = self.offset(
            "_KPROCESS", "UserDirectoryTableBase"
        )

    def offset(self, struct_name: str, member: str) -> int:
        try:
            return int(self.structs[struct_name][1][member][0])
        except KeyError as exc:
            raise ValueError(f"profile lacks {struct_name}.{member}") from exc

    def read(self, cpu, address: int, size: int) -> bytes:
        return bytes(self.panda.virtual_memory_read(cpu, address, size))

    def u64(self, cpu, address: int) -> int:
        return struct.unpack("<Q", self.read(cpu, address, 8))[0]

    def u32(self, cpu, address: int) -> int:
        return struct.unpack("<I", self.read(cpu, address, 4))[0]

    def u8(self, cpu, address: int) -> int:
        return self.read(cpu, address, 1)[0]

    @staticmethod
    def canonical_kernel_pointer(value: int) -> bool:
        return 0xFFFF800000000000 <= value <= 0xFFFFFFFFFFFFFFFF

    def _kpcr_candidates(self, cpu) -> list[int]:
        env = cpu.env_ptr
        values = [
            self._kpcr,
            int(getattr(env, "kernelgsbase", 0)),
            int(self.panda.arch.get_reg(cpu, "GS")),
        ]
        return list(dict.fromkeys(value for value in values if value))

    def current_thread(self, cpu) -> int:
        for kpcr in self._kpcr_candidates(cpu):
            try:
                thread = self.u64(
                    cpu, kpcr + self.kpcr_prcb + self.kprcb_current_thread
                )
            except ValueError:
                continue
            if self.canonical_kernel_pointer(thread):
                self._kpcr = kpcr
                return thread
        raise ValueError("unable to locate KPCR/current ETHREAD")

    def process_asid(self, cpu, eprocess: int) -> int:
        kernel = self.u64(cpu, eprocess + self.kprocess_directory_table)
        user = self.u64(cpu, eprocess + self.kprocess_user_directory_table)
        # KVA shadow gives user processes a separate user page table.  PANDA's
        # current_asid is the active CR3 with its PCID bits cleared.
        return (user or kernel) & ~0xFFF

    def context(self, cpu) -> ThreadContext:
        ethread = self.current_thread(cpu)
        source_pid = self.u64(cpu, ethread + self.ethread_cid + self.cid_pid)
        tid = self.u64(cpu, ethread + self.ethread_cid + self.cid_tid)
        source_eprocess = self.u64(cpu, ethread + self.kthread_process)
        attached_eprocess = self.u64(
            cpu, ethread + self.kthread_apc_state + self.kapc_process
        )
        attached_pid = self.u64(cpu, attached_eprocess + self.eprocess_pid)
        return ThreadContext(
            source_pid=source_pid,
            tid=tid,
            source_eprocess=source_eprocess,
            attached_eprocess=attached_eprocess,
            attached_pid=attached_pid,
            attached_asid=self.process_asid(cpu, attached_eprocess),
        )

    def parent_pid(self, cpu, eprocess: int) -> int:
        return self.u64(cpu, eprocess + self.eprocess_parent)

    def vad_range(
        self, cpu, eprocess: int, address: int
    ) -> tuple[int, int] | None:
        """Return the exact [base, end) VAD containing ``address``."""

        node = self.u64(cpu, eprocess + self.eprocess_vad_root + self.avl_root)
        vpn = address >> 12
        for _ in range(65536):
            if not node:
                return None
            if not self.canonical_kernel_pointer(node):
                raise ValueError("invalid VAD pointer")
            start_vpn = self.u32(cpu, node + self.vad_start) | (
                self.u8(cpu, node + self.vad_start_high) << 32
            )
            end_vpn = self.u32(cpu, node + self.vad_end) | (
                self.u8(cpu, node + self.vad_end_high) << 32
            )
            if vpn < start_vpn:
                node = self.u64(cpu, node + self.vad_left)
            elif vpn > end_vpn:
                node = self.u64(cpu, node + self.vad_right)
            else:
                return start_vpn << 12, (end_vpn + 1) << 12
        raise ValueError("VAD traversal limit exceeded")

    def kernel_base(self, cpu) -> int:
        """Resolve ntoskrnl from LSTAR and validate its in-memory PE header."""

        lstar = int(getattr(cpu.env_ptr, "lstar", 0))
        for symbol in ("KiSystemCall64Shadow", "KiSystemCall64"):
            rva = self.functions.get(symbol)
            if not rva or lstar < rva:
                continue
            base = lstar - rva
            try:
                if self.read(cpu, base, 2) != b"MZ":
                    continue
                pe_offset = self.u32(cpu, base + 0x3C)
                if self.read(cpu, base + pe_offset, 4) != b"PE\0\0":
                    continue
            except ValueError:
                continue
            return base
        raise ValueError("LSTAR does not match the profiled ntoskrnl image")

    def process_table(self, cpu, start_eprocess: int) -> dict[int, tuple[int, int]]:
        """Return PID -> (EPROCESS, ASID) by walking ActiveProcessLinks."""

        result: dict[int, tuple[int, int]] = {}
        start_link = start_eprocess + self.eprocess_links
        link = start_link
        for _ in range(65536):
            eprocess = link - self.eprocess_links
            pid = self.u64(cpu, eprocess + self.eprocess_pid)
            result[pid] = (eprocess, self.process_asid(cpu, eprocess))
            link = self.u64(cpu, link)
            if link == start_link:
                return result
            if not self.canonical_kernel_pointer(link):
                raise ValueError("invalid ActiveProcessLinks pointer")
        raise ValueError("ActiveProcessLinks did not close")
