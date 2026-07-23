#!/usr/bin/env python3
"""Generate the QEMU tracer's offsets from the exact guest kernel profile."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


FIELDS = {
    "KPCR_PRCB": ("_KPCR", "Prcb"),
    "KPRCB_CURRENT_THREAD": ("_KPRCB", "CurrentThread"),
    "KTHREAD_APC_STATE": ("_KTHREAD", "ApcState"),
    "KTHREAD_PROCESS": ("_KTHREAD", "Process"),
    "KAPC_STATE_PROCESS": ("_KAPC_STATE", "Process"),
    "ETHREAD_CID": ("_ETHREAD", "Cid"),
    "CLIENT_ID_PID": ("_CLIENT_ID", "UniqueProcess"),
    "CLIENT_ID_TID": ("_CLIENT_ID", "UniqueThread"),
    "EPROCESS_PID": ("_EPROCESS", "UniqueProcessId"),
    "EPROCESS_CREATE_TIME": ("_EPROCESS", "CreateTime"),
    "EPROCESS_JOB": ("_EPROCESS", "Job"),
    "EPROCESS_PARENT_PID": ("_EPROCESS", "InheritedFromUniqueProcessId"),
    "EPROCESS_ACTIVE_LINKS": ("_EPROCESS", "ActiveProcessLinks"),
    "EPROCESS_OBJECT_TABLE": ("_EPROCESS", "ObjectTable"),
    "EPROCESS_VAD_ROOT": ("_EPROCESS", "VadRoot"),
    "KPROCESS_DIRECTORY_TABLE": ("_KPROCESS", "DirectoryTableBase"),
    "KPROCESS_USER_DIRECTORY_TABLE": ("_KPROCESS", "UserDirectoryTableBase"),
    "HANDLE_TABLE_CODE": ("_HANDLE_TABLE", "TableCode"),
    "OBJECT_HEADER_BODY": ("_OBJECT_HEADER", "Body"),
    "AVL_TREE_ROOT": ("_RTL_AVL_TREE", "Root"),
    "VAD_LEFT": ("_RTL_BALANCED_NODE", "Left"),
    "VAD_RIGHT": ("_RTL_BALANCED_NODE", "Right"),
    "VAD_START": ("_MMVAD_SHORT", "StartingVpn"),
    "VAD_END": ("_MMVAD_SHORT", "EndingVpn"),
    "VAD_START_HIGH": ("_MMVAD_SHORT", "StartingVpnHigh"),
    "VAD_END_HIGH": ("_MMVAD_SHORT", "EndingVpnHigh"),
    "VAD_FLAGS": ("_MMVAD_SHORT", "u"),
    "MMVAD_SUBSECTION": ("_MMVAD", "Subsection"),
    "MMVAD_FIRST_PROTOTYPE_PTE": ("_MMVAD", "FirstPrototypePte"),
    "MMVAD_FILE_OBJECT": ("_MMVAD", "FileObject"),
    "SUBSECTION_CONTROL_AREA": ("_SUBSECTION", "ControlArea"),
    "SUBSECTION_BASE": ("_SUBSECTION", "SubsectionBase"),
    "SUBSECTION_NEXT": ("_SUBSECTION", "NextSubsection"),
    "SUBSECTION_STARTING_SECTOR": ("_SUBSECTION", "StartingSector"),
    "SUBSECTION_PTES": ("_SUBSECTION", "PtesInSubsection"),
    "CONTROL_AREA_FILE_POINTER": ("_CONTROL_AREA", "FilePointer"),
    "FILE_OBJECT_TYPE": ("_FILE_OBJECT", "Type"),
    "FILE_OBJECT_SIZE": ("_FILE_OBJECT", "Size"),
    "FILE_OBJECT_FS_CONTEXT": ("_FILE_OBJECT", "FsContext"),
    "FILE_OBJECT_SECTION_POINTER": ("_FILE_OBJECT", "SectionObjectPointer"),
    "FILE_OBJECT_RELATED": ("_FILE_OBJECT", "RelatedFileObject"),
    "FILE_OBJECT_NAME": ("_FILE_OBJECT", "FileName"),
    "FILE_OBJECT_CURRENT_OFFSET": ("_FILE_OBJECT", "CurrentByteOffset"),
    "UNICODE_STRING_LENGTH": ("_UNICODE_STRING", "Length"),
    "UNICODE_STRING_BUFFER": ("_UNICODE_STRING", "Buffer"),
    "IO_STATUS_INFORMATION": ("_IO_STATUS_BLOCK", "Information"),
}

FUNCTIONS = {
    "NT_FREE_VIRTUAL_MEMORY_RVA": "NtFreeVirtualMemory",
    "NT_UNMAP_VIEW_RVA": "NtUnmapViewOfSection",
    "NT_UNMAP_VIEW_EX_RVA": "NtUnmapViewOfSectionEx",
    "NT_WRITE_FILE_RVA": "NtWriteFile",
    "NT_READ_FILE_RVA": "NtReadFile",
    "NT_WRITE_VIRTUAL_MEMORY_RVA": "NtWriteVirtualMemory",
}

CONSTANTS = {
    "PS_ACTIVE_PROCESS_HEAD_RVA": "PsActiveProcessHead",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("profile", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    guid_age = profile["$METADATA"]["GUID_AGE"]
    lines = [
        "/* Generated; do not edit. */",
        "#ifndef PAPER_TRACE_WIN10_PROFILE_H",
        "#define PAPER_TRACE_WIN10_PROFILE_H",
        f'#define KERNEL_PROFILE_GUID_AGE "{guid_age}"',
    ]
    for name, (structure, member) in FIELDS.items():
        value = int(profile["$STRUCTS"][structure][1][member][0])
        lines.append(f"#define {name} UINT64_C(0x{value:x})")
    for name, function in FUNCTIONS.items():
        value = int(profile["$FUNCTIONS"][function])
        lines.append(f"#define {name} UINT64_C(0x{value:x})")
    for name, constant in CONSTANTS.items():
        value = int(profile["$CONSTANTS"][constant])
        lines.append(f"#define {name} UINT64_C(0x{value:x})")
    lines.extend(["#endif", ""])
    args.output.write_text("\n".join(lines), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
