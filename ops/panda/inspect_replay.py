#!/usr/bin/env python3
"""Small replay integrity check used before enabling the full tracer."""

from pathlib import Path
import sys

from pandare import Panda


PACKER_MARKER_MAGIC = 0x5041434B
RECCTRL_MAGIC = 0x666


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <recording-prefix>")
    recording = str(Path(sys.argv[1]))
    panda = Panda(
        arch="x86_64",
        mem="2G",
        os="windows",
        extra_args=["-display", "none", "-net", "none"],
    )
    markers: list[tuple[int, int]] = []

    @panda.cb_guest_hypercall
    def guest_hypercall(cpu):
        env = cpu.env_ptr
        eax = int(env.regs[0]) & 0xFFFFFFFF
        if eax == PACKER_MARKER_MAGIC:
            pid = int(env.regs[3]) & 0xFFFFFFFF  # RBX
            action = int(env.regs[1]) & 0xFFFFFFFF  # RCX
            markers.append((pid, action))
            lstar = int(getattr(env, "lstar", 0))
            kernelgsbase = int(getattr(env, "kernelgsbase", 0))
            print(
                f"PACKER_MARKER pid={pid} action={action} "
                f"lstar=0x{lstar:x} kernelgsbase=0x{kernelgsbase:x}",
                flush=True,
            )
        elif eax == RECCTRL_MAGIC:
            print("RECCTRL_MARKER", flush=True)
        return False

    panda.run_replay(recording)
    if not markers:
        print("ERROR: replay contained no root-PID marker", file=sys.stderr)
        return 1
    print(f"replay_integrity=ok root_pid={markers[0][0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
