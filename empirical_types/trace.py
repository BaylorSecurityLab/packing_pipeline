from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from .model import Evidence


def analyze_jsonl(
    path: Path, sample_id: str, original_code_bytes: int | None = None
) -> Evidence:
    """Analyze a timestamp-ordered, normalized write/execute trace.

    Shadow byte state is maintained independently for every process and execution
    layer, matching the per-layer state machine in Ugarte et al. Write records may
    provide ``target_pid`` for inter-process writes and ``original`` when normalized
    byte matching proves that the new content belongs to the original application.
    Unmap/free/invalidate records are treated as overwrites, as required by the paper.
    """

    writer_layer: dict[tuple[int, int], int] = {}
    byte_state: dict[tuple[int, int, int], str] = {}
    state_layers_by_memory: dict[tuple[int, int], set[int]] = defaultdict(set)
    new_frame_bits: dict[tuple[int, int], set[int]] = defaultdict(set)
    new_frame_original_identities: dict[tuple[int, int], set[tuple]] = defaultdict(
        set
    )
    frame_number: dict[tuple[int, int], int] = defaultdict(int)
    original_frame_bytes: dict[tuple[int, int, int], set[tuple]] = defaultdict(set)
    frame_written_locations: dict[tuple[int, int, int], set[int]] = defaultdict(set)
    original_frame_blocks: Counter[tuple[int, int, int]] = Counter()
    original_frame_function_alignment: dict[tuple[int, int, int], bool] = {}
    original_frames_by_layer: dict[tuple[int, int], set[int]] = defaultdict(set)
    original_bytes_by_layer: dict[tuple[int, int], set[tuple]] = defaultdict(set)
    original_seen: set[tuple] = set()
    original_at_memory: dict[tuple[int, int], tuple] = {}
    original_live_counts: Counter[tuple] = Counter()
    processes: set[int] = set()
    threads: set[tuple[int, int]] = set()
    last_layer_by_thread: dict[tuple[int, int], int] = {}
    forward = backward = max_layer = 0
    repacked_keys: set[tuple] = set()
    packer_after_original = False
    original_executed = False
    maximum_live = 0

    def number(value: int | str) -> int:
        return int(value, 0) if isinstance(value, str) else value

    def reset_for_new_frame(pid: int, layer: int) -> None:
        for state_key, state in list(byte_state.items()):
            state_pid, state_layer, _ = state_key
            if state_pid != pid or state_layer != layer:
                continue
            if state in {"U", "R"}:
                byte_state[state_key] = "W"
            elif state == "X":
                byte_state[state_key] = "O"

    def original_identity(event: dict, pid: int, address: int, offset: int) -> tuple:
        if event.get("original_rva") is not None:
            return ("rva", number(event["original_rva"]) + offset)
        return ("runtime", pid, address + offset)

    def remove_live(memory_key: tuple[int, int]) -> None:
        identity = original_at_memory.pop(memory_key, None)
        if identity is None:
            return
        original_live_counts[identity] -= 1
        if original_live_counts[identity] <= 0:
            del original_live_counts[identity]

    def add_live(memory_key: tuple[int, int], identity: tuple) -> None:
        if original_at_memory.get(memory_key) == identity:
            return
        remove_live(memory_key)
        original_at_memory[memory_key] = identity
        original_live_counts[identity] += 1

    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        event = json.loads(line)
        kind = event.get("event")
        pid, tid = int(event["pid"]), int(event["tid"])
        address, size = number(event["address"]), int(event.get("size", 1))
        if kind == "exec" and event.get("role") == "system":
            continue
        processes.add(pid)
        threads.add((pid, tid))

        if kind in {"write", "invalidate", "unmap", "free"}:
            target_pid = int(event.get("target_pid", pid))
            processes.add(target_pid)
            source_layer = int(
                event.get("source_layer", last_layer_by_thread.get((pid, tid), 0))
            )
            content_is_original = bool(event.get("original", False))
            for offset in range(size):
                byte_address = address + offset
                memory_key = (target_pid, byte_address)
                writer = max(writer_layer.get(memory_key, -1), source_layer)
                if kind == "write":
                    writer_layer[memory_key] = writer
                    affected_layers = {writer + 1}
                else:
                    affected_layers = set(state_layers_by_memory[memory_key]) or {
                        writer + 1
                    }
                for destination_layer in affected_layers:
                    layer_key = (target_pid, destination_layer)
                    state_key = (target_pid, destination_layer, byte_address)
                    if byte_state.get(state_key) == "U":
                        byte_state[state_key] = "R"
                        if memory_key in original_at_memory:
                            repacked_keys.add(original_at_memory[memory_key])
                    elif byte_state.get(state_key) != "R":
                        byte_state[state_key] = "W"
                    state_layers_by_memory[memory_key].add(destination_layer)
                    new_frame_bits[layer_key].add(byte_address)
                remove_live(memory_key)
                if content_is_original:
                    identity = original_identity(event, target_pid, address, offset)
                    original_seen.add(identity)
                    add_live(memory_key, identity)
                    for destination_layer in affected_layers:
                        new_frame_original_identities[
                            (target_pid, destination_layer)
                        ].add(identity)
                        original_bytes_by_layer[
                            (target_pid, destination_layer)
                        ].add(identity)
            maximum_live = max(maximum_live, len(original_live_counts))
            continue

        if kind != "exec":
            raise ValueError(f"{path}:{line_no}: unknown event {kind!r}")

        memory_keys = [(pid, address + offset) for offset in range(size)]
        layer = max(
            (writer_layer.get(memory_key, -1) + 1 for memory_key in memory_keys),
            default=0,
        )
        max_layer = max(max_layer, layer)
        thread_key = (pid, tid)
        previous_layer = last_layer_by_thread.get(thread_key)
        if previous_layer is not None and layer != previous_layer:
            if layer > previous_layer:
                forward += 1
            else:
                backward += 1
        layer_key = (pid, layer)
        state_keys = [(pid, layer, address + offset) for offset in range(size)]
        starts_frame = any(
            byte_state.get(state_key) in {"W", "R"}
            and state_key[2] in new_frame_bits[layer_key]
            for state_key in state_keys
        )
        if starts_frame:
            frame_number[layer_key] += 1
            frame_key = (pid, layer, frame_number[layer_key])
            frame_written_locations[frame_key].update(new_frame_bits[layer_key])
            original_frame_bytes[frame_key].update(
                new_frame_original_identities[layer_key]
            )
            reset_for_new_frame(pid, layer)
            new_frame_bits[layer_key].clear()
            new_frame_original_identities[layer_key].clear()

        newly_unpacked = {
            memory_key
            for memory_key, state_key in zip(memory_keys, state_keys, strict=True)
            if byte_state.get(state_key) in {"W", "R"}
        }
        is_original = bool(event.get("original", False)) or event.get("role") == "original"
        if is_original:
            original_executed = True
            frame = frame_number[layer_key]
            frame_key = (pid, layer, frame)
            original_frames_by_layer[layer_key].add(frame)
            original_frame_blocks[frame_key] += 1
            if event.get("frame_function_aligned") is not None:
                aligned = bool(event["frame_function_aligned"])
                original_frame_function_alignment[frame_key] = (
                    original_frame_function_alignment.get(frame_key, True) and aligned
                )
            for offset, memory_key in enumerate(memory_keys):
                identity = original_identity(event, pid, address, offset)
                if memory_key in newly_unpacked:
                    original_frame_bytes[frame_key].add(identity)
                original_seen.add(identity)
                add_live(memory_key, identity)
                original_bytes_by_layer[layer_key].add(identity)
        elif original_executed and event.get("role", "packer") == "packer":
            packer_after_original = True
        for memory_key, state_key in zip(memory_keys, state_keys, strict=True):
            byte_state[state_key] = "U" if memory_key in writer_layer else "X"
            state_layers_by_memory[memory_key].add(layer)
        maximum_live = max(maximum_live, len(original_live_counts))
        last_layer_by_thread[thread_key] = layer

    original_frame_keys = [
        (pid, layer, frame)
        for (pid, layer), frames in original_frames_by_layer.items()
        for frame in frames
    ]
    frame_sizes = [
        len(original_frame_bytes[key]) or len(frame_written_locations[key])
        for key in original_frame_keys
    ]
    frame_blocks = [original_frame_blocks[key] for key in original_frame_keys]
    frame_function_aligned = [
        original_frame_function_alignment.get(key, False)
        for key in original_frame_keys
    ]
    multiframe_layers = {
        layer_key
        for layer_key, frames in original_frames_by_layer.items()
        if len(frames) > 1
    }
    multiframe_bytes = set().union(
        *(original_bytes_by_layer[key] for key in multiframe_layers)
    ) if multiframe_layers else set()
    original_multiframe_ratio = (
        len(multiframe_bytes) / len(original_seen) if original_seen else None
    )
    denominator = original_code_bytes or len(original_seen)
    maximum = maximum_live / denominator if denominator else 0.0
    union = len(original_seen) / denominator if denominator else 0.0
    return Evidence(
        sample_id=sample_id,
        layers=max_layer + 1 if processes else 0,
        processes=len(processes),
        threads=len(threads),
        forward_transitions=forward,
        backward_transitions=backward,
        original_code_frames=len(original_frame_keys),
        original_multiframe_ratio=original_multiframe_ratio,
        maximum_simultaneous_code_coverage=min(maximum, 1.0),
        union_code_coverage=min(union, 1.0),
        repacked_original_bytes=len(repacked_keys),
        tail_transition=original_executed and not packer_after_original,
        interleaved=packer_after_original,
        frame_sizes=frame_sizes,
        frame_basic_blocks=frame_blocks,
        frame_function_aligned=frame_function_aligned,
    )
