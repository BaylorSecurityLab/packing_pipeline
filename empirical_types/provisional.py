from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from .manifest import load_conditions


def _json_lines(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    with path.open(encoding="utf-8", errors="replace") as source:
        for line in source:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _normalize_type(value: str | None) -> str | None:
    if not value:
        return None
    normalized = value.strip().upper().replace(" ", "_").replace("-", "_")
    return normalized if normalized.startswith("TYPE_") else None


def sample_identity(row: dict) -> str:
    """Identify a distinct packed payload by content, with legacy fallback."""
    return row.get("packed_sha256") or row["sample_id"]


def repetition_identity(row: dict) -> str:
    """Identify an independent repetition, resisting duplicated run directories."""
    repetition = row.get("repetition")
    if repetition is not None:
        return f"rep:{repetition}"
    return f"run:{row.get('run_directory') or row['sample_id']}"


def dynamic_validation(run_dir: Path) -> dict:
    run_path = run_dir / "run.json"
    sample_path = run_dir / "sample.json"
    drakrun = run_dir / "drakrun"
    run = json.loads(run_path.read_text(encoding="utf-8")) if run_path.exists() else {}
    sample = (
        json.loads(sample_path.read_text(encoding="utf-8"))
        if sample_path.exists()
        else {}
    )
    injections = _json_lines(drakrun / "inject.log")
    injection_attempt = injections[-1] if injections else None
    injection = next(
        (row for row in reversed(injections) if row.get("Status") == "Success"), None
    )
    pid = injection.get("InjectedPid") if injection else None
    loaded_logs = {}
    for filename in ("apimon.log", "exmon.log", "memdump.log", "procmon.log"):
        rows = _json_lines(drakrun / filename)
        loaded_logs[filename.removesuffix(".log")] = rows
    target_process = None
    node_by_pid = {}
    process_tree_path = drakrun / "process_tree.json"
    if process_tree_path.exists():
        try:
            stack = list(json.loads(process_tree_path.read_text(encoding="utf-8")))
            while stack:
                node = stack.pop()
                node_by_pid[node.get("pid")] = node
                stack.extend(node.get("children", []))
            target_process = node_by_pid.get(pid)
        except (json.JSONDecodeError, TypeError):
            pass

    target_pids = {pid} if pid is not None else set()
    auxiliary_children = {"conhost.exe", "werfault.exe", "werfaultsecure.exe"}

    def add_process_subtree(root_pid) -> None:
        stack = [(node_by_pid[root_pid], True)] if root_pid in node_by_pid else []
        while stack:
            node, is_root = stack.pop()
            process_name = str(node.get("procname", "")).rsplit("\\", 1)[-1].lower()
            if not is_root and process_name in auxiliary_children:
                continue
            if node.get("pid") is not None:
                target_pids.add(node["pid"])
            stack.extend((child, False) for child in node.get("children", []))

    if pid is not None:
        add_process_subtree(pid)
    tree_target_pids = set(target_pids)
    memdump_rows = loaded_logs["memdump"]
    changed = True
    while changed:
        changed = False
        for row in memdump_rows:
            source_pid = row.get("PID")
            target_pid = row.get("TargetPID")
            if source_pid in target_pids and target_pid is not None:
                before = len(target_pids)
                target_pids.add(target_pid)
                add_process_subtree(target_pid)
                changed |= len(target_pids) != before

    counts = {}
    for name, rows in loaded_logs.items():
        counts[name] = sum(
            row.get("PID") in target_pids or row.get("DumpPID") in target_pids
            for row in rows
        )
    target_events = sum(counts.values())
    required_artifacts = {
        "metadata": (drakrun / "metadata.json").exists(),
        "injection": injection is not None,
    }
    supplemental_artifacts = {
        "process_tree": (drakrun / "process_tree.json").exists(),
    }
    target_dumps = [row for row in memdump_rows if row.get("DumpPID") in target_pids]
    incoming_writes = [
        row
        for row in memdump_rows
        if row.get("TargetPID") in tree_target_pids
        and row.get("PID") not in tree_target_pids
    ]
    outgoing_writes = [
        row
        for row in memdump_rows
        if row.get("PID") in tree_target_pids
        and row.get("TargetPID") is not None
        and row.get("TargetPID") not in tree_target_pids
    ]
    dumps_by_address = defaultdict(set)
    dump_sizes = []
    for row in target_dumps:
        address = row.get("DumpAddr")
        filename = row.get("DumpFilename")
        if address and filename:
            dumps_by_address[address].add(filename)
        try:
            dump_sizes.append(int(str(row.get("DumpSize", "0")), 0))
        except ValueError:
            pass
    repeated_dump_regions = sum(len(names) > 1 for names in dumps_by_address.values())
    page_aligned = sum(size >= 4096 and size % 4096 == 0 for size in dump_sizes)

    paper_proxy_features = {
        "target_child_processes": len(target_process.get("children", []))
        if target_process
        else None,
        "target_exit_code": target_process.get("exit_code") if target_process else None,
        "tracked_processes": len(target_pids),
        "target_descendant_processes": max(0, len(tree_target_pids) - 1),
        "interprocess_target_processes": len(target_pids - tree_target_pids),
        "target_exception_events": counts["exmon"],
        "target_memory_dump_events": len(target_dumps),
        "unique_target_dump_regions": len(dumps_by_address),
        "repeated_target_dump_regions": repeated_dump_regions,
        "possible_rewrite_candidate": repeated_dump_regions > 0,
        "incoming_interprocess_writes": len(incoming_writes),
        "outgoing_interprocess_writes": len(outgoing_writes),
        "page_granularity_ratio": round(page_aligned / len(dump_sizes), 3)
        if dump_sizes
        else None,
    }
    validated = (
        run.get("return_code") == 0
        and all(required_artifacts.values())
        and target_events > 0
    )
    failure_reason = None
    if run.get("return_code") != 0:
        failure_reason = "backend_nonzero_return"
    elif not required_artifacts["metadata"]:
        failure_reason = "missing_metadata"
    elif injection is None:
        if injection_attempt and injection_attempt.get("ErrorCode") == 740:
            failure_reason = "sample_requires_elevation"
        else:
            failure_reason = "injection_failed"
    elif target_events == 0:
        failure_reason = "no_target_process_events"
    wall_seconds = None
    if run.get("started_at") and run.get("finished_at"):
        try:
            wall_seconds = (
                datetime.fromisoformat(run["finished_at"])
                - datetime.fromisoformat(run["started_at"])
            ).total_seconds()
        except ValueError:
            pass
    return {
        "sample_id": sample.get("sample_id", run_dir.name),
        "packed_sha256": sample.get("packed_sha256"),
        "packer_family": sample.get("packer_family"),
        "packer_version": sample.get("packer_version"),
        "test_case_id": sample.get("test_case_id"),
        "configuration_id": sample.get("configuration_id"),
        "type_hypothesis": sample.get("type_hypothesis"),
        "original_path": sample.get("original_path"),
        "repetition": sample.get("repetition"),
        "retry_for_dynamic_gate": bool(sample.get("retry_for_dynamic_gate")),
        "retry_mode": sample.get("retry_mode"),
        "run_directory": str(run_dir),
        "backend_return_code": run.get("return_code"),
        "started_at": run.get("started_at"),
        "finished_at": run.get("finished_at"),
        "wall_seconds": wall_seconds,
        "injected_pid": pid,
        "target_process_pids": sorted(target_pids),
        "injection_attempt": injection_attempt,
        "target_event_counts": counts,
        "target_events": target_events,
        "required_artifacts": required_artifacts,
        "supplemental_artifacts": supplemental_artifacts,
        "paper_proxy_features": paper_proxy_features,
        "paper_proxy_limitations": (
            "DRAKVUF dumps and API events do not prove that a written region was later "
            "executed; proxy features cannot independently assign exact layers or frames."
        ),
        "dynamically_validated": validated,
        "dynamic_failure_reason": failure_reason,
    }


def auto_label(
    runs: Path,
    manifest: Path,
    minimum_repetitions: int,
    output: Path,
    minimum_distinct_samples: int = 2,
) -> list[dict]:
    if minimum_repetitions < 1:
        raise ValueError("minimum_repetitions must be positive")
    if minimum_distinct_samples < 1:
        raise ValueError("minimum_distinct_samples must be positive")
    cases = load_conditions(manifest)
    evidence = [dynamic_validation(path.parent) for path in runs.rglob("run.json")]
    grouped: dict[tuple, list[dict]] = defaultdict(list)
    for row in evidence:
        grouped[
            (
                row["packer_family"],
                row["packer_version"],
                row["configuration_id"],
                row["test_case_id"],
            )
        ].append(row)
    conditions = []
    for (family, version, configuration_id, test_case_id), members in sorted(
        grouped.items()
    ):
        case = cases.get(test_case_id, {})
        hypothesis = _normalize_type(case.get("type_hypothesis")) or _normalize_type(
            next(
                (
                    row.get("type_hypothesis")
                    for row in members
                    if row.get("type_hypothesis")
                ),
                None,
            )
        )
        validated = [row for row in members if row["dynamically_validated"]]
        validated_by_sample: dict[str, set[str]] = defaultdict(set)
        for row in validated:
            validated_by_sample[sample_identity(row)].add(repetition_identity(row))
        qualifying_samples = {
            sample_id for sample_id, repetitions in validated_by_sample.items()
            if len(repetitions) >= minimum_repetitions
        }
        eligible = len(qualifying_samples) >= minimum_distinct_samples
        auto_type = hypothesis if eligible and hypothesis else None
        for row in members:
            row["auto_label"] = f"PROVISIONAL_{auto_type}" if auto_type else None
            if auto_type and row["dynamically_validated"]:
                row["label_status"] = "provisional_stack_cross_check"
                row["label_method"] = (
                    "manifest hypothesis cross-checked by this sample and independent "
                    "successful DRAKVUF executions; not an exact layer/frame measurement"
                )
            elif auto_type:
                row["label_status"] = "provisional_condition_inference"
                row["label_method"] = (
                    "label inferred from the dynamically validated samples in the same "
                    "packer/version/configuration condition"
                )
            else:
                row["label_status"] = "unresolved"
                row["label_method"] = "minimum dynamic cross-check not met"
            row["cross_check_n"] = sum(
                len(repetitions) for repetitions in validated_by_sample.values()
            )
        conditions.append(
            {
                "packer_family": family,
                "packer_version": version,
                "configuration_id": configuration_id,
                "test_case_id": test_case_id,
                "minimum_repetitions_per_sample": minimum_repetitions,
                "minimum_distinct_samples": minimum_distinct_samples,
                "minimum_total_validated_runs": (
                    minimum_repetitions * minimum_distinct_samples
                ),
                "available_runs": len(members),
                "available_distinct_samples": len(
                    {sample_identity(row) for row in members}
                ),
                "dynamically_validated_runs": len(validated),
                "dynamically_validated_distinct_samples": len(
                    {sample_identity(row) for row in validated}
                ),
                "qualifying_distinct_samples": len(qualifying_samples),
                "hypothesis": hypothesis,
                "auto_label": f"PROVISIONAL_{auto_type}" if auto_type else None,
                "eligible": auto_type is not None,
                "method": "provisional_stack_cross_check",
                "samples": members,
            }
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(conditions, indent=2) + "\n", encoding="utf-8")
    return conditions
