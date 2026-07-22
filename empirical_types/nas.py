from __future__ import annotations

import os
import hashlib
import json
import re
from difflib import SequenceMatcher
from pathlib import Path

import yaml

from .manifest import condition_id, load_conditions
from .provisional import dynamic_validation, repetition_identity, sample_identity


MIN_SAMPLE_SIZE = 1024
MAX_IN_PLACE_VALIDATION_RETRIES = 2


def stage_tree(
    server: str, share: str, remote: str, destination: Path, limit: int | None = None
) -> int:
    """Download an SMB subtree. Credentials come only from environment variables."""
    import smbclient

    username = os.environ.get("PACKER_NAS_USERNAME")
    password = os.environ.get("PACKER_NAS_PASSWORD")
    if not username or not password:
        raise RuntimeError("set PACKER_NAS_USERNAME and PACKER_NAS_PASSWORD")
    smbclient.register_session(server, username=username, password=password)
    root = f"//{server}/{share}/{remote}".rstrip("/")
    count = 0

    def copy_dir(source: str, target: Path) -> None:
        nonlocal count
        if limit is not None and count >= limit:
            return
        target.mkdir(parents=True, exist_ok=True)
        for entry in smbclient.scandir(source):
            if limit is not None and count >= limit:
                break
            child = source + "/" + entry.name
            local = target / entry.name
            if entry.is_dir():
                copy_dir(child, local)
            elif entry.name.lower().endswith(".exe"):
                if local.exists() and local.stat().st_size == entry.stat().st_size:
                    count += 1
                    continue
                with (
                    smbclient.open_file(child, mode="rb") as src,
                    local.open("wb") as dst,
                ):
                    while block := src.read(1024 * 1024):
                        dst.write(block)
                count += 1

    copy_dir(root, destination)
    return count


def _safe(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _execution_risk(sample: dict) -> tuple[int, int, str]:
    """Prefer payloads unlikely to require interactive installation or elevation."""
    name = sample["filename"].lower()
    risk = 0
    if any(token in name for token in ("portable", "unxutils")):
        risk -= 2
    if any(token in name for token in ("setup", "installer", "machine", "nullsoft")):
        risk += 2
    return risk, sample["size"], name


def _remote_exes(smbclient, path: str, depth: int = 1) -> list[dict]:
    files = []
    for entry in smbclient.scandir(path):
        child = path + "/" + entry.name
        if entry.is_dir() and depth > 0 and not entry.name.lower().startswith("cr_"):
            files.extend(_remote_exes(smbclient, child, depth - 1))
        elif (
            not entry.is_dir()
            and entry.name.lower().endswith(".exe")
            and entry.stat().st_size >= MIN_SAMPLE_SIZE
        ):
            files.append(
                {
                    "remote_path": child,
                    "filename": entry.name,
                    "size": entry.stat().st_size,
                }
            )
    return files


def _gui_definition(folder: str, definitions: list[dict]) -> tuple[dict | None, float]:
    needle = _safe(folder)
    best = None
    best_score = 0.0
    for definition in definitions:
        version = str(definition.get("version", "unknown"))
        candidates = {
            _safe(f"{definition.get('packer_name', '')}_{version}"),
            _safe(f"{definition.get('packer_family', '')}_{version}"),
            _safe(str(definition.get("packer_name", ""))),
        }
        score = max(
            SequenceMatcher(None, needle, candidate).ratio()
            for candidate in candidates
            if candidate
        )
        if score > best_score:
            best, best_score = definition, score
    return (best, best_score) if best_score >= 0.55 else (None, best_score)


def plan_matrix(
    server: str,
    share: str,
    remote: str,
    manifest: Path,
    samples_per_condition: int,
) -> dict:
    import smbclient

    username = os.environ.get("PACKER_NAS_USERNAME")
    password = os.environ.get("PACKER_NAS_PASSWORD")
    if not username or not password:
        raise RuntimeError("set PACKER_NAS_USERNAME and PACKER_NAS_PASSWORD")
    smbclient.register_session(server, username=username, password=password)
    data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    cases = load_conditions(manifest)
    definitions = data.get("definitions", [])
    case_family_versions = {
        (case["packer_family"], str(case["version"])) for case in cases.values()
    }
    conditions = {
        case_id: {
            "packer_family": case["packer_family"],
            "packer_version": str(case["version"]),
            "test_case_id": case_id,
            "configuration_id": condition_id(case),
            "type_hypothesis": case.get("type_hypothesis"),
            "source": "yaml_test_case",
            "status": "missing_on_nas",
            "available_samples": 0,
            "samples": [],
        }
        for case_id, case in cases.items()
    }
    gui_conditions_by_identity = {}
    gui_definitions = []
    for definition in definitions:
        identity_key = (
            definition["packer_family"],
            str(definition["version"]),
        )
        if (
            "GUI" not in definition.get("tags", [])
            or identity_key in case_family_versions
        ):
            continue
        gui_definitions.append(definition)
        identity = f"{identity_key[0]}\0{identity_key[1]}\0GUI"
        configuration = "gui-" + hashlib.sha256(identity.encode()).hexdigest()[:12]
        gui_conditions_by_identity[identity_key] = {
            "packer_family": identity_key[0],
            "packer_version": identity_key[1],
            "test_case_id": None,
            "configuration_id": configuration,
            "type_hypothesis": definition.get("type_hypothesis"),
            "source": "gui_family_version",
            "nas_packer_directory": None,
            "mapping_score": None,
            "status": "missing_on_nas",
            "available_samples": 0,
            "samples": [],
            "alternate_samples": [],
        }
    root = f"//{server}/{share}/{remote}".rstrip("/")
    for packer_entry in smbclient.scandir(root):
        if not packer_entry.is_dir() or packer_entry.name.startswith((".", "@")):
            continue
        packer_path = root + "/" + packer_entry.name
        entries = list(smbclient.scandir(packer_path))
        for entry in entries:
            if not entry.is_dir() or entry.name not in cases:
                continue
            files = sorted(
                _remote_exes(smbclient, packer_path + "/" + entry.name),
                key=lambda row: (row["size"], row["filename"]),
            )
            condition = conditions[entry.name]
            condition["nas_packer_directory"] = packer_entry.name
            condition["available_samples"] = len(files)
            condition["samples"] = files[:samples_per_condition]
            condition["alternate_samples"] = files[
                samples_per_condition : samples_per_condition + 5
            ]
            condition["status"] = "planned" if condition["samples"] else "empty_on_nas"
        direct_files = sorted(
            [
                {
                    "remote_path": packer_path + "/" + entry.name,
                    "filename": entry.name,
                    "size": entry.stat().st_size,
                }
                for entry in entries
                if (
                    not entry.is_dir()
                    and entry.name.lower().endswith(".exe")
                    and entry.stat().st_size >= MIN_SAMPLE_SIZE
                )
            ],
            key=lambda row: (row["size"], row["filename"]),
        )
        definition, score = _gui_definition(packer_entry.name, gui_definitions)
        if definition:
            identity_key = (
                definition["packer_family"],
                str(definition["version"]),
            )
            condition = gui_conditions_by_identity[identity_key]
            if direct_files:
                condition.update(
                    {
                        "nas_packer_directory": packer_entry.name,
                        "mapping_score": round(score, 3),
                        "status": "planned",
                        "available_samples": len(direct_files),
                        "samples": direct_files[:samples_per_condition],
                        "alternate_samples": direct_files[
                            samples_per_condition : samples_per_condition + 5
                        ],
                    }
                )
            elif score >= 0.75 and condition["status"] == "missing_on_nas":
                condition.update(
                    {
                        "nas_packer_directory": packer_entry.name,
                        "mapping_score": round(score, 3),
                        "status": "empty_on_nas",
                        "available_samples": 0,
                        "samples": [],
                        "alternate_samples": [],
                    }
                )
    planned = list(conditions.values()) + list(gui_conditions_by_identity.values())
    return {
        "schema_version": 1,
        "server": server,
        "share": share,
        "remote_root": remote,
        "samples_per_condition": samples_per_condition,
        "conditions": planned,
    }


def stage_matrix(plan_path: Path, destination: Path, inventory_path: Path) -> int:
    import smbclient

    username = os.environ.get("PACKER_NAS_USERNAME")
    password = os.environ.get("PACKER_NAS_PASSWORD")
    if not username or not password:
        raise RuntimeError("set PACKER_NAS_USERNAME and PACKER_NAS_PASSWORD")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    smbclient.register_session(plan["server"], username=username, password=password)
    inventory_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with inventory_path.open("w", encoding="utf-8") as inventory_handle:
        for condition in plan["conditions"]:
            for index, sample in enumerate(condition["samples"], 1):
                local_dir = destination / condition["configuration_id"]
                local_dir.mkdir(parents=True, exist_ok=True)
                local = local_dir / f"{index:02d}_{sample['filename']}"
                if not local.exists() or local.stat().st_size != sample["size"]:
                    with (
                        smbclient.open_file(sample["remote_path"], mode="rb") as src,
                        local.open("wb") as dst,
                    ):
                        while block := src.read(1024 * 1024):
                            dst.write(block)
                packed_sha256 = hashlib.sha256(local.read_bytes()).hexdigest()
                sample_id = hashlib.sha256(
                    (
                        condition["configuration_id"]
                        + "\0"
                        + str(index)
                        + "\0"
                        + packed_sha256
                    ).encode()
                ).hexdigest()
                record = {
                    "sample_id": sample_id,
                    "packed_sha256": packed_sha256,
                    "packed_path": str(local.resolve()),
                    "original_path": None,
                    "configuration_id": condition["configuration_id"],
                    "test_case_id": condition["test_case_id"],
                    "packer_family": condition["packer_family"],
                    "packer_version": condition["packer_version"],
                    "condition_source": condition["source"],
                    "type_hypothesis": condition["type_hypothesis"],
                    "nas_remote_path": sample["remote_path"],
                }
                inventory_handle.write(json.dumps(record) + "\n")
                count += 1
    return count


def stage_retry_matrix(
    plan_path: Path,
    runs: Path,
    destination: Path,
    inventory_path: Path,
    minimum_repetitions: int = 3,
    minimum_distinct_samples: int = 2,
) -> dict:
    """Stage unused alternates for conditions that fail the dynamic evidence gate.

    This is intentionally iterative: call it after a retry batch to select the next
    unused alternates for any condition that still lacks enough validated payloads.
    """
    import smbclient

    if minimum_repetitions < 1 or minimum_distinct_samples < 1:
        raise ValueError("minimum repetitions and distinct samples must be positive")
    username = os.environ.get("PACKER_NAS_USERNAME")
    password = os.environ.get("PACKER_NAS_PASSWORD")
    if not username or not password:
        raise RuntimeError("set PACKER_NAS_USERNAME and PACKER_NAS_PASSWORD")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    smbclient.register_session(plan["server"], username=username, password=password)

    completed_by_configuration: dict[str, dict[str, set[str]]] = {}
    validated_by_configuration: dict[str, dict[str, set[str]]] = {}
    sample_records_by_configuration: dict[str, dict[str, dict]] = {}
    used_remote_paths: set[str] = set()
    for run_path in runs.rglob("run.json"):
        validation = dynamic_validation(run_path.parent)
        configuration_id = validation.get("configuration_id")
        sample_id = validation.get("sample_id")
        if configuration_id and sample_id:
            identity = sample_identity(validation)
            completed = completed_by_configuration.setdefault(configuration_id, {})
            completed.setdefault(identity, set()).add(repetition_identity(validation))
            if validation["dynamically_validated"]:
                samples = validated_by_configuration.setdefault(configuration_id, {})
                samples.setdefault(identity, set()).add(
                    repetition_identity(validation)
                )
        sample_path = run_path.parent / "sample.json"
        if sample_path.exists():
            sample = json.loads(sample_path.read_text(encoding="utf-8"))
            if sample.get("nas_remote_path"):
                used_remote_paths.add(sample["nas_remote_path"])
            if configuration_id:
                identity = sample_identity(sample)
                sample_records_by_configuration.setdefault(configuration_id, {})[
                    identity
                ] = {
                    key: value
                    for key, value in sample.items()
                    if key not in {"repetition", "retry_repetitions", "retry_mode"}
                }

    retry_records = []
    shortfalls = []
    conditions_not_ready = 0
    for condition in plan["conditions"]:
        if condition["status"] != "planned":
            continue
        completed = completed_by_configuration.get(condition["configuration_id"], {})
        completed_samples = sum(
            len(repetitions) >= minimum_repetitions
            for repetitions in completed.values()
        )
        if completed_samples < minimum_distinct_samples:
            conditions_not_ready += 1
            continue
        validated = validated_by_configuration.get(condition["configuration_id"], {})
        qualifying = sum(
            len(repetitions) >= minimum_repetitions
            for repetitions in validated.values()
        )
        needed = max(0, minimum_distinct_samples - qualifying)
        if needed == 0:
            continue
        available_records = sample_records_by_configuration.get(
            condition["configuration_id"], {}
        )
        partial_retry_records = []
        for identity, source_record in available_records.items():
            repetitions = completed.get(identity, set())
            if not (0 < len(repetitions) < minimum_repetitions):
                continue
            record = dict(source_record)
            record["retry_for_dynamic_gate"] = True
            record["retry_mode"] = "resume_missing_repetitions"
            record["retry_repetitions"] = [
                repetition
                for repetition in range(1, minimum_repetitions + 1)
                if f"rep:{repetition}" not in repetitions
            ]
            partial_retry_records.append(record)
            if len(partial_retry_records) >= needed:
                break
        retry_records.extend(partial_retry_records)

        in_place_retry_records = []
        remaining_needed = needed - len(partial_retry_records)
        if remaining_needed:
            near_qualifying = sorted(
                (
                    identity
                    for identity, repetitions in validated.items()
                    if len(repetitions) == minimum_repetitions - 1
                    and len(completed.get(identity, set())) >= minimum_repetitions
                    and identity in available_records
                    and available_records[identity].get("packed_path")
                ),
                key=lambda identity: len(completed.get(identity, set())),
            )
            for identity in near_qualifying:
                completed_repetitions = completed[identity]
                extra_attempts = max(
                    0, len(completed_repetitions) - minimum_repetitions
                )
                if extra_attempts >= MAX_IN_PLACE_VALIDATION_RETRIES:
                    continue
                numeric_repetitions = [
                    int(value.removeprefix("rep:"))
                    for value in completed_repetitions
                    if value.startswith("rep:")
                    and value.removeprefix("rep:").isdigit()
                ]
                next_repetition = max(numeric_repetitions, default=0) + 1
                record = dict(available_records[identity])
                record["retry_for_dynamic_gate"] = True
                record["retry_mode"] = "in_place_validation"
                record["retry_repetitions"] = [next_repetition]
                in_place_retry_records.append(record)
                if len(in_place_retry_records) >= remaining_needed:
                    break
        retry_records.extend(in_place_retry_records)
        remaining_needed -= len(in_place_retry_records)
        candidates = sorted(
            (
                sample
                for sample in condition.get("alternate_samples", [])
                if sample["remote_path"] not in used_remote_paths
            ),
            key=_execution_risk,
        )
        chosen = []
        attempted = 0
        duplicate_alternates = 0
        used_identities = set(completed)
        for sample in candidates:
            if len(chosen) >= remaining_needed:
                break
            attempted += 1
            local_dir = destination / condition["configuration_id"]
            local_dir.mkdir(parents=True, exist_ok=True)
            remote_token = hashlib.sha256(sample["remote_path"].encode()).hexdigest()[
                :12
            ]
            local = local_dir / f"retry_{remote_token}_{sample['filename']}"
            if not local.exists() or local.stat().st_size != sample["size"]:
                with (
                    smbclient.open_file(sample["remote_path"], mode="rb") as src,
                    local.open("wb") as dst,
                ):
                    while block := src.read(1024 * 1024):
                        dst.write(block)
            packed_sha256 = hashlib.sha256(local.read_bytes()).hexdigest()
            used_remote_paths.add(sample["remote_path"])
            if packed_sha256 in used_identities:
                duplicate_alternates += 1
                continue
            sample_id = hashlib.sha256(
                (
                    condition["configuration_id"]
                    + "\0retry\0"
                    + sample["remote_path"]
                    + "\0"
                    + packed_sha256
                ).encode()
            ).hexdigest()
            retry_records.append(
                {
                    "sample_id": sample_id,
                    "packed_sha256": packed_sha256,
                    "packed_path": str(local.resolve()),
                    "original_path": None,
                    "configuration_id": condition["configuration_id"],
                    "test_case_id": condition["test_case_id"],
                    "packer_family": condition["packer_family"],
                    "packer_version": condition["packer_version"],
                    "condition_source": condition["source"],
                    "type_hypothesis": condition["type_hypothesis"],
                    "nas_remote_path": sample["remote_path"],
                    "retry_for_dynamic_gate": True,
                    "retry_mode": "alternate_payload",
                }
            )
            chosen.append(sample)
            used_identities.add(packed_sha256)
        shortfalls.append(
            {
                "configuration_id": condition["configuration_id"],
                "packer_family": condition["packer_family"],
                "packer_version": condition["packer_version"],
                "test_case_id": condition["test_case_id"],
                "nas_status": condition["status"],
                "qualifying_distinct_samples": qualifying,
                "additional_samples_needed": needed,
                "retry_samples_staged": (
                    len(partial_retry_records)
                    + len(in_place_retry_records)
                    + len(chosen)
                ),
                "retry_samples_resumed": len(partial_retry_records),
                "in_place_validation_retries": len(in_place_retry_records),
                "new_retry_samples_staged": len(chosen),
                "duplicate_alternates_skipped": duplicate_alternates,
                "unused_alternates_remaining": max(0, len(candidates) - attempted),
            }
        )

    inventory_path.parent.mkdir(parents=True, exist_ok=True)
    with inventory_path.open("w", encoding="utf-8") as handle:
        for record in retry_records:
            handle.write(json.dumps(record) + "\n")
    return {
        "staged_samples": len(retry_records),
        "conditions_below_gate": len(shortfalls),
        "conditions_not_ready": conditions_not_ready,
        "retryable_conditions": sum(
            row["retry_samples_staged"] > 0 for row in shortfalls
        ),
        "exhausted_conditions": sum(
            row["retry_samples_staged"] == 0
            and row["unused_alternates_remaining"] == 0
            for row in shortfalls
        ),
        "conditions_without_enough_alternates": sum(
            row["retry_samples_staged"] < row["additional_samples_needed"]
            for row in shortfalls
        ),
        "shortfalls": shortfalls,
    }
