import json

from ops.qemu.validate_fixture_trace import validate


def test_fixture_gate_requires_generic_kernel_callbacks_disabled(tmp_path):
    trace = tmp_path / "fixture.jsonl"
    summary = {
        "event": "summary",
        "seq": 1,
        "kernel_store_callbacks_registered": True,
    }
    trace.write_text(json.dumps(summary) + "\n", encoding="utf-8")

    _, errors = validate(trace)
    expected = "generic kernel-store callbacks were registered"
    assert expected in errors

    summary["kernel_store_callbacks_registered"] = False
    trace.write_text(json.dumps(summary) + "\n", encoding="utf-8")
    _, errors = validate(trace)
    assert expected not in errors


def test_fixture_gate_requires_exact_virtual_memory_write_hook(tmp_path):
    trace = tmp_path / "fixture.jsonl"
    summary = {
        "event": "summary",
        "seq": 1,
        "virtual_memory_write_events": 0,
        "virtual_memory_write_failures": 0,
    }
    trace.write_text(json.dumps(summary) + "\n", encoding="utf-8")

    _, errors = validate(trace)
    expected = "fixture did not exercise NtWriteVirtualMemory tracing"
    assert expected in errors

    summary["virtual_memory_write_events"] = 1
    trace.write_text(json.dumps(summary) + "\n", encoding="utf-8")
    _, errors = validate(trace)
    assert expected not in errors


def test_fixture_gate_rejects_sample_boundary_flush(tmp_path):
    trace = tmp_path / "fixture.jsonl"
    summary = {"event": "summary", "seq": 1, "tb_flush_requests": 1}
    trace.write_text(json.dumps(summary) + "\n", encoding="utf-8")

    _, errors = validate(trace)
    expected = "sample boundary unexpectedly flushed translated code"
    assert expected in errors

    summary["tb_flush_requests"] = 0
    trace.write_text(json.dumps(summary) + "\n", encoding="utf-8")
    _, errors = validate(trace)
    assert expected not in errors


def test_fixture_gate_requires_pretranslated_user_store_callbacks(tmp_path):
    trace = tmp_path / "fixture.jsonl"
    summary = {
        "event": "summary",
        "seq": 1,
        "always_present_user_store_callbacks": False,
    }
    trace.write_text(json.dumps(summary) + "\n", encoding="utf-8")

    _, errors = validate(trace)
    expected = "pretranslated user-store callbacks were not registered"
    assert expected in errors

    summary["always_present_user_store_callbacks"] = True
    trace.write_text(json.dumps(summary) + "\n", encoding="utf-8")
    _, errors = validate(trace)
    assert expected not in errors


def test_fixture_gate_requires_lossless_buffered_memory_callbacks(tmp_path):
    trace = tmp_path / "fixture.jsonl"
    summary = {
        "event": "summary",
        "seq": 1,
        "buffered_memory_callbacks_registered": False,
        "memory_buffer_overflows": 1,
    }
    trace.write_text(json.dumps(summary) + "\n", encoding="utf-8")

    _, errors = validate(trace)
    registration = "branchless buffered memory callbacks were not registered"
    overflow = "summary memory_buffer_overflows=1, expected 0"
    assert registration in errors
    assert overflow in errors

    summary["buffered_memory_callbacks_registered"] = True
    summary["memory_buffer_overflows"] = 0
    trace.write_text(json.dumps(summary) + "\n", encoding="utf-8")
    _, errors = validate(trace)
    assert registration not in errors
    assert overflow not in errors


def test_fixture_gate_requires_exact_context_refresh_and_cache_hit(tmp_path):
    trace = tmp_path / "fixture.jsonl"
    summary = {
        "event": "summary",
        "seq": 1,
        "block_context_refreshes": 0,
        "block_context_cache_hits": 0,
    }
    trace.write_text(json.dumps(summary) + "\n", encoding="utf-8")

    _, errors = validate(trace)
    refresh = "fixture did not refresh an exact block context"
    cache = "fixture did not exercise the user-block context cache"
    assert refresh in errors
    assert cache in errors

    summary["block_context_refreshes"] = 1
    summary["block_context_cache_hits"] = 1
    trace.write_text(json.dumps(summary) + "\n", encoding="utf-8")
    _, errors = validate(trace)
    assert refresh not in errors
    assert cache not in errors


def test_fixture_gate_requires_recovered_exception_evidence(tmp_path):
    trace = tmp_path / "fixture.jsonl"
    events = [
        {
            "event": "exception_dispatch",
            "seq": 1,
            "source": "RtlRaiseException",
        },
        {"event": "exception_recovered", "seq": 2},
        {
            "event": "summary",
            "seq": 3,
            "exception_dispatch_events": 1,
            "exception_recovery_events": 1,
            "pending_exceptions": 0,
        },
    ]
    trace.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )

    _, errors = validate(trace)
    assert "summary exception dispatch count differs from trace" not in errors
    assert "summary exception recovery count differs from trace" not in errors
    assert "fixture ended with a pending exception" not in errors

    events[-1]["pending_exceptions"] = 1
    trace.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )
    _, errors = validate(trace)
    assert "fixture ended with a pending exception" in errors


def test_fixture_gate_requires_exact_software_exception_source(tmp_path):
    trace = tmp_path / "fixture.jsonl"
    events = [
        {
            "event": "exception_dispatch",
            "seq": 1,
            "source": "processor_exception",
        },
        {"event": "summary", "seq": 2},
    ]
    trace.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )

    _, errors = validate(trace)
    expected = "fixture did not exercise exact RtlRaiseException tracing"
    assert expected in errors

    events[0]["source"] = "RtlRaiseException"
    trace.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )
    _, errors = validate(trace)
    assert expected not in errors


def test_fixture_gate_requires_ready_status_query(tmp_path):
    trace = tmp_path / "fixture.jsonl"
    summary = {"event": "summary", "seq": 1, "marker_query_ready": 0}
    trace.write_text(json.dumps(summary) + "\n", encoding="utf-8")

    _, errors = validate(trace)
    expected = "fixture never reached a ready status query"
    assert expected in errors

    summary["marker_query_ready"] = 1
    trace.write_text(json.dumps(summary) + "\n", encoding="utf-8")
    _, errors = validate(trace)
    assert expected not in errors


def test_fixture_gate_requires_exact_pe_entry_observation(tmp_path):
    trace = tmp_path / "fixture.jsonl"
    summary = {"event": "summary", "seq": 1, "root_entry_seen": False}
    trace.write_text(json.dumps(summary) + "\n", encoding="utf-8")

    _, errors = validate(trace)
    expected = "fixture PE entry point was never observed"
    assert expected in errors

    summary["root_entry_seen"] = True
    trace.write_text(json.dumps(summary) + "\n", encoding="utf-8")
    _, errors = validate(trace)
    assert expected not in errors


def test_fixture_gate_rejects_kernel_address_writes(tmp_path):
    trace = tmp_path / "fixture.jsonl"
    events = [
        {
            "event": "write",
            "seq": 1,
            "pid": 7,
            "target_pid": 8,
            "address": 0xFFFF800000001000,
        },
        {"event": "summary", "seq": 2, "write_events": 1},
    ]
    trace.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )

    _, errors = validate(trace)
    assert "trace contains a kernel-address write" in errors


def test_fixture_gate_requires_sample_recording_start(tmp_path):
    trace = tmp_path / "fixture.jsonl"
    summary = {"event": "summary", "seq": 1, "sample_started": False}
    trace.write_text(json.dumps(summary) + "\n", encoding="utf-8")

    _, errors = validate(trace)
    expected = "fixture sample recording never started"
    assert expected in errors

    summary["sample_started"] = True
    trace.write_text(json.dumps(summary) + "\n", encoding="utf-8")
    _, errors = validate(trace)
    assert expected not in errors
