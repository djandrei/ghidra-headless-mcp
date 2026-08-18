"""Tests for export(): command construction, spec files, read/write intent."""

import json
from pathlib import Path

import pytest

from ghmcp import config, headless
from ghmcp.errors import ExportFailure, NotFound


def test_builds_a_read_only_command_by_default(fake_headless):
    headless.export("prog.bin", "info")
    cmd = fake_headless.last
    assert cmd[:3] == ["-process", "prog.bin", "-noanalysis"]
    assert "-readOnly" in cmd
    assert "-postScript" in cmd
    assert config.EXPORT_SCRIPT in cmd


def test_write_mode_omits_read_only_so_changes_persist(fake_headless):
    headless.export("prog.bin", "edit", {"x": 1}, write=True)
    assert "-readOnly" not in fake_headless.last


def test_read_and_write_differ_only_by_the_read_only_flag(fake_headless):
    headless.export("p", "info")
    read_cmd = [a for a in fake_headless.shape(fake_headless.last) if a != "-readOnly"]
    headless.export("p", "info", write=True)
    assert read_cmd == fake_headless.shape(fake_headless.last)


def test_args_travel_in_a_spec_file_not_on_the_command_line(fake_headless):
    """Batch payloads exceed argv limits, so nothing may be passed positionally."""
    payload = {"targets": [f"func_{i}" for i in range(500)]}
    headless.export("prog.bin", "xrefs", payload)

    assert fake_headless.last_spec == {"mode": "xrefs", "args": payload}
    assert not any("func_499" in part for part in fake_headless.last)


def test_spec_carries_empty_args_when_none_given(fake_headless):
    headless.export("p", "info")
    assert fake_headless.last_spec == {"mode": "info", "args": {}}


def test_script_path_includes_both_our_scripts_and_ghidras(fake_headless):
    headless.export("p", "info")
    cmd = fake_headless.last
    script_path = cmd[cmd.index("-scriptPath") + 1]
    assert str(config.SCRIPT_DIR) in script_path
    assert ";" in script_path


def test_temp_files_are_cleaned_up(fake_headless):
    headless.export("p", "info")
    spec_file = Path(fake_headless.last[-2])
    assert not spec_file.exists()
    assert not spec_file.parent.exists()


def test_missing_output_file_reports_actionably(fake_headless):
    fake_headless.write_output = False
    with pytest.raises(ExportFailure, match="analyze_binary"):
        headless.export("never-analysed.bin", "info")


def test_typed_error_from_the_envelope_propagates(fake_headless):
    fake_headless.envelope = {
        "ok": False,
        "error": {"kind": "not_found", "message": "function not found: nope"},
    }
    with pytest.raises(NotFound, match="nope"):
        headless.export("p", "decompile", {"target": "nope"})


def test_custom_timeout_is_passed_through(monkeypatch, project):
    seen = {}

    def fake_run(args, timeout):
        seen["timeout"] = timeout
        Path(args[-1]).write_text(json.dumps({"ok": True, "data": {}}))

        class P:
            returncode, stdout, stderr = 0, "", ""

        return P()

    monkeypatch.setattr(headless, "run_headless", fake_run)
    headless.export("p", "info", timeout=42)
    assert seen["timeout"] == 42


def test_default_timeout_is_the_query_timeout(fake_headless, monkeypatch):
    monkeypatch.setattr(config, "QUERY_TIMEOUT_S", 123)
    captured = {}
    original = fake_headless.__call__

    def wrapper(args, timeout):
        captured["timeout"] = timeout
        return original(args, timeout)

    monkeypatch.setattr(headless, "run_headless", wrapper)
    headless.export("p", "info")
    assert captured["timeout"] == 123
