"""Branches the rest of the unit suite never reached.

Each is a real path — a timeout, a cross-device copy, a name collision met
twice — that a test elsewhere stubbed around rather than through. No JVM.
"""

import logging
import runpy
import subprocess
import sys

import pytest

import ghidra_headless_mcp as entry
from ghmcp import auth, headless, tools
from ghmcp.errors import GhidraError, HeadlessTimeout
from ghmcp.models import AnalysisResult, ProgramInfo

INFO = {
    "name": "sample.bin",
    "language_id": "x86:LE:64:default",
    "compiler_spec_id": "gcc",
    "image_base": "00400000",
    "function_count": 1,
    "symbol_count": 1,
}


def _proc(stdout="", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


def _stored(program, md5):
    return AnalysisResult(
        program=program, already_analyzed=True, duration_seconds=0.0,
        info=ProgramInfo(**{**INFO, "name": program, "md5": md5}),
    )


# ------------------------------------------------------------- run_headless


def test_a_successful_run_returns_the_process(project, monkeypatch):
    proc = _proc("INFO  done\n")
    seen = {}
    monkeypatch.setattr(
        headless.subprocess, "run", lambda cmd, **kw: seen.update(cmd=cmd, kw=kw) or proc
    )
    before = headless.run_count

    assert headless.run_headless(["-process", "x"], timeout=7) is proc
    assert headless.run_count == before + 1
    assert seen["cmd"][-2:] == ["-process", "x"]
    assert seen["kw"]["timeout"] == 7


def test_a_run_past_its_deadline_is_a_headless_timeout(project, monkeypatch):
    def too_slow(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw["timeout"])

    monkeypatch.setattr(headless.subprocess, "run", too_slow)

    with pytest.raises(HeadlessTimeout, match="exceeded 3s.*ANALYZE_TIMEOUT_S"):
        headless.run_headless(["-process", "x"], timeout=3)


# ------------------------------------------------------------ export_project


def test_export_project_unwraps_the_envelope(monkeypatch):
    seen = {}

    def fake_run_spec(args, spec, *, write, timeout):
        seen.update(args=args, spec=spec, write=write, timeout=timeout)
        return '{"ok": true, "data": ["a.bin"]}'

    monkeypatch.setattr(headless, "_run_spec", fake_run_spec)

    assert headless.export_project("project_files", timeout=5) == ["a.bin"]
    assert seen == {"args": ["-process"], "spec": {"mode": "project_files", "args": {}},
                    "write": False, "timeout": 5}


def test_export_project_on_an_empty_project_is_none(monkeypatch):
    monkeypatch.setattr(headless, "_run_spec", lambda *a, **k: None)

    assert headless.export_project("project_files") is None


# -------------------------------------------- analyze_binary name collisions


def test_a_binary_already_stored_under_its_disambiguated_name_is_reused(
    tmp_path, project, monkeypatch
):
    """Second sight of a binary whose basename belongs to another one."""
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELF ours")
    md5 = tools.file_md5(binary)
    renamed = tools.disambiguate_name("sample.bin", md5)
    stored = {"sample.bin": _stored("sample.bin", "f" * 32), renamed: _stored(renamed, md5)}
    monkeypatch.setattr(headless, "index_read", lambda: ["sample.bin", renamed])
    monkeypatch.setattr(tools, "_stored_result", stored.__getitem__)
    monkeypatch.setattr(headless, "run_headless", pytest.fail)

    assert tools.analyze_binary(str(binary)).program == renamed


def test_a_disambiguated_name_holding_yet_another_binary_is_imported_over(
    tmp_path, project, monkeypatch
):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELF ours")
    renamed = tools.disambiguate_name("sample.bin", tools.file_md5(binary))
    stored = {"sample.bin": _stored("sample.bin", "f" * 32), renamed: _stored(renamed, "e" * 32)}
    monkeypatch.setattr(headless, "index_read", lambda: ["sample.bin", renamed])
    monkeypatch.setattr(tools, "_stored_result", stored.__getitem__)
    monkeypatch.setattr(
        headless, "run_headless",
        lambda args, timeout: _proc(f"INFO  /{renamed}: file created (u) (X)\n"),
    )
    monkeypatch.setattr(headless, "export", lambda *a, **k: {**INFO, "name": renamed})
    monkeypatch.setattr(headless, "index_add", lambda name: None)

    out = tools.analyze_binary(str(binary))

    assert out.program == renamed and out.already_analyzed is False


# ------------------------------------------------------- _stage_for_import


def test_staging_copies_when_a_hard_link_is_impossible(tmp_path, monkeypatch):
    """Across devices os.link fails; the import must still get the bytes."""
    src = tmp_path / "has'quote.bin"
    src.write_bytes(b"\x7fELF bytes")

    def cross_device(a, b):
        raise OSError(18, "Invalid cross-device link")

    monkeypatch.setattr(tools.os, "link", cross_device)
    stack: list = []

    staged = tools._stage_for_import(src, "has_quote.bin", False, stack)
    try:
        assert staged.name == "has_quote.bin"
        assert staged.read_bytes() == b"\x7fELF bytes"
        assert staged.stat().st_ino != src.stat().st_ino
    finally:
        import shutil

        for d in stack:
            shutil.rmtree(d)


# ---------------------------------------------------------- analyze_binaries


def test_a_batch_entry_that_fails_its_individual_import_is_a_failure(
    tmp_path, project, monkeypatch
):
    """A taken name is handed to analyze_binary; its failure must not sink the batch."""
    binary = tmp_path / "a.bin"
    binary.write_bytes(b"\x7fELF ours")
    monkeypatch.setattr(headless, "index_read", lambda: ["a.bin"])
    monkeypatch.setattr(
        tools, "_batch_info",
        lambda names: {"a.bin": ProgramInfo(**{**INFO, "name": "a.bin", "md5": "f" * 32})},
    )

    def fails(path, **kw):
        raise GhidraError("import failed")

    monkeypatch.setattr(tools, "analyze_binary", fails)

    out = tools.analyze_binaries(str(binary))

    assert out.results == []
    assert [(f.program, f.error, f.error_kind) for f in out.failures] == [
        (str(binary), "import failed", "ghidra_error")
    ]


def test_a_batch_import_passes_max_cpu(tmp_path, project, monkeypatch):
    binary = tmp_path / "a.bin"
    binary.write_bytes(b"\x7fELF")
    seen = []
    monkeypatch.setattr(headless, "index_read", lambda: [])
    monkeypatch.setattr(
        headless, "run_headless",
        lambda args, timeout: seen.append(args) or _proc("INFO  /a.bin: file created (u) (X)\n"),
    )
    monkeypatch.setattr(
        headless, "export_multi",
        lambda mode, programs, args=None, **kw: [
            {"program": p, "ok": True, "data": {**INFO, "name": p}} for p in programs
        ],
    )
    monkeypatch.setattr(headless, "index_add", lambda name: None)

    tools.analyze_binaries(str(binary), max_cpu=2)

    assert seen[0][-2:] == ["-max-cpu", "2"]


def test_describing_an_unreadable_file_never_raises(tmp_path):
    assert tools._describe_head(tmp_path / "gone.bin") == "unreadable"


# ------------------------------------------------------------- the launcher


@pytest.mark.parametrize("host, warns", [("127.0.0.1", False), ("0.0.0.0", True)])
def test_run_http_serves_the_guarded_app(monkeypatch, caplog, host, warns):
    import uvicorn

    key = "k" * 40
    served = {}
    monkeypatch.setattr(auth, "require_api_key", lambda: key)
    monkeypatch.setattr(
        uvicorn, "run", lambda app, **kw: served.update(app=app, **kw)
    )

    with caplog.at_level(logging.INFO, logger="ghidra_headless_mcp"):
        entry.run_http(host, 1351)

    assert isinstance(served["app"], auth.BearerAuthMiddleware)
    assert served["app"].key == key
    assert (served["host"], served["port"]) == (host, 1351)
    assert ("not loopback" in caplog.text) is warns


def test_running_the_file_starts_the_stdio_server(monkeypatch):
    from ghmcp.tools import mcp

    started = []
    monkeypatch.setattr(mcp, "run", lambda *a, **k: started.append(True))
    monkeypatch.setattr(sys, "argv", ["ghidra_headless_mcp.py"])

    runpy.run_path(entry.__file__, run_name="__main__")

    assert started == [True]


# ----------------------------------------------- resolve_symbol, no internal name


def test_a_program_without_an_internal_name_still_resolves_by_file_name(fake_headless):
    """Some formats record no internal name; the project file name must do."""
    from tests.test_multiprogram import WINDOWS, _link_envelope

    rows = {name: dict(data) for name, data in WINDOWS.items()}
    rows["KERNELBASE.DLL"]["internal_name"] = None
    fake_headless.envelope = _link_envelope(rows)

    out = tools.resolve_symbol("CreateFileW", list(rows))

    assert out.results[0].terminal_program == "KERNELBASE.DLL"


# ------------------------------------------------ openwebui_uploads_dir, shallow


def test_a_shallow_install_probes_only_the_container_path(monkeypatch):
    """A server checked out near / has no workspace three levels up to probe."""
    from pathlib import Path

    from ghmcp import config

    monkeypatch.delenv("OPENWEBUI_UPLOADS_DIR", raising=False)
    monkeypatch.setattr(config, "ROOT", Path("/srv"))

    assert config.openwebui_uploads_dir() == Path(
        "/workspaces/building-agentic-re/.openwebui-data/uploads"
    )
