"""Analysis options: validation, the pre-script hand-off, reanalyze. No JVM.

run_headless is replaced by a fake that plays the pre-script's part: it reads
the spec the real code wrote and writes the result file the real code reads.
The Java half runs for real in test_integration_analysis_options.py.
"""

import json
import subprocess
from pathlib import Path

import pytest

from ghmcp import config, headless, tools
from ghmcp.errors import BadArgument, ExportFailure

INFO = {"name": "a.bin", "language_id": "x86:LE:64:default", "compiler_spec_id": "gcc",
        "image_base": "00400000", "function_count": 3, "symbol_count": 9}


@pytest.fixture
def prescript(monkeypatch, project):
    """Fake analyzeHeadless running the options pre-script; records each call."""

    class Fake:
        calls: list[list[str]] = []
        specs: list[dict] = []
        result: dict | None = None     # what the pre-script "writes"; None = nothing
        stdout = "INFO  /a.bin: file created (u) (X)\n"

        def __call__(self, args, timeout):
            self.calls.append(list(args))
            if "-preScript" in args:
                i = args.index("-preScript")
                spec, out = Path(args[i + 2]), Path(args[i + 3])
                self.specs.append(json.loads(spec.read_text()))
                if self.result is not None:
                    out.write_text(json.dumps(self.result))
            return subprocess.CompletedProcess(args, 0, self.stdout, "")

    fake = Fake()
    fake.calls, fake.specs = [], []
    monkeypatch.setattr(headless, "run_headless", fake)
    monkeypatch.setattr(headless, "export", lambda program, mode, *a, **k: dict(INFO))
    monkeypatch.setattr(headless, "index_add", lambda name: None)
    monkeypatch.setattr(config, "script_path", lambda: "/scripts")
    return fake


# ---------------------------------------------------------------- validation


@pytest.mark.parametrize("options", [{}, [], "x"])
def test_options_must_be_a_non_empty_object(options):
    with pytest.raises(BadArgument, match="non-empty object"):
        tools.validate_analyzer_options(options)


def test_names_must_be_strings():
    with pytest.raises(BadArgument, match="names must be strings"):
        tools.validate_analyzer_options({1: True})


@pytest.mark.parametrize("value", [None, [1], {"a": 1}])
def test_values_must_be_scalars(value):
    with pytest.raises(BadArgument, match="boolean, number or string"):
        tools.validate_analyzer_options({"X": value})


def test_none_means_no_options():
    assert tools.validate_analyzer_options(None) == {}


# ---------------------------------------------------------- analyze_binary


def test_options_ride_a_pre_script_into_the_import(prescript, tmp_path):
    binary = tmp_path / "a.bin"
    binary.write_bytes(b"\x7fELF")
    prescript.result = {"ok": True, "data": {"applied": {"X": True}}}
    monkey_index = []

    out = tools.analyze_binary(str(binary), analyzer_options={"X": True, "Y.Z": 3})

    call = prescript.calls[0]
    i = call.index("-preScript")
    assert call[i + 1] == "SetAnalysisOptions.java"
    assert call[call.index("-scriptPath") + 1] == "/scripts"
    assert prescript.specs == [{"mode": "import", "options": {"X": True, "Y.Z": 3}}]
    assert out.options_applied == {"X": True}
    # The spec and result files do not outlive the call.
    assert not Path(call[i + 2]).exists() and not monkey_index


def test_no_options_means_no_pre_script(prescript, tmp_path):
    binary = tmp_path / "a.bin"
    binary.write_bytes(b"\x7fELF")

    out = tools.analyze_binary(str(binary))

    assert "-preScript" not in prescript.calls[0]
    assert out.options_applied is None


def test_rejected_options_raise_the_pre_scripts_error(prescript, tmp_path):
    binary = tmp_path / "a.bin"
    binary.write_bytes(b"\x7fELF")
    prescript.result = {"ok": False, "error": {"kind": "bad_argument",
                                               "message": "unknown analysis option: Nope"}}
    prescript.stdout = "INFO  Processing aborted as a result of pre-script.\n"

    with pytest.raises(BadArgument, match="unknown analysis option: Nope"):
        tools.analyze_binary(str(binary), analyzer_options={"Nope": True})


def test_a_pre_script_that_never_ran_is_an_export_failure(prescript, tmp_path):
    binary = tmp_path / "a.bin"
    binary.write_bytes(b"\x7fELF")

    with pytest.raises(ExportFailure, match="did not run"):
        tools.analyze_binary(str(binary), analyzer_options={"X": True})


@pytest.mark.parametrize("path", ["stored", "disambiguated", "recovered"])
def test_options_for_an_analysed_binary_point_to_reanalyze(prescript, tmp_path, monkeypatch, path):
    """Every way analyze_binary can find the program already there refuses."""
    binary = tmp_path / "a.bin"
    binary.write_bytes(b"\x7fELF")
    md5 = tools.file_md5(binary)
    renamed = tools.disambiguate_name("a.bin", md5)

    def stored(name, digest):
        from ghmcp.models import AnalysisResult, ProgramInfo
        return AnalysisResult(program=name, already_analyzed=True, duration_seconds=0,
                              info=ProgramInfo(**{**INFO, "md5": digest}))

    # A refusal is not a stale index entry: nothing may be "repaired".
    monkeypatch.setattr(headless, "index_remove", lambda n: pytest.fail("index repaired"))
    if path == "stored":
        monkeypatch.setattr(headless, "index_read", lambda: ["a.bin"])
        monkeypatch.setattr(tools, "_stored_result", lambda n: stored(n, md5))
    elif path == "disambiguated":
        monkeypatch.setattr(headless, "index_read", lambda: ["a.bin", renamed])
        monkeypatch.setattr(tools, "_stored_result",
                            lambda n: stored(n, md5 if n == renamed else "f" * 32))
    else:
        from ghmcp.errors import NotFound

        def gone(n):
            if n == "a.bin" and not seen:
                seen.append(n)
                raise NotFound("stale")
            return stored(n, md5)

        seen: list = []
        monkeypatch.setattr(headless, "index_read", lambda: ["a.bin"])
        monkeypatch.setattr(headless, "index_remove", lambda n: None)  # genuinely stale
        monkeypatch.setattr(tools, "_project_programs", lambda: ["a.bin"])
        monkeypatch.setattr(tools, "_stored_result", gone)

    with pytest.raises(BadArgument, match="reanalyze"):
        tools.analyze_binary(str(binary), analyzer_options={"X": True})
    assert prescript.calls == []


# ---------------------------------------------------------------- reanalyze


def test_reanalyze_processes_the_program_writably_and_drops_the_cache(prescript, monkeypatch):
    cleared = []
    monkeypatch.setattr(headless, "clear_corpus", lambda p: cleared.append(p) or True)
    prescript.result = {"ok": True, "data": {"applied": {"X": False}}}

    out = tools.reanalyze("a.bin", {"X": False})

    call = prescript.calls[0]
    assert call[:2] == ["-process", "a.bin"]
    assert "-noanalysis" not in call and "-readOnly" not in call
    assert prescript.specs == [{"mode": "process", "options": {"X": False}}]
    assert out.options_applied == {"X": False} and out.info.function_count == 3
    assert cleared == ["a.bin"]


def test_reanalyze_without_options(prescript, monkeypatch):
    monkeypatch.setattr(headless, "clear_corpus", lambda p: True)

    out = tools.reanalyze("a.bin")

    assert prescript.calls == [["-process", "a.bin"]]
    assert out.options_applied is None


def test_reanalyze_refuses_bad_options_before_starting(prescript):
    with pytest.raises(BadArgument):
        tools.reanalyze("a.bin", {"X": None})
    assert prescript.calls == []


# ------------------------------------------------------ list_analysis_options


def test_list_analysis_options_filters_and_pages(fake_headless):
    rows = [{"name": f"A{i}", "type": "boolean", "value": True, "default": False,
             "is_default": False, "analyzer": True, "description": None} for i in range(3)]
    rows.append({"name": "A0.Mode", "type": "enum", "value": "fast", "default": "fast",
                 "is_default": True, "analyzer": False, "description": "speed",
                 "choices": ["fast", "thorough"]})
    fake_headless.envelope = {"ok": True, "mode": "analysis_options", "data": {"options": rows}}

    out = tools.list_analysis_options("p", pattern="A", analyzers_only=True, limit=2, offset=2)

    assert fake_headless.last_spec["args"] == {"pattern": "A", "analyzers_only": True}
    assert (out.total, out.returned) == (4, 2)
    assert out.options[-1].choices == ["fast", "thorough"]
    assert "-readOnly" in fake_headless.last
