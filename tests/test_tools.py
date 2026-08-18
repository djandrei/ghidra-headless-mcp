"""Unit tests for each tool, with the Ghidra layer stubbed."""

import pytest

from ghmcp import headless, tools
from ghmcp.errors import BadArgument, NotFound

FUNCS = {
    "matched": 4,
    "truncated": False,
    "functions": [
        {"name": "main", "address": "00401000", "size": 10, "signature": "int main(void)",
         "calling_convention": "cdecl", "is_thunk": False, "is_external": False},
        {"name": "check_key", "address": "00401146", "size": 20, "signature": "int check_key(char *)",
         "calling_convention": "cdecl", "is_thunk": False, "is_external": False},
        {"name": "printf", "address": "00401030", "size": 5, "signature": "int printf(char *)",
         "calling_convention": "cdecl", "is_thunk": True, "is_external": False},
        {"name": "malloc", "address": "00000000", "size": 0, "signature": "void * malloc(int)",
         "calling_convention": "cdecl", "is_thunk": False, "is_external": True},
    ]
}
STRINGS = {
    "matched": 3,
    "truncated": False,
    "strings": [
        {"address": "00402000", "length": 5, "value": "hello"},
        {"address": "00402010", "length": 8, "value": "KEY here"},
        {"address": "00402020", "length": 3, "value": "abc"},
    ]
}


class TestListFunctions:
    """Filtering is Ghidra's job since Stage 4; these assert what is asked of it."""

    def test_excludes_thunks_and_externals_by_default(self, captured_specs):
        captured_specs.stub["functions"] = FUNCS
        tools.list_functions("p")
        args = captured_specs.calls[0][2]
        assert args["include_thunks"] is False and args["include_external"] is False

    def test_include_thunks_is_forwarded(self, captured_specs):
        captured_specs.stub["functions"] = FUNCS
        tools.list_functions("p", include_thunks=True)
        assert captured_specs.calls[0][2]["include_thunks"] is True

    def test_include_external_is_forwarded(self, captured_specs):
        captured_specs.stub["functions"] = FUNCS
        tools.list_functions("p", include_external=True)
        assert captured_specs.calls[0][2]["include_external"] is True

    def test_name_filter_is_forwarded_as_an_escaped_pattern(self, captured_specs):
        import re

        captured_specs.stub["functions"] = FUNCS
        tools.list_functions("p", name_contains="CHECK")
        assert captured_specs.calls[0][2]["pattern"] == re.escape("CHECK")

    def test_total_comes_from_ghidra_not_the_returned_page(self, captured_specs):
        captured_specs.stub["functions"] = FUNCS
        out = tools.list_functions("p", limit=1)
        assert out.total == 4 and out.returned == 1 and len(out.functions) == 1

    def test_offset_pages_through(self, captured_specs):
        captured_specs.stub["functions"] = FUNCS
        assert tools.list_functions("p", limit=1, offset=1).functions[0].name == "check_key"

    def test_rows_are_not_re_filtered_in_python(self, captured_specs):
        """Java already applied the filter; re-applying it would drop valid rows."""
        captured_specs.stub["functions"] = FUNCS
        out = tools.list_functions("p", name_contains="key", limit=10)
        assert out.returned == 4

    def test_calls_the_functions_mode_read_only(self, captured_specs):
        captured_specs.stub["functions"] = FUNCS
        tools.list_functions("p")
        program, mode, args, write = captured_specs.calls[0]
        assert (program, mode, write) == ("p", "functions", False)


class TestListStrings:
    def test_passes_min_length_and_pattern_to_ghidra(self, captured_specs):
        captured_specs.stub["strings"] = STRINGS
        tools.list_strings("p", min_length=7)
        assert captured_specs.calls[0][2] == {"min_length": 7, "pattern": None}

    def test_contains_filter_is_forwarded_as_an_escaped_pattern(self, captured_specs):
        import re

        captured_specs.stub["strings"] = STRINGS
        tools.list_strings("p", contains="key")
        assert captured_specs.calls[0][2]["pattern"] == re.escape("key")

    def test_paging(self, captured_specs):
        captured_specs.stub["strings"] = STRINGS
        out = tools.list_strings("p", limit=2, offset=1)
        assert out.total == 3 and out.returned == 2
        assert [s.value for s in out.strings] == ["KEY here", "abc"]

    def test_no_matches_returns_empty_not_error(self, captured_specs):
        captured_specs.stub["strings"] = {"matched": 0, "truncated": False, "strings": []}
        out = tools.list_strings("p", pattern="nothing-matches")
        assert out.total == 0 and out.strings == []


class TestDecompileFunction:
    def test_returns_the_c_text(self, captured_specs):
        captured_specs.stub["decompile"] = {
            "name": "check_key", "address": "00401146",
            "signature": "int check_key(char *)", "c": "int check_key(char *p){}",
        }
        out = tools.decompile_function("p", "check_key")
        assert out.name == "check_key" and "check_key" in out.c
        assert out.program == "p"

    def test_passes_the_target_through(self, captured_specs):
        captured_specs.stub["decompile"] = {
            "name": "f", "address": "0", "signature": "s", "c": "x"
        }
        tools.decompile_function("p", "00401146")
        assert captured_specs.calls[0][2] == {"target": "00401146"}

    def test_not_found_propagates_as_a_typed_error(self, captured_specs):
        captured_specs.stub["decompile"] = NotFound("function not found: nope")
        with pytest.raises(NotFound):
            tools.decompile_function("p", "nope")


class TestAnalyzeBinary:
    def test_rejects_a_missing_file_before_starting_a_jvm(self, project):
        with pytest.raises(NotFound, match="binary not found"):
            tools.analyze_binary("/nonexistent/path/to/binary")

    def test_short_circuits_when_already_analysed(self, tmp_path, project, monkeypatch):
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"\x7fELF")
        headless.index_add("sample.bin")

        calls = []
        monkeypatch.setattr(
            headless, "run_headless",
            lambda *a, **k: calls.append(a) or pytest.fail("must not re-analyse"),
        )
        monkeypatch.setattr(headless, "export", lambda *a, **k: _INFO)

        out = tools.analyze_binary(str(binary))
        assert out.already_analyzed is True and out.duration_seconds == 0.0
        assert calls == []

    def test_force_re_analyses_even_when_indexed(self, tmp_path, project, monkeypatch):
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"\x7fELF")
        headless.index_add("sample.bin")

        seen = {}
        monkeypatch.setattr(
            headless, "run_headless", lambda args, timeout: seen.update(args=args)
        )
        monkeypatch.setattr(headless, "export", lambda *a, **k: _INFO)

        out = tools.analyze_binary(str(binary), force=True)
        assert out.already_analyzed is False
        assert "-overwrite" in seen["args"]

    @pytest.mark.parametrize(
        "kwargs,expected",
        [
            ({"processor": "x86:LE:64:default"}, ["-processor", "x86:LE:64:default"]),
            ({"cspec": "gcc"}, ["-cspec", "gcc"]),
            ({"max_cpu": 4}, ["-max-cpu", "4"]),
        ],
    )
    def test_optional_flags_reach_the_command_line(
        self, tmp_path, project, monkeypatch, kwargs, expected
    ):
        binary = tmp_path / "s.bin"
        binary.write_bytes(b"\x7fELF")
        seen = {}
        monkeypatch.setattr(
            headless, "run_headless", lambda args, timeout: seen.update(args=args)
        )
        monkeypatch.setattr(headless, "export", lambda *a, **k: _INFO)

        tools.analyze_binary(str(binary), **kwargs)
        args = seen["args"]
        idx = args.index(expected[0])
        assert args[idx : idx + 2] == expected

    def test_registers_the_program_in_the_index(self, tmp_path, project, monkeypatch):
        binary = tmp_path / "fresh.bin"
        binary.write_bytes(b"\x7fELF")
        monkeypatch.setattr(headless, "run_headless", lambda args, timeout: None)
        monkeypatch.setattr(headless, "export", lambda *a, **k: _INFO)

        tools.analyze_binary(str(binary))
        assert "fresh.bin" in headless.index_read()


class TestListPrograms:
    def test_reports_the_index_and_project_identity(self, project):
        headless.index_add("a.bin")
        out = tools.list_programs()
        assert out.programs == ["a.bin"]
        assert out.project == "test-proj"
        assert out.project_location == str(project)

    def test_empty_project(self, project):
        assert tools.list_programs().programs == []


class TestRunGhidraScript:
    def test_read_only_by_default(self, project, monkeypatch):
        seen = {}
        monkeypatch.setattr(
            headless, "run_headless",
            lambda args, timeout: seen.update(args=args) or _proc(),
        )
        tools.run_ghidra_script("p", "Some.java")
        assert "-readOnly" in seen["args"]

    def test_read_only_false_allows_persistence(self, project, monkeypatch):
        seen = {}
        monkeypatch.setattr(
            headless, "run_headless",
            lambda args, timeout: seen.update(args=args) or _proc(),
        )
        tools.run_ghidra_script("p", "Some.java", read_only=False)
        assert "-readOnly" not in seen["args"]

    @pytest.mark.parametrize("stage,flag", [("post", "-postScript"), ("pre", "-preScript")])
    def test_stage_selects_the_flag(self, project, monkeypatch, stage, flag):
        seen = {}
        monkeypatch.setattr(
            headless, "run_headless",
            lambda args, timeout: seen.update(args=args) or _proc(),
        )
        tools.run_ghidra_script("p", "Some.java", stage=stage)
        assert flag in seen["args"]

    def test_rejects_an_unknown_stage(self, project):
        with pytest.raises(BadArgument, match="stage"):
            tools.run_ghidra_script("p", "Some.java", stage="middle")

    def test_script_args_are_appended_after_the_script_name(self, project, monkeypatch):
        seen = {}
        monkeypatch.setattr(
            headless, "run_headless",
            lambda args, timeout: seen.update(args=args) or _proc(),
        )
        tools.run_ghidra_script("p", "S.java", script_args=["a", "b"])
        args = seen["args"]
        assert args[args.index("S.java") + 1 : args.index("S.java") + 3] == ["a", "b"]

    def test_log_tail_is_capped(self, project, monkeypatch):
        monkeypatch.setattr(
            headless, "run_headless",
            lambda args, timeout: _proc(stdout="\n".join(str(i) for i in range(1000))),
        )
        out = tools.run_ghidra_script("p", "S.java")
        assert len(out.stdout_tail.splitlines()) == 200


def _proc(stdout="", returncode=0):
    class P:
        pass

    p = P()
    p.returncode = returncode
    p.stdout = stdout
    p.stderr = ""
    return p


_INFO = {
    "name": "sample.bin",
    "language_id": "x86:LE:64:default",
    "compiler_spec_id": "gcc",
    "image_base": "00400000",
    "function_count": 1,
    "symbol_count": 1,
    "memory_blocks": [],
}
