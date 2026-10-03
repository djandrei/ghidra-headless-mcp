"""Unit tests for each tool, with the Ghidra layer stubbed."""

from pathlib import Path

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
        )  # noqa: E501
        # The stored program must prove it is this binary, so the stub reports
        # the file's own MD5.
        info = {**_INFO, "md5": tools.file_md5(binary)}
        monkeypatch.setattr(headless, "export", lambda *a, **k: info)

        out = tools.analyze_binary(str(binary))
        assert out.already_analyzed is True and out.duration_seconds == 0.0
        assert calls == []

    def test_force_re_analyses_even_when_indexed(self, tmp_path, project, monkeypatch):
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"\x7fELF")
        headless.index_add("sample.bin")

        seen = {}
        monkeypatch.setattr(
            headless, "run_headless",
            lambda args, timeout: seen.update(args=args) or _proc(
                stdout="INFO  /sample.bin: file created (u) (LocalFileSystem)\n"
            ),
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
            headless, "run_headless",
            lambda args, timeout: seen.update(args=args) or _proc(
                stdout="INFO  /s.bin: file created (u) (LocalFileSystem)\n"
            ),
        )
        monkeypatch.setattr(headless, "export", lambda *a, **k: _INFO)

        tools.analyze_binary(str(binary), **kwargs)
        args = seen["args"]
        idx = args.index(expected[0])
        assert args[idx : idx + 2] == expected

    def test_registers_the_program_in_the_index(self, tmp_path, project, monkeypatch):
        binary = tmp_path / "fresh.bin"
        binary.write_bytes(b"\x7fELF")
        monkeypatch.setattr(
            headless, "run_headless",
            lambda args, timeout: _proc(
                stdout="INFO  /fresh.bin: file created (u) (LocalFileSystem)\n"
            ),
        )
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


class TestScriptErrorDetection:
    """analyzeHeadless exits 0 even when the script threw, so the log decides."""

    def test_a_script_error_is_surfaced_despite_a_zero_exit_code(self, project, monkeypatch):
        log = (
            "INFO  SCRIPT: Some.java (HeadlessAnalyzer)\n"
            "ERROR REPORT SCRIPT ERROR:  (HeadlessAnalyzer) "
            "java.lang.IllegalArgumentException: Error processing variable 'Please Select'\n"
            "\tat Some.run(Some.java:39)\n"
        )
        monkeypatch.setattr(headless, "run_headless",
                            lambda args, timeout: _proc(stdout=log))
        out = tools.run_ghidra_script("p", "Some.java")
        assert out.exit_code == 0
        assert out.script_error is not None
        assert "IllegalArgumentException" in out.script_error

    def test_a_clean_run_reports_no_script_error(self, project, monkeypatch):
        monkeypatch.setattr(headless, "run_headless",
                            lambda args, timeout: _proc(stdout="INFO  all good\n"))
        assert tools.run_ghidra_script("p", "Some.java").script_error is None

    def test_the_first_error_line_is_reported(self, project, monkeypatch):
        log = "ERROR SCRIPT ERROR:  first problem\nERROR SCRIPT ERROR:  second problem\n"
        monkeypatch.setattr(headless, "run_headless",
                            lambda args, timeout: _proc(stdout=log))
        assert "first problem" in tools.run_ghidra_script("p", "S.java").script_error

    def test_an_empty_log_is_not_an_error(self, project, monkeypatch):
        monkeypatch.setattr(headless, "run_headless", lambda args, timeout: _proc(stdout=""))
        assert tools.run_ghidra_script("p", "S.java").script_error is None


class TestImportedProgramName:
    """Ghidra decides the program name, not the file name."""

    def test_reads_the_name_from_the_file_created_line(self):
        log = "INFO  /starter05.x86_64: file created (u) (LocalFileSystem)  \n"
        assert tools._imported_program_name(log, "wrong") == "starter05.x86_64"

    def test_falls_back_to_the_save_succeeded_line(self):
        log = "INFO  REPORT: Save succeeded for: /vidar.exe.dontrun (proj:/vidar) (X)\n"
        assert tools._imported_program_name(log, "wrong") == "vidar.exe.dontrun"

    def test_a_gzf_import_yields_the_packaged_program_not_the_archive(self):
        """The bug this exists to prevent: .gzf strips to its contents."""
        log = "INFO  /vidar.fed19121.exe.dontrun: file created (u) (LocalFileSystem)\n"
        assert tools._imported_program_name(log, "vidar.fed19121.exe.dontrun.gzf") == (
            "vidar.fed19121.exe.dontrun"
        )

    def test_handles_a_name_containing_spaces(self):
        log = "INFO  /my sample.exe: file created (u) (LocalFileSystem)\n"
        assert tools._imported_program_name(log, "x") == "my sample.exe"

    def test_falls_back_when_the_log_says_nothing(self):
        assert tools._imported_program_name("no useful lines here", "fallback.bin") == (
            "fallback.bin"
        )

    def test_empty_log_falls_back(self):
        assert tools._imported_program_name("", "fallback.bin") == "fallback.bin"

    def test_the_created_line_wins_over_a_later_save_line(self):
        log = ("INFO  /first.exe: file created (u) (LocalFileSystem)\n"
               "INFO  REPORT: Save succeeded for: /second.exe (p:/second.exe) (X)\n")
        assert tools._imported_program_name(log, "x") == "first.exe"

    def test_analyze_binary_indexes_the_name_ghidra_reported(
        self, tmp_path, project, monkeypatch
    ):
        binary = tmp_path / "sample.exe.gzf"
        binary.write_bytes(b"\x00")
        monkeypatch.setattr(
            headless, "run_headless",
            lambda args, timeout: _proc(
                stdout="INFO  /sample.exe: file created (u) (LocalFileSystem)\n"
            ),
        )
        monkeypatch.setattr(headless, "export", lambda *a, **k: _INFO)

        out = tools.analyze_binary(str(binary))
        assert out.program == "sample.exe"
        assert headless.index_read() == ["sample.exe"]


class TestResolveProgramName:
    """Three sources, because no single one is sufficient."""

    LOG_FRESH = "INFO  /vidar.exe.dontrun: file created (u) (LocalFileSystem)\n"

    def test_candidate_names_strips_one_container_suffix(self):
        assert tools.candidate_names("vidar.exe.dontrun.gzf") == [
            "vidar.exe.dontrun.gzf", "vidar.exe.dontrun"
        ]

    def test_candidate_names_of_a_plain_name(self):
        assert tools.candidate_names("sample.bin") == ["sample.bin", "sample"]

    def test_log_wins_for_a_fresh_import(self):
        assert tools.resolve_program_name(
            self.LOG_FRESH, "vidar.exe.dontrun.gzf", []
        ) == "vidar.exe.dontrun"

    def test_skipped_import_falls_back_to_the_project_listing(self):
        """The bug: import skipped, log silent, filename ends in .gzf."""
        assert tools.resolve_program_name(
            "", "vidar.exe.dontrun.gzf", ["vidar.exe.dontrun", "other.exe"]
        ) == "vidar.exe.dontrun"

    def test_exact_filename_match_is_preferred_over_the_stem(self):
        assert tools.resolve_program_name(
            "", "sample.bin", ["sample", "sample.bin"]
        ) == "sample.bin"

    def test_a_single_program_project_resolves_even_without_a_match(self):
        assert tools.resolve_program_name("", "weird.name", ["the-only-one"]) == (
            "the-only-one"
        )

    def test_ambiguous_project_falls_back_to_the_filename(self):
        assert tools.resolve_program_name("", "a.bin", ["x", "y"]) == "a.bin"

    def test_log_name_absent_from_the_project_is_not_trusted(self):
        assert tools.resolve_program_name(
            self.LOG_FRESH, "sample.bin", ["sample.bin"]
        ) == "sample.bin"

    def test_empty_everything_falls_back_to_the_filename(self):
        assert tools.resolve_program_name("", "a.bin", []) == "a.bin"


class TestAnalyzeBinaryNameReconciliation:
    def test_short_circuits_on_a_stem_match_in_the_index(self, tmp_path, project, monkeypatch):
        """A .gzf already analysed must not be re-imported under a new name."""
        binary = tmp_path / "vidar.exe.dontrun.gzf"
        binary.write_bytes(b"\x00")
        headless.index_add("vidar.exe.dontrun")

        monkeypatch.setattr(
            headless, "run_headless",
            lambda *a, **k: pytest.fail("must not re-import an existing program"),
        )
        info = {**_INFO, "md5": tools.file_md5(binary)}
        monkeypatch.setattr(headless, "export", lambda *a, **k: info)

        out = tools.analyze_binary(str(binary))
        assert out.program == "vidar.exe.dontrun"
        assert out.already_analyzed is True

    def test_a_skipped_import_still_resolves_via_the_project(
        self, tmp_path, project, monkeypatch
    ):
        binary = tmp_path / "vidar.exe.dontrun.gzf"
        binary.write_bytes(b"\x00")
        monkeypatch.setattr(headless, "run_headless", lambda args, timeout: _proc(stdout=""))
        monkeypatch.setattr(tools, "_project_programs", lambda: ["vidar.exe.dontrun"])
        monkeypatch.setattr(headless, "export", lambda *a, **k: _INFO)

        out = tools.analyze_binary(str(binary))
        assert out.program == "vidar.exe.dontrun"

    def test_the_common_path_does_not_pay_for_a_project_listing(
        self, tmp_path, project, monkeypatch
    ):
        binary = tmp_path / "fresh.bin"
        binary.write_bytes(b"\x00")
        monkeypatch.setattr(
            headless, "run_headless",
            lambda args, timeout: _proc(
                stdout="INFO  /fresh.bin: file created (u) (LocalFileSystem)\n"
            ),
        )
        monkeypatch.setattr(
            tools, "_project_programs",
            lambda: pytest.fail("must not list the project when the log answered"),
        )
        monkeypatch.setattr(headless, "export", lambda *a, **k: _INFO)

        assert tools.analyze_binary(str(binary)).program == "fresh.bin"


class TestStaleIndexRecovery:
    """A failed run must not leave a name behind that poisons later calls."""

    def test_a_stale_index_entry_is_repaired_from_the_project(
        self, tmp_path, project, monkeypatch
    ):
        binary = tmp_path / "vidar.exe.dontrun.gzf"
        binary.write_bytes(b"\x00")
        headless.index_add("vidar.exe.dontrun.gzf")  # the name a buggy run left

        def fake_export(program, mode, args=None, *, write=False, timeout=None):
            if program == "vidar.exe.dontrun.gzf":
                raise NotFound("Requested project program file(s) not found")
            return _INFO

        monkeypatch.setattr(headless, "export", fake_export)
        monkeypatch.setattr(tools, "_project_programs", lambda: ["vidar.exe.dontrun"])
        monkeypatch.setattr(
            headless, "run_headless",
            lambda *a, **k: pytest.fail("must not re-import; the program is present"),
        )

        out = tools.analyze_binary(str(binary))
        assert out.program == "vidar.exe.dontrun"
        assert out.already_analyzed is True
        assert headless.index_read() == ["vidar.exe.dontrun"]

    def test_a_name_is_indexed_only_after_it_is_proven_usable(
        self, tmp_path, project, monkeypatch
    ):
        binary = tmp_path / "bad.bin"
        binary.write_bytes(b"\x00")
        monkeypatch.setattr(
            headless, "run_headless",
            lambda args, timeout: _proc(
                stdout="INFO  /bad.bin: file created (u) (LocalFileSystem)\n"
            ),
        )

        def failing_export(*a, **k):
            raise NotFound("no such program")

        monkeypatch.setattr(headless, "export", failing_export)
        with pytest.raises(NotFound):
            tools.analyze_binary(str(binary))
        assert headless.index_read() == [], "a name that never worked must not be indexed"

    def test_an_unrecoverable_stale_entry_falls_through_to_a_real_import(
        self, tmp_path, project, monkeypatch
    ):
        binary = tmp_path / "gone.bin"
        binary.write_bytes(b"\x00")
        headless.index_add("gone.bin")
        calls = []

        def fake_export(program, mode, args=None, *, write=False, timeout=None):
            if not calls:
                raise NotFound("not in project")
            return _INFO

        monkeypatch.setattr(headless, "export", fake_export)
        monkeypatch.setattr(tools, "_project_programs", lambda: [])
        monkeypatch.setattr(
            headless, "run_headless",
            lambda args, timeout: calls.append(args) or _proc(
                stdout="INFO  /gone.bin: file created (u) (LocalFileSystem)\n"
            ),
        )

        out = tools.analyze_binary(str(binary))
        assert out.already_analyzed is False
        assert calls, "expected a real import after the index could not be repaired"


class TestGhidraInvalidFilenames:
    """Ghidra rejects some characters in a program name; filenames contain them.

    Found benchmarking the crackmes.one archive: "_xk's crackme.exe" failed
    with InvalidInputException, surfaced as an opaque HTTP 500.
    """

    @pytest.mark.parametrize(
        "name,expected",
        [
            ("_xk's crackme.exe", "_xk_s crackme.exe"),
            ('quote".exe', "quote_.exe"),
            ("a|b?c*.bin", "a_b_c_.bin"),
            ("plain name.exe", "plain name.exe"),
            ("normal.bin", "normal.bin"),
        ],
    )
    def test_sanitize(self, name, expected):
        assert tools.sanitize_program_name(name) == expected

    def test_spaces_are_kept(self):
        """Ghidra accepts spaces; mangling them would break every other lookup."""
        assert tools.sanitize_program_name("my sample.exe") == "my sample.exe"

    def test_an_apostrophe_filename_imports_under_a_safe_name(
        self, tmp_path, project, monkeypatch
    ):
        binary = tmp_path / "_xk's crackme.exe"
        binary.write_bytes(b"MZ")
        # a symlink would not do: Ghidra resolves it and reads the target name
        seen = {}
        monkeypatch.setattr(
            headless, "run_headless",
            lambda args, timeout: seen.update(args=args) or _proc(
                stdout="INFO  /_xk_s crackme.exe: file created (u) (LocalFileSystem)\n"
            ),
        )
        monkeypatch.setattr(headless, "export", lambda *a, **k: _INFO)

        out = tools.analyze_binary(str(binary))
        imported = seen["args"][seen["args"].index("-import") + 1]
        assert imported.endswith("_xk_s crackme.exe"), imported
        assert "'" not in imported
        assert out.program == "_xk_s crackme.exe"

    def test_a_clean_filename_is_imported_directly(self, tmp_path, project, monkeypatch):
        binary = tmp_path / "clean.bin"
        binary.write_bytes(b"\x7fELF")
        seen = {}
        monkeypatch.setattr(
            headless, "run_headless",
            lambda args, timeout: seen.update(args=args) or _proc(
                stdout="INFO  /clean.bin: file created (u) (LocalFileSystem)\n"
            ),
        )
        monkeypatch.setattr(headless, "export", lambda *a, **k: _INFO)
        tools.analyze_binary(str(binary))
        imported = seen["args"][seen["args"].index("-import") + 1]
        assert imported == str(binary), "a clean name must not be copied or linked"

    def test_the_staged_file_is_not_a_symlink(self, tmp_path, project, monkeypatch):
        """Ghidra resolves symlinks and takes the name from the target."""
        binary = tmp_path / "has'quote.exe"
        binary.write_bytes(b"MZ")
        seen = {}
        monkeypatch.setattr(
            headless, "run_headless",
            lambda args, timeout: seen.update(
                staged=Path(args[args.index("-import") + 1]),
                is_symlink=Path(args[args.index("-import") + 1]).is_symlink(),
                content=Path(args[args.index("-import") + 1]).read_bytes(),
            ) or _proc(stdout="INFO  /has_quote.exe: file created (u) (X)\n"),
        )
        monkeypatch.setattr(headless, "export", lambda *a, **k: _INFO)
        tools.analyze_binary(str(binary))
        assert seen["is_symlink"] is False
        assert seen["content"] == b"MZ", "the staged file must have the real bytes"
        assert seen["staged"].name == "has_quote.exe"

    def test_a_packed_program_in_a_read_only_directory_is_staged(
        self, tmp_path, project, monkeypatch
    ):
        """Ghidra locks a .gzf beside itself, which a read-only mount forbids."""
        ro = tmp_path / "ro"
        ro.mkdir()
        binary = ro / "sample.exe.gzf"
        binary.write_bytes(b"packed")
        ro.chmod(0o555)
        seen = {}
        monkeypatch.setattr(
            headless, "run_headless",
            lambda args, timeout: seen.update(
                imported=Path(args[args.index("-import") + 1]),
                content=Path(args[args.index("-import") + 1]).read_bytes(),
            ) or _proc(stdout="INFO  /sample.exe: file created (u) (X)\n"),
        )
        monkeypatch.setattr(headless, "export", lambda *a, **k: _INFO)
        try:
            tools.analyze_binary(str(binary))
        finally:
            ro.chmod(0o755)
        assert seen["imported"] != binary, "importing in place cannot take a lock"
        assert seen["imported"].name == binary.name, "the packed name must survive"
        assert seen["content"] == b"packed"

    def test_a_packed_program_in_a_writable_directory_is_imported_in_place(
        self, tmp_path, project, monkeypatch
    ):
        """Staging costs a copy, so only pay it where the lock would fail."""
        binary = tmp_path / "sample.exe.gzf"
        binary.write_bytes(b"packed")
        seen = {}
        monkeypatch.setattr(
            headless, "run_headless",
            lambda args, timeout: seen.update(
                imported=args[args.index("-import") + 1]
            ) or _proc(stdout="INFO  /sample.exe: file created (u) (X)\n"),
        )
        monkeypatch.setattr(headless, "export", lambda *a, **k: _INFO)
        tools.analyze_binary(str(binary))
        assert seen["imported"] == str(binary)

    def test_a_raw_binary_in_a_read_only_directory_is_imported_in_place(
        self, tmp_path, project, monkeypatch
    ):
        """Only packed programs take a lock; raw files load from bytes."""
        ro = tmp_path / "ro2"
        ro.mkdir()
        binary = ro / "clean.bin"
        binary.write_bytes(b"\x7fELF")
        ro.chmod(0o555)
        seen = {}
        monkeypatch.setattr(
            headless, "run_headless",
            lambda args, timeout: seen.update(
                imported=args[args.index("-import") + 1]
            ) or _proc(stdout="INFO  /clean.bin: file created (u) (X)\n"),
        )
        monkeypatch.setattr(headless, "export", lambda *a, **k: _INFO)
        try:
            tools.analyze_binary(str(binary))
        finally:
            ro.chmod(0o755)
        assert seen["imported"] == str(binary)

    def test_the_staging_directory_is_cleaned_up(self, tmp_path, project, monkeypatch):
        binary = tmp_path / "x'y.exe"
        binary.write_bytes(b"MZ")
        seen = {}
        monkeypatch.setattr(
            headless, "run_headless",
            lambda args, timeout: seen.update(d=Path(args[args.index("-import") + 1]).parent)
            or _proc(stdout="INFO  /x_y.exe: file created (u) (X)\n"),
        )
        monkeypatch.setattr(headless, "export", lambda *a, **k: _INFO)
        tools.analyze_binary(str(binary))
        assert not seen["d"].exists(), "staging dir must not be left behind"


class TestBasenameCollision:
    """Two unrelated binaries can share a basename; the project cannot.

    Found in a manual crackme run: two different `crackme` binaries collided in
    the index and the server silently served the first one for queries about
    the second.
    """

    def _setup(self, tmp_path, monkeypatch, first_bytes, second_bytes):
        a = tmp_path / "a" / "sample"
        b = tmp_path / "b" / "sample"
        for p, data in ((a, first_bytes), (b, second_bytes)):
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        return a, b

    def test_a_different_binary_of_the_same_name_is_not_served(
        self, tmp_path, project, monkeypatch
    ):
        a, b = self._setup(tmp_path, monkeypatch, b"\x7fELFAAAA", b"\x7fELFBBBB")
        headless.index_add("sample")
        stored_md5 = tools.file_md5(a)          # the project holds binary A
        imports = []

        def fake_export(program, mode, args=None, *, write=False, timeout=None):
            return {**_INFO, "name": program, "md5": stored_md5}

        monkeypatch.setattr(headless, "export", fake_export)
        monkeypatch.setattr(
            headless, "run_headless",
            lambda args, timeout: imports.append(args) or _proc(
                stdout="INFO  /sample_%s: file created (u) (X)\n" % tools.file_md5(b)[:8]
            ),
        )
        out = tools.analyze_binary(str(b))      # ask about binary B
        assert out.already_analyzed is False, "must not claim B was already done"
        assert imports, "B must actually be imported"
        assert out.program != "sample", "B must not take A's name"
        assert tools.file_md5(b)[:8] in out.program

    def test_the_same_binary_under_the_same_name_still_short_circuits(
        self, tmp_path, project, monkeypatch
    ):
        a, _ = self._setup(tmp_path, monkeypatch, b"\x7fELFAAAA", b"\x7fELFBBBB")
        headless.index_add("sample")
        info = {**_INFO, "md5": tools.file_md5(a)}
        monkeypatch.setattr(headless, "export", lambda *a, **k: info)
        monkeypatch.setattr(
            headless, "run_headless",
            lambda *a, **k: pytest.fail("identical binary must not be re-imported"),
        )
        out = tools.analyze_binary(str(a))
        assert out.already_analyzed is True and out.program == "sample"

    @pytest.mark.parametrize(
        "name,md5,expected",
        [
            ("crackme", "abcdef1234567890", "crackme_abcdef12"),
            ("crackme.exe", "abcdef1234567890", "crackme_abcdef12.exe"),
            ("a.b.c", "0123456789abcdef", "a_01234567.b.c"),
        ],
    )
    def test_disambiguated_names_keep_the_extension(self, name, md5, expected):
        assert tools.disambiguate_name(name, md5) == expected

    def test_file_md5_matches_hashlib(self, tmp_path):
        import hashlib

        f = tmp_path / "x.bin"
        f.write_bytes(b"some bytes here")
        assert tools.file_md5(f) == hashlib.md5(b"some bytes here").hexdigest()

    def test_a_missing_md5_in_the_project_forces_a_reimport(
        self, tmp_path, project, monkeypatch
    ):
        """Cannot prove identity without an MD5, so do not assume it matches."""
        a, _ = self._setup(tmp_path, monkeypatch, b"\x7fELFAAAA", b"\x7fELFBBBB")
        headless.index_add("sample")
        monkeypatch.setattr(headless, "export", lambda *a, **k: {**_INFO, "md5": None})
        imports = []
        monkeypatch.setattr(
            headless, "run_headless",
            lambda args, timeout: imports.append(args) or _proc(
                stdout="INFO  /sample_x: file created (u) (X)\n"),
        )
        tools.analyze_binary(str(a))
        assert imports, "an unverifiable name must not be trusted"


class TestImportFailureIsExplained:
    """analyzeHeadless exits 0 on a failed import, so the log has to be read.

    Found testing binary-samples: Alpha, IA-64 and S/390 binaries produced
    "Requested project program file(s) not found", which reads like a naming
    bug rather than an unsupported architecture.
    """

    def _run(self, tmp_path, project, monkeypatch, log):
        binary = tmp_path / "elf-Linux-Alpha-bash"
        binary.write_bytes(b"\x7fELF")
        monkeypatch.setattr(headless, "run_headless",
                            lambda args, timeout: _proc(stdout=log))
        monkeypatch.setattr(headless, "export", lambda *a, **k: _INFO)
        return tools.analyze_binary(str(binary))

    def test_no_load_spec_names_the_architecture_problem(
        self, tmp_path, project, monkeypatch
    ):
        log = ("INFO  IMPORTING: file:///x/elf-Linux-Alpha-bash (HeadlessAnalyzer)\n"
               "INFO  No load spec found for import file: elf-Linux-Alpha-bash (ProgramLoader)\n"
               "ERROR REPORT: Import failed for file: file:///x/elf-Linux-Alpha-bash\n")
        with pytest.raises(BadArgument) as exc:
            self._run(tmp_path, project, monkeypatch, log)
        msg = str(exc.value)
        assert "no loader" in msg and "processor" in msg

    def test_no_load_spec_shows_the_size_and_leading_bytes(
        self, tmp_path, project, monkeypatch
    ):
        """A 5-byte text stub got the "unsupported processor" story; the size and
        bytes make a non-executable obvious."""
        log = "INFO  No load spec found for import file: x (ProgramLoader)\n"
        with pytest.raises(BadArgument) as exc:
            self._run(tmp_path, project, monkeypatch, log)
        msg = str(exc.value)
        assert "4 bytes" in msg and "\\x7fELF" in msg
        assert "not an executable format" in msg

    def test_a_plain_import_failure_is_reported_as_a_ghidra_error(
        self, tmp_path, project, monkeypatch
    ):
        from ghmcp.errors import GhidraError

        log = "ERROR REPORT: Import failed for file: file:///x/elf-Linux-Alpha-bash\n"
        with pytest.raises(GhidraError, match="corrupt or"):
            self._run(tmp_path, project, monkeypatch, log)

    def test_a_successful_import_is_untouched(self, tmp_path, project, monkeypatch):
        log = "INFO  /elf-Linux-Alpha-bash: file created (u) (LocalFileSystem)\n"
        out = self._run(tmp_path, project, monkeypatch, log)
        assert out.program == "elf-Linux-Alpha-bash"

    def test_the_check_runs_before_the_name_is_resolved(
        self, tmp_path, project, monkeypatch
    ):
        """Otherwise the failure surfaces as a confusing name-resolution error."""
        log = "INFO  No load spec found for import file: x (ProgramLoader)\n"
        monkeypatch.setattr(
            tools, "_project_programs",
            lambda: pytest.fail("must fail before falling back to a project listing"),
        )
        with pytest.raises(BadArgument):
            self._run(tmp_path, project, monkeypatch, log)
