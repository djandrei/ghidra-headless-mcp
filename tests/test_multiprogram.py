"""Project-scope fan-out: program-list normalisation and cross-program search.

No JVM anywhere in here. Stage 1's fan-out reads the decompilation cache, so
these tests stub `load_corpus` rather than `run_headless` — the search path
below it is the same code single-program search already exercises.
"""

import shutil

import pytest

from ghmcp import config, headless, tools
from ghmcp.errors import BadArgument, ExportFailure, GhidraError, NotFound

# ------------------------------------------------------- _normalise_programs


def test_a_single_name_becomes_a_one_element_list():
    assert tools._normalise_programs("a.exe") == ["a.exe"]


def test_a_list_is_preserved_in_order():
    assert tools._normalise_programs(["b", "a", "c"]) == ["b", "a", "c"]


def test_duplicates_are_dropped_but_order_survives():
    assert tools._normalise_programs(["b", "a", "b", "c", "a"]) == ["b", "a", "c"]


def test_empty_names_are_discarded():
    assert tools._normalise_programs(["a", "", "b"]) == ["a", "b"]


def test_an_empty_list_is_rejected():
    with pytest.raises(BadArgument, match="at least one program"):
        tools._normalise_programs([])


def test_only_empty_strings_is_rejected():
    with pytest.raises(BadArgument, match="at least one program"):
        tools._normalise_programs(["", ""])


@pytest.mark.parametrize("value", [None, "*"])
def test_the_wildcard_resolves_from_the_index(project, value):
    headless.index_add("one.exe")
    headless.index_add("two.exe")
    assert tools._normalise_programs(value) == ["one.exe", "two.exe"]


@pytest.mark.parametrize("value", [None, "*"])
def test_the_wildcard_on_an_empty_project_explains_itself(project, value):
    with pytest.raises(BadArgument, match="analyze_binary"):
        tools._normalise_programs(value)


def test_an_unknown_name_is_passed_through(project):
    """Not validated here on purpose: the real Ghidra error names the program
    and is a better message than anything this layer could invent."""
    assert tools._normalise_programs("never-imported") == ["never-imported"]


def test_the_wildcard_does_not_query_ghidra(project, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("resolving '*' must not start a JVM")

    monkeypatch.setattr(headless, "export_project", boom)
    headless.index_add("one.exe")
    assert tools._normalise_programs("*") == ["one.exe"]


# --------------------------------------------------------------- fan-out


def _corpus(*names):
    """A decompiled corpus whose function bodies contain their own names."""
    return [
        {
            "name": n,
            "address": f"0040{i:04x}",
            "signature": f"void {n}(void)",
            "c": f"void {n}(void) {{ CreateFileW(); }}",
        }
        for i, n in enumerate(names)
    ]


@pytest.fixture
def corpora(monkeypatch, project):
    """Map program name -> corpus, or an exception to raise for that program."""
    table: dict[str, object] = {}

    def fake_load_corpus(program, refresh=False):
        value = table[program]
        if isinstance(value, Exception):
            raise value
        return value, not refresh

    monkeypatch.setattr(headless, "load_corpus", fake_load_corpus)
    return table


def test_a_fan_out_returns_one_result_per_program(corpora):
    corpora["a.exe"] = _corpus("alpha")
    corpora["b.exe"] = _corpus("beta", "gamma")

    out = tools.search_code_project("CreateFileW", ["a.exe", "b.exe"])

    assert [r.program for r in out.results] == ["a.exe", "b.exe"]
    assert out.programs_searched == 2
    assert out.failures == []


def test_each_result_names_its_own_program(corpora):
    corpora["a.exe"] = _corpus("alpha")
    corpora["b.exe"] = _corpus("beta")

    out = tools.search_code_project("CreateFileW", ["a.exe", "b.exe"])

    assert out.results[0].matches[0].function == "alpha"
    assert out.results[1].matches[0].function == "beta"


def test_total_matches_sums_across_programs(corpora):
    corpora["a.exe"] = _corpus("alpha")
    corpora["b.exe"] = _corpus("beta", "gamma")

    out = tools.search_code_project("CreateFileW", ["a.exe", "b.exe"])

    assert out.total_matches == 3 == sum(r.returned for r in out.results)


def test_a_program_that_cannot_be_read_becomes_a_failure(corpora):
    corpora["a.exe"] = _corpus("alpha")
    corpora["gone.exe"] = NotFound("no program named gone.exe")

    out = tools.search_code_project("CreateFileW", ["a.exe", "gone.exe"])

    assert [r.program for r in out.results] == ["a.exe"]
    assert len(out.failures) == 1
    assert out.failures[0].program == "gone.exe"
    assert out.failures[0].error_kind == "not_found"


def test_one_failure_does_not_discard_the_others(corpora):
    """The isolation property: a bad program in the middle costs only itself."""
    corpora["a.exe"] = _corpus("alpha")
    corpora["bad.exe"] = GhidraError("decompiler blew up")
    corpora["c.exe"] = _corpus("gamma")

    out = tools.search_code_project("CreateFileW", ["a.exe", "bad.exe", "c.exe"])

    assert [r.program for r in out.results] == ["a.exe", "c.exe"]
    assert [f.program for f in out.failures] == ["bad.exe"]
    assert out.programs_searched == 2


def test_every_program_failing_is_reported_not_raised(corpora):
    corpora["a.exe"] = NotFound("gone")
    corpora["b.exe"] = NotFound("gone")

    out = tools.search_code_project("CreateFileW", ["a.exe", "b.exe"])

    assert out.results == []
    assert out.programs_searched == 0
    assert len(out.failures) == 2


def test_the_wildcard_searches_every_indexed_program(corpora):
    headless.index_add("a.exe")
    headless.index_add("b.exe")
    corpora["a.exe"] = _corpus("alpha")
    corpora["b.exe"] = _corpus("beta")

    out = tools.search_code_project("CreateFileW")

    assert {r.program for r in out.results} == {"a.exe", "b.exe"}


def test_a_bad_regex_fails_the_whole_call_once(corpora):
    """A malformed pattern is the caller's error and identical for every
    program — reporting it N times as per-program failures would be noise."""
    corpora["a.exe"] = _corpus("alpha")
    corpora["b.exe"] = _corpus("beta")

    with pytest.raises(BadArgument, match="invalid regex"):
        tools.search_code_project("(unclosed", ["a.exe", "b.exe"])


def test_an_empty_query_is_rejected_before_any_program_is_touched(corpora):
    def boom(*a, **k):
        raise AssertionError("validation must precede any corpus load")

    corpora["a.exe"] = _corpus("alpha")
    with pytest.raises(BadArgument, match="must not be empty"):
        tools.search_code_project("", ["a.exe"])


def test_an_unknown_mode_is_rejected(corpora):
    with pytest.raises(BadArgument, match="literal.*semantic"):
        tools.search_code_project("x", ["a.exe"], mode="fuzzy")


def test_semantic_mode_reports_the_tfidf_backend(corpora):
    corpora["a.exe"] = _corpus("decrypt_config")

    out = tools.search_code_project("decrypt configuration", ["a.exe"], mode="semantic")

    assert out.backend == "tfidf" and out.mode == "semantic"


def test_literal_mode_reports_the_regex_backend(corpora):
    corpora["a.exe"] = _corpus("alpha")

    assert tools.search_code_project("CreateFileW", ["a.exe"]).backend == "regex"


def test_limit_applies_per_program_not_across_the_batch(corpora):
    corpora["a.exe"] = _corpus("a1", "a2", "a3")
    corpora["b.exe"] = _corpus("b1", "b2", "b3")

    out = tools.search_code_project("CreateFileW", ["a.exe", "b.exe"], limit=2)

    assert [r.returned for r in out.results] == [2, 2]
    assert out.total_matches == 4


def test_refresh_is_passed_through_to_every_program(corpora, monkeypatch):
    seen: list[tuple[str, bool]] = []

    def recording(program, refresh=False):
        seen.append((program, refresh))
        return _corpus("alpha"), False

    monkeypatch.setattr(headless, "load_corpus", recording)
    tools.search_code_project("CreateFileW", ["a.exe", "b.exe"], refresh=True)

    assert seen == [("a.exe", True), ("b.exe", True)]


def test_from_cache_is_reported_per_program(corpora, monkeypatch):
    def mixed(program, refresh=False):
        return _corpus("alpha"), program == "cached.exe"

    monkeypatch.setattr(headless, "load_corpus", mixed)
    out = tools.search_code_project("CreateFileW", ["cached.exe", "cold.exe"])

    assert [r.from_cache for r in out.results] == [True, False]


def test_a_duplicate_program_is_searched_once(corpora):
    corpora["a.exe"] = _corpus("alpha")

    out = tools.search_code_project("CreateFileW", ["a.exe", "a.exe"])

    assert out.programs_searched == 1


def test_single_program_output_matches_search_code(corpora):
    """The fan-out must not reshape what a single program returns."""
    corpora["a.exe"] = _corpus("alpha", "beta")

    single = tools.search_code("a.exe", "CreateFileW")
    fanned = tools.search_code_project("CreateFileW", "a.exe")

    assert fanned.results[0].model_dump() == single.model_dump()


def test_the_fan_out_never_starts_a_jvm(corpora, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("Stage 1 must read the cache, never analyzeHeadless")

    monkeypatch.setattr(headless, "run_headless", boom)
    corpora["a.exe"] = _corpus("alpha")

    assert tools.search_code_project("CreateFileW", ["a.exe"]).programs_searched == 1


# --------------------------------------------------------- export_multi

MULTI_OK = {
    "ok": True,
    "mode": "info",
    "data": {
        "multi": True,
        "count": 2,
        "results": [
            {"program": "a.exe", "ok": True, "data": {"name": "a.exe"}},
            {"program": "b.exe", "ok": True, "data": {"name": "b.exe"}},
        ],
    },
}


def test_export_multi_returns_one_row_per_program(fake_headless):
    fake_headless.envelope = MULTI_OK
    rows = headless.export_multi("info", ["a.exe", "b.exe"])
    assert [r["program"] for r in rows] == ["a.exe", "b.exe"]


def test_the_programs_list_travels_at_the_top_of_the_spec(fake_headless):
    """Modes read `args`; the dispatcher reads `programs`. Nesting the list
    inside args would hand every mode a key it must learn to ignore."""
    fake_headless.envelope = MULTI_OK
    headless.export_multi("symbols", ["a.exe", "b.exe"], {"kind": "export"})

    spec = fake_headless.last_spec
    assert spec["programs"] == ["a.exe", "b.exe"]
    assert spec["args"] == {"kind": "export"}
    assert "programs" not in spec["args"]


def test_the_run_attaches_to_the_first_program_only(fake_headless):
    """-process with no name would attach to every file in turn and overwrite
    the output once per program. The pivot is what stops that."""
    fake_headless.envelope = MULTI_OK
    headless.export_multi("info", ["a.exe", "b.exe", "c.exe"])

    call = fake_headless.last
    assert call[:2] == ["-process", "a.exe"]
    assert call.count("-process") == 1


def test_the_command_shape_is_stable(fake_headless):
    fake_headless.envelope = MULTI_OK
    headless.export_multi("info", ["a.exe", "b.exe"])

    assert fake_headless.shape(fake_headless.last) == [
        "-process", "a.exe", "-noanalysis", "-readOnly",
        "-scriptPath", config.script_path(),
        "-postScript", "HeadlessJsonExport.java", "<spec>", "<out>",
    ]


def test_a_fan_out_is_always_read_only(fake_headless):
    """A headless run saves only the attached program, so a cross-program write
    would silently drop the others' changes."""
    fake_headless.envelope = MULTI_OK
    headless.export_multi("edit", ["a.exe", "b.exe"])
    assert "-readOnly" in fake_headless.last


def test_export_multi_starts_one_jvm_for_many_programs(fake_headless):
    """The feature, asserted directly: N programs, one analyzeHeadless."""
    fake_headless.envelope = MULTI_OK
    headless.export_multi("info", ["a.exe", "b.exe"])
    assert len(fake_headless.calls) == 1


def test_a_per_program_error_row_is_returned_not_raised(fake_headless):
    fake_headless.envelope = {
        "ok": True,
        "mode": "info",
        "data": {
            "multi": True,
            "count": 2,
            "results": [
                {"program": "a.exe", "ok": True, "data": {"name": "a.exe"}},
                {
                    "program": "gone.exe",
                    "ok": False,
                    "error": {"kind": "not_found", "message": "no program named gone.exe"},
                },
            ],
        },
    }
    rows = headless.export_multi("info", ["a.exe", "gone.exe"])

    assert rows[0]["ok"] is True
    assert rows[1]["ok"] is False
    assert rows[1]["error"]["kind"] == "not_found"


def test_an_envelope_level_failure_still_raises(fake_headless):
    """A whole-run failure is not a per-program failure and must not be
    mistaken for an empty batch."""
    fake_headless.envelope = {
        "ok": False,
        "mode": "info",
        "error": {"kind": "bad_argument", "message": "unknown mode: nope"},
    }
    with pytest.raises(BadArgument, match="unknown mode"):
        headless.export_multi("nope", ["a.exe"])


def test_an_empty_program_list_raises_before_any_jvm(fake_headless):
    with pytest.raises(BadArgument, match="at least one program"):
        headless.export_multi("info", [])
    assert fake_headless.calls == []


def test_a_single_program_envelope_is_rejected(fake_headless):
    """Guards against an old export script that ignores the programs key and
    returns a plain single-program payload."""
    fake_headless.envelope = {"ok": True, "mode": "info", "data": {"name": "a.exe"}}
    with pytest.raises(ExportFailure, match="multi-program envelope"):
        headless.export_multi("info", ["a.exe"])


def test_no_output_file_explains_itself(fake_headless):
    fake_headless.write_output = False
    with pytest.raises(ExportFailure, match="analyze_binary"):
        headless.export_multi("info", ["a.exe"])


def test_the_program_list_is_copied_into_the_spec(fake_headless):
    """The caller's list must not be able to mutate under the spec."""
    fake_headless.envelope = MULTI_OK
    names = ["a.exe", "b.exe"]
    headless.export_multi("info", names)
    names.append("c.exe")
    assert fake_headless.last_spec["programs"] == ["a.exe", "b.exe"]


def test_export_still_sends_no_programs_key(fake_headless):
    """The single-program path must stay byte-identical."""
    fake_headless.envelope = {"ok": True, "mode": "info", "data": {}}
    headless.export("a.exe", "info")
    assert "programs" not in fake_headless.last_spec


# ------------------------------------------------- list_symbols_project

def _symbols_envelope(rows: dict, kind: str = "import"):
    """rows: program -> list of symbol names, or an error dict."""
    results = []
    for program, value in rows.items():
        if isinstance(value, dict) and "kind" in value:
            results.append({"program": program, "ok": False, "error": value})
            continue
        results.append({
            "program": program,
            "ok": True,
            "data": {
                "kind": kind,
                "matched": len(value),
                "truncated": False,
                "symbols": [
                    {"name": n, "address": f"0040{i:04x}", "kind": kind,
                     "namespace": "SOME.DLL"}
                    for i, n in enumerate(value)
                ],
            },
        })
    return {"ok": True, "mode": "symbols",
            "data": {"multi": True, "count": len(results), "results": results}}


def test_symbols_project_returns_one_result_per_program(fake_headless):
    fake_headless.envelope = _symbols_envelope({"a.exe": ["CreateFileW"], "b.exe": ["ReadFile"]})
    out = tools.list_symbols_project(programs=["a.exe", "b.exe"])

    assert [r.program for r in out.results] == ["a.exe", "b.exe"]
    assert out.programs_searched == 2
    assert out.total == 2


def test_symbols_project_uses_one_jvm_start(fake_headless):
    fake_headless.envelope = _symbols_envelope({"a.exe": ["x"], "b.exe": ["y"], "c.exe": ["z"]})
    tools.list_symbols_project(programs=["a.exe", "b.exe", "c.exe"])
    assert len(fake_headless.calls) == 1


def test_symbols_project_isolates_one_bad_program(fake_headless):
    fake_headless.envelope = _symbols_envelope({
        "a.exe": ["CreateFileW"],
        "gone.exe": {"kind": "not_found", "message": "no program named gone.exe"},
        "c.exe": ["ReadFile"],
    })
    out = tools.list_symbols_project(programs=["a.exe", "gone.exe", "c.exe"])

    assert [r.program for r in out.results] == ["a.exe", "c.exe"]
    assert [f.program for f in out.failures] == ["gone.exe"]
    assert out.failures[0].error_kind == "not_found"


def test_symbols_project_limit_is_per_program(fake_headless):
    fake_headless.envelope = _symbols_envelope({
        "a.exe": ["a1", "a2", "a3"], "b.exe": ["b1", "b2", "b3"],
    })
    out = tools.list_symbols_project(programs=["a.exe", "b.exe"], limit=2)

    assert [r.returned for r in out.results] == [2, 2]
    assert out.total == 6  # `total` counts matches, not the returned window


def test_symbols_project_rejects_an_unknown_kind(fake_headless):
    with pytest.raises(BadArgument, match="kind must be one of"):
        tools.list_symbols_project(kind="widget", programs=["a.exe"])
    assert fake_headless.calls == []


def test_symbols_project_passes_the_pattern_through(fake_headless):
    fake_headless.envelope = _symbols_envelope({"a.exe": ["CreateFileW"]})
    tools.list_symbols_project(pattern="^Create", programs=["a.exe"])
    assert fake_headless.last_spec["args"]["pattern"] == "^Create"


def test_symbols_project_defaults_to_every_indexed_program(fake_headless, project):
    headless.index_add("a.exe")
    headless.index_add("b.exe")
    fake_headless.envelope = _symbols_envelope({"a.exe": ["x"], "b.exe": ["y"]})
    tools.list_symbols_project()
    assert fake_headless.last_spec["programs"] == ["a.exe", "b.exe"]


# --------------------------------------------------------- xref fan-out

def _xref_envelope(rows: dict, direction: str = "to"):
    results = []
    for program, targets in rows.items():
        results.append({
            "program": program,
            "ok": True,
            "data": {
                "direction": direction,
                "results": [
                    {"target": t, "resolved_address": "00401000", "resolved_kind": "function",
                     "xrefs": [{"from_address": "00401100", "to_address": "00401000",
                                "ref_type": "UNCONDITIONAL_CALL"}]}
                    for t in targets
                ],
            },
        })
    return {"ok": True, "mode": "xrefs",
            "data": {"multi": True, "count": len(results), "results": results}}


SINGLE_XREF = {
    "ok": True,
    "mode": "xrefs",
    "data": {
        "direction": "to",
        "results": [
            {"target": "main", "resolved_address": "00401000", "resolved_kind": "function",
             "xrefs": [{"from_address": "00401100", "to_address": "00401000",
                        "ref_type": "UNCONDITIONAL_CALL"}]}
        ],
    },
}


def test_a_single_program_xref_call_is_unchanged(fake_headless):
    """The widened signature must not reshape what one program returns."""
    fake_headless.envelope = SINGLE_XREF
    out = tools.list_xrefs_to("a.exe", "main")

    assert out.program == "a.exe"
    assert out.results[0].program is None      # field absent for single-program
    assert out.failures == []
    assert "programs" not in fake_headless.last_spec


def test_several_programs_tag_each_xref_row(fake_headless):
    fake_headless.envelope = _xref_envelope({"a.exe": ["main"], "b.exe": ["main"]})
    out = tools.list_xrefs_to(["a.exe", "b.exe"], "main")

    assert out.program == "*"
    assert [r.program for r in out.results] == ["a.exe", "b.exe"]


def test_xref_fan_out_uses_one_jvm_start(fake_headless):
    fake_headless.envelope = _xref_envelope({"a.exe": ["main"], "b.exe": ["main"]})
    tools.list_xrefs_to(["a.exe", "b.exe"], "main")
    assert len(fake_headless.calls) == 1


def test_xref_fan_out_isolates_a_failing_program(fake_headless):
    env = _xref_envelope({"a.exe": ["main"]})
    env["data"]["results"].append(
        {"program": "gone.exe", "ok": False,
         "error": {"kind": "not_found", "message": "missing"}}
    )
    fake_headless.envelope = env
    out = tools.list_xrefs_to(["a.exe", "gone.exe"], "main")

    assert [r.program for r in out.results] == ["a.exe"]
    assert [f.program for f in out.failures] == ["gone.exe"]


def test_the_xref_wildcard_covers_the_project(fake_headless, project):
    headless.index_add("a.exe")
    headless.index_add("b.exe")
    fake_headless.envelope = _xref_envelope({"a.exe": ["main"], "b.exe": ["main"]})
    tools.list_xrefs_to("*", "main")
    assert fake_headless.last_spec["programs"] == ["a.exe", "b.exe"]


def test_a_one_element_list_still_fans_out(fake_headless):
    """An explicit list asks for the fan-out shape even at length one, so a
    caller looping over a list gets consistent output."""
    fake_headless.envelope = _xref_envelope({"a.exe": ["main"]})
    out = tools.list_xrefs_to(["a.exe"], "main")

    assert out.program == "*"
    assert out.results[0].program == "a.exe"


def test_xrefs_from_fans_out_too(fake_headless):
    fake_headless.envelope = _xref_envelope({"a.exe": ["main"], "b.exe": ["main"]}, direction="from")
    out = tools.list_xrefs_from(["a.exe", "b.exe"], "main")

    assert out.direction == "from"
    assert [r.program for r in out.results] == ["a.exe", "b.exe"]


def test_an_empty_target_is_rejected_before_any_jvm(fake_headless):
    with pytest.raises(BadArgument, match="at least one target"):
        tools.list_xrefs_to(["a.exe", "b.exe"], [])
    assert fake_headless.calls == []


# ------------------------------------------------------- resolve_symbol
#
# The join is a pure function over rows, so it is tested directly rather than
# through a subprocess - the same habit as codesearch.py.

def _row(internal, name, roles, address=None, library=None, **extra):
    return {
        "internal_name": internal,
        "count": 1,
        "symbols": [{
            "name": name, "roles": roles, "address": address,
            "library": library, "thunk_target": extra.get("thunk_target"),
            "thunk_library": extra.get("thunk_library"),
            "is_external": bool(library), "is_thunk": extra.get("is_thunk", False),
        }],
    }


def _index(rows):
    idx = {}
    for program, data in rows.items():
        idx[program.lower()] = program
        if data.get("internal_name"):
            idx.setdefault(data["internal_name"].lower(), program)
    return idx


def _join(rows, name="CreateFileW"):
    return tools._resolve_one(name, rows, _index(rows))


WINDOWS = {
    "notepad.exe": _row("notepad.exe", "CreateFileW", ["import"],
                        library="API-MS-WIN-CORE-FILE-L1-1-0.DLL"),
    "KERNEL32.DLL": _row("kernel32.dll", "CreateFileW", ["export", "import", "function"],
                         address="1800570e0", library="API-MS-WIN-CORE-FILE-L1-1-0.DLL"),
    "KERNELBASE.DLL": _row("KernelBase.dll", "CreateFileW", ["export", "function"],
                           address="18003e630"),
    "NTDLL.DLL": _row("ntdll.dll", "CreateFileW", []),
}


def test_the_windows_layering_resolves_to_kernelbase():
    chain = _join(WINDOWS)
    assert chain.terminal_program == "KERNELBASE.DLL"


def test_layers_are_ordered_consumer_to_implementation():
    chain = _join(WINDOWS)
    assert [l.program for l in chain.layers] == [
        "notepad.exe", "KERNEL32.DLL", "KERNELBASE.DLL",
    ]


def test_a_program_that_never_mentions_the_symbol_is_absent_not_a_layer():
    chain = _join(WINDOWS)
    assert chain.absent_from == ["NTDLL.DLL"]
    assert "NTDLL.DLL" not in [l.program for l in chain.layers]


def test_the_forwarder_keeps_both_roles():
    """Exporting and importing the same name is what identifies a forwarder;
    collapsing to one role would lose the fact."""
    chain = _join(WINDOWS)
    kernel32 = next(l for l in chain.layers if l.program == "KERNEL32.DLL")
    assert set(kernel32.roles) == {"export", "import", "function"}
    assert kernel32.is_terminal is False


def test_an_apiset_import_resolves_to_the_implementation():
    chain = _join(WINDOWS)
    notepad = next(l for l in chain.layers if l.program == "notepad.exe")
    assert notepad.library_program == "KERNELBASE.DLL"


def test_the_apiset_hop_is_recorded_in_notes():
    """Following an apiset is a heuristic, so it must be visible rather than
    presented as something the binary stated."""
    chain = _join(WINDOWS)
    assert any("apiset" in n for n in chain.notes)


def test_a_plain_library_import_resolves_by_internal_name():
    """Import tables name kernel32.dll while the project holds KERNEL32.DLL."""
    rows = {
        "app.exe": _row("app.exe", "ReadFile", ["import"], library="kernel32.dll"),
        "KERNEL32.DLL": _row("kernel32.dll", "ReadFile", ["export", "function"],
                             address="18001000"),
    }
    chain = _join(rows, "ReadFile")
    app = next(l for l in chain.layers if l.program == "app.exe")

    assert app.library_program == "KERNEL32.DLL"
    assert not any("apiset" in n for n in chain.notes)


def test_a_library_outside_the_project_stays_unresolved():
    rows = {
        "app.exe": _row("app.exe", "SSL_connect", ["import"], library="libssl.so.3"),
    }
    chain = _join(rows, "SSL_connect")
    assert chain.layers[0].library_program is None
    assert chain.terminal_program is None


def test_two_implementations_are_reported_not_picked():
    """Guessing between two exporters would be worse than saying so."""
    rows = {
        "a.dll": _row("a.dll", "shared", ["export", "function"], address="1000"),
        "b.dll": _row("b.dll", "shared", ["export", "function"], address="2000"),
    }
    chain = _join(rows, "shared")

    assert chain.terminal_program is None
    assert any("ambiguous" in n for n in chain.notes)


def test_an_ambiguous_apiset_is_left_unresolved():
    rows = {
        "app.exe": _row("app.exe", "shared", ["import"], library="api-ms-win-core-x-l1-1-0.dll"),
        "a.dll": _row("a.dll", "shared", ["export", "function"], address="1000"),
        "b.dll": _row("b.dll", "shared", ["export", "function"], address="2000"),
    }
    chain = _join(rows, "shared")

    assert chain.layers[0].library_program is None
    assert any("no single implementation" in n for n in chain.notes)


def test_mutual_forwarding_terminates_and_says_so():
    """Two binaries each forwarding to the other has no implementation here.
    The join is not recursive, so this cannot loop - the test pins that."""
    rows = {
        "a.dll": _row("a.dll", "loop", ["export", "import", "function"], library="b.dll"),
        "b.dll": _row("b.dll", "loop", ["export", "import", "function"], library="a.dll"),
    }
    chain = _join(rows, "loop")

    assert chain.terminal_program is None
    assert any("outside this project" in n for n in chain.notes)


def test_a_symbol_in_no_program_yields_an_empty_chain():
    rows = {"a.exe": _row("a.exe", "nothing", []), "b.exe": _row("b.exe", "nothing", [])}
    chain = _join(rows, "nothing")

    assert chain.layers == []
    assert chain.terminal_program is None
    assert chain.absent_from == ["a.exe", "b.exe"]


def test_a_thunk_target_is_carried_through():
    rows = {
        "a.dll": _row("a.dll", "fn", ["export", "function"], address="1000",
                      is_thunk=True, thunk_target="fn", thunk_library="b.dll"),
    }
    chain = _join(rows, "fn")
    assert chain.layers[0].is_thunk is True
    assert chain.layers[0].thunk_library == "b.dll"


def test_layer_order_is_stable_for_equal_ranks():
    rows = {
        "z.exe": _row("z.exe", "fn", ["import"], library="x.dll"),
        "a.exe": _row("a.exe", "fn", ["import"], library="x.dll"),
    }
    assert [l.program for l in _join(rows, "fn").layers] == ["a.exe", "z.exe"]


# --- the tool around the join

def _link_envelope(rows):
    return {"ok": True, "mode": "link_symbols", "data": {
        "multi": True, "count": len(rows),
        "results": [{"program": p, "ok": True, "data": d} for p, d in rows.items()],
    }}


def test_resolve_symbol_uses_one_jvm_start(fake_headless):
    fake_headless.envelope = _link_envelope(WINDOWS)
    tools.resolve_symbol("CreateFileW", list(WINDOWS))
    assert len(fake_headless.calls) == 1


def test_resolve_symbol_sends_every_name_in_one_spec(fake_headless):
    fake_headless.envelope = _link_envelope(WINDOWS)
    tools.resolve_symbol(["CreateFileW", "ReadFile"], list(WINDOWS))
    assert fake_headless.last_spec["args"]["names"] == ["CreateFileW", "ReadFile"]


def test_resolve_symbol_returns_one_chain_per_name(fake_headless):
    fake_headless.envelope = _link_envelope(WINDOWS)
    out = tools.resolve_symbol(["CreateFileW", "ReadFile"], list(WINDOWS))
    assert [c.name for c in out.results] == ["CreateFileW", "ReadFile"]


def test_resolve_symbol_rejects_an_empty_name(fake_headless):
    with pytest.raises(BadArgument, match="at least one symbol name"):
        tools.resolve_symbol([])
    assert fake_headless.calls == []


def test_resolve_symbol_isolates_a_failing_program(fake_headless):
    env = _link_envelope({"KERNELBASE.DLL": WINDOWS["KERNELBASE.DLL"]})
    env["data"]["results"].append(
        {"program": "gone.exe", "ok": False, "error": {"kind": "not_found", "message": "x"}}
    )
    fake_headless.envelope = env
    out = tools.resolve_symbol("CreateFileW", ["KERNELBASE.DLL", "gone.exe"])

    assert out.programs_searched == 1
    assert [f.program for f in out.failures] == ["gone.exe"]
    assert out.results[0].terminal_program == "KERNELBASE.DLL"


# ------------------------------------------------------ analyze_binaries

def _files(tmp_path, *names):
    """Distinct files, so MD5s differ and nothing collides by accident."""
    made = []
    for i, n in enumerate(names):
        f = tmp_path / n
        f.write_bytes(b"\x7fELF" + bytes([i]) * 64)
        made.append(f)
    return made


def test_collect_accepts_one_path(tmp_path):
    (a,) = _files(tmp_path, "a.bin")
    assert tools._collect_binaries(str(a), recursive=False) == [a]


def test_collect_accepts_a_list(tmp_path):
    a, b = _files(tmp_path, "a.bin", "b.bin")
    assert tools._collect_binaries([str(a), str(b)], recursive=False) == [a, b]


def test_collect_refuses_a_directory_without_recursive(tmp_path):
    _files(tmp_path, "a.bin")
    with pytest.raises(BadArgument, match="recursive=True"):
        tools._collect_binaries(str(tmp_path), recursive=False)


def test_collect_walks_a_directory_when_asked(tmp_path):
    a, b = _files(tmp_path, "a.bin", "b.bin")
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / "c.bin").write_bytes(b"\x7fELFc")
    found = tools._collect_binaries(str(tmp_path), recursive=True)
    assert {p.name for p in found} == {"a.bin", "b.bin", "c.bin"}


def test_collect_deduplicates_overlapping_arguments(tmp_path):
    """A file named directly and also reachable through a directory must not
    be imported twice."""
    a, _ = _files(tmp_path, "a.bin", "b.bin")
    found = tools._collect_binaries([str(a), str(tmp_path)], recursive=True)
    assert [p.name for p in found].count("a.bin") == 1


def test_collect_rejects_a_missing_path(tmp_path):
    with pytest.raises(NotFound, match="binary not found"):
        tools._collect_binaries(str(tmp_path / "nope"), recursive=False)


def test_collect_rejects_an_empty_argument():
    with pytest.raises(BadArgument, match="at least one path"):
        tools._collect_binaries([], recursive=False)


def test_collect_rejects_an_empty_directory(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(NotFound, match="no files found"):
        tools._collect_binaries(str(tmp_path / "empty"), recursive=True)


def test_created_names_match_by_candidate_not_position():
    """A failed import emits no line, so zipping the lists would attribute
    every later program to the wrong file."""
    created = ["b.exe", "c.exe"]
    assert tools._match_created("a.exe", created) is None
    assert tools._match_created("b.exe", created) == "b.exe"


def test_a_packed_container_matches_the_program_it_holds():
    """Importing foo.exe.gzf yields the program foo.exe."""
    assert tools._match_created("foo.exe.gzf", ["foo.exe"]) == "foo.exe"


INFO_KEYS = {
    "executable_format": "ELF", "sha256": None, "language_id": "x86:LE:64:default",
    "compiler_spec_id": "gcc", "image_base": "00400000",
    "function_count": 1, "symbol_count": 1, "memory_blocks": [],
}


def _info(name, md5="0" * 32):
    return {"name": name, "executable_path": f"/{name}", "md5": md5, **INFO_KEYS}


@pytest.fixture
def batch_headless(monkeypatch, project):
    """Stub the two calls a batch import makes, and count them like real ones.

    fake_headless writes its envelope to the command's last argument, which for
    an -import call is a binary path - it would overwrite the test's own files.
    So the import is stubbed at run_headless and the metadata read at
    export_multi, which is also how the rest of the suite stubs project work.
    """

    class Batch:
        def __init__(self):
            self.import_calls: list[list[str]] = []
            self.stdout = ""
            self.info: dict[str, dict] = {}      # program -> info payload
            self.missing: set[str] = set()       # programs export_multi reports as gone

        def run_headless(self, args, timeout):
            headless.run_count += 1
            self.import_calls.append(list(args))

            class Proc:
                pass

            proc = Proc()
            proc.returncode, proc.stdout, proc.stderr = 0, self.stdout, ""
            return proc

        def export_multi(self, mode, programs, args=None, *, timeout=None):
            headless.run_count += 1
            rows = []
            for name in programs:
                if name in self.missing or name not in self.info:
                    rows.append({"program": name, "ok": False,
                                 "error": {"kind": "not_found", "message": "gone"}})
                else:
                    rows.append({"program": name, "ok": True, "data": self.info[name]})
            return rows

    batch = Batch()
    monkeypatch.setattr(headless, "run_headless", batch.run_headless)
    monkeypatch.setattr(headless, "export_multi", batch.export_multi)
    return batch


def _created(*names):
    return "".join(f"INFO  /{n}: file created (x) (LocalFileSystem)\n" for n in names)


def test_the_batch_import_passes_every_path_to_one_command(batch_headless, tmp_path):
    a, b = _files(tmp_path, "a.bin", "b.bin")
    batch_headless.stdout = _created("a.bin", "b.bin")
    batch_headless.info = {"a.bin": _info("a.bin"), "b.bin": _info("b.bin")}

    out = tools.analyze_binaries([str(a), str(b)])

    call = batch_headless.import_calls[0]
    assert call[0] == "-import"
    assert str(a) in call and str(b) in call
    assert len(batch_headless.import_calls) == 1
    assert out.imported == 2


def test_a_batch_import_costs_two_jvm_starts_whatever_the_size(batch_headless, tmp_path):
    """One to import them all, one to read the metadata back - against two per
    binary if each were analysed on its own."""
    files = _files(tmp_path, "a.bin", "b.bin", "c.bin", "d.bin")
    batch_headless.stdout = _created("a.bin", "b.bin", "c.bin", "d.bin")
    batch_headless.info = {f.name: _info(f.name) for f in files}

    out = tools.analyze_binaries([str(f) for f in files])

    assert out.imported == 4
    assert out.jvm_starts == 2


def test_a_binary_that_produced_no_program_is_a_failure(batch_headless, tmp_path):
    a, b = _files(tmp_path, "a.bin", "b.bin")
    batch_headless.stdout = _created("a.bin")     # b.bin silently produced nothing
    batch_headless.info = {"a.bin": _info("a.bin")}

    out = tools.analyze_binaries([str(a), str(b)])

    assert out.imported == 1
    assert [str(b)] == [f.program for f in out.failures]


def test_an_unloadable_binary_gets_ghidra_s_own_reason(batch_headless, tmp_path):
    (a,) = _files(tmp_path, "a.bin")
    batch_headless.stdout = "ERROR No load spec found for import file\n"

    out = tools.analyze_binaries([str(a)])

    assert out.imported == 0
    assert "no loader" in out.failures[0].error


def test_nothing_to_import_costs_one_jvm_start(batch_headless, tmp_path):
    """The point of batching the skip check: re-running over an unchanged
    directory must not cost a JVM start per file."""
    a, b = _files(tmp_path, "a.bin", "b.bin")
    for f in (a, b):
        headless.index_add(f.name)
    batch_headless.info = {f.name: _info(f.name, tools.file_md5(f)) for f in (a, b)}

    out = tools.analyze_binaries([str(a), str(b)])

    assert out.skipped == 2 and out.imported == 0
    assert out.jvm_starts == 1
    assert all(r.already_analyzed for r in out.results)
    assert batch_headless.import_calls == []


def test_a_name_held_by_a_different_binary_is_not_skipped(batch_headless, tmp_path, monkeypatch):
    """Identity is an MD5 question. Trusting the name would silently serve the
    wrong program."""
    (a,) = _files(tmp_path, "a.bin")
    headless.index_add("a.bin")
    batch_headless.info = {"a.bin": _info("a.bin", "f" * 32)}   # some other binary

    handed: list[str] = []

    def fake_single(path, **kwargs):
        handed.append(path)
        from ghmcp.models import AnalysisResult, ProgramInfo
        return AnalysisResult(program="a_deadbeef.bin", already_analyzed=False,
                              duration_seconds=0.0,
                              info=ProgramInfo(**_info("a_deadbeef.bin")))

    monkeypatch.setattr(tools, "analyze_binary", fake_single)
    out = tools.analyze_binaries([str(a)])

    assert handed == [str(a)]
    assert out.results[0].program == "a_deadbeef.bin"


def test_force_skips_the_identity_check_entirely(batch_headless, tmp_path):
    (a,) = _files(tmp_path, "a.bin")
    headless.index_add("a.bin")
    batch_headless.stdout = _created("a.bin")
    batch_headless.info = {"a.bin": _info("a.bin")}

    out = tools.analyze_binaries([str(a)], force=True)

    assert "-overwrite" in batch_headless.import_calls[0]
    assert out.imported == 1


def test_processor_and_cspec_apply_to_the_whole_batch(batch_headless, tmp_path):
    a, b = _files(tmp_path, "a.bin", "b.bin")
    batch_headless.stdout = _created("a.bin", "b.bin")
    batch_headless.info = {"a.bin": _info("a.bin"), "b.bin": _info("b.bin")}

    tools.analyze_binaries([str(a), str(b)], processor="ARM:LE:32:v8", cspec="default")

    call = batch_headless.import_calls[0]
    assert call[call.index("-processor") + 1] == "ARM:LE:32:v8"
    assert call[call.index("-cspec") + 1] == "default"


def test_a_stale_index_entry_is_re_imported_not_reported(batch_headless, tmp_path):
    """The index naming a program the project lost must not make an unanalysed
    binary look analysed."""
    (a,) = _files(tmp_path, "a.bin")
    headless.index_add("a.bin")
    batch_headless.missing = {"a.bin"}
    batch_headless.stdout = _created("a.bin")

    out = tools.analyze_binaries([str(a)])

    assert out.imported == 0 or not out.results[0].already_analyzed
    assert batch_headless.import_calls, "a stale entry must trigger a re-import"


def test_every_imported_program_lands_in_the_index(batch_headless, tmp_path):
    a, b = _files(tmp_path, "a.bin", "b.bin")
    batch_headless.stdout = _created("a.bin", "b.bin")
    batch_headless.info = {"a.bin": _info("a.bin"), "b.bin": _info("b.bin")}

    tools.analyze_binaries([str(a), str(b)])

    assert set(headless.index_read()) >= {"a.bin", "b.bin"}


# ------------------------------------------------------- import staging

def test_staging_never_writes_beside_the_source(tmp_path):
    """A staging directory in the source tree pollutes whatever the caller
    pointed at, and a killed process leaves it there. Observed for real: a
    timed-out batch import left one inside the read-only course clone."""
    src_dir = tmp_path / "assets"
    src_dir.mkdir()
    src = src_dir / "sample.bin"
    src.write_bytes(b"\x7fELF")

    stack: list = []
    try:
        staged = tools._stage_for_import(src, "renamed.bin", False, stack)
        assert staged.name == "renamed.bin"
        assert src_dir not in staged.parents, f"staged inside the source tree: {staged}"
        assert list(src_dir.iterdir()) == [src], "source directory must be untouched"
    finally:
        for d in stack:
            shutil.rmtree(d, ignore_errors=True)


def test_staging_is_skipped_when_the_name_already_matches(tmp_path):
    src = tmp_path / "sample.bin"
    src.write_bytes(b"\x7fELF")
    stack: list = []
    assert tools._stage_for_import(src, "sample.bin", False, stack) == src
    assert stack == []


def test_staging_preserves_the_content(tmp_path):
    src = tmp_path / "sample.bin"
    src.write_bytes(b"\x7fELF\x01\x02\x03")
    stack: list = []
    try:
        staged = tools._stage_for_import(src, "other.bin", False, stack)
        assert staged.read_bytes() == src.read_bytes()
    finally:
        for d in stack:
            shutil.rmtree(d, ignore_errors=True)


def test_a_packed_file_on_a_read_only_directory_is_staged(tmp_path):
    """Ghidra writes a lock file beside a packed program while importing it, so
    a .gzf on a read-only mount fails without staging."""
    src = tmp_path / "sample.gzf"
    src.write_bytes(b"packed")
    stack: list = []
    try:
        staged = tools._stage_for_import(src, "sample.gzf", True, stack)
        assert staged != src and staged.name == "sample.gzf"
    finally:
        for d in stack:
            shutil.rmtree(d, ignore_errors=True)
