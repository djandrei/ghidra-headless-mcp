"""Project-scope fan-out: program-list normalisation and cross-program search.

No JVM anywhere in here. Stage 1's fan-out reads the decompilation cache, so
these tests stub `load_corpus` rather than `run_headless` — the search path
below it is the same code single-program search already exercises.
"""

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
