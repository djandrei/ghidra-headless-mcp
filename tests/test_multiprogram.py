"""Project-scope fan-out: program-list normalisation and cross-program search.

No JVM anywhere in here. Stage 1's fan-out reads the decompilation cache, so
these tests stub `load_corpus` rather than `run_headless` — the search path
below it is the same code single-program search already exercises.
"""

import pytest

from ghmcp import headless, tools
from ghmcp.errors import BadArgument, GhidraError, NotFound

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
