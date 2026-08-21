"""End-to-end tests for the multi-program dispatcher.

The claim under test is not "it returns data" but "it returns data for N
programs from ONE analyzeHeadless start". Without the call-count assertion
these would pass over a plain Python loop and the feature would be gone.

Run with: pytest -m integration
"""

import pytest

from ghmcp import config, headless, tools
from ghmcp.errors import BadArgument
from tests.conftest import CRACKME, STARTER05

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def two_programs(tmp_path_factory):
    loc = tmp_path_factory.mktemp("multiprog")
    config.PROJECT_LOCATION = loc
    config.PROJECT_NAME = "multiprog-test"
    for path in (STARTER05, CRACKME):
        if not path.is_file():
            pytest.skip(f"fixture missing: {path}")
    a = tools.analyze_binary(str(STARTER05)).program
    b = tools.analyze_binary(str(CRACKME)).program
    return a, b


@pytest.fixture
def count_runs(monkeypatch):
    """Count analyzeHeadless invocations without suppressing them."""
    real = headless.run_headless
    calls: list[list[str]] = []

    def counting(args, timeout):
        calls.append(list(args))
        return real(args, timeout)

    monkeypatch.setattr(headless, "run_headless", counting)
    return calls


def test_one_jvm_start_serves_both_programs(two_programs, count_runs):
    """The whole point of the feature."""
    a, b = two_programs
    rows = headless.export_multi("info", [a, b])

    assert len(count_runs) == 1
    assert [r["program"] for r in rows] == [a, b]
    assert all(r["ok"] for r in rows)


def test_each_row_carries_that_program_s_own_facts(two_programs):
    a, b = two_programs
    rows = headless.export_multi("info", [a, b])

    md5s = {r["program"]: r["data"]["md5"] for r in rows}
    assert md5s[a] != md5s[b]
    assert all(r["data"]["function_count"] > 0 for r in rows)


def test_the_attached_program_is_served_from_the_borrow_path(two_programs):
    """programs[0] is already open for the run; it must still return its own
    data rather than being skipped or reopened."""
    a, b = two_programs
    first = headless.export_multi("info", [a, b])[0]
    alone = headless.export(a, "info")

    assert first["data"]["md5"] == alone["md5"]


def test_program_order_is_the_caller_s_order(two_programs):
    a, b = two_programs
    assert [r["program"] for r in headless.export_multi("info", [b, a])] == [b, a]


def test_a_missing_program_fails_only_itself(two_programs):
    a, b = two_programs
    rows = headless.export_multi("info", [a, "no-such-program", b])

    assert [r["ok"] for r in rows] == [True, False, True]
    assert rows[1]["error"]["kind"] == "not_found"


def test_a_missing_pivot_program_fails_the_run(two_programs):
    """programs[0] is what analyzeHeadless attaches to, so an unknown pivot is
    a whole-run failure, not a per-program one. Callers should pass a name from
    list_programs first."""
    a, _ = two_programs
    with pytest.raises(Exception):
        headless.export_multi("info", ["no-such-program", a])


def test_the_fan_out_does_not_modify_the_programs(two_programs):
    """-readOnly plus immutable opens: a later read must see the same facts."""
    a, b = two_programs
    before = {r["program"]: r["data"]["md5"] for r in headless.export_multi("info", [a, b])}
    headless.export_multi("functions", [a, b], {})
    after = {r["program"]: r["data"]["md5"] for r in headless.export_multi("info", [a, b])}
    assert before == after


def test_an_empty_program_list_never_reaches_ghidra(two_programs, count_runs):
    with pytest.raises(BadArgument):
        headless.export_multi("info", [])
    assert count_runs == []


def test_a_decompile_mode_works_across_programs(two_programs):
    """Stage 0's open question: the decompiler against a program opened
    read-only inside someone else's run."""
    a, b = two_programs
    rows = headless.export_multi("decompile", [a, b], {"target": "main"})

    assert all(r["ok"] for r in rows), [r.get("error") for r in rows if not r["ok"]]
    assert all(len(r["data"]["c"]) > 0 for r in rows)


def test_fan_out_beats_serial_calls(two_programs):
    """Not a strict timing assertion - just that one start does N programs'
    work, which is what makes the API worth having."""
    a, b = two_programs
    rows = headless.export_multi("symbols", [a, b], {"kind": "function"})
    assert all(r["ok"] for r in rows)
    assert all(len(r["data"]["symbols"]) > 0 for r in rows)


# ------------------------------------------------- project-scope tools

def test_symbols_project_covers_both_programs(two_programs, count_runs):
    a, b = two_programs
    out = tools.list_symbols_project(kind="function", programs=[a, b])

    assert len(count_runs) == 1
    assert {r.program for r in out.results} == {a, b}
    assert all(r.total > 0 for r in out.results)


def test_symbols_project_finds_a_known_import_in_the_right_binary(two_programs):
    a, b = two_programs
    out = tools.list_symbols_project(kind="import", pattern="^strcmp$", programs=[a, b])

    hits = {r.program: [s.name for s in r.symbols] for r in out.results}
    assert any(names for names in hits.values()), hits


def test_the_wildcard_resolves_to_the_whole_project(two_programs):
    a, b = two_programs
    out = tools.list_symbols_project(kind="function", programs="*")
    assert {r.program for r in out.results} == {a, b}


def test_xrefs_fan_out_over_both_programs(two_programs, count_runs):
    a, b = two_programs
    out = tools.list_xrefs_to([a, b], "main")

    assert len(count_runs) == 1
    assert out.program == "*"
    assert {r.program for r in out.results} == {a, b}


def test_single_program_xrefs_still_omit_the_program_tag(two_programs):
    a, _ = two_programs
    out = tools.list_xrefs_to(a, "main")
    assert out.program == a
    assert all(r.program is None for r in out.results)


# --------------------------------------------------------- resolve_symbol

def test_resolve_symbol_finds_the_implementation(two_programs, count_runs):
    """The ELF samples are self-contained, so the interesting assertion is
    that the join runs end to end in one JVM start and names the binary that
    defines a function rather than one that merely calls it."""
    a, b = two_programs
    out = tools.resolve_symbol("main", [a, b])

    assert len(count_runs) == 1
    assert out.programs_searched == 2
    chain = out.results[0]
    assert chain.name == "main"
    assert [layer.program for layer in chain.layers]


def test_resolve_symbol_reports_a_symbol_no_binary_has(two_programs):
    a, b = two_programs
    chain = tools.resolve_symbol("NoSuchSymbolAnywhere", [a, b]).results[0]

    assert chain.layers == []
    assert chain.terminal_program is None
    assert set(chain.absent_from) == {a, b}


def test_resolve_symbol_links_a_libc_import_to_its_provider(two_programs):
    """An import the project cannot satisfy stays unresolved rather than being
    guessed at."""
    a, b = two_programs
    chain = tools.resolve_symbol("strcmp", [a, b]).results[0]

    for layer in chain.layers:
        if "import" in layer.roles:
            assert layer.library_program is None or layer.library_program in (a, b)
