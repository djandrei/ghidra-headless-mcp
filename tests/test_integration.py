"""End-to-end tests against a real Ghidra install.

Deselected by default (pytest.ini sets -m "not integration") because each test
cold-starts a JVM. Run with:  pytest -m integration
"""

import pytest

from ghmcp import config, headless, tools
from tests.conftest import KNOWN_ADDRESS, KNOWN_FUNCTION, STARTER05

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def analysed(tmp_path_factory):
    """Analyse the fixture binary once for the whole module."""
    loc = tmp_path_factory.mktemp("intproj")
    config.PROJECT_LOCATION = loc
    config.PROJECT_NAME = "int-test"
    if not STARTER05.is_file():
        pytest.skip(f"fixture binary missing: {STARTER05}")
    result = tools.analyze_binary(str(STARTER05))
    return result


def test_analysis_reports_the_expected_architecture(analysed):
    assert analysed.info.language_id == "x86:LE:64:default"
    assert analysed.info.function_count > 0
    assert analysed.already_analyzed is False


def test_analysis_is_idempotent(analysed):
    again = tools.analyze_binary(str(STARTER05))
    assert again.already_analyzed is True


def test_the_program_appears_in_list_programs(analysed):
    assert analysed.program in tools.list_programs().programs


def test_known_function_is_found_at_its_known_address(analysed):
    out = tools.list_functions(analysed.program, name_contains=KNOWN_FUNCTION)
    assert out.total == 1
    assert out.functions[0].address == KNOWN_ADDRESS


def test_decompiles_by_name(analysed):
    out = tools.decompile_function(analysed.program, KNOWN_FUNCTION)
    assert out.address == KNOWN_ADDRESS
    assert "check_key" in out.c or out.name == KNOWN_FUNCTION
    assert len(out.c.splitlines()) > 5


def test_decompiles_by_address(analysed):
    out = tools.decompile_function(analysed.program, KNOWN_ADDRESS)
    assert out.name == KNOWN_FUNCTION


def test_decompiling_a_missing_function_raises_not_found(analysed):
    from ghmcp.errors import NotFound

    with pytest.raises(NotFound):
        tools.decompile_function(analysed.program, "no_such_function_anywhere")


def test_strings_include_the_known_banner(analysed):
    out = tools.list_strings(analysed.program, contains="keygen-me")
    assert out.total >= 1


def test_min_length_filters_in_ghidra(analysed):
    short = tools.list_strings(analysed.program, min_length=4, limit=1000)
    long = tools.list_strings(analysed.program, min_length=40, limit=1000)
    assert long.total < short.total


def test_program_info_hashes_are_populated(analysed):
    info = tools.get_program_info(analysed.program)
    assert info.sha256 and len(info.sha256) == 64
    assert info.memory_blocks


def test_legacy_positional_script_form_still_works(analysed):
    """The pre-Stage-0 calling convention must keep working during migration."""
    import json
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "legacy.json"
        headless.run_headless(
            [
                "-process", analysed.program, "-noanalysis", "-readOnly",
                "-scriptPath", config.script_path(),
                "-postScript", config.EXPORT_SCRIPT, "info", str(out),
            ],
            timeout=config.QUERY_TIMEOUT_S,
        )
        envelope = json.loads(out.read_text())
    assert envelope["ok"] is True
    assert envelope["data"]["language_id"] == "x86:LE:64:default"


# ------------------------------------------------------- Stage 1: xrefs


def test_xrefs_to_a_known_function_find_its_callers(analysed):
    out = tools.list_xrefs_to(analysed.program, KNOWN_FUNCTION)
    row = out.results[0]
    assert row.error is None
    assert row.resolved_kind == "function"
    assert row.resolved_address == KNOWN_ADDRESS
    assert row.total >= 1, "check_key is called from main; expected at least one xref"


def test_xrefs_to_enrich_with_the_calling_function(analysed):
    row = tools.list_xrefs_to(analysed.program, KNOWN_FUNCTION).results[0]
    callers = {x.from_function for x in row.xrefs if x.from_function}
    assert callers, "expected at least one reference from inside a function"


def test_xrefs_from_a_function_are_found(analysed):
    row = tools.list_xrefs_from(analysed.program, "main").results[0]
    assert row.error is None
    assert row.total >= 1


def test_xrefs_accept_an_address_as_well_as_a_name(analysed):
    row = tools.list_xrefs_to(analysed.program, KNOWN_ADDRESS).results[0]
    assert row.resolved_kind == "address"
    assert row.resolved_address == KNOWN_ADDRESS


def test_batch_xrefs_resolve_every_target_in_one_call(analysed):
    out = tools.list_xrefs_to(analysed.program, [KNOWN_FUNCTION, "main"])
    assert len(out.results) == 2
    assert all(r.error is None for r in out.results)


def test_one_bad_target_does_not_fail_the_batch(analysed):
    out = tools.list_xrefs_to(analysed.program, [KNOWN_FUNCTION, "definitely_not_here"])
    assert out.results[0].error is None
    assert out.results[1].error is not None
    assert out.results[1].resolved_address is None


def test_bad_direction_is_rejected_by_the_java_side(analysed):
    from ghmcp import headless as hl
    from ghmcp.errors import BadArgument

    with pytest.raises(BadArgument, match="direction"):
        hl.export(analysed.program, "xrefs", {"targets": ["main"], "direction": "sideways"})


def test_empty_target_list_is_rejected_by_the_java_side(analysed):
    from ghmcp import headless as hl
    from ghmcp.errors import BadArgument

    with pytest.raises(BadArgument, match="at least one target"):
        hl.export(analysed.program, "xrefs", {"targets": [], "direction": "to"})


# -------------------------------------------------- Stage 1: function_at


def test_function_at_resolves_an_entry_point(analysed):
    out = tools.get_function_at(analysed.program, KNOWN_ADDRESS)
    assert out.name == KNOWN_FUNCTION
    assert out.is_entry_point is True


def test_function_at_resolves_an_address_inside_a_body(analysed):
    """An address from a crash dump lands mid-function, not on an entry point."""
    entry = int(KNOWN_ADDRESS, 16)
    out = tools.get_function_at(analysed.program, f"{entry + 4:08x}")
    assert out.name == KNOWN_FUNCTION
    assert out.is_entry_point is False
    assert out.address == KNOWN_ADDRESS


def test_function_at_an_unmapped_address_raises_not_found(analysed):
    from ghmcp.errors import HeadlessError

    with pytest.raises(HeadlessError):
        tools.get_function_at(analysed.program, "00000010")


def test_function_at_rejects_a_nonsense_address(analysed):
    from ghmcp.errors import HeadlessError

    with pytest.raises(HeadlessError):
        tools.get_function_at(analysed.program, "not-an-address")


def test_xrefs_from_a_function_sweep_the_whole_body_not_just_the_entry(analysed):
    """Regression: getReferencesFrom(entryPoint) sees only the first instruction.

    main calls other functions and loads strings from addresses throughout its
    body, so a body-wide sweep must find references the entry point alone
    cannot.
    """
    from ghmcp import headless as hl

    row = tools.list_xrefs_from(analysed.program, "main").results[0]
    entry = row.resolved_address
    entry_only = hl.export(
        analysed.program, "xrefs", {"targets": [entry], "direction": "from"}
    )["results"][0]

    assert row.total > len(entry_only["xrefs"])
    assert len({x.from_address for x in row.xrefs}) > 1
