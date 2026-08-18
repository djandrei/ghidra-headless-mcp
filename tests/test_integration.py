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
