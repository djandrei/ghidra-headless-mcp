"""Analysis options against real Ghidra: list, set at import, set and re-analyse.

Options are picked from what list_analysis_options reports rather than
hard-coded, except one analyzer every x86-64 ELF has, so the module survives
Ghidra renaming a setting between versions.

Run with: pytest -m integration
"""

import pytest

from ghmcp import tools
from ghmcp.errors import BadArgument
from tests.conftest import CRACKME, KEYCHECK, analyse_layout

pytestmark = pytest.mark.integration

ANALYZER = "Decompiler Parameter ID"


@pytest.fixture(scope="module")
def prog(tmp_path_factory):
    return analyse_layout(tmp_path_factory, "options").program


def option(prog, name):
    [o] = [o for o in tools.list_analysis_options(prog, pattern=name).options if o.name == name]
    return o


def test_listing_shows_analyzers_and_their_settings(prog):
    out = tools.list_analysis_options(prog)
    names = {o.name for o in out.options}
    assert ANALYZER in names
    assert any(n.startswith(ANALYZER + ".") for n in names)
    switches = tools.list_analysis_options(prog, analyzers_only=True).options
    assert switches and all(o.analyzer and o.type == "boolean" and "." not in o.name
                            for o in switches)


def test_reanalyze_with_a_flipped_analyzer(prog):
    before = option(prog, ANALYZER)
    out = tools.reanalyze(prog, {ANALYZER: not before.value})
    assert out.options_applied == {ANALYZER: not before.value}
    assert out.info.function_count > 0
    after = option(prog, ANALYZER)
    assert after.value is (not before.value) and after.is_default is False


def test_whole_number_and_choice_options(prog):
    options = tools.list_analysis_options(prog).options
    number = next(o for o in options if o.type == "int" and isinstance(o.value, int))
    choice = next(o for o in options if o.type == "enum" and o.choices and len(o.choices) > 1)
    other = next(c for c in choice.choices if c != choice.value)
    tools.reanalyze(prog, {number.name: number.value + 1, choice.name: other})
    assert option(prog, number.name).value == number.value + 1
    assert option(prog, choice.name).value == other


def test_an_unknown_option_fails_and_changes_nothing(prog):
    before = option(prog, ANALYZER).value
    with pytest.raises(BadArgument, match="unknown analysis option: No Such Analyzer"):
        tools.reanalyze(prog, {"No Such Analyzer": True, ANALYZER: not before})
    assert option(prog, ANALYZER).value is before


def test_a_wrongly_typed_value_fails(prog):
    with pytest.raises(BadArgument, match="boolean"):
        tools.reanalyze(prog, {ANALYZER: "yes"})


def test_options_at_import(prog):
    out = tools.analyze_binary(str(KEYCHECK), analyzer_options={ANALYZER: True})
    assert out.options_applied == {ANALYZER: True}
    assert option(out.program, ANALYZER).value is True


def test_bad_options_at_import_import_nothing(prog):
    with pytest.raises(BadArgument, match="unknown analysis option"):
        tools.analyze_binary(str(CRACKME), analyzer_options={"No Such Analyzer": True})
    assert "crackme.x86_64" not in tools.list_programs(refresh=True).programs


def test_options_for_an_analysed_program_point_to_reanalyze(prog):
    with pytest.raises(BadArgument, match="reanalyze"):
        tools.analyze_binary(str(KEYCHECK), analyzer_options={ANALYZER: False})
