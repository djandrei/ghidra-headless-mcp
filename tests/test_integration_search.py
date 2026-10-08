"""Constant and instruction search against real Ghidra, on the layout fixture.

Expected hits come from objdump of tests/fixtures/bin/layout.x86_64.

Run with: pytest -m integration
"""

import pytest

from ghmcp import headless, tools
from ghmcp.errors import NotFound
from tests.conftest import KEYCHECK, LAYOUT_MAGIC, LAYOUT_MAGIC_AT, analyse_layout

pytestmark = pytest.mark.integration

MAIN_START, MAIN_END = "004012b8", "00401387"


@pytest.fixture(scope="module")
def prog(tmp_path_factory):
    layout = analyse_layout(tmp_path_factory, "search").program
    tools.analyze_binary(str(KEYCHECK))  # a second program, for "*"
    return layout


def hits(out):
    [result] = out.results
    return result.hits


def test_the_magic_constant_is_found_where_it_is_compared(prog):
    [hit] = hits(tools.search_constants(prog, value=LAYOUT_MAGIC))
    assert (hit.address, hit.function, hit.operand) == (LAYOUT_MAGIC_AT, "is_licensed", 1)
    assert hit.value == "0xc0ffee42"


def test_a_constant_given_as_a_hex_string(prog):
    assert hits(tools.search_constants(prog, value="0xC0FFEE42"))[0].address == LAYOUT_MAGIC_AT


def test_minus_one_finds_the_unsigned_all_ones(prog):
    found = {h.address for h in hits(tools.search_constants(prog, value=-1))}
    assert "0040122d" in found  # classify's default: mov eax, 0xffffffff


def test_a_range(prog):
    out = tools.search_constants(prog, min=0xC0FFEE00, max=0xC0FFEEFF)
    assert [h.address for h in hits(out)] == [LAYOUT_MAGIC_AT]


def test_mnemonic_search_inside_an_address_range(prog):
    out = tools.search_instructions(prog, mnemonic="call", start=MAIN_START, end=MAIN_END)
    assert out.total == 6
    assert all(h.function == "main" for h in hits(out))


def test_pattern_search(prog):
    [hit] = hits(tools.search_instructions(prog, pattern=r"CMP.*0xc0ffee42"))
    assert hit.address == LAYOUT_MAGIC_AT


def test_paging(prog):
    first = tools.search_instructions(prog, mnemonic="ret", limit=2)
    rest = tools.search_instructions(prog, mnemonic="ret", limit=100, offset=2)
    assert first.results[0].returned == 2 and first.results[0].truncated
    assert first.results[0].total == rest.results[0].total
    assert not {h.address for h in hits(first)} & {h.address for h in hits(rest)}


def test_the_whole_project_in_one_start(prog):
    before = headless.run_count
    out = tools.search_instructions("*", mnemonic="ret")
    assert headless.run_count - before == 1
    assert {r.program for r in out.results} == {prog, "keycheck.x86_64"}
    assert out.programs_searched == 2 and out.total == sum(r.total for r in out.results)


def test_a_single_missing_program_raises(prog):
    with pytest.raises(NotFound):
        tools.search_constants("no-such-program", value=1)
