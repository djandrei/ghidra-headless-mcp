"""The layout fixture, as Ghidra sees it: the ground truth later tools rely on.

tests/fixtures/README.md states these facts from nm and objdump; this module
checks that Ghidra's analysis agrees, so a failure in a type, control-flow,
search or patch test can be told apart from a fixture that moved.

Run with: pytest -m integration
"""

import pytest

from ghmcp import tools
from tests.conftest import LAYOUT_CHAIN, LAYOUT_MAGIC_AT, analyse_layout

pytestmark = pytest.mark.integration

ADDRESSES = {
    "score_record": "00401176",
    "classify": "004011e0",
    "stage_c": "00401234",
    "stage_b": "00401255",
    "stage_a": "00401275",
    "is_licensed": "00401296",
    "main": "004012b8",
}


@pytest.fixture(scope="module")
def layout(tmp_path_factory):
    return analyse_layout(tmp_path_factory, "layout-truth")


@pytest.mark.parametrize("name, address", sorted(ADDRESSES.items()))
def test_each_fixture_function_is_where_nm_says(layout, name, address):
    out = tools.list_functions(layout.program, name_contains=name)
    assert address in [f.address for f in out.functions if f.name == name]


def test_the_magic_constant_is_an_immediate_at_its_address(layout):
    out = tools.read_bytes(layout.program, LAYOUT_MAGIC_AT, 7)
    # cmp dword [rbp-4], imm32: 81 7d fc, then 0xC0FFEE42 little-endian.
    assert out.hex == "817dfc42eeffc0"


def test_the_struct_is_raw_pointer_arithmetic_before_any_type_exists(layout):
    c = tools.decompile_function(layout.program, "score_record").c
    assert "->" not in c


def test_the_call_chain_is_in_the_call_graph(layout):
    graph = tools.gen_callgraph(layout.program, "main", direction="called", depth=4)
    names = {n.name for n in graph.nodes}
    assert set(LAYOUT_CHAIN) <= names
