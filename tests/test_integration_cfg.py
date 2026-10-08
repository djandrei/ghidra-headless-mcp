"""Control flow and call paths against real Ghidra, on the layout fixture.

classify's switch and the stage_a..stage_c chain have answers fixed by the
fixture's disassembly (tests/fixtures/README.md), not by an earlier run.

Run with: pytest -m integration
"""

import pytest

from ghmcp import tools
from tests.conftest import (
    LAYOUT_CHAIN,
    LAYOUT_SWITCH_BLOCKS,
    LAYOUT_SWITCH_EDGES,
    LAYOUT_SWITCH_FN,
    analyse_layout,
)

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def prog(tmp_path_factory):
    return analyse_layout(tmp_path_factory, "cfg").program


def test_the_switch_has_its_known_blocks_and_edges(prog):
    [cfg] = tools.get_cfg(prog, LAYOUT_SWITCH_FN).results
    assert cfg.ok, cfg.error
    assert (cfg.block_count, cfg.edge_count) == (LAYOUT_SWITCH_BLOCKS, LAYOUT_SWITCH_EDGES)
    assert cfg.blocks[0].start == "004011e0"
    starts = {b.start for b in cfg.blocks}
    assert all(e.source in starts and e.target in starts for e in cfg.edges)
    kinds = {e.kind for e in cfg.edges}
    assert {"conditional", "unconditional", "fall_through"} <= kinds
    # Every case returns through the one epilogue block.
    assert sum(1 for e in cfg.edges if e.target == "00401232") == 5


def test_a_batch_isolates_a_missing_function(prog):
    out = tools.get_cfg(prog, ["is_licensed", "no_such_function"])
    assert (out.succeeded, out.failed) == (1, 1)
    assert out.results[1].error_kind == "not_found"
    licensed = out.results[0]
    # cmp; jne -> two successors, both returning through one exit.
    assert licensed.block_count == 4


def test_the_chain_is_the_one_path_from_main(prog):
    out = tools.find_call_paths(prog, "main", "score_record")
    assert out.path_count == 1 and not out.truncated
    assert [s.name for s in out.paths[0]] == LAYOUT_CHAIN


def test_depth_bounds_the_search(prog):
    assert tools.find_call_paths(prog, "main", "score_record", max_depth=3).path_count == 0
    assert tools.find_call_paths(prog, "main", "score_record", max_depth=4).path_count == 1


def test_paths_by_address_and_to_a_direct_callee(prog):
    out = tools.find_call_paths(prog, "004012b8", "is_licensed")
    assert [[s.name for s in p] for p in out.paths] == [["main", "is_licensed"]]


def test_an_unknown_endpoint_is_not_found(prog):
    from ghmcp.errors import NotFound

    with pytest.raises(NotFound):
        tools.find_call_paths(prog, "main", "no_such_function")
