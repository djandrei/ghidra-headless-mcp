"""get_cfg and find_call_paths over a faked export. No JVM.

The Java half runs for real in test_integration_cfg.py.
"""

import pytest

from ghmcp import tools
from ghmcp.errors import BadArgument


def test_get_cfg_batches_targets_and_reports_each(fake_headless):
    fake_headless.envelope = {"ok": True, "mode": "cfg", "data": {"results": [
        {"target": "f", "ok": True, "function": "f", "address": "00401000",
         "block_count": 2, "edge_count": 1,
         "blocks": [{"start": "00401000", "end": "00401003", "size": 4},
                    {"start": "00401004", "end": "00401004", "size": 1}],
         "edges": [{"source": "00401000", "target": "00401004", "kind": "fall_through"}]},
        {"target": "nope", "ok": False, "error": "function not found: nope",
         "error_kind": "not_found"},
    ]}}

    out = tools.get_cfg("p", ["f", "nope"])

    assert fake_headless.last_spec["args"] == {"targets": ["f", "nope"]}
    assert (out.total, out.succeeded, out.failed) == (2, 1, 1)
    assert out.results[0].edges[0].kind == "fall_through"
    assert out.results[0].edges[0].source == "00401000"
    assert out.results[1].blocks == []


def test_get_cfg_takes_one_name(fake_headless):
    fake_headless.envelope = {"ok": True, "mode": "cfg", "data": {"results": []}}

    tools.get_cfg("p", "main")

    assert fake_headless.last_spec["args"] == {"targets": ["main"]}


def test_find_call_paths_passes_its_limits_and_counts(fake_headless):
    step = lambda n, a: {"name": n, "address": a}  # noqa: E731
    fake_headless.envelope = {"ok": True, "mode": "call_paths", "data": {
        "source": "main", "target": "sink", "truncated": True,
        "paths": [[step("main", "1"), step("sink", "2")],
                  [step("main", "1"), step("mid", "3"), step("sink", "2")]]}}

    out = tools.find_call_paths("p", "0x1", "sink", max_depth=3, max_paths=2)

    assert fake_headless.last_spec["args"] == {
        "source": "0x1", "target": "sink", "max_depth": 3, "max_paths": 2}
    assert (out.source, out.path_count, out.truncated, out.max_depth) == ("main", 2, True, 3)
    assert [s.name for s in out.paths[1]] == ["main", "mid", "sink"]


@pytest.mark.parametrize("limits", [{"max_depth": 0}, {"max_paths": 0}])
def test_find_call_paths_refuses_empty_limits(limits):
    with pytest.raises(BadArgument, match="at least 1"):
        tools.find_call_paths("p", "a", "b", **limits)
