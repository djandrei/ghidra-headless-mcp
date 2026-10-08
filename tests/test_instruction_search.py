"""search_constants and search_instructions: arguments, paging, fan-out. No JVM.

The Java half runs for real in test_integration_search.py.
"""

import pytest

from ghmcp import headless, tools
from ghmcp.errors import BadArgument, NotFound

HIT = {"address": "004012a1", "function": "is_licensed",
       "instruction": "CMP dword ptr [RBP + -0x4],0xc0ffee42", "operand": 1,
       "value": "0xc0ffee42"}


@pytest.fixture
def multi(monkeypatch):
    """Replace export_multi; record the mode, programs and args it was given."""
    seen = {}
    rows = {}

    def fake(mode, programs, args=None, **_kw):
        seen.update(mode=mode, programs=list(programs), args=dict(args or {}))
        return [rows.get(p, {"program": p, "ok": True,
                             "data": {"matched": 3, "truncated": False,
                                      "hits": [HIT, HIT, HIT]}}) for p in programs]

    monkeypatch.setattr(headless, "export_multi", fake)
    return seen, rows


# ---------------------------------------------------------------- constants


@pytest.mark.parametrize("value, sent", [
    (0xC0FFEE42, str(0xC0FFEE42)), ("0xC0FFEE42", str(0xC0FFEE42)), ("-1", "-1"), (" 42 ", "42"),
])
def test_a_value_as_number_or_string(multi, value, sent):
    seen, _ = multi
    tools.search_constants("p", value=value)
    assert seen["mode"] == "search_constants"
    assert seen["args"]["value"] == sent


def test_the_query_line_names_the_constant(multi):
    assert tools.search_constants("p", value=0x10).query == "constant == 0x10"
    assert tools.search_constants("p", value=-1).query == "constant == -1"
    assert tools.search_constants("p", min=1, max=2).query == "constant in [0x1, 0x2]"


def test_a_range_sends_both_bounds_and_the_scan_window(multi):
    seen, _ = multi
    tools.search_constants("p", min="0x10", max=32, start="00401000", end="00402000")
    assert seen["args"] == {"min": "16", "max": "32", "start": "00401000",
                            "end": "00402000", "max_emit": 100}


@pytest.mark.parametrize("kwargs, message", [
    ({}, "give a value"),
    ({"min": 1}, "give a value"),
    ({"value": 1, "min": 0}, "not both"),
    ({"min": 5, "max": 1}, "greater than max"),
    ({"value": "lots"}, "must be an integer"),
    ({"value": True}, "must be an integer"),
])
def test_bad_constant_arguments(kwargs, message):
    with pytest.raises(BadArgument, match=message):
        tools.search_constants("p", **kwargs)


def test_paging_is_per_program_and_asks_java_for_enough(multi):
    seen, _ = multi
    out = tools.search_constants("p", value=1, limit=1, offset=1)
    assert seen["args"]["max_emit"] == 2
    [r] = out.results
    assert (r.total, r.returned, r.truncated) == (3, 1, True)


def test_the_whole_project_fans_out_and_keeps_failures(multi, monkeypatch):
    seen, rows = multi
    monkeypatch.setattr(headless, "index_read", lambda: ["a", "b"])
    rows["b"] = {"program": "b", "ok": False, "error": {"kind": "ghidra_error", "message": "x"}}
    out = tools.search_constants("*", value=1)
    assert seen["programs"] == ["a", "b"]
    assert out.programs_searched == 1 and out.total == 3
    assert [f.program for f in out.failures] == ["b"]


def test_a_single_named_program_that_fails_raises(multi):
    _, rows = multi
    rows["gone"] = {"program": "gone", "ok": False,
                    "error": {"kind": "not_found", "message": "no program named 'gone'"}}
    with pytest.raises(NotFound, match="gone"):
        tools.search_constants("gone", value=1)


def test_a_failure_without_a_kind_is_still_raised(multi):
    _, rows = multi
    rows["odd"] = {"program": "odd", "ok": False, "error": {"message": "broken"}}
    with pytest.raises(Exception, match="broken"):
        tools.search_constants("odd", value=1)


# ------------------------------------------------------------- instructions


def test_mnemonic_search(multi):
    seen, _ = multi
    out = tools.search_instructions(["a", "b"], mnemonic="call")
    assert seen["mode"] == "search_instructions"
    assert seen["args"]["mnemonic"] == "call" and seen["args"]["pattern"] is None
    assert out.query == "mnemonic call" and out.programs_searched == 2


def test_pattern_search(multi):
    seen, _ = multi
    out = tools.search_instructions("p", pattern="XOR.*0x")
    assert seen["args"]["pattern"] == "XOR.*0x"
    assert out.query == "instruction ~ /XOR.*0x/"


@pytest.mark.parametrize("kwargs", [{}, {"mnemonic": "call", "pattern": "x"}])
def test_exactly_one_of_mnemonic_and_pattern(kwargs):
    with pytest.raises(BadArgument, match="mnemonic or a pattern"):
        tools.search_instructions("p", **kwargs)


def test_a_bad_regex_is_refused_before_the_jvm(multi):
    seen, _ = multi
    with pytest.raises(BadArgument, match="invalid regex"):
        tools.search_instructions("p", pattern="(unclosed")
    assert seen == {}
