"""Unit tests for the Stage 1 cross-reference tools."""

import pytest

from ghmcp import models, tools
from ghmcp.errors import BadArgument, NotFound

XREF = {
    "from_address": "00401200",
    "to_address": "00401146",
    "ref_type": "UNCONDITIONAL_CALL",
    "is_primary": True,
    "from_function": "main",
    "from_function_address": "00401000",
}


def _payload(direction="to", rows=None):
    return {"direction": direction, "results": rows if rows is not None else []}


def _row(target="check_key", n=1, **over):
    row = {
        "target": target,
        "resolved_address": "00401146",
        "resolved_kind": "function",
        "error": None,
        "xrefs": [dict(XREF, from_address=f"0040120{i}") for i in range(n)],
    }
    row.update(over)
    return row


class TestNormaliseTargets:
    def test_accepts_a_single_string(self, captured_specs):
        captured_specs.stub["xrefs"] = _payload(rows=[_row()])
        tools.list_xrefs_to("p", "check_key")
        assert captured_specs.calls[0][2]["targets"] == ["check_key"]

    def test_accepts_a_list(self, captured_specs):
        captured_specs.stub["xrefs"] = _payload(rows=[_row("a"), _row("b")])
        tools.list_xrefs_to("p", ["a", "b"])
        assert captured_specs.calls[0][2]["targets"] == ["a", "b"]

    def test_drops_empty_strings(self, captured_specs):
        captured_specs.stub["xrefs"] = _payload(rows=[_row("a")])
        tools.list_xrefs_to("p", ["a", "", "  " and ""])
        assert captured_specs.calls[0][2]["targets"] == ["a"]

    @pytest.mark.parametrize("target", ["", [], [""], ["", ""]])
    def test_empty_request_is_rejected_before_starting_a_jvm(self, captured_specs, target):
        with pytest.raises(BadArgument, match="at least one target"):
            tools.list_xrefs_to("p", target)
        assert captured_specs.calls == []


class TestDirection:
    def test_to_sends_direction_to(self, captured_specs):
        captured_specs.stub["xrefs"] = _payload("to", [_row()])
        tools.list_xrefs_to("p", "f")
        assert captured_specs.calls[0][2]["direction"] == "to"

    def test_from_sends_direction_from(self, captured_specs):
        captured_specs.stub["xrefs"] = _payload("from", [_row()])
        tools.list_xrefs_from("p", "f")
        assert captured_specs.calls[0][2]["direction"] == "from"

    def test_direction_is_echoed_in_the_result(self, captured_specs):
        captured_specs.stub["xrefs"] = _payload("from", [_row()])
        assert tools.list_xrefs_from("p", "f").direction == "from"

    def test_both_are_read_only(self, captured_specs):
        captured_specs.stub["xrefs"] = _payload(rows=[_row()])
        tools.list_xrefs_to("p", "f")
        tools.list_xrefs_from("p", "f")
        assert [c[3] for c in captured_specs.calls] == [False, False]


class TestResults:
    def test_enriches_with_the_containing_function(self, captured_specs):
        captured_specs.stub["xrefs"] = _payload(rows=[_row()])
        entry = tools.list_xrefs_to("p", "check_key").results[0].xrefs[0]
        assert entry.from_function == "main"
        assert entry.ref_type == "UNCONDITIONAL_CALL"

    def test_counts_total_and_returned_separately(self, captured_specs):
        captured_specs.stub["xrefs"] = _payload(rows=[_row(n=10)])
        result = tools.list_xrefs_to("p", "f", limit=3).results[0]
        assert result.total == 10 and result.returned == 3

    def test_paging_is_per_target(self, captured_specs):
        captured_specs.stub["xrefs"] = _payload(rows=[_row("a", n=5), _row("b", n=2)])
        out = tools.list_xrefs_to("p", ["a", "b"], limit=2)
        assert [(r.total, r.returned) for r in out.results] == [(5, 2), (2, 2)]

    def test_offset_pages_within_a_target(self, captured_specs):
        captured_specs.stub["xrefs"] = _payload(rows=[_row(n=5)])
        out = tools.list_xrefs_to("p", "f", limit=2, offset=2)
        assert [x.from_address for x in out.results[0].xrefs] == ["00401202", "00401203"]

    def test_a_target_with_no_references_is_not_an_error(self, captured_specs):
        captured_specs.stub["xrefs"] = _payload(rows=[_row(n=0)])
        result = tools.list_xrefs_to("p", "unused").results[0]
        assert result.total == 0 and result.error is None
        assert result.resolved_address == "00401146"

    def test_one_bad_target_does_not_lose_the_others(self, captured_specs):
        """A model asking about twenty symbols must not lose nineteen to a typo."""
        captured_specs.stub["xrefs"] = _payload(
            rows=[
                _row("good", n=2),
                _row("typo", resolved_address=None, resolved_kind=None,
                     error="not found: typo", xrefs=[]),
            ]
        )
        out = tools.list_xrefs_to("p", ["good", "typo"])
        assert out.results[0].total == 2 and out.results[0].error is None
        assert out.results[1].error == "not found: typo"
        assert out.results[1].resolved_address is None

    def test_resolved_kind_is_reported(self, captured_specs):
        captured_specs.stub["xrefs"] = _payload(
            rows=[_row(resolved_kind="symbol")]
        )
        assert tools.list_xrefs_to("p", "s").results[0].resolved_kind == "symbol"


class TestGetFunctionAt:
    DETAIL = {
        "name": "check_key", "address": "00401146", "size": 20,
        "signature": "int check_key(char *)", "calling_convention": "cdecl",
        "is_thunk": False, "is_external": False,
        "queried_address": "00401146", "is_entry_point": True,
    }

    def test_returns_the_function(self, captured_specs):
        captured_specs.stub["function_at"] = self.DETAIL
        out = tools.get_function_at("p", "00401146")
        assert out.name == "check_key" and out.is_entry_point is True

    def test_reports_when_the_address_is_inside_a_body(self, captured_specs):
        captured_specs.stub["function_at"] = {
            **self.DETAIL, "queried_address": "00401150", "is_entry_point": False
        }
        out = tools.get_function_at("p", "00401150")
        assert out.is_entry_point is False
        assert out.address == "00401146" and out.queried_address == "00401150"

    def test_passes_the_address_through(self, captured_specs):
        captured_specs.stub["function_at"] = self.DETAIL
        tools.get_function_at("p", "0x401146")
        assert captured_specs.calls[0][2] == {"address": "0x401146"}

    def test_not_found_propagates(self, captured_specs):
        captured_specs.stub["function_at"] = NotFound("no function at or containing 0")
        with pytest.raises(NotFound):
            tools.get_function_at("p", "0")


class TestModels:
    def test_xref_entry_tolerates_a_reference_outside_any_function(self):
        entry = models.XrefEntry(
            from_address="00402000", to_address="00401146",
            ref_type="DATA", is_primary=False,
            from_function=None, from_function_address=None,
        )
        assert entry.from_function is None

    def test_target_result_defaults_are_safe(self):
        row = models.XrefTargetResult(target="x")
        assert row.total == 0 and row.xrefs == [] and row.error is None
