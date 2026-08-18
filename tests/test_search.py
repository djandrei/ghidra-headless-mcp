"""Unit tests for Stage 4: regex search pushed into Ghidra."""

import pytest

from ghmcp import tools
from ghmcp.errors import BadArgument
from ghmcp.tools import _pattern


class TestPatternResolution:
    def test_pattern_wins_over_the_literal_alias(self):
        assert _pattern("^main$", "ignored") == "^main$"

    def test_literal_alias_is_escaped_not_passed_through(self):
        """A legacy 'a.b' filter must keep matching only 'a.b', never 'axb'."""
        assert _pattern(None, "a.b") == re_escape("a.b")

    @pytest.mark.parametrize(
        "literal", ["a.b", "f(x)", "a+b", "c[0]", "x|y", "$100", "a\\b"]
    )
    def test_every_regex_metacharacter_is_escaped(self, literal):
        import re

        compiled = re.compile(_pattern(None, literal))
        assert compiled.search(literal)
        assert compiled.pattern != literal or not re.search(r"[.^$*+?()\[\]{}|\\]", literal)

    def test_no_filter_returns_none(self):
        assert _pattern(None, None) is None

    @pytest.mark.parametrize("empty", ["", None])
    def test_empty_values_are_treated_as_no_filter(self, empty):
        assert _pattern(empty, empty) is None


def re_escape(s):
    import re

    return re.escape(s)


FUNCS = {
    "matched": 2,
    "truncated": False,
    "functions": [
        {"name": "main", "address": "00401000", "size": 10, "signature": "int main(void)",
         "calling_convention": "cdecl", "is_thunk": False, "is_external": False},
        {"name": "check_key", "address": "00401146", "size": 20,
         "signature": "int check_key(char *)", "calling_convention": "cdecl",
         "is_thunk": False, "is_external": False},
    ],
}
STRINGS = {"matched": 1, "truncated": False,
           "strings": [{"address": "00402000", "length": 5, "value": "hello"}]}
SYMS = {"kind": "import", "matched": 1, "truncated": False,
        "symbols": [{"name": "printf", "address": "00401000", "kind": "import",
                     "namespace": None, "is_external": True,
                     "source_type": "IMPORTED", "value": None}]}


class TestFilteringMovedIntoGhidra:
    def test_functions_send_the_pattern_and_flags(self, captured_specs):
        captured_specs.stub["functions"] = FUNCS
        tools.list_functions("p", pattern="^ma", include_thunks=True)
        assert captured_specs.calls[0][2] == {
            "pattern": "^ma", "include_thunks": True, "include_external": False
        }

    def test_functions_no_longer_filter_in_python(self, captured_specs):
        """Java returned two rows; Python must not re-filter them away."""
        captured_specs.stub["functions"] = FUNCS
        out = tools.list_functions("p", pattern="nothing-would-match-this")
        assert out.returned == 2

    def test_strings_send_the_pattern(self, captured_specs):
        captured_specs.stub["strings"] = STRINGS
        tools.list_strings("p", pattern="https?://")
        assert captured_specs.calls[0][2]["pattern"] == "https?://"

    def test_strings_keep_sending_min_length(self, captured_specs):
        captured_specs.stub["strings"] = STRINGS
        tools.list_strings("p", pattern="x", min_length=9)
        assert captured_specs.calls[0][2]["min_length"] == 9

    def test_symbols_send_the_pattern_with_the_kind(self, captured_specs):
        captured_specs.stub["symbols"] = SYMS
        tools.list_symbols("p", kind="import", pattern="^Crypt")
        assert captured_specs.calls[0][2] == {"kind": "import", "pattern": "^Crypt"}

    def test_legacy_alias_is_escaped_on_the_wire(self, captured_specs):
        captured_specs.stub["functions"] = FUNCS
        tools.list_functions("p", name_contains="a.b")
        assert captured_specs.calls[0][2]["pattern"] == re_escape("a.b")


class TestTotalsAndTruncation:
    def test_total_comes_from_ghidras_match_count_not_the_page(self, captured_specs):
        captured_specs.stub["functions"] = {**FUNCS, "matched": 9999}
        out = tools.list_functions("p", limit=1)
        assert out.total == 9999 and out.returned == 1

    def test_truncation_is_surfaced(self, captured_specs):
        captured_specs.stub["functions"] = {**FUNCS, "matched": 10_000, "truncated": True}
        assert tools.list_functions("p").truncated is True

    def test_untruncated_default(self, captured_specs):
        captured_specs.stub["strings"] = STRINGS
        assert tools.list_strings("p").truncated is False

    def test_missing_matched_falls_back_to_the_row_count(self, captured_specs):
        """Tolerate an older Java side that predates the matched field."""
        captured_specs.stub["strings"] = {
            "strings": [{"address": "0", "length": 1, "value": "a"}]
        }
        out = tools.list_strings("p")
        assert out.total == 1 and out.truncated is False

    def test_symbols_report_truncation(self, captured_specs):
        captured_specs.stub["symbols"] = {**SYMS, "matched": 6000, "truncated": True}
        out = tools.list_symbols("p")
        assert out.total == 6000 and out.truncated is True


class TestPagingStillApplies:
    def test_functions_page_within_the_returned_rows(self, captured_specs):
        captured_specs.stub["functions"] = FUNCS
        out = tools.list_functions("p", limit=1, offset=1)
        assert [f.name for f in out.functions] == ["check_key"]

    def test_invalid_kind_still_rejected_locally(self, captured_specs):
        with pytest.raises(BadArgument):
            tools.list_symbols("p", kind="bogus", pattern="x")
        assert captured_specs.calls == []
