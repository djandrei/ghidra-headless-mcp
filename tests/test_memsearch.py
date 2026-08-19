"""Unit tests for search_memory — raw byte search, added after the
crackmes.one benchmark showed list_strings missing every UTF-16LE flag."""

import pytest

from ghmcp import tools
from ghmcp.errors import BadArgument

HITS = {
    "query": "5694-5378",
    "count": 2,
    "truncated": False,
    "hits": [
        {"address": "0046df5c", "encoding": "utf16le", "block": ".data", "in_function": None},
        {"address": "00401234", "encoding": "ascii", "block": ".text", "in_function": "main"},
    ],
}


class TestArguments:
    def test_text_is_forwarded(self, captured_specs):
        captured_specs.stub["search_memory"] = HITS
        tools.search_memory("p", text="5694-5378")
        assert captured_specs.calls[0][2] == {"limit": 50, "text": "5694-5378"}

    def test_hex_is_forwarded(self, captured_specs):
        captured_specs.stub["search_memory"] = {**HITS, "query": "4d5a"}
        tools.search_memory("p", hex="4d 5a")
        assert captured_specs.calls[0][2] == {"limit": 50, "hex": "4d 5a"}

    def test_neither_is_rejected_before_a_jvm_starts(self, captured_specs):
        with pytest.raises(BadArgument, match="requires text or hex"):
            tools.search_memory("p")
        assert captured_specs.calls == []

    def test_both_is_rejected(self, captured_specs):
        with pytest.raises(BadArgument, match="not both"):
            tools.search_memory("p", text="a", hex="41")
        assert captured_specs.calls == []

    def test_limit_is_forwarded(self, captured_specs):
        captured_specs.stub["search_memory"] = HITS
        tools.search_memory("p", text="x", limit=5)
        assert captured_specs.calls[0][2]["limit"] == 5

    def test_is_read_only(self, captured_specs):
        captured_specs.stub["search_memory"] = HITS
        tools.search_memory("p", text="x")
        assert captured_specs.calls[0][3] is False


class TestResults:
    def test_reports_each_hit_with_its_encoding(self, captured_specs):
        captured_specs.stub["search_memory"] = HITS
        out = tools.search_memory("p", text="5694-5378")
        assert out.count == 2
        assert {h.encoding for h in out.hits} == {"utf16le", "ascii"}

    def test_hits_carry_block_and_function_context(self, captured_specs):
        captured_specs.stub["search_memory"] = HITS
        out = tools.search_memory("p", text="x")
        assert out.hits[0].block == ".data"
        assert out.hits[1].in_function == "main"

    def test_no_hits_is_not_an_error(self, captured_specs):
        captured_specs.stub["search_memory"] = {
            "query": "nope", "count": 0, "truncated": False, "hits": []
        }
        assert tools.search_memory("p", text="nope").count == 0

    def test_truncation_is_surfaced(self, captured_specs):
        captured_specs.stub["search_memory"] = {**HITS, "truncated": True}
        assert tools.search_memory("p", text="x").truncated is True

    def test_docstring_explains_when_to_prefer_it_over_list_strings(self):
        doc = tools.search_memory.__doc__ or ""
        assert "list_strings" in doc and "defined" in doc
