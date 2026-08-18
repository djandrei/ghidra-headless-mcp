"""Unit tests for the Stage 3 symbol inventory tools."""

import pytest

from ghmcp import models, tools
from ghmcp.errors import BadArgument


def _sym(name, kind="import", **over):
    base = {
        "name": name, "address": "00401000", "kind": kind,
        "namespace": None, "is_external": kind == "import",
        "source_type": "IMPORTED", "value": None,
    }
    base.update(over)
    return base


def _payload(kind="import", names=("printf", "malloc", "CreateFileA")):
    return {
        "kind": kind,
        "matched": len(names),
        "truncated": False,
        "symbols": [_sym(n, kind) for n in names],
    }


class TestKindValidation:
    @pytest.mark.parametrize("kind", tools.SYMBOL_KINDS)
    def test_every_documented_kind_is_accepted(self, captured_specs, kind):
        captured_specs.stub["symbols"] = _payload(kind)
        tools.list_symbols("p", kind=kind)
        assert captured_specs.calls[0][2] == {"kind": kind, "pattern": None}

    @pytest.mark.parametrize("kind", ["imports", "IMPORT", "", "segment", "everything"])
    def test_unknown_kind_is_rejected_before_a_jvm_starts(self, captured_specs, kind):
        with pytest.raises(BadArgument, match="kind must be one of"):
            tools.list_symbols("p", kind=kind)
        assert captured_specs.calls == []

    def test_error_message_lists_the_valid_kinds(self, captured_specs):
        with pytest.raises(BadArgument) as exc:
            tools.list_symbols("p", kind="nope")
        for kind in tools.SYMBOL_KINDS:
            assert kind in str(exc.value)

    def test_default_kind_is_imports(self, captured_specs):
        captured_specs.stub["symbols"] = _payload()
        tools.list_symbols("p")
        assert captured_specs.calls[0][2]["kind"] == "import"


class TestResults:
    def test_returns_all_symbols(self, captured_specs):
        captured_specs.stub["symbols"] = _payload()
        out = tools.list_symbols("p")
        assert out.total == 3
        assert [s.name for s in out.symbols] == ["printf", "malloc", "CreateFileA"]

    def test_kind_is_echoed_from_the_java_side(self, captured_specs):
        captured_specs.stub["symbols"] = _payload("export")
        assert tools.list_symbols("p", kind="export").kind == "export"

    def test_name_filter_is_forwarded_as_an_escaped_pattern(self, captured_specs):
        import re

        captured_specs.stub["symbols"] = _payload()
        tools.list_symbols("p", name_contains="createfile")
        assert captured_specs.calls[0][2]["pattern"] == re.escape("createfile")

    def test_paging(self, captured_specs):
        captured_specs.stub["symbols"] = _payload()
        out = tools.list_symbols("p", limit=2, offset=1)
        assert out.total == 3 and out.returned == 2
        assert [s.name for s in out.symbols] == ["malloc", "CreateFileA"]

    def test_total_comes_from_ghidras_match_count(self, captured_specs):
        captured_specs.stub["symbols"] = {**_payload(), "matched": 42}
        assert tools.list_symbols("p", limit=1).total == 42

    def test_data_entries_carry_a_value(self, captured_specs):
        captured_specs.stub["symbols"] = {
            "kind": "data", "matched": 1, "truncated": False,
            "symbols": [_sym("s_hello", "data", source_type="string", value="hello")],
        }
        out = tools.list_symbols("p", kind="data")
        assert out.symbols[0].value == "hello"
        assert out.symbols[0].source_type == "string"

    def test_is_read_only(self, captured_specs):
        captured_specs.stub["symbols"] = _payload()
        tools.list_symbols("p")
        assert captured_specs.calls[0][3] is False

    def test_empty_result_is_not_an_error(self, captured_specs):
        captured_specs.stub["symbols"] = {
            "kind": "class", "matched": 0, "truncated": False, "symbols": []
        }
        out = tools.list_symbols("p", kind="class")
        assert out.total == 0 and out.symbols == []


class TestListMemoryBlocks:
    INFO = {
        "name": "p", "language_id": "x86:LE:64:default", "compiler_spec_id": "gcc",
        "image_base": "00400000", "function_count": 1, "symbol_count": 1,
        "memory_blocks": [
            {"name": ".text", "start": "00401000", "end": "00401fff", "size": 4096,
             "readable": True, "writable": False, "executable": True},
            {"name": ".data", "start": "00402000", "end": "00402fff", "size": 4096,
             "readable": True, "writable": True, "executable": False},
        ],
    }

    def test_lists_blocks_with_permissions(self, captured_specs):
        captured_specs.stub["info"] = self.INFO
        out = tools.list_memory_blocks("p")
        assert out.total == 2
        assert out.blocks[0].executable is True
        assert out.blocks[1].writable is True

    def test_reuses_the_info_mode_rather_than_adding_one(self, captured_specs):
        captured_specs.stub["info"] = self.INFO
        tools.list_memory_blocks("p")
        assert captured_specs.calls[0][1] == "info"


class TestModels:
    def test_symbol_entry_tolerates_a_null_address(self):
        """External symbols can have no address in the program's space."""
        sym = models.SymbolEntry(name="printf", kind="import", address=None)
        assert sym.address is None

    def test_symbol_entry_defaults(self):
        sym = models.SymbolEntry(name="x", kind="label")
        assert sym.is_external is False and sym.namespace is None and sym.value is None
