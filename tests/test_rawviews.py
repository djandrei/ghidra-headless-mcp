"""Unit tests for the Stage 2 raw-view tools."""

import pytest

from ghmcp import models, tools
from ghmcp.errors import BadArgument, NotFound

DISASM = {
    "target": "check_key",
    "resolved_address": "00401146",
    "scope": "function",
    "instruction_count": 3,
    "truncated": False,
    "listing": "00401146    PUSH RBP\n00401147    MOV RBP,RSP\n0040114a    RET\n",
}
BYTES = {
    "address": "00402000",
    "requested_size": 8,
    "size": 8,
    "hex": "48656c6c6f0a0041",
    "ascii": "Hello..A",
}


class TestDisassemble:
    def test_returns_the_listing(self, captured_specs):
        captured_specs.stub["disassemble"] = DISASM
        out = tools.disassemble("p", "check_key")
        assert out.instruction_count == 3
        assert "PUSH RBP" in out.listing
        assert out.program == "p"

    def test_defaults_are_sent_explicitly(self, captured_specs):
        captured_specs.stub["disassemble"] = DISASM
        tools.disassemble("p", "check_key")
        assert captured_specs.calls[0][2] == {
            "target": "check_key", "count": 20, "include_bytes": False
        }

    def test_include_bytes_is_passed_through(self, captured_specs):
        captured_specs.stub["disassemble"] = DISASM
        tools.disassemble("p", "f", include_bytes=True)
        assert captured_specs.calls[0][2]["include_bytes"] is True

    def test_count_is_passed_through(self, captured_specs):
        captured_specs.stub["disassemble"] = DISASM
        tools.disassemble("p", "f", count=200)
        assert captured_specs.calls[0][2]["count"] == 200

    @pytest.mark.parametrize("count", [0, -1, -999])
    def test_non_positive_count_is_rejected_before_a_jvm_starts(
        self, captured_specs, count
    ):
        with pytest.raises(BadArgument, match="count must be positive"):
            tools.disassemble("p", "f", count=count)
        assert captured_specs.calls == []

    def test_is_read_only(self, captured_specs):
        captured_specs.stub["disassemble"] = DISASM
        tools.disassemble("p", "f")
        assert captured_specs.calls[0][3] is False

    def test_scope_reports_how_the_target_was_interpreted(self, captured_specs):
        captured_specs.stub["disassemble"] = {**DISASM, "scope": "address"}
        assert tools.disassemble("p", "00401146").scope == "address"

    def test_truncation_is_surfaced(self, captured_specs):
        captured_specs.stub["disassemble"] = {**DISASM, "truncated": True}
        assert tools.disassemble("p", "f").truncated is True

    def test_unresolvable_target_propagates(self, captured_specs):
        captured_specs.stub["disassemble"] = NotFound("cannot resolve: nope")
        with pytest.raises(NotFound):
            tools.disassemble("p", "nope")


class TestReadBytes:
    def test_returns_hex_and_ascii(self, captured_specs):
        captured_specs.stub["read_bytes"] = BYTES
        out = tools.read_bytes("p", "00402000", size=8)
        assert out.hex == "48656c6c6f0a0041"
        assert out.ascii == "Hello..A"

    def test_default_size(self, captured_specs):
        captured_specs.stub["read_bytes"] = BYTES
        tools.read_bytes("p", "00402000")
        assert captured_specs.calls[0][2] == {"address": "00402000", "size": 32}

    @pytest.mark.parametrize("size", [0, -1])
    def test_non_positive_size_is_rejected_locally(self, captured_specs, size):
        with pytest.raises(BadArgument, match="size must be positive"):
            tools.read_bytes("p", "0", size=size)
        assert captured_specs.calls == []

    def test_short_read_at_a_block_boundary_is_reported_not_hidden(self, captured_specs):
        captured_specs.stub["read_bytes"] = {
            **BYTES, "requested_size": 64, "size": 8
        }
        out = tools.read_bytes("p", "00402000", size=64)
        assert out.requested_size == 64 and out.size == 8

    def test_unreadable_memory_propagates(self, captured_specs):
        captured_specs.stub["read_bytes"] = NotFound("cannot read 32 bytes at 0")
        with pytest.raises(NotFound):
            tools.read_bytes("p", "0")

    def test_is_read_only(self, captured_specs):
        captured_specs.stub["read_bytes"] = BYTES
        tools.read_bytes("p", "0")
        assert captured_specs.calls[0][3] is False


class TestModels:
    def test_hex_length_is_twice_the_byte_count(self):
        b = models.BytesRead(**BYTES, program="p")
        assert len(b.hex) == 2 * b.size

    def test_disassembly_requires_a_listing(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            models.Disassembly(
                program="p", target="f", resolved_address="0", scope="function",
                instruction_count=1, truncated=False,
            )
