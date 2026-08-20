"""Unit tests for the batched decompile and read_bytes paths.

The batch forms exist because this backend cold-starts a JVM per call: the
nullhaven run made eleven single decompile calls at ~3.2 s each where one
batched call would have cost roughly one. These tests pin the two properties
that make batching safe to reach for — the wire format the Java side expects,
and per-target error isolation.
"""

import pytest

from ghmcp import models, tools
from ghmcp.errors import BadArgument, NotFound

DECOMP = {
    "name": "check_key",
    "address": "00401146",
    "signature": "int check_key(char *)",
    "c": "int check_key(char *p){}",
}
BYTES = {
    "address": "00402000",
    "requested_size": 8,
    "size": 8,
    "hex": "48656c6c6f0a0041",
    "ascii": "Hello..A",
}


def _drow(target="check_key", **over):
    row = {"target": target, **DECOMP}
    row.update(over)
    return row


def _brow(target="00402000", **over):
    row = {"target": target, **BYTES}
    row.update(over)
    return row


class TestDecompileBatchWireFormat:
    def test_a_string_still_uses_the_flat_legacy_request(self, captured_specs):
        captured_specs.stub["decompile"] = DECOMP
        tools.decompile_function("p", "check_key")
        assert captured_specs.calls[0][2] == {"target": "check_key"}

    def test_a_string_still_returns_the_flat_model(self, captured_specs):
        captured_specs.stub["decompile"] = DECOMP
        out = tools.decompile_function("p", "check_key")
        assert isinstance(out, models.Decompilation)
        assert out.name == "check_key"

    def test_a_list_sends_targets_not_target(self, captured_specs):
        captured_specs.stub["decompile"] = {"results": [_drow("a"), _drow("b")]}
        tools.decompile_function("p", ["a", "b"])
        assert captured_specs.calls[0][2] == {"targets": ["a", "b"]}

    def test_a_single_element_list_still_batches(self, captured_specs):
        captured_specs.stub["decompile"] = {"results": [_drow("a")]}
        out = tools.decompile_function("p", ["a"])
        assert captured_specs.calls[0][2] == {"targets": ["a"]}
        assert isinstance(out, models.DecompilationBatch)

    def test_empty_strings_are_dropped(self, captured_specs):
        captured_specs.stub["decompile"] = {"results": [_drow("a")]}
        tools.decompile_function("p", ["a", "", "  " and ""])
        assert captured_specs.calls[0][2] == {"targets": ["a"]}

    @pytest.mark.parametrize("function", [[], [""], ["", ""]])
    def test_an_empty_batch_is_rejected_before_a_jvm_starts(
        self, captured_specs, function
    ):
        with pytest.raises(BadArgument, match="at least one function"):
            tools.decompile_function("p", function)
        assert captured_specs.calls == []

    def test_the_batch_is_read_only(self, captured_specs):
        captured_specs.stub["decompile"] = {"results": [_drow()]}
        tools.decompile_function("p", ["check_key"])
        assert captured_specs.calls[0][3] is False


class TestDecompileBatchResults:
    def test_every_target_gets_a_slot_in_order(self, captured_specs):
        captured_specs.stub["decompile"] = {
            "results": [_drow("a"), _drow("b"), _drow("c")]
        }
        out = tools.decompile_function("p", ["a", "b", "c"])
        assert [r.target for r in out.results] == ["a", "b", "c"]
        assert out.total == 3

    def test_counts_add_up(self, captured_specs):
        captured_specs.stub["decompile"] = {
            "results": [
                _drow("a"),
                {"target": "nope", "error": "function not found: nope",
                 "error_kind": "not_found"},
                _drow("c"),
            ]
        }
        out = tools.decompile_function("p", ["a", "nope", "c"])
        assert (out.total, out.succeeded, out.failed) == (3, 2, 1)

    def test_one_bad_target_does_not_lose_the_others(self, captured_specs):
        captured_specs.stub["decompile"] = {
            "results": [
                {"target": "nope", "error": "function not found: nope",
                 "error_kind": "not_found"},
                _drow("good"),
            ]
        }
        out = tools.decompile_function("p", ["nope", "good"])
        assert out.results[0].ok is False
        assert out.results[0].error_kind == "not_found"
        assert out.results[1].ok is True
        assert out.results[1].c == DECOMP["c"]

    def test_a_failed_slot_carries_no_c_text(self, captured_specs):
        captured_specs.stub["decompile"] = {
            "results": [{"target": "x", "error": "boom", "error_kind": "ghidra_error"}]
        }
        out = tools.decompile_function("p", ["x"])
        assert out.results[0].c is None and out.results[0].address is None

    def test_program_is_echoed(self, captured_specs):
        captured_specs.stub["decompile"] = {"results": [_drow()]}
        assert tools.decompile_function("p", ["check_key"]).program == "p"

    def test_a_whole_call_failure_still_raises(self, captured_specs):
        captured_specs.stub["decompile"] = NotFound("no such program")
        with pytest.raises(NotFound):
            tools.decompile_function("p", ["a", "b"])


class TestReadBytesBatchWireFormat:
    def test_a_string_still_uses_the_flat_legacy_request(self, captured_specs):
        captured_specs.stub["read_bytes"] = BYTES
        tools.read_bytes("p", "00402000", size=8)
        assert captured_specs.calls[0][2] == {"address": "00402000", "size": 8}

    def test_a_list_sends_address_size_pairs(self, captured_specs):
        captured_specs.stub["read_bytes"] = {"results": [_brow("a"), _brow("b")]}
        tools.read_bytes("p", ["a", "b"], size=16)
        assert captured_specs.calls[0][2] == {
            "reads": [{"address": "a", "size": 16}, {"address": "b", "size": 16}]
        }

    def test_a_scalar_size_is_applied_to_every_address(self, captured_specs):
        captured_specs.stub["read_bytes"] = {"results": [_brow("a"), _brow("b"), _brow("c")]}
        tools.read_bytes("p", ["a", "b", "c"], size=4)
        assert [r["size"] for r in captured_specs.calls[0][2]["reads"]] == [4, 4, 4]

    def test_per_address_sizes_are_passed_through(self, captured_specs):
        captured_specs.stub["read_bytes"] = {"results": [_brow("a"), _brow("b")]}
        tools.read_bytes("p", ["a", "b"], size=[23, 256])
        assert captured_specs.calls[0][2]["reads"] == [
            {"address": "a", "size": 23},
            {"address": "b", "size": 256},
        ]

    def test_default_size_applies_in_batch_form(self, captured_specs):
        captured_specs.stub["read_bytes"] = {"results": [_brow("a")]}
        tools.read_bytes("p", ["a"])
        assert captured_specs.calls[0][2]["reads"] == [{"address": "a", "size": 32}]

    def test_the_batch_is_read_only(self, captured_specs):
        captured_specs.stub["read_bytes"] = {"results": [_brow()]}
        tools.read_bytes("p", ["00402000"])
        assert captured_specs.calls[0][3] is False


class TestReadBytesBatchValidation:
    def test_mismatched_size_list_is_rejected_before_a_jvm_starts(self, captured_specs):
        with pytest.raises(BadArgument, match="3 sizes for 2 addresses"):
            tools.read_bytes("p", ["a", "b"], size=[1, 2, 3])
        assert captured_specs.calls == []

    def test_a_size_list_with_a_single_address_is_rejected(self, captured_specs):
        with pytest.raises(BadArgument, match="list of sizes needs a list of addresses"):
            tools.read_bytes("p", "a", size=[1])
        assert captured_specs.calls == []

    @pytest.mark.parametrize("size", [0, -1])
    def test_non_positive_scalar_size_is_rejected_in_batch_form(
        self, captured_specs, size
    ):
        with pytest.raises(BadArgument, match="size must be positive"):
            tools.read_bytes("p", ["a", "b"], size=size)
        assert captured_specs.calls == []

    @pytest.mark.parametrize("sizes", [[8, 0], [0, 8], [8, -4]])
    def test_a_non_positive_size_anywhere_in_the_list_is_rejected(
        self, captured_specs, sizes
    ):
        with pytest.raises(BadArgument, match="size must be positive"):
            tools.read_bytes("p", ["a", "b"], size=sizes)
        assert captured_specs.calls == []

    @pytest.mark.parametrize("address", [[], [""], ["", ""]])
    def test_an_empty_batch_is_rejected_before_a_jvm_starts(
        self, captured_specs, address
    ):
        with pytest.raises(BadArgument, match="at least one address"):
            tools.read_bytes("p", address)
        assert captured_specs.calls == []

    def test_dropped_empty_addresses_do_not_desync_the_sizes(self, captured_specs):
        # "a", "", "b" normalises to two addresses, so two sizes must match.
        with pytest.raises(BadArgument, match="3 sizes for 2 addresses"):
            tools.read_bytes("p", ["a", "", "b"], size=[1, 2, 3])
        assert captured_specs.calls == []


class TestReadBytesBatchResults:
    def test_every_span_gets_a_slot_in_order(self, captured_specs):
        captured_specs.stub["read_bytes"] = {
            "results": [_brow("a"), _brow("b"), _brow("c")]
        }
        out = tools.read_bytes("p", ["a", "b", "c"])
        assert [r.target for r in out.results] == ["a", "b", "c"]
        assert out.total == 3

    def test_one_unresolvable_address_does_not_lose_the_others(self, captured_specs):
        captured_specs.stub["read_bytes"] = {
            "results": [
                {"target": "nope", "error": "cannot resolve: nope",
                 "error_kind": "not_found"},
                _brow("good"),
            ]
        }
        out = tools.read_bytes("p", ["nope", "good"])
        assert (out.succeeded, out.failed) == (1, 1)
        assert out.results[0].hex is None
        assert out.results[1].hex == BYTES["hex"]

    def test_a_short_read_is_reported_per_span(self, captured_specs):
        captured_specs.stub["read_bytes"] = {
            "results": [_brow("a", requested_size=64, size=8)]
        }
        out = tools.read_bytes("p", ["a"], size=64)
        assert out.results[0].requested_size == 64 and out.results[0].size == 8

    def test_program_is_echoed(self, captured_specs):
        captured_specs.stub["read_bytes"] = {"results": [_brow()]}
        assert tools.read_bytes("p", ["00402000"]).program == "p"

    def test_a_whole_call_failure_still_raises(self, captured_specs):
        captured_specs.stub["read_bytes"] = NotFound("no such program")
        with pytest.raises(NotFound):
            tools.read_bytes("p", ["a", "b"])


class TestBatchModels:
    def test_ok_tracks_the_error_field(self):
        good = models.DecompilationResult(target="a", name="a", c="x")
        bad = models.DecompilationResult(target="b", error="boom", error_kind="not_found")
        assert good.ok is True and bad.ok is False

    def test_bytes_result_ok_tracks_the_error_field(self):
        good = models.BytesReadResult(target="a", hex="00")
        bad = models.BytesReadResult(target="b", error="boom", error_kind="not_found")
        assert good.ok is True and bad.ok is False

    def test_batches_are_serialisable(self):
        batch = models.DecompilationBatch(
            program="p", total=1, succeeded=1, failed=0,
            results=[models.DecompilationResult(target="a", name="a", c="x")],
        )
        assert batch.model_dump()["results"][0]["target"] == "a"
