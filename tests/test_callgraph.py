"""Unit tests for Stage 6: call graph generation."""

import pytest

from ghmcp import models, tools
from ghmcp.errors import BadArgument, NotFound

GRAPH = {
    "function": "main",
    "address": "00401267",
    "direction": "called",
    "requested_depth": 3,
    "reached_depth": 2,
    "node_count": 3,
    "edge_count": 2,
    "truncated": False,
    "nodes": [
        {"id": "n0", "name": "main"},
        {"id": "n1", "name": "check_key"},
        {"id": "n2", "name": "printf"},
    ],
    "mermaid": 'flowchart TD\n    n0["main"]\n    n1["check_key"]\n    n0 --> n1\n',
}


class TestArguments:
    def test_defaults_are_sent(self, captured_specs):
        captured_specs.stub["callgraph"] = GRAPH
        tools.gen_callgraph("p", "main")
        assert captured_specs.calls[0][2] == {
            "function": "main", "direction": "called", "depth": 3, "max_nodes": 300
        }

    @pytest.mark.parametrize("direction", ["called", "calling"])
    def test_both_directions_are_accepted(self, captured_specs, direction):
        captured_specs.stub["callgraph"] = {**GRAPH, "direction": direction}
        out = tools.gen_callgraph("p", "main", direction=direction)
        assert out.direction == direction

    @pytest.mark.parametrize("direction", ["callers", "CALLED", "", "both"])
    def test_bad_direction_is_rejected_before_a_jvm_starts(self, captured_specs, direction):
        with pytest.raises(BadArgument, match="direction"):
            tools.gen_callgraph("p", "main", direction=direction)
        assert captured_specs.calls == []

    @pytest.mark.parametrize("depth", [0, -1])
    def test_non_positive_depth_is_rejected(self, captured_specs, depth):
        with pytest.raises(BadArgument, match="depth must be positive"):
            tools.gen_callgraph("p", "main", depth=depth)
        assert captured_specs.calls == []

    def test_depth_and_max_nodes_are_forwarded(self, captured_specs):
        captured_specs.stub["callgraph"] = GRAPH
        tools.gen_callgraph("p", "main", depth=7, max_nodes=50)
        args = captured_specs.calls[0][2]
        assert args["depth"] == 7 and args["max_nodes"] == 50

    def test_is_read_only(self, captured_specs):
        captured_specs.stub["callgraph"] = GRAPH
        tools.gen_callgraph("p", "main")
        assert captured_specs.calls[0][3] is False


class TestResult:
    def test_returns_mermaid_source(self, captured_specs):
        captured_specs.stub["callgraph"] = GRAPH
        out = tools.gen_callgraph("p", "main")
        assert out.mermaid.startswith("flowchart TD")
        assert "-->" in out.mermaid

    def test_nodes_are_structured_too(self, captured_specs):
        captured_specs.stub["callgraph"] = GRAPH
        out = tools.gen_callgraph("p", "main")
        assert [n.name for n in out.nodes] == ["main", "check_key", "printf"]
        assert out.node_count == 3 and out.edge_count == 2

    def test_reached_depth_can_be_lower_than_requested(self, captured_specs):
        """A shallow graph must not claim it traversed the full depth."""
        captured_specs.stub["callgraph"] = GRAPH
        out = tools.gen_callgraph("p", "main", depth=3)
        assert out.requested_depth == 3 and out.reached_depth == 2

    def test_truncation_is_surfaced(self, captured_specs):
        captured_specs.stub["callgraph"] = {**GRAPH, "truncated": True}
        assert tools.gen_callgraph("p", "main").truncated is True

    def test_missing_function_propagates(self, captured_specs):
        captured_specs.stub["callgraph"] = NotFound("function not found: nope")
        with pytest.raises(NotFound):
            tools.gen_callgraph("p", "nope")


class TestModel:
    def test_requires_mermaid_source(self):
        from pydantic import ValidationError

        payload = {k: v for k, v in GRAPH.items() if k != "mermaid"}
        with pytest.raises(ValidationError):
            models.CallGraph(program="p", **payload)

    def test_empty_graph_is_representable(self):
        graph = models.CallGraph(
            program="p", function="leaf", address="0", direction="called",
            requested_depth=3, reached_depth=0, node_count=1, edge_count=0,
            truncated=False, nodes=[{"id": "n0", "name": "leaf"}],
            mermaid='flowchart TD\n    n0["leaf"]\n',
        )
        assert graph.edge_count == 0
