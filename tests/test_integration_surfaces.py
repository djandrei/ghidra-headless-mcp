"""Every surface against real Ghidra, on one project: the answers must agree.

The same calls go through /api/<tool> and /mcp (both in-process, the --http
app) and through mcpo (serve-mcpo.sh, a subprocess). A read returns the same
JSON on all three; an edit made through any one of them is visible through
the others. One tool per family, the new ones included.

Run with: pytest -m integration
"""

import json

import httpx
import pytest
from starlette.testclient import TestClient

import ghidra_headless_mcp as entry
from ghmcp import config
from tests.conftest import LAYOUT_MAGIC_AT, analyse_layout
from tests.surfaces import MCPO_AVAILABLE, serve_mcpo
from tests.test_surfaces import McpSession

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not MCPO_AVAILABLE, reason="mcpo is not installed"),
]

KEY = "correct-horse-battery-staple"
AUTH = {"Authorization": f"Bearer {KEY}"}

# Read-only calls, one per tool family, against the layout fixture.
READS = {
    "get_program_info": {},
    "list_functions": {"pattern": "^stage_"},
    "decompile_function": {"function": "classify"},
    "disassemble": {"target": "is_licensed"},
    "read_bytes": {"address": LAYOUT_MAGIC_AT, "size": 7},
    "list_xrefs_to": {"target": "score_record"},
    "gen_callgraph": {"function": "main", "depth": 4},
    "get_cfg": {"function": ["classify", "is_licensed"]},
    "find_call_paths": {"source": "main", "target": "score_record"},
    "search_constants": {"value": "0xC0FFEE42"},
    "search_instructions": {"mnemonic": "call"},
    "list_types": {"kind": "struct"},
    "get_type": {"name": "int"},
    "list_analysis_options": {"analyzers_only": True},
}


@pytest.fixture(scope="module")
def surfaces(tmp_path_factory):
    program = analyse_layout(tmp_path_factory, "surfaces").program
    from ghmcp.tools import mcp

    mcp._session_manager = None
    env = {"PROJECT_LOCATION": str(config.PROJECT_LOCATION),
           "PROJECT_NAME": config.PROJECT_NAME}
    with serve_mcpo(tmp_path_factory.mktemp("mcpo"), KEY, env) as mcpo_base, \
            TestClient(entry.build_http_app(KEY), base_url="http://localhost:1351") as http:
        yield program, http, McpSession(http), mcpo_base
    mcp._session_manager = None


def via_api(http, tool, args):
    r = http.post(f"/api/{tool}", json=args, headers=AUTH)
    assert r.status_code == 200, r.text
    return r.json()


def via_mcp(session, tool, args):
    result = session.call(tool, args)
    assert result["isError"] is False, result["content"][0]["text"]
    return json.loads(result["content"][0]["text"])


def via_mcpo(base, tool, args):
    r = httpx.post(f"{base}/{tool}", json=args, headers=AUTH, timeout=600)
    assert r.status_code == 200, r.text
    return r.json()


def without_nulls(value):
    """mcpo omits null fields entirely; the --http surfaces send them as null."""
    if isinstance(value, dict):
        return {k: without_nulls(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [without_nulls(v) for v in value]
    return value


@pytest.mark.parametrize("tool", sorted(READS))
def test_every_surface_returns_the_same_answer(surfaces, tool):
    program, http, session, mcpo = surfaces
    args = {"program": program, **READS[tool]}

    api = via_api(http, tool, args)
    assert via_mcp(session, tool, args) == api
    assert via_mcpo(mcpo, tool, args) == without_nulls(api)


def test_the_answers_are_the_right_ones(surfaces):
    """Agreement alone could be agreement on nothing: spot-check the content."""
    program, http, _, _ = surfaces
    [hit] = via_api(http, "search_constants",
                    {"program": program, **READS["search_constants"]})["results"][0]["hits"]
    assert hit["address"] == LAYOUT_MAGIC_AT
    paths = via_api(http, "find_call_paths", {"program": program, **READS["find_call_paths"]})
    assert paths["path_count"] == 1
    cfg = via_api(http, "get_cfg", {"program": program, **READS["get_cfg"]})
    assert cfg["results"][0]["block_count"] == 13


def test_an_edit_through_any_surface_is_seen_by_the_others(surfaces):
    program, http, session, mcpo = surfaces

    def define(name):
        return {"program": program, "edits": [
            {"kind": "define_type", "c": f"struct {name} {{ int a; }};", "category": "/surf"}]}

    assert via_api(http, "apply_edits", define("from_api"))["applied"] == 1
    assert via_mcp(session, "apply_edits", define("from_mcp"))["applied"] == 1
    assert via_mcpo(mcpo, "apply_edits", define("from_mcpo"))["applied"] == 1

    names = {"program": program, "category": "/surf"}
    expected = ["from_api", "from_mcp", "from_mcpo"]
    for listing in (via_api(http, "list_types", names), via_mcp(session, "list_types", names),
                    via_mcpo(mcpo, "list_types", names)):  # no nullable fields here
        assert [t["name"] for t in listing["types"]] == expected


def test_a_missing_program_is_reported_on_each_surface(surfaces):
    _, http, session, mcpo = surfaces
    args = {"program": "no-such-program", "function": "main"}

    assert http.post("/api/get_cfg", json=args, headers=AUTH).status_code == 404
    result = session.call("get_cfg", args)
    assert result["isError"] and "no-such-program" in result["content"][0]["text"]
    # mcpo maps every tool error to 500 (see test_surface_mcpo).
    assert httpx.post(f"{mcpo}/get_cfg", json=args, headers=AUTH, timeout=120).status_code == 500
