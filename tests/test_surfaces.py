"""Every tool through the two in-process HTTP surfaces: /api/<tool> and /mcp.

No JVM: each tool's function is swapped for a recorder (see surfaces.py), so
what is under test is the surface — schemas, argument coercion, result
serialisation and error reporting — for all 42 tools, not their logic.

Scenarios per tool, on both surfaces: a valid call, a call missing its
required arguments, and the tool raising. Per surface: schema publication,
wrongly-typed arguments, unknown tools, ignored extras, authentication and,
for /mcp, the session handshake.
"""

import json

import pytest
from starlette.testclient import TestClient

import ghidra_headless_mcp as entry
from ghmcp.errors import NotFound
from tests.surfaces import (
    VALID_ARGS,
    WRONG_TYPE,
    FakeTools,
    as_json,
    registered_tools,
    required_params,
)

KEY = "correct-horse-battery-staple"
AUTH = {"Authorization": f"Bearer {KEY}"}
ALL = sorted(VALID_ARGS)
WITH_REQUIRED = [n for n in ALL if required_params(n)]


@pytest.fixture
def fakes(monkeypatch):
    return FakeTools(monkeypatch)


def assert_received(fakes, name, sent):
    [received] = fakes.calls[name]
    for key, value in sent.items():
        assert received[key] == value, (name, key)


# --------------------------------------------------------------- coverage


def test_every_registered_tool_has_a_valid_call():
    """A new tool must be added to VALID_ARGS, and so to every surface test."""
    assert set(VALID_ARGS) == set(registered_tools())
    assert len(VALID_ARGS) == 42


# ================================================================ /api/<tool>


@pytest.fixture(scope="module")
def api():
    return TestClient(entry.build_http_app(KEY), raise_server_exceptions=False)


@pytest.mark.parametrize("name", ALL)
def test_api_valid_call(api, fakes, name):
    r = api.post(f"/api/{name}", json=VALID_ARGS[name], headers=AUTH)

    assert r.status_code == 200, r.text
    assert r.json() == as_json(fakes.results[name])
    assert_received(fakes, name, VALID_ARGS[name])


@pytest.mark.parametrize("name", WITH_REQUIRED)
def test_api_missing_required_arguments_is_422(api, fakes, name):
    r = api.post(f"/api/{name}", json={}, headers=AUTH)

    assert r.status_code == 422
    err = r.json()["error"]
    assert err["kind"] == "invalid_arguments"
    assert {d["loc"][0] for d in err["detail"]} == required_params(name)
    assert name not in fakes.calls


@pytest.mark.parametrize("name", sorted(WRONG_TYPE))
def test_api_wrongly_typed_argument_is_422(api, fakes, name):
    r = api.post(f"/api/{name}", json=WRONG_TYPE[name], headers=AUTH)

    assert r.status_code == 422
    assert name not in fakes.calls


@pytest.mark.parametrize("name", ALL)
def test_api_tool_error_keeps_its_kind(api, fakes, name):
    fakes.raises[name] = NotFound(f"{name}: nothing there")

    r = api.post(f"/api/{name}", json=VALID_ARGS[name], headers=AUTH)

    assert r.status_code == 404
    assert r.json() == {"error": {"kind": "not_found", "message": f"{name}: nothing there"}}


def test_api_unknown_arguments_are_ignored(api, fakes):
    """FastMCP's argument models ignore extras; pinned so a change is noticed."""
    r = api.post("/api/list_uploads", json={"surprise": 1}, headers=AUTH)

    assert r.status_code == 200
    assert "surprise" not in fakes.calls["list_uploads"][0]


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"}])
def test_api_every_tool_needs_the_token(api, fakes, headers):
    for name in ALL:
        assert api.post(f"/api/{name}", json=VALID_ARGS[name], headers=headers).status_code == 401
    assert fakes.calls == {}


# ===================================================================== /mcp


class McpSession:
    """A minimal streamable-http MCP client over a TestClient."""

    HEADERS = {**AUTH, "Accept": "application/json, text/event-stream"}

    def __init__(self, client):
        self.client = client
        self.next_id = 0
        r = self.post({"method": "initialize", "params": {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "surface-test", "version": "0"}}})
        assert r.status_code == 200, r.text
        self.session = r.headers["mcp-session-id"]
        self.client.post("/mcp", headers=self.headers(),
                         json={"jsonrpc": "2.0", "method": "notifications/initialized"})

    def headers(self):
        h = dict(self.HEADERS)
        if getattr(self, "session", None):
            h["mcp-session-id"] = self.session
        return h

    def post(self, message, headers=None):
        self.next_id += 1
        body = {"jsonrpc": "2.0", "id": self.next_id, **message}
        return self.client.post("/mcp", json=body, headers=headers or self.headers())

    def rpc(self, method, params=None):
        r = self.post({"method": method, "params": params or {}})
        assert r.status_code == 200, r.text
        return decode(r)

    def call(self, name, arguments):
        return self.rpc("tools/call", {"name": name, "arguments": arguments})["result"]


def decode(response):
    """One JSON-RPC message, from a JSON body or a server-sent event stream."""
    if response.headers["content-type"].startswith("application/json"):
        return response.json()
    data = [line[5:].strip() for line in response.text.splitlines() if line.startswith("data:")]
    return json.loads(data[-1])


@pytest.fixture(scope="module")
def mcp_client():
    from ghmcp.tools import mcp

    # FastMCP builds its session manager once and a manager runs only once, so
    # an app another test module already started cannot be started again.
    mcp._session_manager = None
    # localhost: the MCP transport's DNS-rebinding guard refuses other Host
    # headers (see test_mcp_refuses_a_non_local_host_header).
    with TestClient(entry.build_http_app(KEY), base_url="http://localhost:1351") as client:
        yield client
    mcp._session_manager = None


@pytest.fixture
def session(mcp_client):
    return McpSession(mcp_client)


def test_mcp_lists_every_tool_with_its_schemas(session):
    tools = {t["name"]: t for t in session.rpc("tools/list")["result"]["tools"]}

    assert set(tools) == set(registered_tools())
    for name, tool in tools.items():
        assert tool["description"].strip(), name
        assert set(tool["inputSchema"].get("required", [])) == required_params(name), name
        if name != "clear_code_cache":  # the one tool returning a bare dict
            assert tool.get("outputSchema"), name


@pytest.mark.parametrize("name", ALL)
def test_mcp_valid_call(session, fakes, name):
    result = session.call(name, VALID_ARGS[name])

    assert result["isError"] is False
    expected = as_json(fakes.results[name])
    assert json.loads(result["content"][0]["text"]) == expected
    if name != "clear_code_cache":
        # A union return (one result or a batch) has no single object schema,
        # so FastMCP wraps its structured output as {"result": ...}.
        wrapped = registered_tools()[name].fn_metadata.wrap_output
        assert result["structuredContent"] == ({"result": expected} if wrapped else expected)
    assert_received(fakes, name, VALID_ARGS[name])


@pytest.mark.parametrize("name", WITH_REQUIRED)
def test_mcp_missing_required_arguments_is_an_error_result(session, fakes, name):
    result = session.call(name, {})

    assert result["isError"] is True
    text = result["content"][0]["text"]
    assert all(p in text for p in required_params(name)), text
    assert name not in fakes.calls


@pytest.mark.parametrize("name", sorted(WRONG_TYPE))
def test_mcp_wrongly_typed_argument_is_an_error_result(session, fakes, name):
    assert session.call(name, WRONG_TYPE[name])["isError"] is True
    assert name not in fakes.calls


@pytest.mark.parametrize("name", ALL)
def test_mcp_tool_error_is_an_error_result_with_the_message(session, fakes, name):
    fakes.raises[name] = NotFound(f"{name}: nothing there")

    result = session.call(name, VALID_ARGS[name])

    assert result["isError"] is True
    assert f"{name}: nothing there" in result["content"][0]["text"]


def test_mcp_unknown_tool_is_an_error_result(session):
    result = session.call("no_such_tool", {})

    assert result["isError"] is True
    assert "Unknown tool" in result["content"][0]["text"]


def test_mcp_needs_the_token(mcp_client):
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    for headers in ({}, {"Authorization": "Bearer wrong"}):
        h = {"Accept": "application/json, text/event-stream", **headers}
        assert mcp_client.post("/mcp", json=body, headers=h).status_code == 401


def test_mcp_refuses_a_non_local_host_header(mcp_client):
    """Pinned current behaviour: the MCP SDK's DNS-rebinding guard accepts only
    localhost, 127.0.0.1 and [::1] as Host. A client reaching the container at
    host.docker.internal or the bridge address gets 421 on /mcp — /api does
    not have the guard and answers there."""
    h = {**McpSession.HEADERS, "Host": "172.17.0.1:1351"}
    body = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-03-26", "capabilities": {},
        "clientInfo": {"name": "t", "version": "0"}}}
    assert mcp_client.post("/mcp", json=body, headers=h).status_code == 421
    api = mcp_client.post("/api/list_uploads", json={}, headers={**AUTH, "Host": "172.17.0.1:1351"})
    assert api.status_code == 200


def test_mcp_refuses_a_call_without_a_session(mcp_client, fakes):
    r = mcp_client.post("/mcp", headers=McpSession.HEADERS, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "list_uploads", "arguments": {}}})

    assert r.status_code == 400
    assert fakes.calls == {}
