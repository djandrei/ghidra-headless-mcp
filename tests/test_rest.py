"""/api/<tool>: the tools as plain HTTP/JSON, with status codes that mean something.

Unit tests only — no JVM. Each drives the real --http app (auth middleware,
routing, the tool layer) and stubs headless.export where a tool would reach
Ghidra.
"""

import json
import threading
import time

import pytest
from mcp.types import ImageContent, TextContent
from starlette.testclient import TestClient

import ghidra_headless_mcp as entry
from ghmcp import headless, rest
from ghmcp.errors import ExportFailure, GhidraError, HeadlessTimeout

KEY = "correct-horse-battery-staple"
AUTH = {"Authorization": f"Bearer {KEY}"}

INFO = {
    "name": "keycheck",
    "language_id": "x86:LE:64:default",
    "compiler_spec_id": "gcc",
    "image_base": "00400000",
    "function_count": 11,
    "symbol_count": 40,
}


@pytest.fixture
def client(project, monkeypatch):
    monkeypatch.delenv("UPLOAD_DIR", raising=False)
    return TestClient(entry.build_http_app(KEY), raise_server_exceptions=False)


def post(client, tool, body=None, **kw):
    kw.setdefault("headers", AUTH)
    if body is not None and "content" not in kw:
        kw["json"] = body
    return client.post(f"/api/{tool}", **kw)


def export_returning(monkeypatch, value=None, raises=None, delay=0.0):
    def fake(program, mode, args=None, **_kw):
        time.sleep(delay)
        if raises is not None:
            raise raises
        return value

    monkeypatch.setattr(headless, "export", fake)


# ------------------------------------------------------------------ success


def test_a_successful_call_returns_the_tool_result(client, monkeypatch):
    export_returning(monkeypatch, INFO)

    r = post(client, "get_program_info", {"program": "keycheck"})

    assert r.status_code == 200
    assert r.json()["name"] == "keycheck"
    assert r.json()["function_count"] == 11


def test_the_body_matches_what_mcpo_returns(client, monkeypatch, project):
    """A client moves between the surfaces by changing only its base URL."""
    import asyncio

    from mcpo.utils.main import process_tool_response
    from mcp.types import CallToolResult

    from ghmcp.tools import mcp

    export_returning(monkeypatch, INFO)
    content, _ = asyncio.run(mcp.call_tool("get_program_info", {"program": "keycheck"}))
    [mcpo_body] = process_tool_response(CallToolResult(content=content))

    assert post(client, "get_program_info", {"program": "keycheck"}).json() == mcpo_body


def test_an_empty_body_means_no_arguments(client):
    r = post(client, "list_uploads", content=b"")

    assert r.status_code == 200
    assert r.json()["uploads"] == []


# --------------------------------------------- the caller's fault: 4xx, final


def test_a_missing_file_is_404_not_500(client):
    r = post(client, "analyze_binary", {"binary_path": "/nope/missing.bin"})

    assert r.status_code == 404
    assert r.json() == {
        "error": {"kind": "not_found", "message": "binary not found: /nope/missing.bin"}
    }


def test_a_bad_argument_is_400(client):
    r = post(client, "upload_binary", {"filename": "../x", "content_base64": "QUJD"})

    assert r.status_code == 400
    assert r.json()["error"]["kind"] == "bad_argument"
    assert "path separators" in r.json()["error"]["message"]


def test_an_oversized_upload_is_400_and_not_worth_retrying(client, monkeypatch):
    from ghmcp import config

    monkeypatch.setattr(config, "MAX_UPLOAD_BYTES", 4)
    r = post(client, "upload_binary", {"filename": "a.bin", "content_base64": "QUJDREVGR0g="})

    assert r.status_code == 400
    assert "MAX_UPLOAD_BYTES" in r.json()["error"]["message"]


def test_a_missing_argument_is_422_with_the_detail(client):
    r = post(client, "analyze_binary", {})

    assert r.status_code == 422
    err = r.json()["error"]
    assert err["kind"] == "invalid_arguments"
    assert err["detail"][0]["loc"] == ["binary_path"]


def test_a_wrongly_typed_argument_is_422(client):
    r = post(client, "list_functions", {"program": "p", "limit": "many"})

    assert r.status_code == 422


def test_an_unknown_tool_is_404(client):
    r = post(client, "no_such_tool", {})

    assert r.status_code == 404
    assert r.json()["error"] == {"kind": "not_found", "message": "no tool named 'no_such_tool'"}


@pytest.mark.parametrize("body", [b"{not json", b"\xff\xfe", b"[1, 2]", b'"text"'])
def test_a_body_that_is_not_a_json_object_is_400(client, body):
    r = post(client, "list_uploads", content=body)

    assert r.status_code == 400
    assert r.json()["error"]["kind"] == "bad_argument"


# ------------------------------------------------ the server's fault: 5xx


@pytest.mark.parametrize(
    "exc, status, kind",
    [
        (HeadlessTimeout("analyzeHeadless timed out"), 504, "timeout"),
        (GhidraError("decompiler crashed"), 500, "ghidra_error"),
        (ExportFailure("no output"), 500, "export_failure"),
    ],
)
def test_ghidra_failures_are_5xx_with_their_kind(client, monkeypatch, exc, status, kind):
    export_returning(monkeypatch, raises=exc)

    r = post(client, "get_program_info", {"program": "keycheck"})

    assert r.status_code == status
    assert r.json()["error"] == {"kind": kind, "message": str(exc)}


def test_an_unexpected_exception_is_500(client, monkeypatch):
    export_returning(monkeypatch, raises=OSError("disk gone"))

    r = post(client, "get_program_info", {"program": "keycheck"})

    assert r.status_code == 500
    assert r.json()["error"] == {"kind": "error", "message": "disk gone"}


def test_a_validation_error_inside_a_tool_is_the_servers_fault(client, monkeypatch):
    """An export of the wrong shape is a 500, not a 422 blaming the caller."""
    export_returning(monkeypatch, {"name": "keycheck"})

    r = post(client, "get_program_info", {"program": "keycheck"})

    assert r.status_code == 500
    assert r.json()["error"]["kind"] == "error"


def test_a_tool_error_with_no_cause_is_500():
    from mcp.server.fastmcp.exceptions import ToolError

    r = rest.failure_response("x", ToolError("bare"))

    assert r.status_code == 500
    assert json.loads(r.body)["error"] == {"kind": "error", "message": "bare"}


# ------------------------------------------------------------------- auth


def test_api_needs_the_token(client):
    r = client.post("/api/list_uploads", json={})

    assert r.status_code == 401


def test_a_wrong_token_is_refused(client):
    r = client.post("/api/list_uploads", json={}, headers={"Authorization": "Bearer nope"})

    assert r.status_code == 401


def test_only_post_is_routed(client):
    assert client.get("/api/list_uploads", headers=AUTH).status_code == 405


# ------------------------------------------------- the event loop stays free


def test_healthz_answers_while_a_slow_tool_runs(project, monkeypatch):
    """A long analysis must not stall every other request on the process."""
    export_returning(monkeypatch, INFO, delay=2.0)
    app = entry.build_http_app(KEY)

    with TestClient(app) as shared:  # one event loop for both requests
        slow = threading.Thread(
            target=post, args=(shared, "get_program_info", {"program": "keycheck"})
        )
        slow.start()
        time.sleep(0.3)
        started = time.monotonic()
        assert shared.get("/healthz").status_code == 200
        waited = time.monotonic() - started
        slow.join()

    assert waited < 1.0


# --------------------------------------------------------- content_to_json


def test_content_is_decoded_like_mcpo_does():
    blocks = [
        TextContent(type="text", text='{"a": 1}'),
        TextContent(type="text", text="plain words"),
        ImageContent(type="image", data="AAAA", mimeType="image/png"),
    ]

    assert rest.content_to_json(blocks) == [{"a": 1}, "plain words"]
    assert rest.content_to_json(blocks[:1]) == {"a": 1}
