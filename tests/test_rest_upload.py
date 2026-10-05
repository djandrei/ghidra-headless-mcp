"""POST /api/upload: raw bytes streamed to disk, for programs.

Unit tests only — no JVM; analyze_binary is replaced where a call would reach
Ghidra. The memory test drives the ASGI app directly, because Starlette's
TestClient reads a whole request body into memory before sending it.
"""

import asyncio
import base64
import hashlib
import tracemalloc
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import ghidra_headless_mcp as entry
from ghmcp import config, tools

KEY = "correct-horse-battery-staple"
AUTH = {"Authorization": f"Bearer {KEY}"}
BLOB = b"\x7fELF" + bytes(range(256)) * 64


@pytest.fixture
def uploads(project, monkeypatch):
    monkeypatch.delenv("UPLOAD_DIR", raising=False)
    return project / "samples"


@pytest.fixture
def client(uploads):
    return TestClient(entry.build_http_app(KEY), raise_server_exceptions=False)


def upload(client, data=BLOB, headers=None, **params):
    params.setdefault("filename", "sample.bin")
    return client.post(
        "/api/upload",
        params={k: str(v).lower() for k, v in params.items()},
        content=data,
        headers={**AUTH, "Content-Type": "application/octet-stream", **(headers or {})},
    )


@pytest.fixture
def analyze_spy(monkeypatch):
    calls = []

    def spy(path, force=False):
        p = Path(path)
        calls.append({"path": p, "bytes": p.read_bytes(), "force": force})
        return None

    monkeypatch.setattr(tools, "analyze_binary", spy)
    return calls


# ------------------------------------------------------------------ storing


def test_the_body_is_stored_under_the_name_with_its_hashes(client, uploads):
    r = upload(client)

    assert r.status_code == 200
    body = r.json()
    assert (uploads / "sample.bin").read_bytes() == BLOB
    assert body["path"] == str(uploads / "sample.bin")
    assert body["size"] == len(BLOB)
    assert body["md5"] == hashlib.md5(BLOB).hexdigest()
    assert body["sha256"] == hashlib.sha256(BLOB).hexdigest()
    assert body["written"] and body["kept"]
    assert [p.name for p in uploads.iterdir()] == ["sample.bin"]


def test_the_body_matches_upload_binary_through_api(client, uploads):
    """The two routes are one implementation: same file, same answer."""
    streamed = upload(client).json()
    via_tool = client.post(
        "/api/upload_binary",
        json={"filename": "sample.bin", "content_base64": base64.b64encode(BLOB).decode()},
        headers=AUTH,
    ).json()

    assert via_tool == {**streamed, "written": False}


def test_identical_content_writes_nothing_and_different_needs_overwrite(client, uploads):
    upload(client)
    assert upload(client).json()["written"] is False

    refused = upload(client, b"other")
    assert refused.status_code == 400
    assert "overwrite" in refused.json()["error"]["message"]

    replaced = upload(client, b"other", overwrite=True)
    assert replaced.json()["replaced"] is True
    assert (uploads / "sample.bin").read_bytes() == b"other"


def test_unusual_characters_are_sanitised_like_upload_binary(client, uploads):
    assert upload(client, filename="my crackme.exe").json()["filename"] == "my_crackme.exe"


# -------------------------------------------------------- analyze and keep


def test_analyze_true_keep_false_imports_and_discards(client, uploads, analyze_spy):
    r = upload(client, analyze=True, keep=False)

    assert r.status_code == 200
    assert r.json()["kept"] is False and r.json()["path"] is None
    assert analyze_spy[0]["bytes"] == BLOB
    assert analyze_spy[0]["path"].name == "sample.bin"
    assert list(uploads.iterdir()) == []


def test_analyze_true_imports_the_stored_file(client, uploads, analyze_spy):
    upload(client, analyze=True)

    assert analyze_spy[0]["path"] == uploads / "sample.bin"


def test_an_import_failure_is_mapped_like_any_tool_error(client, uploads, monkeypatch):
    from ghmcp.errors import BadArgument

    def not_a_binary(path, force=False):
        raise BadArgument("Ghidra could not load it")

    monkeypatch.setattr(tools, "analyze_binary", not_a_binary)

    r = upload(client, analyze=True, keep=False)

    assert r.status_code == 400
    assert r.json()["error"] == {"kind": "bad_argument", "message": "Ghidra could not load it"}
    assert list(uploads.iterdir()) == []


# ----------------------------------------------------- refused before reading


@pytest.mark.parametrize("name", ["", "../x", "a/b", ".hidden"])
def test_a_bad_filename_is_400_and_nothing_is_written(client, uploads, name):
    r = upload(client, filename=name)

    assert r.status_code == 400
    assert r.json()["error"]["kind"] == "bad_argument"
    assert not uploads.exists()


def test_keep_false_without_analyze_is_400(client, uploads):
    r = upload(client, keep=False)

    assert r.status_code == 400
    assert "analyze=True" in r.json()["error"]["message"]


def test_a_flag_that_is_not_a_boolean_is_400(client, uploads):
    r = upload(client, analyze="maybe")

    assert r.status_code == 400
    assert "analyze must be true or false" in r.json()["error"]["message"]


@pytest.mark.parametrize("value, expected", [("1", True), ("YES", True), ("off", False)])
def test_flags_accept_the_usual_spellings(client, uploads, analyze_spy, value, expected):
    upload(client, analyze=value)

    assert bool(analyze_spy) is expected


def test_an_empty_body_is_400(client, uploads):
    r = upload(client, b"")

    assert r.status_code == 400
    assert "empty" in r.json()["error"]["message"]
    assert list(uploads.iterdir()) == []


def test_the_upload_route_needs_the_token(client, uploads):
    r = client.post("/api/upload", params={"filename": "a.bin"}, content=BLOB)

    assert r.status_code == 401
    assert not uploads.exists()


# ---------------------------------------------------------------- the cap


def test_a_declared_length_over_the_cap_is_413_before_reading(client, uploads, monkeypatch):
    monkeypatch.setattr(config, "MAX_STREAM_UPLOAD_BYTES", 10)

    r = upload(client, b"x" * 11)

    assert r.status_code == 413
    assert r.json()["error"]["kind"] == "too_large"
    assert "MAX_STREAM_UPLOAD_BYTES" in r.json()["error"]["message"]
    assert not uploads.exists()


def test_a_body_exactly_at_the_cap_is_accepted(client, uploads, monkeypatch):
    monkeypatch.setattr(config, "MAX_STREAM_UPLOAD_BYTES", 10)

    assert upload(client, b"x" * 10).status_code == 200


def test_a_non_numeric_content_length_is_400():
    scope_headers = [(b"authorization", f"Bearer {KEY}".encode()), (b"content-length", b"lots")]
    status, body, _ = drive(entry.build_http_app(KEY), [b"x"], scope_headers)

    assert status == 400
    assert b"Content-Length" in body


# ---------------------------------------------- streaming, driven over ASGI


def drive(app, chunks, headers, query=b"filename=big.bin"):
    """One ASGI request whose body arrives chunk by chunk from an iterator.

    Returns (status, body, peak_traced_bytes). The chunks are produced on
    demand, so the test itself never holds the whole body either.
    """
    chunks = iter(chunks)
    sent = []

    async def receive():
        chunk = next(chunks, None)
        if chunk is None:
            return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.request", "body": chunk, "more_body": True}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": "POST", "scheme": "http", "path": "/api/upload", "raw_path": b"/api/upload",
        "root_path": "", "query_string": query, "headers": headers,
        "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 1351),
    }
    tracemalloc.start()
    try:
        asyncio.run(app(scope, receive, send))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, body, peak


def test_a_large_upload_is_never_held_in_memory(uploads):
    """The point of streaming: 64 MiB in, a few hundred KB of Python memory."""
    chunk = bytes(range(256)) * 256  # 64 KiB
    count = 1024
    digest = hashlib.sha256()
    for _ in range(count):
        digest.update(chunk)

    status, body, peak = drive(
        entry.build_http_app(KEY),
        (chunk for _ in range(count)),
        [(b"authorization", f"Bearer {KEY}".encode())],
    )

    assert status == 200, body
    stored = uploads / "big.bin"
    assert stored.stat().st_size == len(chunk) * count
    assert f'"sha256":"{digest.hexdigest()}"'.encode() in body
    assert peak < 4 * 1024 * 1024


def test_an_undeclared_body_over_the_cap_is_cut_off_and_removed(uploads, monkeypatch):
    monkeypatch.setattr(config, "MAX_STREAM_UPLOAD_BYTES", 100)

    status, body, _ = drive(
        entry.build_http_app(KEY),
        (b"x" * 40 for _ in range(10)),
        [(b"authorization", f"Bearer {KEY}".encode())],
    )

    assert status == 413
    assert b"too_large" in body
    assert list(uploads.iterdir()) == []


def test_a_client_that_disconnects_leaves_no_partial_file(uploads):
    app = entry.build_http_app(KEY)
    messages = iter([
        {"type": "http.request", "body": b"x" * 100, "more_body": True},
        {"type": "http.disconnect"},
    ])

    async def receive():
        return next(messages)

    async def send(message):
        pass

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": "POST", "scheme": "http", "path": "/api/upload", "raw_path": b"/api/upload",
        "root_path": "", "query_string": b"filename=cut.bin",
        "headers": [(b"authorization", f"Bearer {KEY}".encode())],
        "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 1351),
    }
    from starlette.requests import ClientDisconnect

    with pytest.raises(ClientDisconnect):
        asyncio.run(app(scope, receive, send))
    assert list(uploads.iterdir()) == []
