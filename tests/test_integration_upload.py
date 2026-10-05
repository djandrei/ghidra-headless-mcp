"""End-to-end: a binary sent through upload_binary is analysed by real Ghidra.

The point is the hand-off — the bytes arrive base64-encoded, land in the upload
directory, and analyze_binary imports them from there — so one sample suffices.

Run with: pytest -m integration
"""

import base64

import pytest

from ghmcp import config, tools
from tests.conftest import KEYCHECK, KNOWN_FUNCTION

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def uploaded(tmp_path_factory):
    if not KEYCHECK.is_file():
        pytest.skip(f"fixture missing: {KEYCHECK}")
    loc = tmp_path_factory.mktemp("uploadtest")
    config.PROJECT_LOCATION = loc
    config.PROJECT_NAME = "upload-test"
    encoded = base64.b64encode(KEYCHECK.read_bytes()).decode()
    return tools.upload_binary("uploaded-keycheck", encoded, analyze=True)


def test_the_upload_lands_beside_the_project(uploaded):
    assert uploaded.path == str(config.PROJECT_LOCATION / "samples" / "uploaded-keycheck")
    assert uploaded.written


def test_analyze_true_imports_the_uploaded_file(uploaded):
    assert uploaded.analysis is not None
    assert uploaded.analysis.program == "uploaded-keycheck"
    assert uploaded.analysis.info.md5 == uploaded.md5


def test_the_uploaded_program_answers_queries(uploaded):
    out = tools.decompile_function(uploaded.analysis.program, KNOWN_FUNCTION)
    assert KNOWN_FUNCTION in out.c


def test_reuploading_reuses_the_existing_analysis(uploaded):
    encoded = base64.b64encode(KEYCHECK.read_bytes()).decode()
    again = tools.upload_binary("uploaded-keycheck", encoded, analyze=True)
    assert not again.written
    assert again.analysis.already_analyzed


# ------------------------------------------------ the OpenWebUI attachment path


def test_a_chat_attachment_is_found_and_analysed_from_disk(uploaded, tmp_path, monkeypatch):
    """The path the chat should have taken: list_chat_uploads, then analyze_binary.

    Two calls, no bytes through the model.
    """
    chat = tmp_path / "openwebui-uploads"
    chat.mkdir()
    (chat / "6eb39c47-e7e0-46a4-88b4-38081130b00a_attached-keycheck").write_bytes(
        KEYCHECK.read_bytes()
    )
    monkeypatch.setenv("OPENWEBUI_UPLOADS_DIR", str(chat))

    found = tools.list_chat_uploads(pattern="attached")
    assert found.returned == 1
    result = tools.analyze_binary(found.uploads[0].path)

    assert result.info.md5 == uploaded.md5  # the same bytes as the base64 upload
    # Named as attached, not after OpenWebUI's "<uuid>_" storage name.
    assert result.program == "attached-keycheck"
    assert tools.get_program_info("attached-keycheck").md5 == uploaded.md5


def test_asking_about_a_program_never_imported_is_a_short_not_found(uploaded):
    from ghmcp.errors import NotFound

    with pytest.raises(NotFound) as exc:
        tools.get_program_info("keycheck.aarch64")
    assert "list_programs" in str(exc.value) and len(str(exc.value)) < 300


def test_a_text_stub_is_called_out_by_its_bytes(uploaded):
    """The chat's 5-byte test upload, which Ghidra cannot load."""
    from ghmcp.errors import BadArgument

    stub = tools.upload_binary("stub.bin", base64.b64encode(b"HPL\r\n").decode())
    try:
        with pytest.raises(BadArgument) as exc:
            tools.analyze_binary(stub.path)
        assert "5 bytes" in str(exc.value) and "HPL" in str(exc.value)
    finally:
        tools.delete_upload("stub.bin")


# ------------------------------------------------ keep=False: import and discard


def test_keep_false_imports_and_leaves_no_file(uploaded):
    """One call does what a client otherwise needs three and a lock for."""
    encoded = base64.b64encode(KEYCHECK.read_bytes()).decode()

    result = tools.upload_binary("discarded-keycheck", encoded, analyze=True, keep=False)

    assert result.kept is False and result.path is None
    assert result.analysis.program == "discarded-keycheck"
    assert "discarded-keycheck" not in [u.filename for u in tools.list_uploads().uploads]
    samples = config.PROJECT_LOCATION / "samples"
    assert not [p for p in samples.iterdir() if p.name.startswith(".")]
    # The program outlives its file.
    out = tools.decompile_function("discarded-keycheck", KNOWN_FUNCTION)
    assert KNOWN_FUNCTION in out.c


# ------------------------------------------------ POST /api/upload on --http


def test_a_streamed_upload_is_imported_and_discarded(uploaded):
    """The route a program uses: raw bytes, no base64, one request."""
    from starlette.testclient import TestClient

    import ghidra_headless_mcp as entry

    key = "integration-key-long-enough-to-pass-the-check"
    client = TestClient(entry.build_http_app(key))
    auth = {"Authorization": f"Bearer {key}"}

    r = client.post(
        "/api/upload",
        params={"filename": "streamed-keycheck", "analyze": "true", "keep": "false"},
        content=KEYCHECK.read_bytes(),
        headers={**auth, "Content-Type": "application/octet-stream"},
    )

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["kept"] is False and body["analysis"]["program"] == "streamed-keycheck"
    assert body["md5"] == uploaded.md5
    programs = client.post("/api/list_programs", json={}, headers=auth).json()
    assert "streamed-keycheck" in programs["programs"]
    missing = client.post(
        "/api/get_program_info", json={"program": "never-imported"}, headers=auth
    )
    assert missing.status_code == 404
