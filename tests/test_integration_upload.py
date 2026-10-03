"""End-to-end: a binary sent through upload_binary is analysed by real Ghidra.

The point is the hand-off — the bytes arrive base64-encoded, land in the upload
directory, and analyze_binary imports them from there — so one sample suffices.

Run with: pytest -m integration
"""

import base64

import pytest

from ghmcp import config, tools
from tests.conftest import KNOWN_FUNCTION, STARTER05

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def uploaded(tmp_path_factory):
    if not STARTER05.is_file():
        pytest.skip(f"fixture missing: {STARTER05}")
    loc = tmp_path_factory.mktemp("uploadtest")
    config.PROJECT_LOCATION = loc
    config.PROJECT_NAME = "upload-test"
    encoded = base64.b64encode(STARTER05.read_bytes()).decode()
    return tools.upload_binary("uploaded-starter05", encoded, analyze=True)


def test_the_upload_lands_beside_the_project(uploaded):
    assert uploaded.path == str(config.PROJECT_LOCATION / "samples" / "uploaded-starter05")
    assert uploaded.written


def test_analyze_true_imports_the_uploaded_file(uploaded):
    assert uploaded.analysis is not None
    assert uploaded.analysis.program == "uploaded-starter05"
    assert uploaded.analysis.info.md5 == uploaded.md5


def test_the_uploaded_program_answers_queries(uploaded):
    out = tools.decompile_function(uploaded.analysis.program, KNOWN_FUNCTION)
    assert KNOWN_FUNCTION in out.c


def test_reuploading_reuses_the_existing_analysis(uploaded):
    encoded = base64.b64encode(STARTER05.read_bytes()).decode()
    again = tools.upload_binary("uploaded-starter05", encoded, analyze=True)
    assert not again.written
    assert again.analysis.already_analyzed


# ------------------------------------------------ the OpenWebUI attachment path


def test_a_chat_attachment_is_found_and_analysed_from_disk(uploaded, tmp_path, monkeypatch):
    """The path the chat should have taken: list_chat_uploads, then analyze_binary.

    Two calls, no bytes through the model.
    """
    chat = tmp_path / "openwebui-uploads"
    chat.mkdir()
    (chat / "6eb39c47-e7e0-46a4-88b4-38081130b00a_attached-starter05").write_bytes(
        STARTER05.read_bytes()
    )
    monkeypatch.setenv("OPENWEBUI_UPLOADS_DIR", str(chat))

    found = tools.list_chat_uploads(pattern="attached")
    assert found.returned == 1
    result = tools.analyze_binary(found.uploads[0].path)

    assert result.info.md5 == uploaded.md5  # the same bytes as the base64 upload


def test_asking_about_a_program_never_imported_is_a_short_not_found(uploaded):
    from ghmcp.errors import NotFound

    with pytest.raises(NotFound) as exc:
        tools.get_program_info("demo_keycheck.aarch64")
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
