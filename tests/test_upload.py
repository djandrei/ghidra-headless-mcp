"""upload_binary: getting a file onto the server through the tool surface.

Unit tests only — no JVM. The one path that reaches Ghidra (analyze=True) is
checked by replacing analyze_binary, and for real in test_integration_upload.
"""

import base64
import hashlib
import stat

import pytest

from ghmcp import config, tools
from ghmcp.errors import BadArgument

BLOB = b"\x7fELF" + bytes(range(256)) * 4


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


@pytest.fixture
def uploads(project, monkeypatch):
    """The default upload directory under the throwaway project."""
    monkeypatch.delenv("UPLOAD_DIR", raising=False)
    return project / "samples"


def test_stores_the_file_beside_the_project_and_reports_its_hashes(uploads):
    result = tools.upload_binary("sample.bin", b64(BLOB))

    target = uploads / "sample.bin"
    assert target.read_bytes() == BLOB
    assert result.path == str(target)
    assert result.filename == "sample.bin"
    assert result.size == len(BLOB)
    assert result.md5 == hashlib.md5(BLOB).hexdigest()
    assert result.sha256 == hashlib.sha256(BLOB).hexdigest()
    assert result.written and not result.replaced
    assert result.analysis is None


def test_stored_file_is_not_executable(uploads):
    tools.upload_binary("sample.bin", b64(BLOB))

    mode = (uploads / "sample.bin").stat().st_mode
    assert not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def test_upload_dir_env_overrides_the_default(project, tmp_path, monkeypatch):
    elsewhere = tmp_path / "elsewhere"
    monkeypatch.setenv("UPLOAD_DIR", str(elsewhere))

    result = tools.upload_binary("sample.bin", b64(BLOB))

    assert result.path == str(elsewhere / "sample.bin")
    assert not (project / "samples").exists()


def test_line_wrapped_base64_is_accepted(uploads):
    encoded = b64(BLOB)
    wrapped = "\n".join(encoded[i : i + 76] for i in range(0, len(encoded), 76))

    assert tools.upload_binary("sample.bin", wrapped).size == len(BLOB)


@pytest.mark.parametrize(
    "name", ["../escape.bin", "a/b.bin", "/etc/passwd", "..\\x.bin", "x\x00.bin", ""]
)
def test_names_that_choose_a_directory_are_refused(uploads, name):
    with pytest.raises(BadArgument):
        tools.upload_binary(name, b64(BLOB))
    assert not uploads.exists() or not any(uploads.iterdir())


@pytest.mark.parametrize("name", [".", "..", ".hidden"])
def test_names_starting_with_a_dot_are_refused(uploads, name):
    with pytest.raises(BadArgument, match="start with"):
        tools.upload_binary(name, b64(BLOB))


def test_unusual_characters_become_underscores(uploads):
    result = tools.upload_binary("_xk's crack me!.exe", b64(BLOB))

    assert result.filename == "_xk_s_crack_me_.exe"
    assert (uploads / "_xk_s_crack_me_.exe").is_file()


def test_overlong_names_are_refused(uploads):
    with pytest.raises(BadArgument, match="longer than"):
        tools.upload_binary("a" * 201, b64(BLOB))


def test_invalid_base64_is_refused(uploads):
    with pytest.raises(BadArgument, match="not valid base64"):
        tools.upload_binary("sample.bin", "this is not base64!!")


def test_empty_content_is_refused(uploads):
    with pytest.raises(BadArgument, match="empty"):
        tools.upload_binary("sample.bin", "")


def test_oversized_upload_is_refused_without_writing(uploads, monkeypatch):
    monkeypatch.setattr(config, "MAX_UPLOAD_BYTES", 100)

    with pytest.raises(BadArgument, match="upload limit"):
        tools.upload_binary("sample.bin", b64(b"x" * 101))
    assert not (uploads / "sample.bin").exists()


def test_a_file_exactly_at_the_limit_is_accepted(uploads, monkeypatch):
    monkeypatch.setattr(config, "MAX_UPLOAD_BYTES", 100)

    assert tools.upload_binary("sample.bin", b64(b"x" * 100)).size == 100


def test_identical_reupload_writes_nothing(uploads):
    tools.upload_binary("sample.bin", b64(BLOB))
    before = (uploads / "sample.bin").stat().st_mtime_ns

    again = tools.upload_binary("sample.bin", b64(BLOB))

    assert not again.written and not again.replaced
    assert (uploads / "sample.bin").stat().st_mtime_ns == before


def test_different_content_under_a_taken_name_needs_overwrite(uploads):
    tools.upload_binary("sample.bin", b64(BLOB))

    with pytest.raises(BadArgument, match="overwrite=True"):
        tools.upload_binary("sample.bin", b64(b"other"))
    assert (uploads / "sample.bin").read_bytes() == BLOB


def test_overwrite_replaces_a_different_file(uploads):
    tools.upload_binary("sample.bin", b64(BLOB))

    result = tools.upload_binary("sample.bin", b64(b"other"), overwrite=True)

    assert result.written and result.replaced
    assert (uploads / "sample.bin").read_bytes() == b"other"


def test_a_symlink_in_the_upload_dir_is_never_written_through(uploads, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"keep me")
    uploads.mkdir(parents=True)
    (uploads / "sample.bin").symlink_to(outside)

    with pytest.raises(BadArgument, match="symlink"):
        tools.upload_binary("sample.bin", b64(BLOB), overwrite=True)
    assert outside.read_bytes() == b"keep me"


def test_no_temporary_files_are_left_behind(uploads):
    tools.upload_binary("sample.bin", b64(BLOB))

    assert [p.name for p in uploads.iterdir()] == ["sample.bin"]


def test_analyze_true_hands_the_stored_path_to_analyze_binary(uploads, monkeypatch):
    calls = []
    sentinel = object()
    monkeypatch.setattr(
        tools, "analyze_binary", lambda path, force=False: calls.append((path, force)) or sentinel
    )
    monkeypatch.setattr(tools, "UploadResult", lambda **kw: kw)

    result = tools.upload_binary("sample.bin", b64(BLOB), analyze=True)

    assert calls == [(str(uploads / "sample.bin"), False)]
    assert result["analysis"] is sentinel


def test_replacing_a_file_reanalyses_it(uploads, monkeypatch):
    calls = []
    monkeypatch.setattr(
        tools, "analyze_binary", lambda path, force=False: calls.append(force)
    )
    monkeypatch.setattr(tools, "UploadResult", lambda **kw: kw)
    tools.upload_binary("sample.bin", b64(BLOB))

    tools.upload_binary("sample.bin", b64(b"other"), overwrite=True, analyze=True)

    assert calls == [True]
