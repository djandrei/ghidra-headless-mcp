"""upload_binary: getting a file onto the server through the tool surface.

Unit tests only — no JVM. The one path that reaches Ghidra (analyze=True) is
checked by replacing analyze_binary, and for real in test_integration_upload.
"""

import base64
import hashlib
import os
import stat
import time
from pathlib import Path

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


# --------------------------------------------- keep=False: import and discard


@pytest.fixture
def analyze_spy(monkeypatch):
    """Replace analyze_binary with a recorder that notes what it could see."""
    calls = []

    def spy(path, force=False):
        p = Path(path)
        calls.append({"path": p, "existed": p.is_file(), "bytes": p.read_bytes(),
                      "force": force})
        return None

    monkeypatch.setattr(tools, "analyze_binary", spy)
    return calls


def test_keep_false_imports_the_file_then_leaves_nothing_behind(uploads, analyze_spy):
    result = tools.upload_binary("sample.bin", b64(BLOB), analyze=True, keep=False)

    [call] = analyze_spy
    assert call["existed"] and call["bytes"] == BLOB
    # Imported under its own name, so the program is named as usual.
    assert call["path"].name == "sample.bin"
    assert not call["path"].exists()
    assert list(uploads.iterdir()) == []
    assert result.kept is False and result.path is None
    assert result.filename == "sample.bin" and result.size == len(BLOB)
    assert result.sha256 == hashlib.sha256(BLOB).hexdigest()


def test_keep_false_never_uses_the_shared_upload_path(uploads, analyze_spy):
    """Two clients sending one name must not reach each other's file."""
    tools.upload_binary("sample.bin", b64(BLOB), analyze=True, keep=False)
    tools.upload_binary("sample.bin", b64(BLOB), analyze=True, keep=False)

    first, second = (c["path"] for c in analyze_spy)
    assert first.parent != second.parent
    assert uploads not in (first.parent, second.parent)
    assert all(c["path"].parent.parent == uploads for c in analyze_spy)


def test_keep_false_leaves_a_stored_file_of_the_same_name_alone(uploads, analyze_spy):
    tools.upload_binary("sample.bin", b64(b"stored"))

    tools.upload_binary("sample.bin", b64(BLOB), analyze=True, keep=False)

    assert (uploads / "sample.bin").read_bytes() == b"stored"
    assert analyze_spy[0]["bytes"] == BLOB


def test_keep_false_cleans_up_when_the_import_fails(uploads, monkeypatch):
    from ghmcp.errors import GhidraError

    def fail(path, force=False):
        raise GhidraError("analysis failed")

    monkeypatch.setattr(tools, "analyze_binary", fail)

    with pytest.raises(GhidraError):
        tools.upload_binary("sample.bin", b64(BLOB), analyze=True, keep=False)
    assert list(uploads.iterdir()) == []


def test_keep_false_without_analyze_is_refused_before_anything_is_written(uploads):
    with pytest.raises(BadArgument, match="analyze=True"):
        tools.upload_binary("sample.bin", b64(BLOB), keep=False)
    assert not uploads.exists()


def test_keep_false_is_absent_from_a_kept_result(uploads):
    result = tools.upload_binary("sample.bin", b64(BLOB))

    assert result.kept is True and result.path == str(uploads / "sample.bin")


def test_a_refused_upload_leaves_no_temporary_file(uploads):
    tools.upload_binary("sample.bin", b64(BLOB))

    with pytest.raises(BadArgument, match="different file"):
        tools.upload_binary("sample.bin", b64(b"other"))
    assert [p.name for p in uploads.iterdir()] == ["sample.bin"]


def test_a_failed_temporary_write_leaves_nothing(uploads, monkeypatch):
    def broken_fdopen(fd, mode):
        os.close(fd)
        raise OSError("disk full")

    monkeypatch.setattr(tools.os, "fdopen", broken_fdopen)

    with pytest.raises(OSError, match="disk full"):
        tools.upload_binary("sample.bin", b64(BLOB))
    assert list(uploads.iterdir()) == []


# ------------------------------------------------- stale temporary entries


def _age(path: Path, seconds: float) -> None:
    then = time.time() - seconds
    os.utime(path, (then, then), follow_symlinks=False)


def test_stale_temporary_entries_are_swept_on_the_next_upload(uploads, monkeypatch):
    monkeypatch.setattr(config, "ANALYZE_TIMEOUT_S", 10)
    uploads.mkdir(parents=True)
    stale_dir = uploads / ".import-old"
    stale_dir.mkdir()
    (stale_dir / "big.bin").write_bytes(BLOB)
    stale_file = uploads / ".upload-old"
    stale_file.write_bytes(BLOB)
    _age(stale_dir, 21)
    _age(stale_file, 21)

    tools.upload_binary("sample.bin", b64(BLOB))

    assert sorted(p.name for p in uploads.iterdir()) == ["sample.bin"]


def test_fresh_temporary_entries_belong_to_a_live_call_and_stay(uploads, monkeypatch):
    monkeypatch.setattr(config, "ANALYZE_TIMEOUT_S", 10)
    uploads.mkdir(parents=True)
    (uploads / ".import-live").mkdir()
    (uploads / ".upload-live").write_bytes(b"x")
    _age(uploads / ".upload-live", 19)

    tools.upload_binary("sample.bin", b64(BLOB))

    assert sorted(p.name for p in uploads.iterdir()) == [
        ".import-live", ".upload-live", "sample.bin",
    ]


def test_the_sweep_touches_only_its_own_prefixes(uploads, monkeypatch):
    monkeypatch.setattr(config, "ANALYZE_TIMEOUT_S", 10)
    uploads.mkdir(parents=True)
    for name in ("old.bin", ".hidden"):
        (uploads / name).write_bytes(b"x")
        _age(uploads / name, 1000)

    assert tools.sweep_stale_uploads(uploads) == []
    assert sorted(p.name for p in uploads.iterdir()) == [".hidden", "old.bin"]


def test_the_sweep_removes_a_stale_symlink_without_following_it(uploads, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ANALYZE_TIMEOUT_S", 10)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")
    uploads.mkdir(parents=True)
    link = uploads / ".import-link"
    link.symlink_to(outside, target_is_directory=True)
    _age(link, 1000)

    assert tools.sweep_stale_uploads(uploads) == [".import-link"]
    assert not link.is_symlink() and (outside / "keep.txt").read_text() == "keep"


# ------------------------------------------- a text rendering is not base64


def test_a_text_rendering_of_a_binary_is_named_as_such(uploads):
    """What a model pasted from an OpenWebUI attachment: extracted text."""
    rendering = "ELF·@@\n@8@@@@@@øø88@8@@@ èýèýA"

    with pytest.raises(BadArgument) as exc:
        tools.upload_binary("demo_keycheck.aarch64", rendering)

    msg = str(exc.value)
    assert "not base64" in msg and "list_chat_uploads" in msg
    assert not uploads.exists() or not any(uploads.iterdir())


def test_control_characters_are_named_the_same_way(uploads):
    with pytest.raises(BadArgument, match="list_chat_uploads"):
        tools.upload_binary("x.bin", "\x7fELF\x02\x01\x01")


def test_plain_invalid_ascii_keeps_the_generic_message(uploads):
    with pytest.raises(BadArgument, match="not valid base64") as exc:
        tools.upload_binary("x.bin", "abc$def")
    assert "list_chat_uploads" not in str(exc.value)


# ------------------------------------------------- list_uploads / delete_upload


def test_list_uploads_shows_stored_files_and_hides_temp_files(uploads):
    tools.upload_binary("b.bin", b64(BLOB))
    tools.upload_binary("a.bin", b64(b"other"))
    (uploads / ".upload-xyz").write_bytes(b"in flight")

    out = tools.list_uploads()

    assert out.directory == str(uploads)
    assert [u.filename for u in out.uploads] == ["a.bin", "b.bin"]
    assert out.uploads[1].size == len(BLOB)


def test_list_uploads_is_empty_before_anything_is_stored(uploads):
    assert tools.list_uploads().uploads == []


def test_delete_upload_removes_the_file(uploads):
    tools.upload_binary("stub.bin", b64(b"HPL\r\n"))

    out = tools.delete_upload("stub.bin")

    assert out.deleted and out.path == str(uploads / "stub.bin")
    assert not (uploads / "stub.bin").exists()


def test_after_deleting_a_stub_the_real_file_uploads_without_overwrite(uploads):
    """The chat's trap: a 5-byte test stub squatting on the real name."""
    tools.upload_binary("demo_keycheck.aarch64", b64(b"HPL\r\n"))
    tools.delete_upload("demo_keycheck.aarch64")

    assert tools.upload_binary("demo_keycheck.aarch64", b64(BLOB)).written


def test_deleting_a_missing_upload_is_not_found(uploads):
    from ghmcp.errors import NotFound

    with pytest.raises(NotFound, match="list_uploads"):
        tools.delete_upload("nothing.bin")


@pytest.mark.parametrize("name", ["../escape.bin", "a/b.bin", "/etc/passwd", ".hidden", ".."])
def test_delete_upload_never_leaves_the_upload_directory(uploads, tmp_path, name):
    with pytest.raises(BadArgument):
        tools.delete_upload(name)


def test_a_name_that_sanitising_would_change_is_refused(uploads):
    """Else "a b.bin" would delete "a_b.bin" — a different file."""
    tools.upload_binary("a_b.bin", b64(BLOB))

    with pytest.raises(BadArgument, match="list_uploads"):
        tools.delete_upload("a b.bin")
    assert (uploads / "a_b.bin").exists()


def test_delete_upload_refuses_a_symlink(uploads, tmp_path):
    outside = tmp_path / "keep.txt"
    outside.write_text("keep")
    uploads.mkdir(parents=True)
    (uploads / "link.bin").symlink_to(outside)

    with pytest.raises(BadArgument, match="not a plain file"):
        tools.delete_upload("link.bin")
    assert outside.read_text() == "keep" and (uploads / "link.bin").is_symlink()
