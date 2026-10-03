"""list_chat_uploads: finding a file the user attached in OpenWebUI.

The case that motivated it: a model was given an attachment, saw only
OpenWebUI's text extraction of it, tried to base64 that through upload_binary,
and concluded the file was not on the server — while OpenWebUI had saved it to
a directory the server could read all along.
"""

import os
import time

import pytest

from ghmcp import config, tools
from ghmcp.errors import NotFound

UUID_A = "6eb39c47-e7e0-46a4-88b4-38081130b00a"
UUID_B = "1bfca827-11f4-4b77-9f58-d576fa2871a7"


@pytest.fixture
def chat_dir(tmp_path, monkeypatch):
    d = tmp_path / "uploads"
    d.mkdir()
    monkeypatch.setenv("OPENWEBUI_UPLOADS_DIR", str(d))
    return d


def _attach(directory, name, data=b"\x7fELF", age=0.0):
    path = directory / name
    path.write_bytes(data)
    t = time.time() - age
    os.utime(path, (t, t))
    return path


def test_the_uuid_prefix_is_split_from_the_attached_name(chat_dir):
    path = _attach(chat_dir, f"{UUID_A}_demo_keycheck.aarch64")

    out = tools.list_chat_uploads()

    assert out.directory == str(chat_dir)
    assert out.total == out.returned == 1
    row = out.uploads[0]
    assert row.name == "demo_keycheck.aarch64"
    assert row.upload_id == UUID_A
    assert row.path == str(path)
    assert row.size == 4


def test_the_returned_path_is_what_analyze_binary_needs(chat_dir):
    path = _attach(chat_dir, f"{UUID_A}_demo_keycheck.aarch64")

    assert os.path.isfile(tools.list_chat_uploads().uploads[0].path)
    assert tools.list_chat_uploads().uploads[0].path == str(path)


def test_newest_first(chat_dir):
    _attach(chat_dir, f"{UUID_B}_old.bin", age=3600)
    _attach(chat_dir, f"{UUID_A}_new.bin", age=0)

    assert [u.name for u in tools.list_chat_uploads().uploads] == ["new.bin", "old.bin"]


def test_pattern_is_a_case_insensitive_substring_of_the_attached_name(chat_dir):
    _attach(chat_dir, f"{UUID_A}_demo_keycheck.aarch64")
    _attach(chat_dir, f"{UUID_B}_crackme.x86_64")

    out = tools.list_chat_uploads(pattern="KEYCHECK")

    assert [u.name for u in out.uploads] == ["demo_keycheck.aarch64"]


def test_the_uuid_does_not_match_a_pattern(chat_dir):
    _attach(chat_dir, f"{UUID_A}_x.bin")

    assert tools.list_chat_uploads(pattern="6eb39c47").total == 0


def test_limit_caps_rows_but_total_counts_all(chat_dir):
    for i in range(5):
        _attach(chat_dir, f"{UUID_A[:-1]}{i}_f{i}.bin", age=i)

    out = tools.list_chat_uploads(limit=2)

    assert out.total == 5 and out.returned == 2


def test_a_name_without_the_uuid_prefix_is_still_listed(chat_dir):
    _attach(chat_dir, "copied_in_by_hand.bin")

    row = tools.list_chat_uploads().uploads[0]
    assert row.name == "copied_in_by_hand.bin" and row.upload_id is None


def test_symlinks_and_directories_are_not_listed(chat_dir, tmp_path):
    outside = tmp_path / "secret"
    outside.write_text("no")
    (chat_dir / f"{UUID_A}_link.bin").symlink_to(outside)
    (chat_dir / f"{UUID_B}_dir").mkdir()

    assert tools.list_chat_uploads().total == 0


def test_a_missing_directory_says_where_it_looked(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENWEBUI_UPLOADS_DIR", str(tmp_path / "absent"))

    with pytest.raises(NotFound, match="OPENWEBUI_UPLOADS_DIR"):
        tools.list_chat_uploads()


def test_the_default_is_the_course_openwebui_directory(monkeypatch):
    monkeypatch.delenv("OPENWEBUI_UPLOADS_DIR", raising=False)

    assert config.openwebui_uploads_dir().parts[-2:] == (".openwebui-data", "uploads")


def test_the_upload_binary_description_sends_attachments_here():
    """The model reads tool descriptions, not the README."""
    assert "list_chat_uploads" in tools.upload_binary.__doc__
