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
    path = _attach(chat_dir, f"{UUID_A}_keycheck.aarch64")

    out = tools.list_chat_uploads()

    assert out.directory == str(chat_dir)
    assert out.total == out.returned == 1
    row = out.uploads[0]
    assert row.name == "keycheck.aarch64"
    assert row.upload_id == UUID_A
    assert row.path == str(path)
    assert row.size == 4


def test_the_returned_path_is_what_analyze_binary_needs(chat_dir):
    path = _attach(chat_dir, f"{UUID_A}_keycheck.aarch64")

    assert os.path.isfile(tools.list_chat_uploads().uploads[0].path)
    assert tools.list_chat_uploads().uploads[0].path == str(path)


def test_newest_first(chat_dir):
    _attach(chat_dir, f"{UUID_B}_old.bin", age=3600)
    _attach(chat_dir, f"{UUID_A}_new.bin", age=0)

    assert [u.name for u in tools.list_chat_uploads().uploads] == ["new.bin", "old.bin"]


def test_pattern_is_a_case_insensitive_substring_of_the_attached_name(chat_dir):
    _attach(chat_dir, f"{UUID_A}_keycheck.aarch64")
    _attach(chat_dir, f"{UUID_B}_crackme.x86_64")

    out = tools.list_chat_uploads(pattern="KEYCHECK")

    assert [u.name for u in out.uploads] == ["keycheck.aarch64"]


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


def test_there_is_no_default_uploads_directory(monkeypatch):
    monkeypatch.delenv("OPENWEBUI_UPLOADS_DIR", raising=False)

    assert config.openwebui_uploads_dir() is None


def test_unset_says_which_variable_to_set(monkeypatch):
    monkeypatch.delenv("OPENWEBUI_UPLOADS_DIR", raising=False)

    with pytest.raises(NotFound, match="OPENWEBUI_UPLOADS_DIR is not set"):
        tools.list_chat_uploads()


def test_unset_leaves_uuid_shaped_names_alone(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENWEBUI_UPLOADS_DIR", raising=False)
    path = tmp_path / f"{UUID_A}_x.bin"

    assert tools.import_filename(path) == path.name


def test_the_upload_binary_description_sends_attachments_here():
    """The model reads tool descriptions, not the README."""
    assert "list_chat_uploads" in tools.upload_binary.__doc__


# ------------------------------------- importing names the program as attached


@pytest.fixture
def importer(project, monkeypatch):
    """Fake the import JVM: record the path Ghidra is handed and name the
    program after it, as Ghidra does."""
    from ghmcp import headless
    from tests.test_tools import _INFO, _proc

    seen = []

    def run(args, timeout):
        path = args[args.index("-import") + 1]
        seen.append(path)
        name = os.path.basename(path)
        return _proc(stdout=f"INFO  /{name}: file created (u) (LocalFileSystem)\n")

    monkeypatch.setattr(headless, "run_headless", run)
    monkeypatch.setattr(headless, "export", lambda *a, **k: _INFO)
    return seen


def test_an_attachment_is_imported_under_the_name_the_user_gave_it(chat_dir, importer):
    path = _attach(chat_dir, f"{UUID_A}_keycheck.aarch64")

    result = tools.analyze_binary(str(path))

    assert result.program == "keycheck.aarch64"
    assert os.path.basename(importer[0]) == "keycheck.aarch64"


def test_the_path_from_list_chat_uploads_gives_the_clean_name(chat_dir, importer):
    _attach(chat_dir, f"{UUID_A}_keycheck.aarch64")

    found = tools.list_chat_uploads(pattern="keycheck").uploads[0]

    assert tools.analyze_binary(found.path).program == found.name


def test_a_uuid_prefix_outside_the_uploads_directory_is_kept(chat_dir, tmp_path, importer):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    path = _attach(elsewhere, f"{UUID_A}_keycheck.aarch64")

    assert tools.analyze_binary(str(path)).program == f"{UUID_A}_keycheck.aarch64"


def test_a_file_in_the_uploads_directory_without_the_prefix_is_kept(chat_dir, importer):
    path = _attach(chat_dir, "plain_name.bin")

    assert tools.analyze_binary(str(path)).program == "plain_name.bin"


def test_import_filename_only_strips_where_openwebui_stores(chat_dir, tmp_path):
    inside = chat_dir / f"{UUID_A}_x.bin"
    nested = chat_dir / "sub" / f"{UUID_A}_x.bin"
    outside = tmp_path / f"{UUID_A}_x.bin"

    assert tools.import_filename(inside) == "x.bin"
    assert tools.import_filename(nested) == f"{UUID_A}_x.bin"
    assert tools.import_filename(outside) == f"{UUID_A}_x.bin"


def test_the_batch_tool_names_attachments_the_same_way(chat_dir, project, monkeypatch):
    from ghmcp import headless
    from tests.test_tools import _INFO, _proc

    _attach(chat_dir, f"{UUID_A}_keycheck.aarch64")
    seen = []

    def run(args, timeout):
        paths = args[args.index("-import") + 1:]
        paths = [p for p in paths if not p.startswith("-")]
        seen.extend(paths)
        lines = "".join(
            f"INFO  /{os.path.basename(p)}: file created (u) (LocalFileSystem)\n" for p in paths
        )
        return _proc(stdout=lines)

    monkeypatch.setattr(headless, "run_headless", run)
    monkeypatch.setattr(
        headless, "export_multi",
        lambda mode, programs, *a, **k: [{"ok": True, "program": p, "data": _INFO} for p in programs],
    )

    out = tools.analyze_binaries(str(chat_dir), recursive=True)

    assert [r.program for r in out.results] == ["keycheck.aarch64"]
    assert os.path.basename(seen[0]) == "keycheck.aarch64"
