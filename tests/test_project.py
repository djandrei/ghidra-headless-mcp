"""Unit tests for Stage 8: project listing and deletion."""

import pytest

from ghmcp import config, headless, tools
from ghmcp.errors import NotFound


@pytest.fixture
def project_api(monkeypatch, project):
    """Stub both export paths and record what was asked of them."""
    state = {"files": ["a.bin", "b.bin"], "calls": [], "project_calls": []}

    def fake_export(program, mode, args=None, *, write=False, timeout=None):
        state["calls"].append((program, mode, dict(args or {}), write))
        if mode == "delete_program":
            name = args["name"]
            if name not in state["files"]:
                raise NotFound(f"no program named {name}")
            state["files"].remove(name)
            return {"deleted": name, "pathname": f"/{name}"}
        raise AssertionError(f"unexpected mode {mode}")

    def fake_export_project(mode, args=None, *, write=False, timeout=None):
        state["project_calls"].append(mode)
        if not state["files"]:
            return None
        return {"count": len(state["files"]),
                "files": [{"name": n, "pathname": f"/{n}", "content_type": "Program",
                           "is_busy": False} for n in state["files"]]}

    monkeypatch.setattr(headless, "export", fake_export)
    monkeypatch.setattr(headless, "export_project", fake_export_project)
    return state


class TestListPrograms:
    def test_defaults_to_the_local_index_without_a_jvm(self, project_api):
        headless.index_add("indexed.bin")
        out = tools.list_programs()
        assert out.programs == ["indexed.bin"]
        assert project_api["project_calls"] == [], "must not query Ghidra by default"

    def test_refresh_asks_ghidra(self, project_api):
        out = tools.list_programs(refresh=True)
        assert out.programs == ["a.bin", "b.bin"]
        assert project_api["project_calls"] == ["project_files"]

    def test_refresh_finds_programs_the_index_never_knew(self, project_api):
        """The limitation Stage 8 exists to retire."""
        assert tools.list_programs().programs == []
        assert tools.list_programs(refresh=True).programs == ["a.bin", "b.bin"]

    def test_refresh_repairs_the_index(self, project_api):
        tools.list_programs(refresh=True)
        assert headless.index_read() == ["a.bin", "b.bin"]

    def test_refresh_drops_stale_index_entries(self, project_api):
        headless.index_add("deleted-elsewhere.bin")
        tools.list_programs(refresh=True)
        assert "deleted-elsewhere.bin" not in headless.index_read()

    def test_empty_project_returns_empty(self, project_api):
        project_api["files"] = []
        assert tools.list_programs(refresh=True).programs == []

    def test_reports_project_identity(self, project_api, project):
        out = tools.list_programs()
        assert out.project == "test-proj"
        assert out.project_location == str(project)


class TestDeleteProgram:
    def test_rejects_a_program_not_in_the_project(self, project_api):
        with pytest.raises(NotFound, match="no program named"):
            tools.delete_program("never-existed.bin")

    def test_attaches_to_a_different_program(self, project_api):
        """Ghidra cannot delete a file that is open, so never attach to the target."""
        tools.delete_program("a.bin")
        attached, mode, args, write = project_api["calls"][0]
        assert attached == "b.bin"
        assert mode == "delete_program" and args == {"name": "a.bin"}

    def test_uses_write_mode(self, project_api):
        tools.delete_program("a.bin")
        assert project_api["calls"][0][3] is True

    def test_removes_the_index_entry(self, project_api):
        headless.index_add("a.bin")
        tools.delete_program("a.bin")
        assert "a.bin" not in headless.index_read()

    def test_removes_the_cached_decompilation(self, project_api):
        headless.cache_dir().mkdir(parents=True, exist_ok=True)
        headless.corpus_path("a.bin").write_text("{}")
        tools.delete_program("a.bin")
        assert not headless.corpus_path("a.bin").is_file()

    def test_reports_success(self, project_api):
        out = tools.delete_program("a.bin")
        assert out.deleted is True and out.deleted_project is False
        assert "a.bin" in out.detail

    def test_deleting_the_last_program_removes_the_project(self, project_api, project):
        project_api["files"] = ["only.bin"]
        rep = project / "test-proj.rep"
        rep.mkdir()
        (rep / "marker").write_text("x")
        gpr = project / "test-proj.gpr"
        gpr.write_text("x")

        out = tools.delete_program("only.bin")
        assert out.deleted_project is True
        assert not rep.exists() and not gpr.exists()
        assert project_api["calls"] == [], "no JVM needed to delete the whole project"

    def test_last_program_path_is_safe_when_nothing_is_on_disk(self, project_api):
        project_api["files"] = ["only.bin"]
        out = tools.delete_program("only.bin")
        assert out.deleted_project is True
        assert "nothing on disk" in out.detail
