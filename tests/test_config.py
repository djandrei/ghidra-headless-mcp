"""Tests for Ghidra discovery and configuration."""

import pytest

from ghmcp import config


def _install(tmp_path, name="ghidra_test"):
    root = tmp_path / name
    (root / "support").mkdir(parents=True)
    script = root / "support" / "analyzeHeadless"
    script.write_text("#!/bin/sh\n")
    script.chmod(0o755)
    return root


def test_env_var_install_wins(tmp_path, monkeypatch):
    root = _install(tmp_path)
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(root))
    assert config.find_ghidra() == root / "support" / "analyzeHeadless"


def test_env_var_is_probed_before_anything_else(tmp_path, monkeypatch):
    root = _install(tmp_path)
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(root))
    assert config.candidate_roots()[0] == root


def test_devcontainer_path_is_probed_when_no_env_var(monkeypatch):
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    from pathlib import Path

    assert Path("/ghidra") in config.candidate_roots()


def test_missing_install_raises_naming_what_was_tried(tmp_path, monkeypatch):
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path / "nowhere"))
    monkeypatch.setattr(config, "candidate_roots", lambda: [tmp_path / "nowhere"])
    with pytest.raises(RuntimeError, match="nowhere"):
        config.find_ghidra()


def test_env_var_pointing_at_a_bad_dir_falls_through_to_other_candidates(
    tmp_path, monkeypatch
):
    good = _install(tmp_path, "good")
    monkeypatch.setattr(
        config, "candidate_roots", lambda: [tmp_path / "missing", good]
    )
    assert config.find_ghidra() == good / "support" / "analyzeHeadless"


def test_script_path_lists_our_scripts_first(tmp_path, monkeypatch):
    root = _install(tmp_path)
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(root))
    parts = config.script_path().split(";")
    assert parts[0] == str(config.SCRIPT_DIR)
    assert parts[1].endswith("Ghidra/Features/Base/ghidra_scripts")


def test_script_path_uses_semicolons_as_ghidra_expects(tmp_path, monkeypatch):
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(_install(tmp_path)))
    assert config.script_path().count(";") == 1


def test_export_script_name_matches_the_file_on_disk():
    assert (config.SCRIPT_DIR / config.EXPORT_SCRIPT).is_file()


class TestResolvedPathCaching:
    """Probing globs the home directory and /opt; do it once, not per call."""

    def test_the_second_call_does_not_probe_again(self, tmp_path, monkeypatch):
        root = _install(tmp_path)
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(root))
        calls = []
        real = config.candidate_roots
        monkeypatch.setattr(
            config, "candidate_roots", lambda: calls.append(1) or real()
        )

        first = config.find_ghidra()
        second = config.find_ghidra()
        assert first == second
        assert len(calls) == 1, "second call must be served from the cache"

    def test_changing_the_env_var_invalidates_the_cache(self, tmp_path, monkeypatch):
        a = _install(tmp_path, "ghidra_a")
        b = _install(tmp_path, "ghidra_b")
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(a))
        assert config.find_ghidra() == a / "support" / "analyzeHeadless"
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(b))
        assert config.find_ghidra() == b / "support" / "analyzeHeadless"

    def test_unsetting_the_env_var_invalidates_the_cache(self, tmp_path, monkeypatch):
        root = _install(tmp_path)
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(root))
        config.find_ghidra()
        monkeypatch.delenv("GHIDRA_INSTALL_DIR")
        other = _install(tmp_path, "other")
        monkeypatch.setattr(config, "candidate_roots", lambda: [other])
        assert config.find_ghidra() == other / "support" / "analyzeHeadless"

    def test_a_vanished_install_is_re_probed_not_returned_stale(
        self, tmp_path, monkeypatch
    ):
        """A path that no longer exists would fail as an opaque exec error."""
        gone = _install(tmp_path, "gone")
        monkeypatch.setattr(config, "candidate_roots", lambda: [gone])
        config.find_ghidra()

        (gone / "support" / "analyzeHeadless").unlink()
        replacement = _install(tmp_path, "replacement")
        monkeypatch.setattr(config, "candidate_roots", lambda: [replacement])
        assert config.find_ghidra() == replacement / "support" / "analyzeHeadless"

    def test_a_failure_is_not_cached(self, tmp_path, monkeypatch):
        """An install appearing later must be picked up."""
        monkeypatch.setattr(config, "candidate_roots", lambda: [tmp_path / "missing"])
        with pytest.raises(RuntimeError):
            config.find_ghidra()

        later = _install(tmp_path, "later")
        monkeypatch.setattr(config, "candidate_roots", lambda: [later])
        assert config.find_ghidra() == later / "support" / "analyzeHeadless"

    def test_reset_forces_a_re_probe(self, tmp_path, monkeypatch):
        root = _install(tmp_path)
        monkeypatch.setattr(config, "candidate_roots", lambda: [root])
        config.find_ghidra()
        calls = []
        monkeypatch.setattr(config, "candidate_roots", lambda: calls.append(1) or [root])
        config.reset_ghidra_cache()
        config.find_ghidra()
        assert len(calls) == 1

    def test_script_path_benefits_from_the_same_cache(self, tmp_path, monkeypatch):
        root = _install(tmp_path)
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(root))
        config.find_ghidra()
        calls = []
        monkeypatch.setattr(config, "candidate_roots", lambda: calls.append(1) or [root])
        config.script_path()
        assert calls == [], "script_path must reuse the cached path"
