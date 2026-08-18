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
