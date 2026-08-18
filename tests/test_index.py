"""Tests for the program index that backs list_programs."""

import json

from ghmcp import headless


def test_starts_empty(project):
    assert headless.index_read() == []


def test_add_then_read(project):
    headless.index_add("a.bin")
    assert headless.index_read() == ["a.bin"]


def test_add_is_idempotent(project):
    headless.index_add("a.bin")
    headless.index_add("a.bin")
    assert headless.index_read() == ["a.bin"]


def test_entries_are_sorted_for_stable_output(project):
    for name in ("c.bin", "a.bin", "b.bin"):
        headless.index_add(name)
    assert headless.index_read() == ["a.bin", "b.bin", "c.bin"]


def test_remove(project):
    headless.index_add("a.bin")
    headless.index_add("b.bin")
    headless.index_remove("a.bin")
    assert headless.index_read() == ["b.bin"]


def test_remove_of_absent_entry_is_a_no_op(project):
    headless.index_add("a.bin")
    headless.index_remove("missing.bin")
    assert headless.index_read() == ["a.bin"]


def test_corrupt_index_is_treated_as_empty_not_fatal(project):
    """A truncated write must not make every later call fail."""
    headless.index_path().write_text("{ this is not json")
    assert headless.index_read() == []


def test_non_list_index_is_treated_as_empty(project):
    headless.index_path().write_text(json.dumps({"unexpected": "shape"}))
    assert headless.index_read() == []


def test_index_lives_under_the_project_location(project):
    headless.index_add("a.bin")
    assert headless.index_path().parent == project
    assert headless.index_path().exists()
