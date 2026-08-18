"""End-to-end tests for project listing and deletion.

Destructive, so they use their own project.

Run with: pytest -m integration
"""

import pytest

from ghmcp import config, headless, tools
from ghmcp.errors import NotFound
from tests.conftest import CRACKME, STARTER05

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def two_programs(tmp_path_factory):
    loc = tmp_path_factory.mktemp("projtest")
    config.PROJECT_LOCATION = loc
    config.PROJECT_NAME = "proj-test"
    for path in (STARTER05, CRACKME):
        if not path.is_file():
            pytest.skip(f"fixture missing: {path}")
    a = tools.analyze_binary(str(STARTER05)).program
    b = tools.analyze_binary(str(CRACKME)).program
    return a, b


def test_refresh_lists_both_programs_from_ghidra(two_programs):
    a, b = two_programs
    out = tools.list_programs(refresh=True)
    assert set(out.programs) >= {a, b}


def test_refresh_finds_a_program_the_index_never_recorded(two_programs):
    """The index limitation Stage 8 retires."""
    a, b = two_programs
    headless.index_remove(b)
    assert b not in tools.list_programs().programs
    assert b in tools.list_programs(refresh=True).programs


def test_refresh_repairs_the_index(two_programs):
    a, b = two_programs
    headless.index_remove(b)
    tools.list_programs(refresh=True)
    assert b in headless.index_read()


def test_deleting_an_unknown_program_raises(two_programs):
    with pytest.raises(NotFound):
        tools.delete_program("no_such_program.bin")


def test_deleting_a_program_removes_it_from_the_project(two_programs):
    a, b = two_programs
    out = tools.delete_program(b)
    assert out.deleted is True and out.deleted_project is False

    remaining = tools.list_programs(refresh=True).programs
    assert b not in remaining
    assert a in remaining


def test_the_surviving_program_still_works(two_programs):
    """Deleting one program must not disturb the other."""
    a, _ = two_programs
    assert tools.get_program_info(a).function_count > 0


def test_deleting_the_last_program_removes_the_project(two_programs):
    a, _ = two_programs
    out = tools.delete_program(a)
    assert out.deleted is True
    assert out.deleted_project is True
    assert not (config.PROJECT_LOCATION / f"{config.PROJECT_NAME}.rep").exists()
    assert tools.list_programs().programs == []
