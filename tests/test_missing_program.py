"""A program the project does not hold is NotFound, not a 3 KB log dump.

Observed: get_program_info("demo_keycheck.aarch64") before the binary was
imported returned 2,948 characters of JVM start-up log; the one line that
mattered was buried in it.
"""

import pytest

from ghmcp import headless, tools
from ghmcp.errors import ExportFailure, NotFound

GHIDRA_SAYS = (
    "INFO  Initializing Random Number Generator... (SecureRandomFactory)\n"
    "INFO  Opening existing project: /projects/headless-mcp (HeadlessAnalyzer)\n"
    "ERROR Abort due to Headless analyzer error: Requested project program "
    "file(s) not found: demo_keycheck.aarch64 (HeadlessAnalyzer) "
    "java.io.IOException: Requested project program file(s) not found: "
    "demo_keycheck.aarch64\n"
)


@pytest.fixture
def ghidra_exits(project, monkeypatch):
    def install(stdout, returncode=1):
        class Proc:
            pass

        Proc.returncode, Proc.stdout, Proc.stderr = returncode, stdout, ""
        monkeypatch.setattr(headless.subprocess, "run", lambda *a, **k: Proc())

    return install


def test_the_missing_program_is_not_found_and_named(ghidra_exits):
    ghidra_exits(GHIDRA_SAYS)

    with pytest.raises(NotFound) as exc:
        headless.run_headless(["-process", "demo_keycheck.aarch64"], timeout=10)

    msg = str(exc.value)
    assert "'demo_keycheck.aarch64'" in msg
    assert "list_programs" in msg and "analyze_binary" in msg
    assert "Random Number Generator" not in msg and len(msg) < 300


def test_a_name_with_spaces_survives(ghidra_exits):
    ghidra_exits("ERROR Requested project program file(s) not found: my sample.exe\n")

    with pytest.raises(NotFound, match="'my sample.exe'"):
        headless.run_headless(["-process", "my sample.exe"], timeout=10)


def test_every_per_program_tool_gets_the_short_error(ghidra_exits, monkeypatch):
    ghidra_exits(GHIDRA_SAYS)

    with pytest.raises(NotFound, match="no program named"):
        tools.get_program_info("demo_keycheck.aarch64")


def test_other_failures_still_carry_the_log(ghidra_exits):
    ghidra_exits("ERROR something else entirely\n")

    with pytest.raises(ExportFailure, match="something else entirely"):
        headless.run_headless(["-process", "x"], timeout=10)
