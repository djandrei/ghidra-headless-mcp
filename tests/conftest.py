"""Shared fixtures.

Unit tests never spawn a JVM: `fake_headless` intercepts run_headless and
writes whatever envelope the test asks for into the out-file the real code
chose. That exercises the genuine command construction and file plumbing while
staying in-process and fast.
"""

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ghmcp import config, headless  # noqa: E402


def _course_clone() -> Path:
    """Root of the course clone the integration samples come from.

    Three cases, most specific first. `COURSE_CLONE` names it outright. Failing
    that the workspace layout applies, this repo sitting at
    claude/mcp-servers/ghidra-headless-mcp. In the container it sits at /srv
    instead, so ROOT has no third parent and the clone is wherever compose
    bind-mounted it — which is the devcontainer's own path, by design.
    """
    env = os.environ.get("COURSE_CLONE")
    if env:
        return Path(env)
    if len(ROOT.parents) > 2:
        return ROOT.parents[2] / "building-agentic-re"
    return Path("/workspaces/building-agentic-re")


COURSE_CLONE = _course_clone()

# Ground truth for the integration fixture, verified by hand against Ghidra 12.1.2.
STARTER05 = COURSE_CLONE / "exercises/starters/assets/starter05.x86_64"
CRACKME = COURSE_CLONE / "exercises/ai-assisted-re/assets/crackme.x86_64"
VIDAR_GZF = (
    COURSE_CLONE
    / "exercises/ai-assisted-re/assets/vidar"
    / "vidar.fed19121e9d547d9762e7aa6dd53e0756c414bd0a0650e38d6b0c01b000ad2fc.exe.dontrun.gzf"
)
KNOWN_FUNCTION = "check_key"
KNOWN_ADDRESS = "00401146"


# Integration-module convention: a *module-scoped* fixture may assign
# config.PROJECT_LOCATION / PROJECT_NAME directly, claiming the project for that
# whole module — modules run sequentially, so they cannot collide. A *function*
# -scoped test must use monkeypatch.setattr instead; assigning directly leaks
# into every later test in the file, which is exactly how
# test_importing_a_gzf_uses_the_packaged_program_name once broke the test
# appended after it.


@pytest.fixture(autouse=True)
def _clear_ghidra_cache():
    """Keep the resolved-path cache from leaking between tests.

    find_ghidra() caches per process, so without this a test that points
    GHIDRA_INSTALL_DIR at a fake install would poison every later test.
    """
    config.reset_ghidra_cache()
    yield
    config.reset_ghidra_cache()


@pytest.fixture
def project(tmp_path, monkeypatch):
    """Point the server at a throwaway project location."""
    loc = tmp_path / "proj"
    loc.mkdir()
    monkeypatch.setattr(config, "PROJECT_LOCATION", loc)
    monkeypatch.setattr(config, "PROJECT_NAME", "test-proj")
    return loc


@pytest.fixture
def fake_headless(monkeypatch, project):
    """Replace run_headless with a recorder that fabricates an envelope.

    The test sets `.envelope` (or `.raw`); the fake writes it to the out-file
    named in the command it was handed, so export()'s real path handling runs.
    """

    class Fake:
        def __init__(self):
            self.calls: list[list[str]] = []
            # Spec files live in a TemporaryDirectory that export() removes on
            # return, so capture their content while the call is in flight.
            self.specs: list[dict] = []
            self.envelope: dict | None = {"ok": True, "mode": "test", "data": {}}
            self.raw: str | None = None
            self.returncode = 0
            self.stdout = ""
            self.write_output = True

        def __call__(self, args, timeout):
            self.calls.append(list(args))
            if len(args) >= 2 and Path(args[-2]).is_file():
                self.specs.append(json.loads(Path(args[-2]).read_text()))
            if self.write_output and args and Path(args[-1]).parent.is_dir():
                out = Path(args[-1])
                out.write_text(
                    self.raw if self.raw is not None else json.dumps(self.envelope)
                )

            class Proc:
                pass

            proc = Proc()
            proc.returncode = self.returncode
            proc.stdout = self.stdout
            proc.stderr = ""
            return proc

        @property
        def last(self) -> list[str]:
            return self.calls[-1]

        @property
        def last_spec(self) -> dict:
            return self.specs[-1]

        def shape(self, call: list[str]) -> list[str]:
            """A command with the random temp paths replaced, for comparison."""
            return [
                "<spec>" if part.endswith("spec.json")
                else "<out>" if part.endswith("export.json")
                else part
                for part in call
            ]

    fake = Fake()
    monkeypatch.setattr(headless, "run_headless", fake)
    return fake


@pytest.fixture
def captured_specs(monkeypatch, project):
    """Capture each spec dict passed to export, and return canned data."""
    seen: list[tuple[str, str, dict, bool]] = []
    responses: dict[str, object] = {}

    def fake_export(program, mode, args=None, *, write=False, timeout=None):
        seen.append((program, mode, dict(args or {}), write))
        if mode not in responses:
            raise AssertionError(f"test did not stub a response for mode {mode!r}")
        value = responses[mode]
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(headless, "export", fake_export)

    class Captured:
        calls = seen
        stub = responses

    return Captured()
