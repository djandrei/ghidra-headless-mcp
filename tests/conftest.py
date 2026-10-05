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


# The integration fixtures: built from tests/fixtures/src by build.sh and
# make-gzf.sh, and committed, so their addresses are ground truth. See
# tests/fixtures/README.md.
FIXTURES = ROOT / "tests" / "fixtures" / "bin"
KEYCHECK = FIXTURES / "keycheck.x86_64"     # ELF x86-64, non-PIE: check_key called from main
CRACKME = FIXTURES / "crackme.x86_64"       # ELF x86-64: strcmp, malloc, memcpy
PE32_GZF = FIXTURES / "sample-pe32.exe.gzf"  # PE32 i386, analysed: GetProcAddress, CreateFileA
MACHO_GZF = FIXTURES / "sample-macho.gzf"    # Mach-O arm64, analysed: _objc_msgSend
# An import -> forwarder -> implementation chain of x86-64 PEs over `do_work`.
CHAIN = [FIXTURES / name for name in ("chainapp.exe", "chainfwd.dll", "chainimpl.dll")]
KNOWN_FUNCTION = "check_key"
KNOWN_ADDRESS = "00401176"  # nm tests/fixtures/bin/keycheck.x86_64 | grep check_key


# The Windows-layering tests need real Windows binaries — notepad.exe and the
# kernel32, kernelbase and ntdll it loads — exported from Ghidra as .gzf. They
# are Microsoft's and cannot be redistributed here, so WINDOWS_SAMPLES_DIR names
# a directory holding them, and every test using them skips when it does not.
MULTIBIN_DIR = Path(os.environ.get("WINDOWS_SAMPLES_DIR", ROOT / "tests" / "windows-samples"))
MULTIBIN_GZF = [
    MULTIBIN_DIR / name
    for name in ("notepad.exe.gzf", "KERNEL32.DLL.gzf", "KERNELBASE.DLL.gzf", "NTDLL.DLL.gzf")
]
# Ghidra names a program after what a container packages, so foo.exe.gzf
# imports as foo.exe.
MULTIBIN_PROGRAMS = ["notepad.exe", "KERNEL32.DLL", "KERNELBASE.DLL", "NTDLL.DLL"]


def import_packed(paths):
    """Import pre-analysed .gzf without re-running analysis.

    A packed program already carries Ghidra's analysis; analyze_binary would
    re-run every analyzer, which for KERNELBASE.DLL alone is minutes. Tests
    import them the way a person would.

    Ghidra writes a lock file *beside* a packed program while importing it, so
    a .gzf in a read-only directory fails with "Read-only file system" — which
    is every sample in the container, where compose mounts the samples
    directory read-only. Those are staged in a temp directory first, exactly as
    analyze_binary's _stage_for_import does. The filename is kept, so Ghidra
    names each program as it would have unstaged.
    """
    import shutil
    import tempfile

    from ghmcp import headless

    staging = tempfile.mkdtemp(prefix="ghmcp-test-import-")
    try:
        staged = []
        for p in map(Path, paths):
            if os.access(p.parent, os.W_OK):
                staged.append(p)
                continue
            target = Path(staging) / p.name
            try:
                os.link(p, target)
            except OSError:
                shutil.copy2(p, target)
            staged.append(target)
        headless.run_headless(
            ["-import", *[str(p) for p in staged], "-noanalysis"], timeout=1800
        )
    finally:
        shutil.rmtree(staging, ignore_errors=True)


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


@pytest.fixture(scope="session")
def _stub_ghidra_root(tmp_path_factory):
    """A directory shaped like a Ghidra install, with nothing in it that runs."""
    root = tmp_path_factory.mktemp("stub-ghidra")
    (root / "support").mkdir()
    (root / "support" / "analyzeHeadless").write_text("#!/bin/sh\nexit 99\n")
    (root / "Ghidra" / "Features" / "Base" / "ghidra_scripts").mkdir(parents=True)
    return root


@pytest.fixture(autouse=True)
def _unit_tests_never_need_ghidra(request, _stub_ghidra_root, monkeypatch):
    """Point unit tests at a stub install, so they pass where Ghidra is absent.

    "No JVM" was never "no Ghidra": the fakes replace run_headless, but
    building -scriptPath locates the install first, so 57 unit tests failed on
    a machine without one — CI's, for instance — while passing on every
    workstation that happened to have Ghidra. Integration tests keep the real
    install; tests that set GHIDRA_INSTALL_DIR themselves still win, since their
    monkeypatch runs after this one.
    """
    if "integration" in request.keywords:
        return
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(_stub_ghidra_root))


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
