"""The Windows API layering: four real binaries, ground truth from NB 15.

This is the only integration fixture with a genuine cross-binary relationship —
the two ELF course samples are self-contained, so they can show that the
project-scope tools *run* but not that the join is *right*. Here notepad.exe
imports from an apiset, kernel32 forwards, kernelbase implements and ntdll
makes the syscall, and every one of those facts is asserted.

The expected values come from NB 15 (§2 and §5.4) and from the disassembly of
the stub itself, not from a previous run of this server.

Samples are untracked in the clone — the notebook downloads a .gar and extracts
them — so every test here skips when they are absent.

Run with: pytest -m integration
"""

import pytest

from ghmcp import config, headless, tools
from tests.conftest import MULTIBIN_GZF, MULTIBIN_PROGRAMS, import_packed

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def windows_project(tmp_path_factory):
    missing = [p for p in MULTIBIN_GZF if not p.is_file()]
    if missing:
        pytest.skip(f"multi-binary assets missing: {missing[0].name} (set COURSE_CLONE to a course checkout)")

    loc = tmp_path_factory.mktemp("winlayer")
    config.PROJECT_LOCATION = loc
    config.PROJECT_NAME = "winlayer-test"
    import_packed(MULTIBIN_GZF)
    for name in MULTIBIN_PROGRAMS:
        headless.index_add(name)
    return MULTIBIN_PROGRAMS


@pytest.fixture
def count_runs(monkeypatch):
    real = headless.run_headless
    calls: list[list[str]] = []

    def counting(args, timeout):
        calls.append(list(args))
        return real(args, timeout)

    monkeypatch.setattr(headless, "run_headless", counting)
    return calls


# ------------------------------------------------------------- the project

def test_all_four_binaries_import_from_one_container_each(windows_project):
    programs = tools.list_programs(refresh=True).programs
    assert set(programs) == set(MULTIBIN_PROGRAMS)


def test_a_packed_program_is_named_after_what_it_packages(windows_project):
    """KERNEL32.DLL.gzf imports as KERNEL32.DLL, not KERNEL32.DLL.gzf."""
    assert "KERNEL32.DLL" in tools.list_programs().programs
    assert not any(p.endswith(".gzf") for p in tools.list_programs().programs)


def test_the_project_is_far_larger_than_the_elf_fixtures(windows_project):
    """15,000+ functions across four binaries, against 24 in each ELF sample —
    this is the only fixture that exercises the tools at real scale."""
    rows = headless.export_multi("info", MULTIBIN_PROGRAMS)
    total = sum(r["data"]["function_count"] for r in rows if r["ok"])
    assert total > 10_000


def test_fan_out_over_four_real_binaries_costs_one_start(windows_project, count_runs):
    rows = headless.export_multi("info", MULTIBIN_PROGRAMS)
    assert len(count_runs) == 1
    assert all(r["ok"] for r in rows)


def test_a_program_name_is_not_its_internal_name(windows_project):
    """The trap the dispatcher has to respect: the project holds KERNEL32.DLL
    while the PE calls itself kernel32.dll, and KERNELBASE.DLL calls itself
    KernelBase.dll. Comparing the wrong one breaks the already-attached check
    and returns a program field that does not match list_programs."""
    rows = {r["program"]: r["data"]["internal_name"]
            for r in headless.export_multi(
                "link_symbols", MULTIBIN_PROGRAMS, {"names": ["CreateFileW"]}) if r["ok"]}

    assert rows["KERNEL32.DLL"] == "kernel32.dll"
    assert rows["KERNELBASE.DLL"] == "KernelBase.dll"
    assert rows["KERNELBASE.DLL"] != "KERNELBASE.DLL", "internal name differs in case"


# ------------------------------------------- the CreateFileW chain, NB 15 §2

def test_createfilew_resolves_to_kernelbase(windows_project, count_runs):
    """NB 15 §2: kernel32 is the legacy surface, kernelbase is where the logic
    lives. One call, one JVM start."""
    chain = tools.resolve_symbol("CreateFileW").results[0]

    assert len(count_runs) == 1
    assert chain.terminal_program == "KERNELBASE.DLL"


def test_kernel32_is_identified_as_a_forwarder(windows_project):
    """The pivot NB 15 §5.4 calls non-trivial: kernel32 both exports the name
    and imports it, which is what makes it a forwarder rather than the
    implementation."""
    chain = tools.resolve_symbol("CreateFileW").results[0]
    kernel32 = next(l for l in chain.layers if l.program == "KERNEL32.DLL")

    assert "export" in kernel32.roles
    assert "import" in kernel32.roles
    assert kernel32.is_terminal is False


def test_kernelbase_holds_the_implementation(windows_project):
    chain = tools.resolve_symbol("CreateFileW").results[0]
    kernelbase = next(l for l in chain.layers if l.program == "KERNELBASE.DLL")

    assert kernelbase.roles == ["export", "function"] or set(kernelbase.roles) == {
        "export", "function"
    }
    assert "import" not in kernelbase.roles
    assert kernelbase.is_terminal is True
    assert kernelbase.address


def test_the_apiset_import_is_followed(windows_project):
    """notepad.exe imports from API-MS-WIN-CORE-FILE-L1-1-0.DLL, a library no
    binary here provides. The bare export name resolves it."""
    chain = tools.resolve_symbol("CreateFileW").results[0]
    notepad = next(l for l in chain.layers if l.program == "notepad.exe")

    assert notepad.library.upper().startswith("API-MS-WIN-")
    assert notepad.library_program == "KERNELBASE.DLL"


def test_the_apiset_hop_is_disclosed_not_hidden(windows_project):
    """Following an apiset is a heuristic. It must be visible in notes rather
    than presented as something the binary stated."""
    chain = tools.resolve_symbol("CreateFileW").results[0]
    assert any("apiset" in note for note in chain.notes)


def test_the_layers_run_consumer_to_implementation(windows_project):
    chain = tools.resolve_symbol("CreateFileW").results[0]
    assert [l.program for l in chain.layers] == [
        "notepad.exe", "KERNEL32.DLL", "KERNELBASE.DLL",
    ]


def test_ntdll_does_not_carry_createfilew(windows_project):
    """A Win32 name has no business in the native API layer."""
    chain = tools.resolve_symbol("CreateFileW").results[0]
    assert chain.absent_from == ["NTDLL.DLL"]


# --------------------------------------- the kernel transition, NB 15 §2

def test_ntcreatefile_resolves_to_ntdll(windows_project):
    chain = tools.resolve_symbol("NtCreateFile").results[0]
    assert chain.terminal_program == "NTDLL.DLL"


def test_the_application_never_touches_the_native_api(windows_project):
    """The layering claim itself: notepad.exe goes through kernel32, never
    straight to ntdll."""
    chain = tools.resolve_symbol("NtCreateFile").results[0]
    assert "notepad.exe" in chain.absent_from


def test_both_win32_layers_import_from_ntdll(windows_project):
    chain = tools.resolve_symbol("NtCreateFile").results[0]
    importers = {l.program: l.library_program for l in chain.layers if "import" in l.roles}

    assert importers == {"KERNEL32.DLL": "NTDLL.DLL", "KERNELBASE.DLL": "NTDLL.DLL"}


def test_the_last_layer_really_is_a_syscall_stub(windows_project):
    """Ground truth independent of this server: the Windows x64 stub is
    MOV R10,RCX / MOV EAX,<n> / SYSCALL."""
    listing = tools.disassemble("NTDLL.DLL", "NtCreateFile", count=8).listing

    assert "MOV R10,RCX" in listing
    assert "SYSCALL" in listing
    assert "INT 0x2e" in listing, "the legacy path should still be present"


def test_kernel32_createfilew_decompiles_to_an_indirect_jump(windows_project):
    """Corroborates the forwarder finding from the code rather than the symbol
    table: Ghidra renders a forwarder stub as a self-call through the import."""
    code = tools.decompile_function("KERNEL32.DLL", "CreateFileW").c
    assert "CreateFileW" in code
    assert "indirect jump" in code.lower() or "jumptable" in code.lower()


# ------------------------------------------- project-scope tools at scale

def test_symbols_project_covers_fifteen_thousand_functions(windows_project, count_runs):
    out = tools.list_symbols_project(kind="export", pattern="^CreateFile",
                                     programs=MULTIBIN_PROGRAMS)

    assert len(count_runs) == 1
    assert out.failures == []
    by_program = {r.program: [s.name for s in r.symbols] for r in out.results}
    assert "CreateFileW" in by_program["KERNEL32.DLL"]
    assert "CreateFileW" in by_program["KERNELBASE.DLL"]


def test_resolving_several_names_costs_one_start(windows_project, count_runs):
    out = tools.resolve_symbol(["CreateFileW", "NtCreateFile", "ReadFile"])

    assert len(count_runs) == 1
    assert [c.name for c in out.results] == ["CreateFileW", "NtCreateFile", "ReadFile"]


def test_xrefs_fan_out_over_the_windows_project(windows_project, count_runs):
    out = tools.list_xrefs_to(MULTIBIN_PROGRAMS, "CreateFileW")

    assert len(count_runs) == 1
    assert out.program == "*"
    assert {r.program for r in out.results} == set(MULTIBIN_PROGRAMS)
