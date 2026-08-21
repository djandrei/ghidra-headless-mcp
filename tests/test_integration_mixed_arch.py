"""Project-scope tools over binaries that are not all the same shape.

Everything else in the integration suite is x86-64 ELF, so a classifier that
quietly assumed ELF conventions — or a dispatcher that assumed one language per
project — would pass every other test. This fixture mixes three formats and two
architectures in one Ghidra project:

    Mach-O arm64   (KiTTY, a macOS stealer)
    PE32 x86       (Vidar, a Windows stealer)
    ELF x86-64     (a course crackme)

Both malware samples exist only as Ghidra databases and are never executed;
that is why they are kept as .gzf and named .dontrun.

Run with: pytest -m integration
"""

import pytest

from ghmcp import config, headless, tools
from tests.conftest import CRACKME, KITTY_GZF, VIDAR_GZF, import_packed

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def mixed_project(tmp_path_factory):
    for path in (KITTY_GZF, VIDAR_GZF, CRACKME):
        if not path.is_file():
            pytest.skip(f"fixture missing: {path.name}")

    loc = tmp_path_factory.mktemp("mixedarch")
    config.PROJECT_LOCATION = loc
    config.PROJECT_NAME = "mixedarch-test"

    import_packed([KITTY_GZF, VIDAR_GZF])
    tools.analyze_binary(str(CRACKME))
    programs = tools.list_programs(refresh=True).programs

    by_kind = {}
    for name in programs:
        low = name.lower()
        if "kitty" in low:
            by_kind["macho"] = name
        elif "vidar" in low:
            by_kind["pe32"] = name
        else:
            by_kind["elf"] = name
    assert len(by_kind) == 3, f"unexpected project contents: {programs}"
    return by_kind


@pytest.fixture
def count_runs(monkeypatch):
    real = headless.run_headless
    calls: list[list[str]] = []

    def counting(args, timeout):
        calls.append(list(args))
        return real(args, timeout)

    monkeypatch.setattr(headless, "run_headless", counting)
    return calls


def test_three_formats_coexist_in_one_project(mixed_project):
    rows = {r["program"]: r["data"] for r in headless.export_multi(
        "info", sorted(mixed_project.values())) if r["ok"]}
    formats = {name: d["executable_format"] for name, d in rows.items()}
    languages = {name: d["language_id"] for name, d in rows.items()}

    assert "Mac OS X Mach-O" in formats[mixed_project["macho"]]
    assert "Portable Executable" in formats[mixed_project["pe32"]]
    assert "ELF" in formats[mixed_project["elf"]]

    assert languages[mixed_project["macho"]].startswith("AARCH64")
    assert languages[mixed_project["pe32"]].startswith("x86:LE:32")
    assert languages[mixed_project["elf"]].startswith("x86:LE:64")


def test_one_start_serves_three_architectures(mixed_project, count_runs):
    """The dispatcher rebinds currentProgram across a language change, not just
    across programs."""
    rows = headless.export_multi("info", sorted(mixed_project.values()))

    assert len(count_runs) == 1
    assert all(r["ok"] for r in rows), [r.get("error") for r in rows if not r["ok"]]


def test_symbols_project_classifies_imports_in_every_format(mixed_project, count_runs):
    out = tools.list_symbols_project(kind="import", programs=sorted(mixed_project.values()))

    assert len(count_runs) == 1
    assert out.failures == []
    by_program = {r.program: r.total for r in out.results}
    assert all(total > 0 for total in by_program.values()), by_program


def test_a_macho_objc_selector_is_found_by_name(mixed_project):
    """Mach-O ground truth from the KiTTY analysis run: Objective-C selector
    names survive as symbols."""
    out = tools.list_symbols_project(kind="function", pattern="objc_msgSend",
                                     programs=[mixed_project["macho"]])
    assert out.total > 0


def test_a_pe32_import_is_found_by_name(mixed_project):
    """PE32 ground truth from the Vidar run: it imports the Win32 crypto and
    networking APIs."""
    out = tools.list_symbols_project(kind="import", pattern="^(Get|Create|Reg)",
                                     programs=[mixed_project["pe32"]])
    assert out.total > 0


def test_resolve_symbol_works_across_formats(mixed_project, count_runs):
    """The join must not fall over when the programs disagree about
    architecture, endianness or symbol conventions."""
    out = tools.resolve_symbol(["malloc", "memcpy"], sorted(mixed_project.values()))

    assert len(count_runs) == 1
    assert out.programs_searched == 3
    assert out.failures == []
    assert [c.name for c in out.results] == ["malloc", "memcpy"]


def test_a_symbol_present_in_only_one_format_is_located(mixed_project):
    """Absence is as informative as presence, and must be reported per program
    rather than collapsing the chain.

    The name carries Mach-O's leading underscore: resolve_symbol matches
    exactly, as documented, so `objc_msgSend` finds nothing and `_objc_msgSend`
    finds the stub. That is the right trade — these names come from
    list_symbols, and fuzzy matching across formats would make "which binary
    has this exact symbol" unanswerable.
    """
    chain = tools.resolve_symbol("_objc_msgSend", sorted(mixed_project.values())).results[0]

    located = [l.program for l in chain.layers]
    assert mixed_project["macho"] in located
    assert mixed_project["pe32"] in chain.absent_from
    assert mixed_project["elf"] in chain.absent_from


def test_resolve_symbol_matches_exactly_across_formats(mixed_project):
    """The companion to the test above: without the Mach-O underscore the same
    lookup finds nothing anywhere. Pinned so a later change to fuzzy matching
    is a deliberate decision rather than a silent one."""
    chain = tools.resolve_symbol("objc_msgSend", sorted(mixed_project.values())).results[0]

    assert chain.layers == []
    assert set(chain.absent_from) == set(mixed_project.values())


def test_code_search_spans_three_architectures(mixed_project):
    """Decompilation across arm64 and two x86 variants in one call. Slow the
    first time - it decompiles all three binaries - and cached after."""
    out = tools.search_code_project("memcpy|strcpy|malloc", mode="literal",
                                    programs=sorted(mixed_project.values()), limit=3)

    assert out.programs_searched == 3
    assert out.failures == []
    assert out.total_matches > 0


def test_xrefs_fan_out_across_formats(mixed_project, count_runs):
    out = tools.list_xrefs_to(sorted(mixed_project.values()), "main")

    assert len(count_runs) == 1
    assert {r.program for r in out.results} == set(mixed_project.values())
