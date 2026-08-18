"""MCP tool definitions.

Tools stay thin: validate and shape arguments, call one export mode, build a
typed model. Anything that talks to Ghidra belongs in headless.py; anything
reusable across tools belongs in paging.py.
"""

import logging
import re
import time
from pathlib import Path
from typing import Literal

from mcp.server.fastmcp import FastMCP

from . import config, headless
from .errors import BadArgument, NotFound
from .models import (
    AnalysisResult,
    BytesRead,
    Decompilation,
    Disassembly,
    FunctionDetail,
    FunctionList,
    FunctionSummary,
    MemoryBlockList,
    ProgramInfo,
    ProgramList,
    ScriptResult,
    StringHit,
    SymbolEntry,
    SymbolList,
    StringList,
    XrefEntry,
    XrefList,
    XrefTargetResult,
)
from .paging import page

logger = logging.getLogger("ghidra_headless_mcp")

mcp = FastMCP("ghidra-headless-mcp")


def _pattern(pattern: str | None, literal: str | None) -> str | None:
    """Resolve the regex argument against its deprecated literal alias.

    The literal is escaped rather than passed through, so a legacy caller
    filtering on "a.b" keeps matching only "a.b" and does not silently start
    matching "axb" now that the field is a regex.
    """
    if pattern:
        return pattern
    if literal:
        return re.escape(literal)
    return None


@mcp.tool()
def analyze_binary(
    binary_path: str,
    force: bool = False,
    processor: str | None = None,
    cspec: str | None = None,
    max_cpu: int | None = None,
) -> AnalysisResult:
    """Import a binary into the Ghidra project and run full auto-analysis.

    This is the slow call — minutes for a large binary, since it cold-starts a
    JVM and runs every analyzer. Run it once per binary; all other tools then
    query the stored result in seconds.

    Args:
        binary_path: Path to the binary on disk.
        force: Re-import and re-analyse even if the program is already in the
            project (passes -overwrite). Default skips the work.
        processor: Language ID such as "x86:LE:64:default". Only needed when
            Ghidra's auto-detection is wrong (raw firmware, headless blobs).
        cspec: Compiler spec ID, e.g. "gcc". Rarely needed alongside processor.
        max_cpu: Cap the analyzer's CPU cores.
    """
    src = Path(binary_path).expanduser().resolve()
    if not src.is_file():
        raise NotFound(f"binary not found: {src}")

    program = src.name
    if program in headless.index_read() and not force:
        logger.info("%s already analysed; returning stored info", program)
        return AnalysisResult(
            program=program,
            already_analyzed=True,
            duration_seconds=0.0,
            info=ProgramInfo(**headless.export(program, "info")),
        )

    args = ["-import", str(src)]
    if force:
        args.append("-overwrite")
    if processor:
        args += ["-processor", processor]
    if cspec:
        args += ["-cspec", cspec]
    if max_cpu:
        args += ["-max-cpu", str(max_cpu)]

    started = time.monotonic()
    headless.run_headless(args, timeout=config.ANALYZE_TIMEOUT_S)
    elapsed = time.monotonic() - started

    headless.index_add(program)
    logger.info("analysed %s in %.1fs", program, elapsed)
    return AnalysisResult(
        program=program,
        already_analyzed=False,
        duration_seconds=round(elapsed, 1),
        info=ProgramInfo(**headless.export(program, "info")),
    )


@mcp.tool()
def list_programs() -> ProgramList:
    """List the programs analyzed into this project, by name.

    Names come from an index this server maintains, not from the project
    itself, so programs imported by an external analyzeHeadless run or the
    Ghidra GUI will not appear. Use these names for the `program` argument of
    the other tools.
    """
    return ProgramList(
        project=config.PROJECT_NAME,
        project_location=str(config.PROJECT_LOCATION),
        programs=headless.index_read(),
    )


@mcp.tool()
def get_program_info(program: str) -> ProgramInfo:
    """Get metadata for an analyzed program: hashes, architecture, image base,
    function and symbol counts, and the memory block layout.

    Args:
        program: Program name as returned by list_programs.
    """
    return ProgramInfo(**headless.export(program, "info"))


@mcp.tool()
def list_functions(
    program: str,
    pattern: str | None = None,
    name_contains: str | None = None,
    limit: int = 200,
    offset: int = 0,
    include_thunks: bool = False,
    include_external: bool = False,
) -> FunctionList:
    """List or search functions in an analyzed program.

    Stripped binaries yield mostly FUN_<address> names — that is Ghidra's
    auto-analysis result, not a failure of this tool.

    Filtering happens inside Ghidra, so a narrow pattern on a large binary
    transfers a few rows instead of tens of thousands.

    Args:
        program: Program name as returned by list_programs.
        pattern: Case-insensitive regular expression matched against the
            function name, e.g. "^main$" or "crypt|aes|rc4". A plain substring
            is a valid regex, so it keeps working.
        name_contains: Deprecated literal-substring filter, kept for
            compatibility. Ignored when `pattern` is given.
        limit: Maximum functions to return. Keep this small; a large binary has
            thousands and they will not fit in a model's context.
        offset: Skip this many matches, for paging.
        include_thunks: Include thunk functions.
        include_external: Include external (imported) functions.
    """
    data = headless.export(
        program,
        "functions",
        {
            "pattern": _pattern(pattern, name_contains),
            "include_thunks": include_thunks,
            "include_external": include_external,
        },
    )
    items = [FunctionSummary(**f) for f in data["functions"]]
    window = page(items, limit, offset)
    return FunctionList(
        program=program,
        total=data.get("matched", len(items)),
        returned=len(window),
        truncated=data.get("truncated", False),
        functions=window,
    )


@mcp.tool()
def decompile_function(program: str, function: str) -> Decompilation:
    """Decompile one function to C.

    Args:
        program: Program name as returned by list_programs.
        function: Function name ("main", "FUN_0041d000") or entry-point address
            ("0041d000"). Names are tried exactly first, then case-insensitively.
    """
    data = headless.export(program, "decompile", {"target": function})
    return Decompilation(program=program, **data)


@mcp.tool()
def list_strings(
    program: str,
    pattern: str | None = None,
    contains: str | None = None,
    min_length: int = 4,
    limit: int = 200,
    offset: int = 0,
) -> StringList:
    """List defined strings in an analyzed program.

    These are strings Ghidra's analysis *defined* as data, which is not the same
    set the `strings` utility reports — encrypted or packed data will not show
    up here until it is defined.

    Args:
        program: Program name as returned by list_programs.
        pattern: Case-insensitive regular expression matched against the string
            value, e.g. "https?://" or "\\.onion$".
        contains: Deprecated literal-substring filter, kept for compatibility.
            Ignored when `pattern` is given.
        min_length: Minimum string length.
        limit: Maximum strings to return.
        offset: Skip this many matches, for paging.
    """
    data = headless.export(
        program,
        "strings",
        {"min_length": min_length, "pattern": _pattern(pattern, contains)},
    )
    items = [StringHit(**s) for s in data["strings"]]
    window = page(items, limit, offset)
    return StringList(
        program=program,
        total=data.get("matched", len(items)),
        returned=len(window),
        truncated=data.get("truncated", False),
        strings=window,
    )


@mcp.tool()
def run_ghidra_script(
    program: str,
    script_name: str,
    script_args: list[str] | None = None,
    stage: Literal["post", "pre"] = "post",
    read_only: bool = True,
) -> ScriptResult:
    """Run an arbitrary Ghidra script against an analyzed program.

    The escape hatch for anything the typed tools above do not cover — Ghidra
    ships ~190 scripts in Ghidra/Features/Base/ghidra_scripts. The script must
    be headless-safe: one calling GUI-only methods raises ImproperUseException.
    Script stdout is returned as a log tail, not parsed, so prefer a script that
    writes its own output file.

    Args:
        program: Program name as returned by list_programs.
        script_name: Script filename, e.g. "ExportFunctionInfoScript.java".
        script_args: Arguments passed through to the script.
        stage: Run before ("pre") or after ("post") the no-op analysis pass.
        read_only: Discard any changes the script makes. Set False to persist
            renames, comments and applied types into the project.
    """
    if stage not in ("post", "pre"):
        raise BadArgument(f"stage must be 'post' or 'pre', got {stage!r}")

    args = ["-process", program, "-noanalysis", "-scriptPath", config.script_path()]
    if read_only:
        args.append("-readOnly")
    args += [f"-{stage}Script", script_name, *(script_args or [])]

    proc = headless.run_headless(args, timeout=config.QUERY_TIMEOUT_S)
    return ScriptResult(
        program=program,
        script=script_name,
        exit_code=proc.returncode,
        stdout_tail="\n".join((proc.stdout or "").splitlines()[-200:]),
    )


# ------------------------------------------------------------------ xrefs


def _normalise_targets(target: str | list[str]) -> list[str]:
    """Accept one target or many, and reject an empty request early."""
    targets = [target] if isinstance(target, str) else list(target)
    targets = [t for t in targets if t]
    if not targets:
        raise BadArgument("at least one target is required")
    return targets


def _xrefs(
    program: str, target: str | list[str], direction: str, limit: int, offset: int
) -> XrefList:
    data = headless.export(
        program, "xrefs", {"targets": _normalise_targets(target), "direction": direction}
    )
    results = []
    for row in data["results"]:
        entries = [XrefEntry(**x) for x in row.get("xrefs", [])]
        window = page(entries, limit, offset)
        results.append(
            XrefTargetResult(
                target=row["target"],
                resolved_address=row.get("resolved_address"),
                resolved_kind=row.get("resolved_kind"),
                error=row.get("error"),
                total=len(entries),
                returned=len(window),
                xrefs=window,
            )
        )
    return XrefList(program=program, direction=data["direction"], results=results)


@mcp.tool()
def list_xrefs_to(
    program: str,
    target: str | list[str],
    limit: int = 100,
    offset: int = 0,
) -> XrefList:
    """Find everything that references a function, symbol or address.

    The impact-analysis question: who can reach this code. Each result carries
    the function containing the reference, so "called from main" is answerable
    without a second lookup.

    Pass a list of targets to resolve many in one call — this backend pays a
    JVM start per call, so batching is much faster than looping.

    Args:
        program: Program name as returned by list_programs.
        target: Function name, symbol name, or address — or a list of them. A
            target that cannot be resolved reports its own error and does not
            fail the others.
        limit: Maximum references per target.
        offset: Skip this many references per target, for paging.
    """
    return _xrefs(program, target, "to", limit, offset)


@mcp.tool()
def list_xrefs_from(
    program: str,
    target: str | list[str],
    limit: int = 100,
    offset: int = 0,
) -> XrefList:
    """Find everything a function, symbol or address references.

    The outward walk: what this code touches. Use it to follow control and data
    flow from an entry point, or to see which strings and imports a function
    uses.

    Args:
        program: Program name as returned by list_programs.
        target: Function name, symbol name, or address — or a list of them.
        limit: Maximum references per target.
        offset: Skip this many references per target, for paging.
    """
    return _xrefs(program, target, "from", limit, offset)


@mcp.tool()
def get_function_at(program: str, address: str) -> FunctionDetail:
    """Identify the function at, or containing, an address.

    Answers "what am I looking at" for an address from a crash dump, a
    cross-reference, or a disassembly listing. If the address is inside a
    function rather than its entry point, the containing function is returned
    with is_entry_point set to False.

    Args:
        program: Program name as returned by list_programs.
        address: Address in hex, with or without a 0x prefix.
    """
    return FunctionDetail(**headless.export(program, "function_at", {"address": address}))


# -------------------------------------------------------------- raw views


@mcp.tool()
def disassemble(
    program: str,
    target: str,
    count: int = 20,
    include_bytes: bool = False,
) -> Disassembly:
    """Disassemble a function body, or N instructions from any address.

    Reach for this when the decompiler cannot be trusted: obfuscated or
    hand-written assembly, data misidentified as code, or shellcode with no
    function structure at all. Unlike decompile_function, an address target
    needs no entry point.

    Args:
        program: Program name as returned by list_programs.
        target: Function name (disassembles the whole body) or an address
            (disassembles `count` instructions forward from there).
        count: Maximum instructions. Capped at 200.
        include_bytes: Add a column of raw instruction bytes in hex, for
            checking what the disassembler actually consumed.
    """
    if count <= 0:
        raise BadArgument("count must be positive")
    data = headless.export(
        program,
        "disassemble",
        {"target": target, "count": count, "include_bytes": include_bytes},
    )
    return Disassembly(program=program, **data)


@mcp.tool()
def read_bytes(program: str, address: str, size: int = 32) -> BytesRead:
    """Read raw bytes from the program at an address.

    The tool that lets an analysis extract material rather than describe it: an
    encrypted blob, a key table, a header. Returns hex plus a printable
    rendering.

    Args:
        program: Program name as returned by list_programs.
        address: Address, symbol name, or function name to read from.
        size: Number of bytes. Capped at 4096 to protect the response size.
    """
    if size <= 0:
        raise BadArgument("size must be positive")
    data = headless.export(program, "read_bytes", {"address": address, "size": size})
    return BytesRead(program=program, **data)


# ------------------------------------------------------ symbol inventory

SYMBOL_KINDS = ("import", "export", "data", "class", "namespace", "label", "function")


@mcp.tool()
def list_symbols(
    program: str,
    kind: str = "import",
    pattern: str | None = None,
    name_contains: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> SymbolList:
    """List symbols of one kind: imports, exports, data, classes, namespaces…

    Imports are the fastest read on what a binary can do — a sample that
    imports CryptEncrypt, InternetOpenUrl and CreateRemoteThread has announced
    most of its capability before a single function is decompiled. Exports
    matter for libraries; classes and namespaces expose recovered C++ or Java
    structure.

    Args:
        program: Program name as returned by list_programs.
        kind: One of import, export, data, class, namespace, label, function.
        pattern: Case-insensitive regular expression matched against the symbol
            name, e.g. "^Crypt" or "socket|connect|send".
        name_contains: Deprecated literal-substring filter, kept for
            compatibility. Ignored when `pattern` is given.
        limit: Maximum symbols to return.
        offset: Skip this many matches, for paging.
    """
    if kind not in SYMBOL_KINDS:
        raise BadArgument(f"kind must be one of {', '.join(SYMBOL_KINDS)}, got {kind!r}")

    data = headless.export(
        program, "symbols", {"kind": kind, "pattern": _pattern(pattern, name_contains)}
    )
    items = [SymbolEntry(**sym) for sym in data["symbols"]]
    window = page(items, limit, offset)
    return SymbolList(
        program=program,
        kind=data["kind"],
        total=data.get("matched", len(items)),
        returned=len(window),
        truncated=data.get("truncated", False),
        symbols=window,
    )


@mcp.tool()
def list_memory_blocks(program: str) -> MemoryBlockList:
    """List the program's memory blocks: the map of where code and data sit.

    Use it to find the section holding a packed payload, to see which regions
    are writable and executable, or to pick an address range for read_bytes.

    Args:
        program: Program name as returned by list_programs.
    """
    info = ProgramInfo(**headless.export(program, "info"))
    return MemoryBlockList(
        program=program, total=len(info.memory_blocks), blocks=info.memory_blocks
    )
