"""MCP server exposing Ghidra's headless analyzer as tools.

Wraps `analyzeHeadless` rather than the Ghidra GUI or a running GhidraMCP
bridge, so it needs nothing but a Ghidra install on disk.

Two-phase design, forced by how analyzeHeadless works. Every invocation is a
JVM cold start, so importing and auto-analysing a binary (`analyze_binary`,
minutes) is done ONCE into a persistent project; every later query re-opens
that project with `-process -noanalysis -readOnly` and a postScript that dumps
JSON (seconds). Re-analysing per query would make the server unusable.

Configuration (env vars, matching the course's other Ghidra-backed servers):

    GHIDRA_INSTALL_DIR   Ghidra root holding support/analyzeHeadless.
                         Auto-detected if unset.
    PROJECT_LOCATION     Directory holding the Ghidra project.
                         Default: ./projects next to this file.
    PROJECT_NAME         Project name. Default: headless-mcp.

Transport is stdio, so ALL logging goes to stderr; anything on stdout
corrupts the JSON-RPC stream.
"""

import json
import logging
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Literal

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("ghidra_headless_mcp")

mcp = FastMCP("ghidra-headless-mcp")

HERE = Path(__file__).resolve().parent
SCRIPT_DIR = HERE / "ghidra_scripts"
EXPORT_SCRIPT = "HeadlessJsonExport.java"

PROJECT_LOCATION = Path(os.environ.get("PROJECT_LOCATION", HERE / "projects")).resolve()
PROJECT_NAME = os.environ.get("PROJECT_NAME", "headless-mcp")

# Ghidra locks a project for the duration of a headless run, so concurrent tool
# calls would fail with a lock error rather than queue. Serialise them here.
_GHIDRA_LOCK = threading.Lock()

ANALYZE_TIMEOUT_S = int(os.environ.get("ANALYZE_TIMEOUT_S", "1800"))
QUERY_TIMEOUT_S = int(os.environ.get("QUERY_TIMEOUT_S", "600"))


# --------------------------------------------------------------- responses


class MemoryBlock(BaseModel):
    name: str
    start: str
    end: str
    size: int
    readable: bool
    writable: bool
    executable: bool


class ProgramInfo(BaseModel):
    name: str
    executable_path: str | None = None
    executable_format: str | None = None
    md5: str | None = None
    sha256: str | None = None
    language_id: str
    compiler_spec_id: str
    image_base: str
    function_count: int
    symbol_count: int
    memory_blocks: list[MemoryBlock] = Field(default_factory=list)


class FunctionSummary(BaseModel):
    name: str
    address: str
    size: int
    signature: str
    calling_convention: str | None = None
    is_thunk: bool = False
    is_external: bool = False


class FunctionList(BaseModel):
    program: str
    total: int = Field(description="Matches before limit/offset were applied.")
    returned: int
    functions: list[FunctionSummary]


class Decompilation(BaseModel):
    program: str
    name: str
    address: str
    signature: str | None = None
    c: str


class StringHit(BaseModel):
    address: str
    length: int
    value: str


class StringList(BaseModel):
    program: str
    total: int
    returned: int
    strings: list[StringHit]


class AnalysisResult(BaseModel):
    program: str
    already_analyzed: bool = Field(
        description="True when the program was already in the project and "
        "re-analysis was skipped because force=False."
    )
    duration_seconds: float
    info: ProgramInfo


class ProgramList(BaseModel):
    project: str
    project_location: str
    programs: list[str]


class ScriptResult(BaseModel):
    program: str
    script: str
    exit_code: int
    stdout_tail: str = Field(description="Last 200 lines of the headless log.")


# ----------------------------------------------------------------- plumbing


def _find_ghidra() -> Path:
    """Locate analyzeHeadless, preferring GHIDRA_INSTALL_DIR."""
    candidates: list[Path] = []
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env:
        candidates.append(Path(env))
    candidates += [
        Path("/ghidra"),                            # course devcontainer
        *sorted(Path.home().glob("bin/ghidra_*")),  # host installs
        *sorted(Path("/opt").glob("ghidra*")),
    ]
    for root in candidates:
        script = root / "support" / "analyzeHeadless"
        if script.is_file():
            return script
    raise RuntimeError(
        "analyzeHeadless not found. Set GHIDRA_INSTALL_DIR to a Ghidra "
        f"install root (tried: {', '.join(str(c) for c in candidates)})."
    )


def _script_path() -> str:
    """Search path for -scriptPath: this server's scripts, then Ghidra's own.

    Ghidra searches only what -scriptPath names, so the bundled script
    directory has to be listed explicitly or run_ghidra_script cannot reach
    the ~190 stock scripts.
    """
    bundled = _find_ghidra().parent.parent / "Ghidra" / "Features" / "Base" / "ghidra_scripts"
    return f"{SCRIPT_DIR};{bundled}"


def _run_headless(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    """Invoke analyzeHeadless with the project location and name prepended."""
    PROJECT_LOCATION.mkdir(parents=True, exist_ok=True)
    cmd = [str(_find_ghidra()), str(PROJECT_LOCATION), PROJECT_NAME, *args]
    logger.info("running: %s", " ".join(cmd))

    with _GHIDRA_LOCK:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"analyzeHeadless exceeded {timeout}s. Raise ANALYZE_TIMEOUT_S / "
                "QUERY_TIMEOUT_S, or analyse a smaller binary."
            ) from exc

    if proc.returncode != 0:
        tail = "\n".join((proc.stdout or "").splitlines()[-40:])
        raise RuntimeError(
            f"analyzeHeadless exited {proc.returncode}:\n{tail}\n{proc.stderr[-2000:]}"
        )
    return proc


def _export(program: str, mode: str, arg: str | None = None) -> dict:
    """Re-open an analysed program read-only and dump `mode` as JSON."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "export.json"
        script_args = [mode, str(out)]
        if arg is not None:
            script_args.append(arg)

        _run_headless(
            [
                "-process", program,
                "-noanalysis",
                "-readOnly",
                "-scriptPath", _script_path(),
                "-postScript", EXPORT_SCRIPT, *script_args,
            ],
            timeout=QUERY_TIMEOUT_S,
        )

        if not out.is_file():
            raise RuntimeError(
                f"the export script produced no output for program {program!r}. "
                "Has it been analysed? Call analyze_binary first, or check "
                "list_programs for the exact name."
            )
        return json.loads(out.read_text())


def _index_path() -> Path:
    return PROJECT_LOCATION / f"{PROJECT_NAME}.programs.json"


def _index_read() -> list[str]:
    p = _index_path()
    return json.loads(p.read_text()) if p.is_file() else []


def _index_add(program: str) -> None:
    known = _index_read()
    if program not in known:
        known.append(program)
        _index_path().write_text(json.dumps(sorted(known), indent=2))


# --------------------------------------------------------------------- tools


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
    import time

    src = Path(binary_path).expanduser().resolve()
    if not src.is_file():
        raise RuntimeError(f"binary not found: {src}")

    program = src.name
    if program in _index_read() and not force:
        logger.info("%s already analysed; returning stored info", program)
        return AnalysisResult(
            program=program,
            already_analyzed=True,
            duration_seconds=0.0,
            info=ProgramInfo(**_export(program, "info")),
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
    _run_headless(args, timeout=ANALYZE_TIMEOUT_S)
    elapsed = time.monotonic() - started

    _index_add(program)
    logger.info("analysed %s in %.1fs", program, elapsed)
    return AnalysisResult(
        program=program,
        already_analyzed=False,
        duration_seconds=round(elapsed, 1),
        info=ProgramInfo(**_export(program, "info")),
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
        project=PROJECT_NAME,
        project_location=str(PROJECT_LOCATION),
        programs=_index_read(),
    )


@mcp.tool()
def get_program_info(program: str) -> ProgramInfo:
    """Get metadata for an analyzed program: hashes, architecture, image base,
    function and symbol counts, and the memory block layout.

    Args:
        program: Program name as returned by list_programs.
    """
    return ProgramInfo(**_export(program, "info"))


@mcp.tool()
def list_functions(
    program: str,
    name_contains: str | None = None,
    limit: int = 200,
    offset: int = 0,
    include_thunks: bool = False,
    include_external: bool = False,
) -> FunctionList:
    """List functions in an analyzed program.

    Stripped binaries yield mostly FUN_<address> names — that is Ghidra's
    auto-analysis result, not a failure of this tool.

    Args:
        program: Program name as returned by list_programs.
        name_contains: Case-insensitive substring filter on the function name.
        limit: Maximum functions to return. Keep this small; a large binary has
            thousands and they will not fit in a model's context.
        offset: Skip this many matches, for paging.
        include_thunks: Include thunk functions.
        include_external: Include external (imported) functions.
    """
    items = [FunctionSummary(**f) for f in _export(program, "functions")["functions"]]

    if not include_thunks:
        items = [f for f in items if not f.is_thunk]
    if not include_external:
        items = [f for f in items if not f.is_external]
    if name_contains:
        needle = name_contains.lower()
        items = [f for f in items if needle in f.name.lower()]

    total = len(items)
    page = items[offset : offset + limit]
    return FunctionList(
        program=program, total=total, returned=len(page), functions=page
    )


@mcp.tool()
def decompile_function(program: str, function: str) -> Decompilation:
    """Decompile one function to C.

    Args:
        program: Program name as returned by list_programs.
        function: Function name ("main", "FUN_0041d000") or entry-point address
            ("0041d000"). Names are tried exactly first, then case-insensitively.
    """
    data = _export(program, "decompile", function)
    if "error" in data and "c" not in data:
        raise RuntimeError(data["error"])
    return Decompilation(program=program, **data)


@mcp.tool()
def list_strings(
    program: str,
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
        contains: Case-insensitive substring filter.
        min_length: Minimum string length.
        limit: Maximum strings to return.
        offset: Skip this many matches, for paging.
    """
    items = [
        StringHit(**s) for s in _export(program, "strings", str(min_length))["strings"]
    ]
    if contains:
        needle = contains.lower()
        items = [s for s in items if needle in s.value.lower()]

    total = len(items)
    page = items[offset : offset + limit]
    return StringList(program=program, total=total, returned=len(page), strings=page)


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
    args = ["-process", program, "-noanalysis", "-scriptPath", _script_path()]
    if read_only:
        args.append("-readOnly")
    args += [f"-{stage}Script", script_name, *(script_args or [])]

    proc = _run_headless(args, timeout=QUERY_TIMEOUT_S)
    return ScriptResult(
        program=program,
        script=script_name,
        exit_code=proc.returncode,
        stdout_tail="\n".join((proc.stdout or "").splitlines()[-200:]),
    )


if __name__ == "__main__":
    logger.info(
        "ghidra-headless-mcp starting: project=%s location=%s",
        PROJECT_NAME,
        PROJECT_LOCATION,
    )
    mcp.run()
