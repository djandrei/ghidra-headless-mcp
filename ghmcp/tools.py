"""MCP tool definitions.

Tools stay thin: validate and shape arguments, call one export mode, build a
typed model. Anything that talks to Ghidra belongs in headless.py; anything
reusable across tools belongs in paging.py.
"""

import base64
import binascii
import hashlib
import logging
import os
import re
import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from mcp.server.fastmcp import FastMCP

from . import codesearch, config, headless
from .errors import BadArgument, GhidraError, HeadlessError, NotFound, from_envelope
from .models import (
    AnalysisBatchResult,
    AnalysisResult,
    BytesRead,
    BytesReadBatch,
    BytesReadResult,
    CallGraph,
    ChatUpload,
    ChatUploadList,
    CodeMatch,
    CodeSearchProjectResults,
    CodeSearchResults,
    DeleteResult,
    EditBatchResult,
    EditResult,
    Decompilation,
    DecompilationBatch,
    DecompilationResult,
    Disassembly,
    FunctionDetail,
    FunctionList,
    FunctionSummary,
    MemoryBlockList,
    MemoryHit,
    MemorySearchResults,
    ProgramFailure,
    ProgramInfo,
    ProgramList,
    ScriptResult,
    StringHit,
    SymbolChain,
    SymbolEntry,
    SymbolList,
    SymbolListProject,
    SymbolLocation,
    SymbolResolution,
    StoredUpload,
    StringList,
    UploadDeleteResult,
    UploadList,
    UploadResult,
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


def _normalise_programs(program: str | list[str] | None) -> list[str]:
    """Accept one program, many, or None/"*" meaning every program in the index.

    Mirrors _normalise_targets. "*" resolves from the local index rather than
    the project, so it stays free; a caller wanting programs imported by an
    external run calls list_programs(refresh=True) first, which repairs the
    index.

    Duplicates are dropped but order is preserved, so a caller can rely on the
    results coming back in the order it asked for.
    """
    if program is None or program == "*":
        names = headless.index_read()
        if not names:
            raise BadArgument(
                "the project holds no programs. Call analyze_binary first, or "
                "list_programs(refresh=True) if they were imported elsewhere."
            )
        return names

    names = [program] if isinstance(program, str) else list(program)
    names = [n for n in names if n]
    if not names:
        raise BadArgument("at least one program is required")

    seen: set[str] = set()
    return [n for n in names if not (n in seen or seen.add(n))]


def _fan_out(mode: str, programs: list[str], args: dict, build):
    """Run one mode over several programs and split the rows by outcome.

    `build(program, data)` turns one program's payload into its typed model.
    Successes and failures come back separately so a caller never has to check
    an optional error field on every row.

    Rows use .get() throughout: mcpo omits null fields entirely, so `detail`
    and `error` are absent rather than None.
    """
    results, failures = [], []
    for row in headless.export_multi(mode, programs, args):
        if row.get("ok"):
            results.append(build(row["program"], row["data"]))
        else:
            err = row.get("error") or {}
            failures.append(
                ProgramFailure(
                    program=row.get("program", "?"),
                    error=err.get("message", "unknown failure"),
                    error_kind=err.get("kind"),
                )
            )
    return results, failures


# Formats Ghidra imports as a packed program rather than loading from bytes.
# It takes a lock file beside the source for these, and only these.
PACKED_SUFFIXES = {".gzf", ".gar"}


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
        binary_path: Path to the binary on disk, as this server sees it. For
            a file attached in the chat, get it from list_chat_uploads; for one
            sent with upload_binary, use the path that returned.
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

    # The project may hold this binary under a different name than the file
    # carries, so check every candidate before deciding to re-analyse.
    md5 = file_md5(src)
    known = headless.index_read()
    attached_as = import_filename(src)
    desired = sanitize_program_name(attached_as)

    # A name in the index proves nothing about *which* binary holds it. Compare
    # Ghidra's recorded MD5 with the file's before trusting it, or two unrelated
    # samples that share a basename silently become one.
    existing = next((n for n in candidate_names(attached_as) if n in known), None)
    if existing and not force:
        try:
            stored = _stored_result(existing)
            if (stored.info.md5 or "").lower() == md5:
                return stored
            logger.info(
                "%r is taken by a different binary (project md5 %s, file md5 %s); "
                "importing under a distinct name", existing, stored.info.md5, md5
            )
            desired = disambiguate_name(desired, md5)
            # The disambiguated name may itself already hold this exact binary.
            if desired in known:
                again = _stored_result(desired)
                if (again.info.md5 or "").lower() == md5:
                    return again
        except HeadlessError:
            # The index named a program the project does not have. Repair from
            # the project rather than re-importing, and never let a stale entry
            # be the reason an analysed binary looks unanalysed.
            logger.warning("index entry %r is stale; repairing from the project", existing)
            headless.index_remove(existing)
            names = _project_programs()
            for name in names:
                headless.index_add(name)
            recovered = next((n for n in candidate_names(attached_as) if n in names), None)
            if recovered:
                return _stored_result(recovered)
    # Stage under the chosen name when it differs from the file's: Ghidra names
    # the program after the file, rejects some characters filenames carry, and
    # cannot hold two programs of the same name.
    # Ghidra writes a lock file *beside* a packed program while importing it, so
    # a .gzf on a read-only mount fails with "Read-only file system" however
    # ordinary its name is. Raw binaries take no lock and import in place. This
    # is not hypothetical: the container mounts the course clone read-only.
    needs_lock_beside_it = src.suffix.lower() in PACKED_SUFFIXES and not os.access(
        src.parent, os.W_OK
    )
    import_stack: list = []
    src = _stage_for_import(src, desired, needs_lock_beside_it, import_stack)

    program = desired

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
    try:
        proc = headless.run_headless(args, timeout=config.ANALYZE_TIMEOUT_S)
    finally:
        for d in import_stack:
            shutil.rmtree(d, ignore_errors=True)
    elapsed = time.monotonic() - started

    # Ghidra, not the filename, decides what the program is called: importing
    # foo.exe.gzf yields "foo.exe". Assuming the filename made every follow-up
    # call fail with "Requested project program file(s) not found".
    _raise_if_import_failed(proc.stdout or "", src)

    from_log = _imported_program_name(proc.stdout or "", "")
    # Only pay for a project listing when the log did not answer, which is the
    # skipped-import case rather than the common one.
    project_names = [] if from_log else _project_programs()
    program = resolve_program_name(proc.stdout or "", src.name, project_names)

    # Index only after the name is proven usable. Recording it first is what
    # let a failed run leave a name behind that no later call could resolve.
    info = ProgramInfo(**headless.export(program, "info"))
    headless.index_add(program)
    logger.info("analysed %s in %.1fs", program, elapsed)
    return AnalysisResult(
        program=program,
        already_analyzed=False,
        duration_seconds=round(elapsed, 1),
        info=info,
    )


def _stage_for_import(src: Path, desired: str, needs_lock: bool, stack: list) -> Path:
    """Return the path to hand -import, staging a copy when needed.

    Two reasons to stage, both real:

    * the program must be named something other than the file is called —
      Ghidra names the program after the file and rejects characters filenames
      carry;
    * the file is packed and its directory is read-only — Ghidra writes a lock
      file *beside* a packed program while importing it, so a .gzf on a
      read-only mount fails with "Read-only file system". The container mounts
      the course clone read-only, so this is not hypothetical.

    A symlink does not work: Ghidra resolves it and takes the program name from
    the target. Hard-link where the filesystem allows, copy across devices.
    Directories to clean up are appended to `stack`.

    The staging directory goes in the system temp location, never beside the
    source. Staging in the source directory writes into whatever tree the
    caller pointed at - which for the course clone is a directory this project
    is not allowed to touch - and a process killed before the cleanup runs
    leaves it there. Observed: a timed-out batch import left a staging
    directory holding a hard link inside the read-only clone.
    """
    if desired == src.name and not needs_lock:
        return src

    tmpdir = tempfile.mkdtemp(prefix="ghmcp-import-")
    stack.append(tmpdir)
    staged = Path(tmpdir) / desired
    try:
        os.link(src, staged)
    except OSError:
        shutil.copy2(src, staged)
    if desired != src.name:
        logger.info("importing %r as %r", src.name, desired)
    else:
        logger.info("staging %r: its directory is read-only and Ghidra locks a "
                    "packed program in place", src.name)
    return staged


@mcp.tool()
def analyze_binaries(
    paths: str | list[str],
    force: bool = False,
    recursive: bool = False,
    processor: str | None = None,
    cspec: str | None = None,
    max_cpu: int | None = None,
) -> AnalysisBatchResult:
    """Import and auto-analyse several binaries in one analyzeHeadless run.

    The batch form of analyze_binary, and the way to load a program together
    with its libraries for cross-binary work: an application and its DLLs, a
    dropper and its payload, a firmware's bootloader and kernel. Once they
    share a project, search_code_project, list_symbols_project and
    resolve_symbol can reason across them.

    Analysis itself is not faster — every binary still runs every analyzer —
    but the JVM starts once instead of once per binary, and the metadata is
    read back for all of them in a second single start.

    Binaries already in the project are skipped without being re-imported, as
    with analyze_binary, and identity is checked by MD5 rather than by name.
    A binary whose name is taken by a *different* binary is handed to
    analyze_binary individually, which knows how to import it under a distinct
    name; that costs an extra JVM start for that one file.

    Args:
        paths: File path, list of paths, or a directory. Directories need
            recursive=True.
        force: Re-import and re-analyse even when already present.
        recursive: Descend into any directory in `paths`. Off by default so a
            directory argument cannot silently import hundreds of files.
        processor: Language ID such as "x86:LE:64:default", applied to every
            binary in the batch.
        cspec: Compiler spec ID, applied to every binary in the batch.
        max_cpu: Cap the analyzer's CPU cores.
    """
    started = time.monotonic()
    starts_before = headless.run_count
    sources = _collect_binaries(paths, recursive)
    known = headless.index_read()

    results: list[AnalysisResult] = []
    failures: list[ProgramFailure] = []
    pending: list[tuple[Path, str]] = []   # (source, program name to import as)

    # Which sources already have their name in the project, and what those
    # programs actually are. Asked once for the whole batch: a re-run over an
    # unchanged directory is then a single JVM start rather than one per file.
    taken: dict[Path, str] = {}
    if not force:
        for src in sources:
            existing = next((n for n in candidate_names(import_filename(src)) if n in known), None)
            if existing:
                taken[src] = existing
    stored_info = _batch_info(sorted(set(taken.values())))

    for src in sources:
        desired = sanitize_program_name(import_filename(src))
        existing = taken.get(src)
        info = stored_info.get(existing) if existing else None

        # No name clash, or the index named a program the project does not
        # actually hold — either way, import it.
        if info is None:
            pending.append((src, desired))
            continue

        # The name is taken. Whether by this binary or another is an MD5
        # question, and the answer decides between skipping and a rename that
        # only analyze_binary knows how to do.
        if (info.md5 or "").lower() == file_md5(src):
            results.append(
                AnalysisResult(program=existing, already_analyzed=True,
                               duration_seconds=0.0, info=info)
            )
            continue

        logger.info("%r is taken by a different binary; handing %s to analyze_binary",
                    existing, src.name)
        try:
            results.append(analyze_binary(str(src), processor=processor, cspec=cspec,
                                          max_cpu=max_cpu))
        except HeadlessError as exc:
            failures.append(ProgramFailure(program=str(src), error=str(exc),
                                           error_kind=exc.kind))

    if pending:
        imported, import_failures = _import_batch(
            pending, force=force, processor=processor, cspec=cspec, max_cpu=max_cpu
        )
        results.extend(imported)
        failures.extend(import_failures)

    skipped = sum(1 for r in results if r.already_analyzed)
    return AnalysisBatchResult(
        results=results,
        failures=failures,
        imported=len(results) - skipped,
        skipped=skipped,
        duration_seconds=round(time.monotonic() - started, 1),
        jvm_starts=headless.run_count - starts_before,
    )


def _batch_info(programs: list[str]) -> dict[str, ProgramInfo]:
    """Metadata for several programs in one JVM start, skipping any that fail.

    A program in the index that the project does not hold is a stale entry, not
    an error: it comes back missing and the caller re-imports.
    """
    if not programs:
        return {}
    out: dict[str, ProgramInfo] = {}
    for row in headless.export_multi("info", programs):
        if row.get("ok"):
            out[row["program"]] = ProgramInfo(**row["data"])
        else:
            logger.warning("index entry %r is stale; it will be re-imported",
                           row.get("program"))
    return out


def _collect_binaries(paths: str | list[str], recursive: bool) -> list[Path]:
    """Resolve the argument to a list of existing files, in a stable order."""
    raw = [paths] if isinstance(paths, str) else list(paths)
    if not raw:
        raise BadArgument("at least one path is required")

    found: list[Path] = []
    for item in raw:
        path = Path(item).expanduser().resolve()
        if path.is_dir():
            if not recursive:
                raise BadArgument(
                    f"{path} is a directory; pass recursive=True to import what "
                    "is inside it"
                )
            found.extend(sorted(p for p in path.rglob("*") if p.is_file()))
        elif path.is_file():
            found.append(path)
        else:
            raise NotFound(f"binary not found: {path}")

    if not found:
        raise NotFound(f"no files found in {', '.join(str(p) for p in raw)}")

    # A path given twice, or reachable both directly and through a directory,
    # must not be imported twice.
    seen: set[Path] = set()
    return [p for p in found if not (p in seen or seen.add(p))]


def _import_batch(
    pending: list[tuple[Path, str]],
    *,
    force: bool,
    processor: str | None,
    cspec: str | None,
    max_cpu: int | None,
) -> tuple[list[AnalysisResult], list[ProgramFailure]]:
    """Import every pending binary in one run, then read all metadata in one more.

    analyzeHeadless takes several paths after -import, so N binaries cost one
    JVM start rather than N. The log then carries one "file created" line per
    binary, which is what tells us the names Ghidra chose — importing foo.exe.gzf
    yields "foo.exe", and assuming the filename is what once made every
    follow-up call fail with "Requested project program file(s) not found".
    """
    stack: list = []
    staged: list[tuple[Path, Path]] = []
    try:
        for src, desired in pending:
            needs_lock = src.suffix.lower() in PACKED_SUFFIXES and not os.access(
                src.parent, os.W_OK
            )
            staged.append((src, _stage_for_import(src, desired, needs_lock, stack)))

        args = ["-import", *[str(path) for _, path in staged]]
        if force:
            args.append("-overwrite")
        if processor:
            args += ["-processor", processor]
        if cspec:
            args += ["-cspec", cspec]
        if max_cpu:
            args += ["-max-cpu", str(max_cpu)]

        proc = headless.run_headless(args, timeout=config.ANALYZE_TIMEOUT_S)
    finally:
        for directory in stack:
            shutil.rmtree(directory, ignore_errors=True)

    log = proc.stdout or ""
    created = [m.group(1).strip() for m in _CREATED.finditer(log)]

    programs: list[str] = []
    failures: list[ProgramFailure] = []
    for original, path in staged:
        name = _match_created(path.name, created)
        if name is None:
            failures.append(
                ProgramFailure(
                    program=str(original),
                    error=_import_failure_reason(log, path),
                    error_kind="import_failed",
                )
            )
            continue
        created.remove(name)
        programs.append(name)

    if not programs:
        return [], failures

    # Metadata for the whole batch in one more JVM start.
    results: list[AnalysisResult] = []
    for row in headless.export_multi("info", programs):
        if not row.get("ok"):
            err = row.get("error") or {}
            failures.append(
                ProgramFailure(program=row.get("program", "?"),
                               error=err.get("message", "unknown failure"),
                               error_kind=err.get("kind"))
            )
            continue
        headless.index_add(row["program"])
        results.append(
            AnalysisResult(
                program=row["program"],
                already_analyzed=False,
                duration_seconds=0.0,
                info=ProgramInfo(**row["data"]),
            )
        )
    return results, failures


def _match_created(filename: str, created: list[str]) -> str | None:
    """Which created program came from this file, if any.

    Matched by candidate name rather than by position: a failed import emits no
    line at all, so zipping the two lists would silently attribute every later
    program to the wrong file.
    """
    for candidate in candidate_names(filename):
        if candidate in created:
            return candidate
    return None


def _import_failure_reason(log: str, src: Path) -> str:
    """The most specific message the log supports for one failed import."""
    try:
        _raise_if_import_failed(log, src)
    except HeadlessError as exc:
        return str(exc)
    return (
        f"Ghidra imported no program for {src.name!r}. analyzeHeadless exits 0 on "
        "a failed import, so check the headless log for the loader's message."
    )


def _describe_head(path: Path, count: int = 8) -> str:
    """'<size> bytes, starts b"..."' for an error message; never raises."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(count)
        return f"{path.stat().st_size} bytes, starts {head!r}"
    except OSError:
        return "unreadable"


def _raise_if_import_failed(log: str, src: Path) -> None:
    """Turn a silent import failure into a message that names the cause.

    analyzeHeadless exits 0 when an import fails, so nothing downstream notices
    until the follow-up query reports "Requested project program file(s) not
    found" — which reads like a naming problem and is not.
    """
    if "No load spec found" in log:
        # Two quite different files end here: a real binary for a processor
        # Ghidra lacks, and something that is not an executable at all — a
        # 5-byte text stub produced this message once and read as the former.
        # The size and leading bytes tell the reader which one they have.
        raise BadArgument(
            f"Ghidra has no loader for {src.name!r} ({_describe_head(src)}). "
            "Either it is not an executable format Ghidra knows — check it is the "
            "file you meant — or it is one for a processor Ghidra lacks: ~40 "
            "processor modules ship, with no Alpha, IA-64 or S/390, for instance. "
            "For raw code of a known processor, pass `processor` to force a language."
        )
    if "REPORT: Import failed for file" in log:
        raise GhidraError(
            f"Ghidra failed to import {src.name!r}; the file may be corrupt or "
            "truncated. Check the headless log for the loader's own message."
        )


def _stored_result(program: str) -> AnalysisResult:
    """The already-analysed answer for a program the project holds."""
    logger.info("%s already analysed; returning stored info", program)
    return AnalysisResult(
        program=program,
        already_analyzed=True,
        duration_seconds=0.0,
        info=ProgramInfo(**headless.export(program, "info")),
    )


def _project_programs() -> list[str]:
    """Program names straight from the Ghidra project.

    Authoritative, unlike the local index, so anything imported by an external
    analyzeHeadless run or the Ghidra GUI is included. Costs a JVM start, hence
    the cached index for the common path.
    """
    data = headless.export_project("project_files")
    if not data:
        return []
    return sorted(f["name"] for f in data.get("files", []))


_CREATED = re.compile(r"^INFO\s+/(.+?): file created", re.MULTILINE)
_SAVED = re.compile(r"REPORT: Save succeeded for(?: processed file)?: /(.+?) \(", re.MULTILINE)


# Ghidra rejects these outright in a program name with InvalidInputException.
# An apostrophe is the one that actually bites: public crackme filenames are
# full of them ("_xk's crackme.exe").
GHIDRA_INVALID_NAME_CHARS = "'\"/\\:|?*<>"


def sanitize_program_name(filename: str) -> str:
    """Filename Ghidra will accept as a program name."""
    return "".join("_" if c in GHIDRA_INVALID_NAME_CHARS else c for c in filename)


def file_md5(path: Path) -> str:
    """MD5 of a file, to compare against the MD5 Ghidra records for a program."""
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def disambiguate_name(filename: str, md5: str) -> str:
    """A distinct program name for a binary whose basename is already taken.

    Two unrelated crackmes are both called `crackme`; the project can only
    hold one of that name, and silently serving the wrong one is far worse
    than an unfamiliar name.
    """
    stem, dot, suffix = filename.partition(".")
    tag = md5[:8]
    return f"{stem}_{tag}{dot}{suffix}" if dot else f"{stem}_{tag}"


def import_filename(src: Path) -> str:
    """The filename a program should be named after: src's, or the attached name.

    OpenWebUI stores a chat attachment as "<uuid>_<filename>". Importing that
    as-is names the program "aedeed9c-6c2b-4ca0-82c6-c06f2fbc3481_demo_keycheck.
    aarch64", which a model then has to carry through every later call. A file
    directly inside the OpenWebUI uploads directory is named after what the
    user attached instead. Anywhere else the filename stands, uuid-shaped or
    not: the prefix only means something where OpenWebUI put it.
    """
    m = _CHAT_UPLOAD_NAME.match(src.name)
    if m and src.parent == config.openwebui_uploads_dir().resolve():
        return m.group(2)
    return src.name


def candidate_names(filename: str) -> list[str]:
    """Names a file might carry inside the project, most likely first.

    A Ghidra container imports as the program it packages, so foo.exe.gzf
    becomes foo.exe. Only one suffix is stripped: that is the container
    convention, and stripping further would start matching unrelated programs.
    """
    names = [filename]
    stem = Path(filename).stem
    if stem and stem != filename:
        names.append(stem)
    return names


def _imported_program_name(log: str, fallback: str) -> str:
    """Recover the program name Ghidra created, from the import log alone.

    The log states it outright for a fresh import. It says nothing when the
    program already existed and the import was skipped, which is why callers
    must reconcile against the project — see resolve_program_name.
    """
    for pattern in (_CREATED, _SAVED):
        match = pattern.search(log)
        if match:
            return match.group(1).strip()
    return fallback


def resolve_program_name(log: str, filename: str, project_names: list[str]) -> str:
    """Decide what the imported program is actually called.

    Three sources, because no single one is sufficient:

    * the import log, authoritative for a fresh import;
    * the project listing, needed when the import was skipped because the
      program already existed, in which case the log is silent;
    * the filename, as a last resort.

    Getting this wrong is not subtle - every follow-up call fails with
    "Requested project program file(s) not found".
    """
    from_log = _imported_program_name(log, "")
    if from_log and (not project_names or from_log in project_names):
        return from_log

    for candidate in candidate_names(filename):
        if candidate in project_names:
            return candidate

    if len(project_names) == 1:
        return project_names[0]

    return from_log or filename


# ----------------------------------------------------------------- upload

# What a stored filename may contain. Anything else becomes "_": the name is
# only a label, the content is what matters, and a conservative alphabet keeps
# shells, Ghidra and every client's quoting out of trouble.
_UPLOAD_NAME_OK = re.compile(r"[A-Za-z0-9._+-]")
_UPLOAD_NAME_MAX = 200


def sanitize_upload_name(filename: str) -> str:
    """The name upload_binary stores a file under, or BadArgument.

    Path separators are refused rather than stripped: "../../etc/x" is a caller
    trying to choose a directory, and quietly storing it as "x" would hide that.
    Leading dots are refused too, which rules out ".", ".." and hidden files.
    """
    if not filename or "/" in filename or "\\" in filename or "\x00" in filename:
        raise BadArgument(
            f"filename must be a bare name with no path separators, got {filename!r}"
        )
    name = "".join(c if _UPLOAD_NAME_OK.fullmatch(c) else "_" for c in filename)
    if name.startswith("."):
        raise BadArgument(f"filename must not start with '.', got {filename!r}")
    if len(name) > _UPLOAD_NAME_MAX:
        raise BadArgument(f"filename is longer than {_UPLOAD_NAME_MAX} characters")
    return name


def decode_upload(content_base64: str, limit: int) -> bytes:
    """Strict base64 decode with the size cap checked before decoding.

    Whitespace is dropped first because models wrap long base64 across lines.
    The length check runs on the encoded form so an oversized payload is
    refused without first being decoded into memory.
    """
    encoded = "".join(content_base64.split())
    if len(encoded) // 4 * 3 > limit + 2:
        raise BadArgument(
            f"file exceeds the {limit}-byte upload limit (MAX_UPLOAD_BYTES). "
            "Large binaries should be copied in, not sent through the model: "
            "see the README, *Getting a binary to the server*."
        )
    # Base64 is printable ASCII. Anything else is not damaged base64 but no
    # base64 at all — typically a chat attachment's *text rendering*, which a
    # model copies out of its context believing it to be the file. Observed:
    # 1,219 chars, 431 of them non-ASCII, starting "ELF·@@". Retrying cannot
    # help, so the message says where the real bytes are instead.
    foreign = sum(1 for ch in encoded if ord(ch) > 126 or ord(ch) < 32)
    if foreign:
        raise BadArgument(
            f"content_base64 is not base64: {foreign} of its {len(encoded)} "
            "characters are non-ASCII or control characters, so it is a text "
            "rendering of the file, not an encoding of it. Re-sending it cannot "
            "work. A file attached in the chat is already on disk: call "
            "list_chat_uploads, then analyze_binary with its path."
        )
    try:
        data = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BadArgument(f"content_base64 is not valid base64: {exc}") from None
    if not data:
        raise BadArgument("content_base64 decodes to an empty file")
    if len(data) > limit:
        raise BadArgument(f"file exceeds the {limit}-byte upload limit (MAX_UPLOAD_BYTES)")
    return data


@mcp.tool()
def upload_binary(
    filename: str,
    content_base64: str,
    overwrite: bool = False,
    analyze: bool = False,
) -> UploadResult:
    """Store a binary on the server so analyze_binary can import it.

    NOT for a file the user attached in the chat: that is already on disk —
    call list_chat_uploads and pass its path to analyze_binary. What the chat
    shows of an attachment is extracted text, not the file's bytes; encoding
    it as base64 produces a different, broken file.

    The way to get a file the server cannot already see — one on the client's
    machine, or produced during the session — onto it. Files land in one
    upload directory (UPLOAD_DIR, default <project>/samples), never anywhere
    else, and are stored non-executable: they are analysed, never run.

    The bytes travel inside this call, so they pass through the model's
    context. Fine for a crackme; for anything over a few hundred KB prefer
    copying the file in (see the README). Capped by MAX_UPLOAD_BYTES (4 MiB).

    Args:
        filename: Bare name to store it under, e.g. "crackme.x86_64". No path
            separators; characters outside [A-Za-z0-9._+-] become "_".
        content_base64: The file's bytes, base64-encoded. Line breaks are fine.
        overwrite: Replace a *different* file already stored under this name.
            Re-uploading identical content is always fine and writes nothing.
        analyze: Also run analyze_binary on it and include the result.
    """
    name = sanitize_upload_name(filename)
    data = decode_upload(content_base64, config.MAX_UPLOAD_BYTES)
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    directory = config.upload_dir()
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / name

    written, replaced = True, False
    if target.is_symlink():
        # Not ours: nothing here creates links, so something else put it there.
        raise BadArgument(f"{target} is a symlink; refusing to write through it")
    if target.exists():
        if file_md5(target) == md5:
            written = False
        elif not overwrite:
            raise BadArgument(
                f"{name!r} already holds a different file (md5 {file_md5(target)}). "
                "Pass overwrite=True to replace it, or choose another filename."
            )
        else:
            replaced = True

    if written:
        # Write beside the target and rename over it: a reader never sees a
        # half-written binary, and os.replace swaps a link rather than following it.
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".upload-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.chmod(tmp, 0o644)
            os.replace(tmp, target)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        logger.info("stored upload %s (%d bytes, sha256 %s)", target, len(data), sha256)

    analysis = analyze_binary(str(target), force=replaced) if analyze else None
    return UploadResult(
        path=str(target),
        filename=name,
        size=len(data),
        md5=md5,
        sha256=sha256,
        written=written,
        replaced=replaced,
        analysis=analysis,
    )


def _iso_mtime(st: os.stat_result) -> str:
    return datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(timespec="seconds")


# OpenWebUI stores an attachment as "<uuid4>_<original filename>".
_CHAT_UPLOAD_NAME = re.compile(r"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})_(.+)$")


@mcp.tool()
def list_chat_uploads(pattern: str = "", limit: int = 50) -> ChatUploadList:
    """Find files the user attached in the OpenWebUI chat, already on disk.

    Use this — not upload_binary — when the user attached the binary to the
    conversation. OpenWebUI saves every attachment to disk where this server
    can read it; pass the returned path to analyze_binary. What the chat itself
    shows of an attachment is extracted text and cannot be turned back into
    the file.

    Read-only: lists the directory, never opens or changes a file.

    Args:
        pattern: Case-insensitive substring of the attached filename, e.g.
            "keycheck". Empty lists everything.
        limit: Maximum entries, newest first.
    """
    directory = config.openwebui_uploads_dir()
    if not directory.is_dir():
        raise NotFound(
            f"no OpenWebUI uploads directory at {directory}. Set "
            "OPENWEBUI_UPLOADS_DIR if OpenWebUI keeps its data elsewhere."
        )
    needle = pattern.lower()
    found: list[tuple[float, ChatUpload]] = []
    with os.scandir(directory) as it:
        for entry in it:
            # Regular files only: a symlink here could point anywhere.
            if not entry.is_file(follow_symlinks=False):
                continue
            m = _CHAT_UPLOAD_NAME.match(entry.name)
            upload_id, name = (m.group(1), m.group(2)) if m else (None, entry.name)
            if needle and needle not in name.lower():
                continue
            st = entry.stat(follow_symlinks=False)
            found.append((st.st_mtime, ChatUpload(
                name=name, path=str(directory / entry.name), size=st.st_size,
                modified=_iso_mtime(st), upload_id=upload_id,
            )))
    found.sort(key=lambda pair: pair[0], reverse=True)
    rows = [upload for _, upload in found[: max(limit, 0)]]
    return ChatUploadList(
        directory=str(directory), total=len(found), returned=len(rows), uploads=rows
    )


@mcp.tool()
def list_uploads() -> UploadList:
    """List the files upload_binary has stored, so they can be reused or removed.

    These are files, not programs: a file is analysed only once analyze_binary
    has imported it, and list_programs shows what has been.
    """
    directory = config.upload_dir()
    rows: list[StoredUpload] = []
    if directory.is_dir():
        with os.scandir(directory) as it:
            for entry in it:
                # Skip upload_binary's in-flight temp files and anything not a
                # plain file it could have written.
                if entry.name.startswith(".") or not entry.is_file(follow_symlinks=False):
                    continue
                st = entry.stat(follow_symlinks=False)
                rows.append(StoredUpload(
                    filename=entry.name, path=str(directory / entry.name),
                    size=st.st_size, modified=_iso_mtime(st),
                ))
    rows.sort(key=lambda r: r.filename)
    return UploadList(directory=str(directory), uploads=rows)


@mcp.tool()
def delete_upload(filename: str) -> UploadDeleteResult:
    """Delete a file upload_binary stored — a mistaken or test upload, say.

    Only the upload directory is touched, and only a plain file in it. This
    removes the file, not any program imported from it: use delete_program for
    that.

    Args:
        filename: The stored name, as list_uploads or upload_binary returned it.
    """
    # The same rules as storing: a bare name, so this can never reach outside
    # the upload directory. Sanitising must not change it, or it names a
    # different file than the caller meant.
    name = sanitize_upload_name(filename)
    if name != filename:
        raise BadArgument(
            f"{filename!r} is not a stored upload name (stored names use only "
            "[A-Za-z0-9._+-]); call list_uploads for the exact name."
        )
    target = config.upload_dir() / name
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise BadArgument(f"{target} is not a plain file upload_binary wrote; refusing")
    if not target.exists():
        raise NotFound(f"no upload named {name!r}; call list_uploads for the names")
    target.unlink()
    logger.info("deleted upload %s", target)
    return UploadDeleteResult(
        filename=name, path=str(target), deleted=True,
        detail="file removed; any program imported from it is still in the project",
    )


@mcp.tool()
def list_programs(refresh: bool = False) -> ProgramList:
    """List the programs available in this Ghidra project.

    By default this reads a local index the server maintains, which is instant.
    Pass refresh=True to ask Ghidra itself — slower, but it also finds programs
    imported by an external analyzeHeadless run or by the Ghidra GUI, and it
    repairs the index if the two have drifted.

    Args:
        refresh: Query the project instead of the local index.
    """
    if refresh:
        programs = _project_programs()
        # Re-point the index at reality rather than letting them drift further.
        for name in programs:
            headless.index_add(name)
        for stale in set(headless.index_read()) - set(programs):
            headless.index_remove(stale)
    else:
        programs = headless.index_read()

    return ProgramList(
        project=config.PROJECT_NAME,
        project_location=str(config.PROJECT_LOCATION),
        programs=programs,
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
def decompile_function(
    program: str, function: str | list[str]
) -> Decompilation | DecompilationBatch:
    """Decompile one function to C — or a list of them in a single call.

    Pass a list to decompile many at once. This backend cold-starts a JVM per
    call and the decompiler is opened once per batch, so ten functions in one
    call cost roughly what one costs; ten separate calls cost ten times as much.

    A list returns a batch envelope with one entry per target and per-target
    errors, matching list_xrefs_to. A single string returns the flat result.

    Args:
        program: Program name as returned by list_programs.
        function: Function name ("main", "FUN_0041d000") or entry-point address
            ("0041d000"), or a list of them. Names are tried exactly first, then
            case-insensitively. A target that cannot be resolved reports its own
            error and does not fail the others.
    """
    if isinstance(function, str):
        data = headless.export(program, "decompile", {"target": function})
        return Decompilation(program=program, **data)

    targets = _normalise_targets(function, what="function")
    data = headless.export(program, "decompile", {"targets": targets})
    results = [DecompilationResult(**row) for row in data["results"]]
    failed = sum(1 for r in results if not r.ok)
    return DecompilationBatch(
        program=program,
        total=len(results),
        succeeded=len(results) - failed,
        failed=failed,
        results=results,
    )


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
    log = proc.stdout or ""
    return ScriptResult(
        program=program,
        script=script_name,
        exit_code=proc.returncode,
        script_error=_script_error(log),
        stdout_tail="\n".join(log.splitlines()[-200:]),
    )


def _script_error(log: str) -> str | None:
    """Pull a script's own failure out of the headless log.

    analyzeHeadless exits 0 even when the script it ran threw, so the exit code
    cannot be trusted on its own. Ghidra reports the failure as a
    "SCRIPT ERROR:" line; surfacing it here saves every caller from scraping
    the log. A bundled script that calls a GUI-only method such as askFile()
    fails exactly this way.
    """
    for line in log.splitlines():
        if "SCRIPT ERROR" in line:
            return line.split("SCRIPT ERROR:", 1)[-1].strip() or line.strip()
    return None


# ------------------------------------------------------------------ xrefs


def _normalise_targets(target: str | list[str], what: str = "target") -> list[str]:
    """Accept one target or many, and reject an empty request early.

    `what` names the thing in the error, so a batch of addresses complains
    about addresses rather than about generic targets.
    """
    targets = [target] if isinstance(target, str) else list(target)
    targets = [t for t in targets if t]
    if not targets:
        raise BadArgument(f"at least one {what} is required")
    return targets


def _xref_rows(program: str | None, data: dict, limit: int, offset: int) -> list:
    """Turn one program's xref payload into typed rows.

    `program` is None for a single-program call, which leaves the field unset
    and keeps that output byte-identical to what it has always been.
    """
    rows = []
    for row in data["results"]:
        entries = [XrefEntry(**x) for x in row.get("xrefs", [])]
        window = page(entries, limit, offset)
        rows.append(
            XrefTargetResult(
                target=row["target"],
                program=program,
                resolved_address=row.get("resolved_address"),
                resolved_kind=row.get("resolved_kind"),
                error=row.get("error"),
                total=len(entries),
                returned=len(window),
                xrefs=window,
            )
        )
    return rows


def _xrefs(
    program: str | list[str], target: str | list[str], direction: str, limit: int, offset: int
) -> XrefList:
    targets = _normalise_targets(target)
    names = _normalise_programs(program)
    args = {"targets": targets, "direction": direction}

    # One program keeps the original single-program command and output shape.
    if len(names) == 1 and isinstance(program, str):
        data = headless.export(names[0], "xrefs", args)
        return XrefList(
            program=names[0],
            direction=data["direction"],
            results=_xref_rows(None, data, limit, offset),
        )

    results: list = []
    directions: list[str] = []

    def build(name: str, data: dict):
        directions.append(data["direction"])
        results.extend(_xref_rows(name, data, limit, offset))
        return name

    _, failures = _fan_out("xrefs", names, args, build)
    return XrefList(
        program="*",
        direction=directions[0] if directions else direction,
        results=results,
        failures=failures,
    )


@mcp.tool()
def list_xrefs_to(
    program: str | list[str],
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
        program: Program name as returned by list_programs — or a list of
            names, or "*" for every program in the project. With several
            programs each result names its own, and the whole call costs one
            JVM start rather than one per program.
        target: Function name, symbol name, or address — or a list of them. A
            target that cannot be resolved reports its own error and does not
            fail the others.
        limit: Maximum references per target.
        offset: Skip this many references per target, for paging.
    """
    return _xrefs(program, target, "to", limit, offset)


@mcp.tool()
def list_xrefs_from(
    program: str | list[str],
    target: str | list[str],
    limit: int = 100,
    offset: int = 0,
) -> XrefList:
    """Find everything a function, symbol or address references.

    The outward walk: what this code touches. Use it to follow control and data
    flow from an entry point, or to see which strings and imports a function
    uses.

    Args:
        program: Program name as returned by list_programs — or a list of
            names, or "*" for every program in the project.
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

    Only *defined* instructions are listed. Where Ghidra has not disassembled
    the bytes — a computed jump table, inline data — the listing silently
    resumes at the next defined instruction, so check `skipped_bytes` and fall
    back to `read_bytes` when it is non-zero.
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
def read_bytes(
    program: str,
    address: str | list[str],
    size: int | list[int] = 32,
) -> BytesRead | BytesReadBatch:
    """Read raw bytes from the program — one span, or many in a single call.

    The tool that lets an analysis extract material rather than describe it: an
    encrypted blob, a key table, a header. Returns hex plus a printable
    rendering.

    Pass a list of addresses to pull several spans at once; a binary that hides
    a key table, a ciphertext and a lookup table costs one JVM start instead of
    three. `size` may be a single number applied to every address, or a list of
    the same length giving each span its own size.

    Args:
        program: Program name as returned by list_programs.
        address: Address, symbol name, or function name to read from, or a list
            of them. An address that cannot be resolved reports its own error
            and does not fail the others.
        size: Number of bytes, or one size per address. Each is capped at 4096
            to protect the response size.
    """
    if isinstance(address, str):
        if isinstance(size, list):
            raise BadArgument("a list of sizes needs a list of addresses")
        if size <= 0:
            raise BadArgument("size must be positive")
        data = headless.export(program, "read_bytes", {"address": address, "size": size})
        return BytesRead(program=program, **data)

    targets = _normalise_targets(address, what="address")
    if isinstance(size, list):
        if len(size) != len(targets):
            raise BadArgument(
                f"got {len(size)} sizes for {len(targets)} addresses; "
                "give one size or one per address"
            )
        sizes = size
    else:
        sizes = [size] * len(targets)
    for one in sizes:
        if one <= 0:
            raise BadArgument("size must be positive")

    reads = [{"address": a, "size": s} for a, s in zip(targets, sizes)]
    data = headless.export(program, "read_bytes", {"reads": reads})
    results = [BytesReadResult(**row) for row in data["results"]]
    failed = sum(1 for r in results if not r.ok)
    return BytesReadBatch(
        program=program,
        total=len(results),
        succeeded=len(results) - failed,
        failed=failed,
        results=results,
    )


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
            Note that "data" lists *defined data items*, so a label sitting over
            bytes Ghidra never typed is invisible to it — use "label" for those.
            A named array like ENCODED can be either, depending on the binary.
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
def list_symbols_project(
    kind: str = "import",
    pattern: str | None = None,
    programs: str | list[str] | None = None,
    limit: int = 50,
    offset: int = 0,
) -> SymbolListProject:
    """List symbols of one kind across every binary in the project at once.

    The cross-binary inventory question. `kind="import"` over an application
    and its libraries shows which binary reaches which API; `kind="export"`
    shows which one provides it. Together they are how you find the layer that
    actually implements a call — see resolve_symbol for the linked version.

    One JVM start covers every program, so this is far cheaper than a
    list_symbols call per binary.

    Args:
        kind: One of import, export, data, class, namespace, label, function.
        pattern: Case-insensitive regular expression matched against the symbol
            name, e.g. "^Crypt" or "socket|connect|send".
        programs: Program name, list of names, or omitted/"*" for every program
            in the project.
        limit: Maximum symbols **per program**, not across the batch — a shared
            cap would let one large binary crowd out the rest. Lower than
            list_symbols' default because output multiplies by program count.
        offset: Skip this many matches per program, for paging.
    """
    if kind not in SYMBOL_KINDS:
        raise BadArgument(f"kind must be one of {', '.join(SYMBOL_KINDS)}, got {kind!r}")
    names = _normalise_programs(programs)

    def build(program: str, data: dict) -> SymbolList:
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

    results, failures = _fan_out(
        "symbols", names, {"kind": kind, "pattern": pattern}, build
    )
    return SymbolListProject(
        kind=kind,
        programs_searched=len(results),
        total=sum(r.total for r in results),
        results=results,
        failures=failures,
    )


# Windows resolves these to a real DLL at load time through the apiset schema,
# which is not in any binary we hold. The bare export name is unique, so
# matching on it recovers the hop the schema would have made.
_APISET = re.compile(r"^(api|ext)-ms-", re.IGNORECASE)

# Rank orders the layers consumer-first. A program that only imports is
# furthest from the implementation; one that only exports holds it.
_ROLE_RANK = {
    (True, False): 0,   # imports, does not export - the caller
    (True, True): 1,    # both - a forwarder
    (False, True): 2,   # exports only - the implementation
}


def _rank(location: SymbolLocation) -> int:
    has_import = "import" in location.roles
    has_export = "export" in location.roles
    return _ROLE_RANK.get((has_import, has_export), 3)


def _resolve_one(name: str, rows: dict[str, dict], index: dict[str, str]) -> SymbolChain:
    """Join one symbol's per-program rows into a chain. Pure function."""
    layers: list[SymbolLocation] = []
    absent: list[str] = []
    notes: list[str] = []

    for program, data in rows.items():
        entry = next((s for s in data.get("symbols", []) if s.get("name") == name), None)
        if entry is None or not entry.get("roles"):
            absent.append(program)
            continue
        layers.append(
            SymbolLocation(
                program=program,
                internal_name=data.get("internal_name"),
                roles=entry.get("roles", []),
                address=entry.get("address"),
                library=entry.get("library"),
                thunk_target=entry.get("thunk_target"),
                thunk_library=entry.get("thunk_library"),
                is_thunk=bool(entry.get("is_thunk")),
            )
        )

    terminals = [loc.program for loc in layers if _rank(loc) == 2]
    for location in layers:
        location.is_terminal = location.program in terminals

    # Point each importer at the program that provides its library, by file
    # name or by the internal name an import table actually records.
    for location in layers:
        if not location.library:
            continue
        location.library_program = index.get(location.library.lower())
        if location.library_program is None and _APISET.match(location.library):
            if len(terminals) == 1:
                location.library_program = terminals[0]
                notes.append(
                    f"{location.program} imports {name} from the apiset "
                    f"{location.library}, which no program here provides; resolved to "
                    f"{terminals[0]}, the only binary that exports {name} without "
                    "importing it"
                )
            else:
                notes.append(
                    f"{location.program} imports {name} from the apiset "
                    f"{location.library}; no single implementation in this project "
                    "to resolve it to"
                )

    layers.sort(key=lambda loc: (_rank(loc), loc.program))

    terminal = terminals[0] if len(terminals) == 1 else None
    if len(terminals) > 1:
        notes.append(
            f"{name} is exported without being imported by {', '.join(sorted(terminals))} — "
            "ambiguous, so no single implementation is named"
        )
    elif not terminals and layers:
        notes.append(
            f"no program here exports {name} without also importing it, so the "
            "implementation is outside this project"
        )

    return SymbolChain(
        name=name,
        layers=layers,
        terminal_program=terminal,
        absent_from=sorted(absent),
        notes=notes,
    )


@mcp.tool()
def resolve_symbol(
    name: str | list[str],
    programs: str | list[str] | None = None,
) -> SymbolResolution:
    """Trace a symbol across every binary in the project and link the layers.

    The cross-binary question in one call: which binary imports this, which
    exports it, which one holds the real implementation, and what the
    forwarders in between point at. Answering it by hand means a symbol lookup
    per binary and a guess about which library a name resolves to.

    Windows API layering is the worked example. `resolve_symbol("CreateFileW")`
    over notepad.exe and its DLLs reports notepad importing it from an apiset,
    kernel32 both exporting and importing it — the signature of a forwarder —
    and kernelbase exporting it without importing, which is where the code
    lives. The same shape answers "which shared library implements this" for
    ELF, and "which stage of the dropper defines this" for malware.

    Apisets get followed: an import from `api-ms-win-*` names a library that no
    binary provides, so the bare export name is matched against the project
    instead. `notes` records every such hop rather than hiding it.

    One JVM start regardless of how many programs or names are asked for.

    Args:
        name: Symbol name, or a list of names, matched exactly and
            case-sensitively — these come from list_symbols, not from a user.
        programs: Program name, list of names, or omitted/"*" for every program
            in the project.
    """
    names = _normalise_targets(name, "symbol name")
    program_names = _normalise_programs(programs)

    rows: dict[str, dict] = {}

    def build(program: str, data: dict) -> str:
        rows[program] = data
        return program

    _, failures = _fan_out("link_symbols", program_names, {"names": names}, build)

    # A library is named as it appears in an import table, which may be either
    # the project file name or the program's own internal name.
    index: dict[str, str] = {}
    for program, data in rows.items():
        index[program.lower()] = program
        internal = data.get("internal_name")
        if internal:
            index.setdefault(internal.lower(), program)

    return SymbolResolution(
        programs_searched=len(rows),
        results=[_resolve_one(n, rows, index) for n in names],
        failures=failures,
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


# --------------------------------------------------------------- edits

# kind -> required fields. Validated before a JVM starts, so a malformed batch
# costs nothing.
EDIT_KINDS: dict[str, tuple[str, ...]] = {
    "rename_function": ("target", "new_name"),
    "rename_variable": ("function", "variable", "new_name"),
    "rename_data": ("address", "new_name"),
    "set_prototype": ("target", "prototype"),
    "set_variable_type": ("function", "variable", "type"),
    "set_comment": ("address", "comment"),
}

COMMENT_TYPES = ("decompiler", "pre", "eol", "post", "plate", "repeatable")


def validate_edits(edits: list[dict]) -> list[dict]:
    """Check every edit's shape up front.

    A batch is one JVM start; discovering at edit 40 that edit 3 was malformed
    wastes the whole run, so structural problems are caught here rather than in
    Ghidra.
    """
    if not edits:
        raise BadArgument("at least one edit is required")

    for i, edit in enumerate(edits):
        if not isinstance(edit, dict):
            raise BadArgument(f"edit {i} is not an object")
        kind = edit.get("kind")
        if kind not in EDIT_KINDS:
            raise BadArgument(
                f"edit {i}: unknown kind {kind!r}; want one of {', '.join(EDIT_KINDS)}"
            )
        for field in EDIT_KINDS[kind]:
            if not edit.get(field):
                raise BadArgument(f"edit {i} ({kind}): missing required field {field!r}")
        if kind == "set_comment":
            ctype = edit.get("comment_type", "decompiler")
            if ctype not in COMMENT_TYPES:
                raise BadArgument(
                    f"edit {i}: comment_type must be one of {', '.join(COMMENT_TYPES)}"
                )
    return edits


@mcp.tool()
def apply_edits(program: str, edits: list[dict]) -> EditBatchResult:
    """Apply many edits to the program database in a single call.

    This is the tool to reach for when recording what an analysis learned:
    renaming a pass of functions, applying types, leaving comments. Every call
    to this backend cold-starts a JVM, so one batch of 200 renames takes
    seconds where 200 single calls take minutes.

    Edits are isolated: one failure reports at its index and the rest still
    apply, so a single stale variable name does not discard the batch. Check
    `failed` and retry only the indices that report ok=False.

    Each edit is an object with a `kind` and its fields:
      {"kind": "rename_function",   "target": "FUN_00401146", "new_name": "check_key"}
      {"kind": "rename_variable",   "function": "check_key", "variable": "local_10",
       "new_name": "key_len"}
      {"kind": "rename_data",       "address": "00402000", "new_name": "g_banner"}
      {"kind": "set_prototype",     "target": "check_key",
       "prototype": "int check_key(char *key)"}
      {"kind": "set_variable_type", "function": "check_key", "variable": "param_1",
       "type": "char *"}
      {"kind": "set_comment",       "address": "00401146", "comment": "RC4 key setup",
       "comment_type": "decompiler"}

    Args:
        program: Program name as returned by list_programs.
        edits: The edits to apply, in order.
    """
    data = headless.export(
        program, "edit", {"edits": validate_edits(edits)}, write=True
    )
    return EditBatchResult(program=program, **data)


def _apply_one(program: str, edit: dict) -> EditResult:
    """Run a single edit through the batch path and raise on failure.

    The singles are wrappers rather than separate implementations so there is
    one place where an edit is validated, applied and reported.
    """
    batch = apply_edits(program, [edit])
    result = batch.results[0]
    if not result.ok:
        raise from_envelope(result.error_kind or "error", result.error or "edit failed")
    return result


@mcp.tool()
def rename_function(program: str, target: str, new_name: str) -> EditResult:
    """Rename a function, recording what it actually does.

    The highest-value single edit in reverse engineering: FUN_0041d000 becomes
    rc4_decrypt_config, and every later decompilation of every caller reads
    better for it.

    Args:
        program: Program name as returned by list_programs.
        target: Current function name or entry-point address.
        new_name: The new name.
    """
    return _apply_one(program, {"kind": "rename_function", "target": target,
                                "new_name": new_name})


@mcp.tool()
def rename_variable(
    program: str, function: str, variable: str, new_name: str
) -> EditResult:
    """Rename a parameter or local variable inside a function.

    Works on decompiler-synthesised names (local_10, uVar1) as well as real
    database variables — the two need different Ghidra APIs, which this hides.

    Args:
        program: Program name as returned by list_programs.
        function: Function name or entry-point address.
        variable: Current variable name, exactly as the decompiler shows it.
        new_name: The new name.
    """
    return _apply_one(program, {"kind": "rename_variable", "function": function,
                                "variable": variable, "new_name": new_name})


@mcp.tool()
def rename_data(program: str, address: str, new_name: str) -> EditResult:
    """Name a global or data label at an address.

    Creates the label if none exists yet, so an unnamed table can be named in
    one step.

    Args:
        program: Program name as returned by list_programs.
        address: Address of the data.
        new_name: The new label.
    """
    return _apply_one(program, {"kind": "rename_data", "address": address,
                                "new_name": new_name})


@mcp.tool()
def set_function_prototype(program: str, target: str, prototype: str) -> EditResult:
    """Set a function's signature.

    The highest-leverage correction available: a fixed prototype changes
    argument recovery in every caller's decompilation, not just this function's.
    An unparseable prototype returns Ghidra's own parse error, which names the
    token that failed.

    The calling convention is not part of the prototype — Ghidra's parser
    rejects "void __cdecl f(void)". A function keeps the convention it has; one
    auto-analysis left "unknown" gets the compiler's default, so the decompiler
    does not warn about locked parameter storage afterwards.

    Args:
        program: Program name as returned by list_programs.
        target: Function name or entry-point address.
        prototype: A C prototype, e.g. "int check_key(char *key, int len)".
            No calling-convention keyword.
    """
    return _apply_one(program, {"kind": "set_prototype", "target": target,
                                "prototype": prototype})


@mcp.tool()
def set_variable_type(
    program: str, function: str, variable: str, type: str
) -> EditResult:
    """Apply a data type to a parameter or local variable.

    Turns pointer arithmetic on an undefined8 into readable field access. The
    type must already exist in the program's type manager.

    Args:
        program: Program name as returned by list_programs.
        function: Function name or entry-point address.
        variable: Variable name as the decompiler shows it.
        type: Type name, e.g. "char *", "int", "DWORD".
    """
    return _apply_one(program, {"kind": "set_variable_type", "function": function,
                                "variable": variable, "type": type})


@mcp.tool()
def set_comment(
    program: str,
    address: str,
    comment: str,
    comment_type: str = "decompiler",
) -> EditResult:
    """Leave a comment at an address — where an analysis records its reasoning.

    Args:
        program: Program name as returned by list_programs.
        address: Address to annotate.
        comment: The comment text.
        comment_type: One of decompiler (shown above the statement in
            pseudo-C), pre, eol, post, plate, repeatable.
    """
    return _apply_one(program, {"kind": "set_comment", "address": address,
                                "comment": comment, "comment_type": comment_type})


# ----------------------------------------------------------- call graph


@mcp.tool()
def gen_callgraph(
    program: str,
    function: str,
    direction: str = "called",
    depth: int = 3,
    max_nodes: int = 300,
) -> CallGraph:
    """Generate a MermaidJS call graph around a function.

    "called" answers what this function reaches — the usual way to understand
    an entry point. "calling" answers who reaches it, which is the shape of an
    impact analysis for a vulnerable sink.

    The Mermaid source is ready to paste into a report or render directly;
    nodes and edges are also returned structurally if you need to walk them.

    Args:
        program: Program name as returned by list_programs.
        function: Function name or entry-point address to centre on.
        direction: "called" (callees) or "calling" (callers).
        depth: Levels to traverse. Capped at 10 — a deep graph on a real binary
            is enormous and unreadable.
        max_nodes: Node ceiling, capped at 300. Expansion stops and reports
            truncated=True rather than returning something unusable.
    """
    if direction not in ("called", "calling"):
        raise BadArgument(f"direction must be 'called' or 'calling', got {direction!r}")
    if depth <= 0:
        raise BadArgument("depth must be positive")

    data = headless.export(
        program,
        "callgraph",
        {"function": function, "direction": direction, "depth": depth,
         "max_nodes": max_nodes},
    )
    return CallGraph(program=program, **data)


# ---------------------------------------------------------- code search


@mcp.tool()
def search_code(
    program: str,
    query: str,
    mode: str = "literal",
    limit: int = 5,
    context: int = 0,
    refresh: bool = False,
) -> CodeSearchResults:
    """Search the decompiled pseudo-C of every function.

    Two modes over the same corpus:

    * literal — a case-insensitive regex over the C text, reporting the first
      matching line per function. Use it when you know a token: an API name, a
      constant, a format string.
    * semantic — ranked by similarity, so "validate licence key" can surface a
      function built from related identifiers without containing those words.

    The first call decompiles the whole binary, which is slow; the result is
    cached, so later searches are fast. `from_cache` reports which happened.

    Args:
        program: Program name as returned by list_programs.
        query: A regex in literal mode, or a natural-language phrase in
            semantic mode.
        mode: "literal" or "semantic".
        limit: Maximum functions to return.
        context: Lines of surrounding C to include per hit (literal mode).
        refresh: Rebuild the decompilation cache first — needed after renames
            or retypes if you want the search to see them.
    """
    _validate_search(query, mode)
    return _search_one(program, query, mode, limit, context, refresh)


def _validate_search(query: str, mode: str) -> str:
    """Check the arguments both search tools share, and name the backend."""
    if mode not in ("literal", "semantic"):
        raise BadArgument(f"mode must be 'literal' or 'semantic', got {mode!r}")
    if not query:
        raise BadArgument("query must not be empty")
    return "regex" if mode == "literal" else "tfidf"


def _search_one(
    program: str, query: str, mode: str, limit: int, context: int, refresh: bool
) -> CodeSearchResults:
    """Search one program's cached corpus. Arguments are already validated."""
    functions, from_cache = headless.load_corpus(program, refresh=refresh)

    if mode == "literal":
        try:
            hits = codesearch.literal_search(functions, query, limit=limit, context=context)
        except re.error as exc:
            raise BadArgument(f"invalid regex: {exc}") from exc
        backend = "regex"
    else:
        index = codesearch.build_index(functions)
        hits = codesearch.semantic_search(index, query, limit=limit)
        backend = "tfidf"

    return CodeSearchResults(
        program=program,
        query=query,
        mode=mode,
        backend=backend,
        indexed_functions=len(functions),
        from_cache=from_cache,
        returned=len(hits),
        matches=[CodeMatch(**hit) for hit in hits],
    )


@mcp.tool()
def search_code_project(
    query: str,
    programs: str | list[str] | None = None,
    mode: str = "literal",
    limit: int = 50,
    context: int = 0,
    refresh: bool = False,
) -> CodeSearchProjectResults:
    """Search the decompiled pseudo-C of every binary in the project at once.

    The cross-binary form of search_code: one call answers "which of my
    binaries mentions this" instead of one call per binary. Use it to find
    where a shared API, constant or format string is used across an
    application and its libraries.

    Cost: the first search of a program decompiles the whole binary, which is
    the slowest thing this server does — fanning out over four never-searched
    binaries pays that four times. Every later search of the same programs
    reads the cache and is fast. `from_cache` on each result says which
    happened.

    Args:
        query: A regex in literal mode, or a natural-language phrase in
            semantic mode.
        programs: Program name, list of names, or omitted/"*" for every program
            in the project.
        mode: "literal" or "semantic".
        limit: Maximum functions to return **per program**, not across the
            batch — a shared cap would let one binary crowd out the rest. Lower
            than search_code's default because the output multiplies by the
            program count.
        context: Lines of surrounding C to include per hit (literal mode).
        refresh: Rebuild each program's decompilation cache first.
    """
    backend = _validate_search(query, mode)
    names = _normalise_programs(programs)

    results: list[CodeSearchResults] = []
    failures: list[ProgramFailure] = []
    for name in names:
        try:
            results.append(_search_one(name, query, mode, limit, context, refresh))
        except BadArgument:
            # A malformed regex is the caller's error and identical for every
            # program, so it fails the whole call rather than N times over.
            raise
        except HeadlessError as exc:
            failures.append(
                ProgramFailure(program=name, error=str(exc), error_kind=exc.kind)
            )

    return CodeSearchProjectResults(
        query=query,
        mode=mode,
        backend=backend,
        programs_searched=len(results),
        total_matches=sum(r.returned for r in results),
        results=results,
        failures=failures,
    )


@mcp.tool()
def clear_code_cache(program: str) -> dict:
    """Drop a program's cached decompilation so the next search rebuilds it.

    Use after a batch of renames or retypes, when you want search to see the
    improved output. `search_code(refresh=True)` does the same thing in one
    step.

    Args:
        program: Program name as returned by list_programs.
    """
    return {"program": program, "cleared": headless.clear_corpus(program)}


# --------------------------------------------------- project management


@mcp.tool()
def delete_program(program: str) -> DeleteResult:
    """Remove a program from the Ghidra project.

    Also drops its cached decompilation and its index entry, so nothing stale
    survives.

    Ghidra cannot delete a program while it is open, and a headless run must be
    attached to something — so this attaches to a different program in the
    project. When the target is the only program left, deleting it means
    deleting the project that contains nothing else, which is what happens;
    the result says so via deleted_project.

    Args:
        program: Program name as returned by list_programs.
    """
    programs = _project_programs()
    if program not in programs:
        raise NotFound(f"no program named {program!r} in the project")

    others = [name for name in programs if name != program]
    if others:
        # Attach to a different program so the target is not open (and so busy).
        data = headless.export(
            others[0], "delete_program", {"name": program}, write=True
        )
        detail = f"deleted {data['deleted']} from {data['pathname']}"
        deleted_project = False
    else:
        removed = _remove_project_files()
        detail = (
            f"{program} was the only program; removed the project itself "
            f"({', '.join(removed) if removed else 'nothing on disk'})"
        )
        deleted_project = True

    headless.index_remove(program)
    headless.clear_corpus(program)
    return DeleteResult(
        program=program, deleted=True, deleted_project=deleted_project, detail=detail
    )


def _remove_project_files() -> list[str]:
    """Delete this server's Ghidra project directory and marker file."""
    import shutil

    removed = []
    rep = config.PROJECT_LOCATION / f"{config.PROJECT_NAME}.rep"
    gpr = config.PROJECT_LOCATION / f"{config.PROJECT_NAME}.gpr"
    if rep.is_dir():
        shutil.rmtree(rep)
        removed.append(rep.name)
    if gpr.is_file():
        gpr.unlink()
        removed.append(gpr.name)
    return removed


@mcp.tool()
def search_memory(
    program: str,
    text: str | None = None,
    hex: str | None = None,
    limit: int = 50,
) -> MemorySearchResults:
    """Search the program's raw bytes for text or a hex pattern.

    Use this when `list_strings` comes up empty but you believe the data is
    there. `list_strings` reports only strings Ghidra's analyser *defined*;
    this reads the bytes, so it also finds length-prefixed wide strings (how
    Delphi and VB store them), text in undefined data, and anything the string
    analyser skipped.

    Text is searched as ASCII, UTF-16LE and UTF-16BE, and each hit says which
    encoding matched and which block and function it landed in.

    Args:
        program: Program name as returned by list_programs.
        text: Text to look for, tried in three encodings.
        hex: Hex byte pattern instead, e.g. "4d5a9000" (spaces allowed).
        limit: Maximum hits to return.
    """
    if not text and not hex:
        raise BadArgument("search_memory requires text or hex")
    if text and hex:
        raise BadArgument("give text or hex, not both")

    args: dict = {"limit": limit}
    if text:
        args["text"] = text
    else:
        args["hex"] = hex
    data = headless.export(program, "search_memory", args)
    return MemorySearchResults(program=program, **data)
