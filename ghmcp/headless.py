"""The analyzeHeadless plumbing: spec in, envelope out.

One place decides how a mode is invoked, whether the run may write, and how a
failure becomes a typed exception. Tools above this layer never build a command
line or parse JSON themselves.
"""

import contextlib
import fcntl
import json
import logging
import os
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from . import config
from .errors import BadArgument, ExportFailure, GhidraError, HeadlessTimeout, from_envelope

logger = logging.getLogger("ghidra_headless_mcp")

# Ghidra locks a project for the duration of a headless run, so concurrent calls
# would fail with a lock error rather than queue. Serialise them here.
_GHIDRA_LOCK = threading.Lock()

# A threading lock only covers one process. mcpo can end up running a second
# stdio server against the same project - observed when one analyze call ran for
# 23 minutes - and the two then race for Ghidra's own project lock, after which
# every import fails with LockException until someone notices. A lock file next
# to the project makes the exclusion hold across processes.
LOCK_WAIT_S = int(os.environ.get("PROJECT_LOCK_WAIT_S", "3600"))


@contextlib.contextmanager
def project_lock(timeout: int | None = None):
    """Exclude other *processes* from this Ghidra project."""
    config.PROJECT_LOCATION.mkdir(parents=True, exist_ok=True)
    path = config.PROJECT_LOCATION / f".{config.PROJECT_NAME}.ghmcp.lock"
    deadline = time.monotonic() + (timeout if timeout is not None else LOCK_WAIT_S)
    fh = open(path, "w")
    try:
        while True:
            try:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise HeadlessTimeout(
                        f"another process has held {path} for over "
                        f"{timeout if timeout is not None else LOCK_WAIT_S}s. A previous "
                        "analyzeHeadless may be orphaned; check for stray processes."
                    )
                logger.info("waiting for the project lock held by another process")
                time.sleep(2)
        yield
    finally:
        with contextlib.suppress(Exception):
            fcntl.flock(fh, fcntl.LOCK_UN)
        fh.close()


# Every analyzeHeadless invocation this process has made. A JVM start is the
# dominant cost of this backend, so tools that claim to save one can report the
# real number rather than an estimate, and tests can assert on it.
run_count = 0


def run_headless(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    """Invoke analyzeHeadless with the project location and name prepended."""
    global run_count
    run_count += 1
    config.PROJECT_LOCATION.mkdir(parents=True, exist_ok=True)
    cmd = [str(config.find_ghidra()), str(config.PROJECT_LOCATION), config.PROJECT_NAME, *args]
    logger.info("running: %s", " ".join(cmd))

    with _GHIDRA_LOCK, project_lock():
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise HeadlessTimeout(
                f"analyzeHeadless exceeded {timeout}s. Raise ANALYZE_TIMEOUT_S / "
                "QUERY_TIMEOUT_S, or analyse a smaller binary."
            ) from exc

    if proc.returncode != 0:
        # Ghidra's own lock, not ours: something outside this server holds the
        # project. Say so, instead of dumping a wall of headless log.
        if "LockException" in (proc.stdout or "") or "Unable to lock project" in (proc.stdout or ""):
            raise GhidraError(
                f"Ghidra could not lock the project {config.PROJECT_NAME!r}: another "
                "analyzeHeadless still holds it. Check for an orphaned process, and "
                f"for a stale {config.PROJECT_NAME}.lock in {config.PROJECT_LOCATION}."
            )
        tail = "\n".join((proc.stdout or "").splitlines()[-40:])
        raise ExportFailure(
            f"analyzeHeadless exited {proc.returncode}:\n{tail}\n{(proc.stderr or '')[-2000:]}"
        )
    return proc


def parse_envelope(text: str) -> Any:
    """Unwrap {"ok": true, "data": ...} or raise the typed error it carries."""
    try:
        envelope = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ExportFailure(f"export script emitted invalid JSON: {exc}") from exc

    if not isinstance(envelope, dict) or "ok" not in envelope:
        raise ExportFailure(f"export script emitted an unrecognised envelope: {text[:200]}")

    if envelope["ok"]:
        if "data" not in envelope:
            raise ExportFailure("envelope reported ok but carried no data")
        return envelope["data"]

    err = envelope.get("error") or {}
    raise from_envelope(err.get("kind", "error"), err.get("message", "unknown failure"))


def _run_spec(
    process: list[str], spec: dict, *, write: bool, timeout: int | None
) -> str | None:
    """Write the spec, invoke analyzeHeadless, return the raw output or None.

    The three export entry points differ only in what they put after -process
    and how they treat a missing output file, so everything else lives here.
    Args travel in a spec file, not on the command line: batch payloads exceed
    argv limits and defeat shell quoting.

    `write=False` passes -readOnly so nothing can be persisted by accident.
    `write=True` omits it, and Ghidra saves the program when the run completes.
    Routing every mutation through this one flag keeps read/write intent
    explicit at the call site.
    """
    with tempfile.TemporaryDirectory() as tmp:
        spec_file = Path(tmp) / "spec.json"
        out_file = Path(tmp) / "export.json"
        spec_file.write_text(json.dumps(spec))

        cmd = [*process, "-noanalysis"]
        if not write:
            cmd.append("-readOnly")
        cmd += [
            "-scriptPath", config.script_path(),
            "-postScript", config.EXPORT_SCRIPT, str(spec_file), str(out_file),
        ]

        run_headless(cmd, timeout=timeout or config.QUERY_TIMEOUT_S)

        return out_file.read_text() if out_file.is_file() else None


def export(
    program: str,
    mode: str,
    args: dict | None = None,
    *,
    write: bool = False,
    timeout: int | None = None,
) -> Any:
    """Run one export mode against an analysed program and return its data."""
    output = _run_spec(
        ["-process", program],
        {"mode": mode, "args": args or {}},
        write=write,
        timeout=timeout,
    )
    if output is None:
        raise ExportFailure(
            f"the export script produced no output for program {program!r}. "
            "Has it been analysed? Call analyze_binary first, or check "
            "list_programs for the exact name."
        )
    return parse_envelope(output)


def export_multi(
    mode: str,
    programs: list[str],
    args: dict | None = None,
    *,
    timeout: int | None = None,
) -> list[dict]:
    """Run one mode over several programs in a single JVM start.

    This is the whole point of the multi-binary work. Opening a second program
    inside a live JVM costs milliseconds; starting analyzeHeadless again costs
    seconds. Fanning out over four binaries measures at roughly 1.7x one call
    rather than 4x.

    analyzeHeadless attaches to programs[0] and the script opens the rest
    read-only. `-process` with no name would attach to every file in turn and
    re-run the postScript once per program, overwriting the output each time --
    harmless for a mode like project_files, silently wrong for anything that
    aggregates. Hence the explicit pivot.

    Always read-only: a headless run saves only the attached program, so a
    cross-program write would drop the others' changes without saying so.

    Returns one row per program, each {"program", "ok", "data"|"error"}.
    Callers report per-program failures rather than losing the batch.
    """
    if not programs:
        raise BadArgument("at least one program is required")

    output = _run_spec(
        ["-process", programs[0]],
        {"mode": mode, "args": args or {}, "programs": list(programs)},
        write=False,
        timeout=timeout,
    )
    if output is None:
        raise ExportFailure(
            f"the export script produced no output for program {programs[0]!r}. "
            "Has it been analysed? Call analyze_binary first, or check "
            "list_programs for the exact name."
        )

    data = parse_envelope(output)
    if not isinstance(data, dict) or "results" not in data:
        raise ExportFailure(
            "export_multi expected a multi-program envelope; the export script "
            "may predate the programs key"
        )
    return data["results"]


def export_project(
    mode: str, args: dict | None = None, *, write: bool = False, timeout: int | None = None
) -> Any:
    """Run a mode against the project rather than a named program.

    `-process` with no program attaches to every file in turn, so this works
    even when no program name is known yet — which is exactly the case when
    listing the project for the first time. Modes used this way must not depend
    on currentProgram.

    Returns None when the project holds no programs at all: the script never
    runs, so no output file is produced.
    """
    output = _run_spec(
        ["-process"], {"mode": mode, "args": args or {}}, write=write, timeout=timeout
    )
    return None if output is None else parse_envelope(output)


# ------------------------------------------------------------------ index


def index_path() -> Path:
    return config.PROJECT_LOCATION / f"{config.PROJECT_NAME}.programs.json"


def index_read() -> list[str]:
    p = index_path()
    if not p.is_file():
        return []
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError:
        logger.warning("program index at %s is corrupt; treating as empty", p)
        return []
    return data if isinstance(data, list) else []


def index_add(program: str) -> None:
    known = index_read()
    if program not in known:
        known.append(program)
        index_path().parent.mkdir(parents=True, exist_ok=True)
        index_path().write_text(json.dumps(sorted(known), indent=2))


def index_remove(program: str) -> None:
    known = index_read()
    if program in known:
        known.remove(program)
        index_path().write_text(json.dumps(sorted(known), indent=2))


# ------------------------------------------------------ decompilation cache


def cache_dir() -> Path:
    return config.PROJECT_LOCATION / "cache"


def corpus_path(program: str) -> Path:
    """Where a program's decompiled corpus is cached."""
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in program)
    return cache_dir() / f"{safe}.decompiled.json"


def load_corpus(program: str, refresh: bool = False) -> tuple[list[dict], bool]:
    """Return (functions, cached).

    Decompiling a whole binary is the most expensive thing this server does, so
    it happens once per program and every later query reads the cache. That is
    what makes repeated code search cheap despite the per-call JVM start.
    """
    path = corpus_path(program)
    if path.is_file() and not refresh:
        try:
            return json.loads(path.read_text())["functions"], True
        except (json.JSONDecodeError, KeyError):
            logger.warning("decompilation cache at %s is unusable; rebuilding", path)

    data = export(program, "decompile_all", {})
    cache_dir().mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    return data["functions"], False


def clear_corpus(program: str) -> bool:
    path = corpus_path(program)
    if path.is_file():
        path.unlink()
        return True
    return False
