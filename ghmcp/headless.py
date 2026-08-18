"""The analyzeHeadless plumbing: spec in, envelope out.

One place decides how a mode is invoked, whether the run may write, and how a
failure becomes a typed exception. Tools above this layer never build a command
line or parse JSON themselves.
"""

import json
import logging
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any

from . import config
from .errors import ExportFailure, HeadlessTimeout, from_envelope

logger = logging.getLogger("ghidra_headless_mcp")

# Ghidra locks a project for the duration of a headless run, so concurrent calls
# would fail with a lock error rather than queue. Serialise them here.
_GHIDRA_LOCK = threading.Lock()


def run_headless(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    """Invoke analyzeHeadless with the project location and name prepended."""
    config.PROJECT_LOCATION.mkdir(parents=True, exist_ok=True)
    cmd = [str(config.find_ghidra()), str(config.PROJECT_LOCATION), config.PROJECT_NAME, *args]
    logger.info("running: %s", " ".join(cmd))

    with _GHIDRA_LOCK:
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


def export(
    program: str,
    mode: str,
    args: dict | None = None,
    *,
    write: bool = False,
    timeout: int | None = None,
) -> Any:
    """Run one export mode against an analysed program and return its data.

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
        spec_file.write_text(json.dumps({"mode": mode, "args": args or {}}))

        cmd = ["-process", program, "-noanalysis"]
        if not write:
            cmd.append("-readOnly")
        cmd += [
            "-scriptPath", config.script_path(),
            "-postScript", config.EXPORT_SCRIPT, str(spec_file), str(out_file),
        ]

        run_headless(cmd, timeout=timeout or config.QUERY_TIMEOUT_S)

        if not out_file.is_file():
            raise ExportFailure(
                f"the export script produced no output for program {program!r}. "
                "Has it been analysed? Call analyze_binary first, or check "
                "list_programs for the exact name."
            )
        return parse_envelope(out_file.read_text())


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
    with tempfile.TemporaryDirectory() as tmp:
        spec_file = Path(tmp) / "spec.json"
        out_file = Path(tmp) / "export.json"
        spec_file.write_text(json.dumps({"mode": mode, "args": args or {}}))

        cmd = ["-process", "-noanalysis"]
        if not write:
            cmd.append("-readOnly")
        cmd += [
            "-scriptPath", config.script_path(),
            "-postScript", config.EXPORT_SCRIPT, str(spec_file), str(out_file),
        ]
        run_headless(cmd, timeout=timeout or config.QUERY_TIMEOUT_S)

        if not out_file.is_file():
            return None
        return parse_envelope(out_file.read_text())


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
