"""Configuration and Ghidra discovery.

Every value is read from the environment at import time so a test can point the
server at a throwaway project by setting PROJECT_LOCATION before import, and so
the running server's configuration is visible in one place.
"""

import os
from pathlib import Path

# Server root: the directory holding ghidra_headless_mcp.py and ghidra_scripts/.
ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "ghidra_scripts"
EXPORT_SCRIPT = "HeadlessJsonExport.java"

PROJECT_LOCATION = Path(os.environ.get("PROJECT_LOCATION", ROOT / "projects")).resolve()
PROJECT_NAME = os.environ.get("PROJECT_NAME", "headless-mcp")

ANALYZE_TIMEOUT_S = int(os.environ.get("ANALYZE_TIMEOUT_S", "1800"))
QUERY_TIMEOUT_S = int(os.environ.get("QUERY_TIMEOUT_S", "600"))

# upload_binary's cap on one file. The bytes reach the server as base64 inside
# a tool call, so they pass through the model's context first; 4 MiB is already
# far more than a model should be asked to carry, and well past a crackme.
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(4 * 1024 * 1024)))


def upload_dir() -> Path:
    """Where upload_binary writes: UPLOAD_DIR, else <PROJECT_LOCATION>/samples.

    A function rather than a constant so it follows PROJECT_LOCATION when a test
    (or anything else) moves the project after import. Beside the project is the
    one place every deployment can already write — the course clone is mounted
    read-only — and both projects/ and projects-docker/ are gitignored, so
    uploaded samples cannot be committed by accident.
    """
    env = os.environ.get("UPLOAD_DIR")
    return Path(env).resolve() if env else PROJECT_LOCATION / "samples"

# Resolved analyzeHeadless path, and the GHIDRA_INSTALL_DIR value it was
# resolved under. Probing globs the home directory and /opt, which is wasteful
# to repeat for every call; caching makes it happen once per process.
_resolved: Path | None = None
_resolved_for: str | None = None


def candidate_roots() -> list[Path]:
    """Ghidra install roots to probe, most specific first."""
    roots: list[Path] = []
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env:
        roots.append(Path(env))
    roots.append(Path("/ghidra"))  # course devcontainer
    roots += sorted(Path.home().glob("bin/ghidra_*"), reverse=True)
    roots += sorted(Path("/opt").glob("ghidra*"), reverse=True)
    return roots


def find_ghidra() -> Path:
    """Locate support/analyzeHeadless, preferring GHIDRA_INSTALL_DIR.

    The result is cached for the life of the process. Two things still
    invalidate it, both cheap to check and both real:

    * GHIDRA_INSTALL_DIR changing — the cache records which value it resolved
      under, so pointing the server at another install takes effect;
    * the cached file no longer existing — one stat, against globbing the home
      directory and /opt again. Without it a moved or upgraded install would
      hand subprocess a path that no longer exists, and the failure would
      surface as an opaque exec error rather than the message below.

    Raises RuntimeError naming everything probed, because "Ghidra not found" is
    useless to someone whose install is in an unusual place.
    """
    global _resolved, _resolved_for

    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if _resolved is not None and _resolved_for == env and _resolved.is_file():
        return _resolved

    tried = candidate_roots()
    for root in tried:
        script = root / "support" / "analyzeHeadless"
        if script.is_file():
            _resolved, _resolved_for = script, env
            return script

    # Do not cache a failure: an install appearing later must be picked up.
    _resolved, _resolved_for = None, None
    raise RuntimeError(
        "analyzeHeadless not found. Set GHIDRA_INSTALL_DIR to a Ghidra install "
        f"root (tried: {', '.join(str(t) for t in tried)})."
    )


def reset_ghidra_cache() -> None:
    """Forget the resolved path. For tests, and for a deliberate re-probe."""
    global _resolved, _resolved_for
    _resolved = _resolved_for = None


def script_path() -> str:
    """Search path for -scriptPath: this server's scripts, then Ghidra's own.

    Ghidra searches only what -scriptPath names, so the bundled script directory
    must be listed explicitly or run_ghidra_script cannot reach the stock
    scripts.
    """
    bundled = find_ghidra().parent.parent / "Ghidra" / "Features" / "Base" / "ghidra_scripts"
    return f"{SCRIPT_DIR};{bundled}"
