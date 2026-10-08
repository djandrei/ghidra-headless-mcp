"""Configuration and Ghidra discovery.

Every value is read from the environment at import time so a test can point the
server at a throwaway project by setting PROJECT_LOCATION before import, and so
the running server's configuration is visible in one place.
"""

import os
import re
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
# a tool call; when a model makes that call they pass through its context too,
# and 4 MiB is already far more than a model should be asked to carry, and well
# past a crackme.
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(4 * 1024 * 1024)))

# POST /api/upload's cap. That route streams raw bytes to disk with no base64
# and no model in the path, so it can take whole DLLs; a separate cap keeps the
# model-facing one modest while a program sends what it needs to.
MAX_STREAM_UPLOAD_BYTES = int(
    os.environ.get("MAX_STREAM_UPLOAD_BYTES", str(128 * 1024 * 1024))
)


class InvalidSetting(ValueError):
    """An environment setting the server cannot use; it refuses to start."""


# A host name, IPv4 address or bracketed IPv6 address, optionally ":port".
_HOST_ENTRY = re.compile(r"^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)(?::(\d{1,5}))?$")


def extra_allowed_hosts() -> list[str]:
    """GHMCP_ALLOWED_HOSTS: Host headers /mcp accepts beyond loopback.

    The MCP SDK guards /mcp against DNS rebinding by accepting only the Host
    headers it is told to, and by default that is localhost, 127.0.0.1 and
    [::1]. A client in another container reaches this server as, say,
    host.docker.internal:1351 or 172.17.0.1:1351, and gets 421 Misdirected
    Request until that name is listed here.

    Comma-separated. "name" allows any port, "name:1351" only that one.
    Returns patterns in the SDK's form ("name:*", "name:1351"). A malformed
    entry raises InvalidSetting rather than being skipped: a typo should stop
    the server, not leave a client mysteriously refused. There is no
    wildcard for "any host" — that would switch the protection off.
    """
    raw = os.environ.get("GHMCP_ALLOWED_HOSTS", "")
    patterns = []
    for entry in (e.strip() for e in raw.split(",")):
        if not entry:
            continue
        m = _HOST_ENTRY.match(entry)
        if not m or (m.group(2) and not 0 < int(m.group(2)) < 65536):
            raise InvalidSetting(
                f"GHMCP_ALLOWED_HOSTS: {entry!r} is not a host name or address with an "
                "optional :port (e.g. host.docker.internal, 172.17.0.1:1351)"
            )
        patterns.append(f"{m.group(1)}:{m.group(2) or '*'}")
    return patterns


def upload_dir() -> Path:
    """Where upload_binary writes: UPLOAD_DIR, else <PROJECT_LOCATION>/samples.

    A function rather than a constant so it follows PROJECT_LOCATION when a test
    (or anything else) moves the project after import. Beside the project is the
    one place every deployment can already write — the samples mount is
    read-only — and both projects/ and projects-docker/ are gitignored, so
    uploaded samples cannot be committed by accident.
    """
    env = os.environ.get("UPLOAD_DIR")
    return Path(env).resolve() if env else PROJECT_LOCATION / "samples"


def openwebui_uploads_dir() -> Path | None:
    """Where OpenWebUI keeps chat attachments, from OPENWEBUI_UPLOADS_DIR.

    OpenWebUI stores each attachment as <uuid>_<filename> in its DATA_DIR's
    uploads/. Where that is depends entirely on how OpenWebUI was deployed, so
    there is no default to guess: None when the variable is unset.
    """
    env = os.environ.get("OPENWEBUI_UPLOADS_DIR")
    return Path(env).resolve() if env else None

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
    roots.append(Path("/ghidra"))  # ghidra-python images, Dockerfile.slim
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
