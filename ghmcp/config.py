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

# Candidate install roots, in priority order. GHIDRA_INSTALL_DIR wins.
_CANDIDATE_ROOTS: list[Path] = []


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

    Raises RuntimeError naming everything probed, because "Ghidra not found" is
    useless to someone whose install is in an unusual place.
    """
    tried = candidate_roots()
    for root in tried:
        script = root / "support" / "analyzeHeadless"
        if script.is_file():
            return script
    raise RuntimeError(
        "analyzeHeadless not found. Set GHIDRA_INSTALL_DIR to a Ghidra install "
        f"root (tried: {', '.join(str(t) for t in tried)})."
    )


def script_path() -> str:
    """Search path for -scriptPath: this server's scripts, then Ghidra's own.

    Ghidra searches only what -scriptPath names, so the bundled script directory
    must be listed explicitly or run_ghidra_script cannot reach the stock
    scripts.
    """
    bundled = find_ghidra().parent.parent / "Ghidra" / "Features" / "Base" / "ghidra_scripts"
    return f"{SCRIPT_DIR};{bundled}"
