"""ghidra-headless-mcp — Ghidra's headless analyzer behind MCP.

Split into modules because the tool surface reaches parity with GhidraMCP
and pyghidra-mcp; see docs/roadmap.md.
"""

__version__ = "0.1.0"

__all__ = ["config", "errors", "headless", "models", "tools"]
