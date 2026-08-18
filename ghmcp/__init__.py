"""ghidra-headless-mcp — Ghidra's headless analyzer behind MCP.

Split into modules because the tool surface is growing toward parity with
GhidraMCP and pyghidra-mcp; see ghidra_headless_mcp_roadmap.md.
"""

__all__ = ["config", "errors", "headless", "models", "tools"]
