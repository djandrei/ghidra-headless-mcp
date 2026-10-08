"""The stdio transport, end to end: the real server as a subprocess, driven by
the MCP SDK's own client.

stdio is what an MCP client that spawns the server uses, and the transport
where a stray print would corrupt the stream. No JVM: the calls here are the
tools that never reach Ghidra, plus failures that are decided before it would.
"""

import os
import sys
from pathlib import Path

import anyio
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from tests.surfaces import registered_tools, required_params

ROOT = Path(__file__).resolve().parents[1]


def run(tmp_path, steps):
    """Start the server over stdio, run `steps(session)`, return its result."""
    env = {**os.environ, "PROJECT_LOCATION": str(tmp_path / "proj"),
           "UPLOAD_DIR": str(tmp_path / "uploads")}
    env.pop("OPENWEBUI_UPLOADS_DIR", None)
    params = StdioServerParameters(
        command=sys.executable, args=[str(ROOT / "ghidra_headless_mcp.py")],
        env=env, cwd=str(ROOT))

    async def main():
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await steps(session)

    return anyio.run(main)


def test_stdio_lists_every_tool_with_its_required_arguments(tmp_path):
    async def steps(s):
        return (await s.list_tools()).tools

    tools = {t.name: t for t in run(tmp_path, steps)}
    assert set(tools) == set(registered_tools())
    for name, tool in tools.items():
        assert set(tool.inputSchema.get("required", [])) == required_params(name), name


def test_stdio_round_trips_a_file_through_the_upload_tools(tmp_path):
    async def steps(s):
        stored = await s.call_tool("upload_binary",
                                   {"filename": "a.bin", "content_base64": "f0VMRg=="})
        listed = await s.call_tool("list_uploads", {})
        deleted = await s.call_tool("delete_upload", {"filename": "a.bin"})
        after = await s.call_tool("list_uploads", {})
        return stored, listed, deleted, after

    stored, listed, deleted, after = run(tmp_path, steps)
    assert not stored.isError and stored.structuredContent["size"] == 4
    assert [u["filename"] for u in listed.structuredContent["uploads"]] == ["a.bin"]
    assert not deleted.isError and deleted.structuredContent["deleted"] is True
    assert after.structuredContent["uploads"] == []
    assert (tmp_path / "uploads").is_dir() and not any((tmp_path / "uploads").iterdir())


def test_stdio_reports_failures_as_error_results(tmp_path):
    async def steps(s):
        return (
            await s.call_tool("analyze_binary", {"binary_path": str(tmp_path / "missing.bin")}),
            await s.call_tool("get_cfg", {}),
            await s.call_tool("upload_binary", {"filename": "../x", "content_base64": "QUJD"}),
            await s.call_tool("list_chat_uploads", {}),
            await s.call_tool("no_such_tool", {}),
            await s.call_tool("list_programs", {}),  # still serving after all that
        )

    missing, no_args, bad_name, unconfigured, unknown, healthy = run(tmp_path, steps)
    assert missing.isError and "binary not found" in missing.content[0].text
    assert no_args.isError and "program" in no_args.content[0].text
    assert bad_name.isError and "path separators" in bad_name.content[0].text
    assert unconfigured.isError and "OPENWEBUI_UPLOADS_DIR" in unconfigured.content[0].text
    assert unknown.isError and "Unknown tool" in unknown.content[0].text
    assert not healthy.isError and healthy.structuredContent["programs"] == []


def test_stdio_needs_no_api_key(tmp_path, monkeypatch):
    """The client spawned the process, so it already has what a key would grant."""
    monkeypatch.delenv("GHMCP_API_KEY", raising=False)

    async def steps(s):
        return await s.call_tool("list_uploads", {})

    assert not run(tmp_path, steps).isError
