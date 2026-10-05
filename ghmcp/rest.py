"""Plain HTTP/JSON tool calls, with status codes that say whose fault it was.

mcpo cannot do this. The MCP SDK turns every tool exception into an isError
result carrying only its message, and mcpo answers every isError with HTTP 500
— a missing file, an oversized upload and a crashed decompiler all look the
same, and a client that retries 5xx sends a bad 100 MiB upload three times.
Here the tool runs in-process, so the exception's type is still there to map.

    POST /api/<tool>     JSON object of arguments -> the tool's JSON result

A success body is what mcpo returns for the same call, so a client moves
between the two by changing its base URL. A failure is

    {"error": {"kind": "<kind>", "message": "..."}}

with the kind from errors.py and the status below. Mounted inside the --http
app, so BearerAuthMiddleware guards it like /mcp.
"""

import asyncio
import json
import logging

import anyio
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import TextContent
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from .errors import HeadlessError
from .tools import mcp

log = logging.getLogger("ghidra_headless_mcp.rest")

# The caller's fault: retrying the same request cannot help. Everything else
# that a tool raises is the server's, and stays 500.
STATUS_BY_KIND = {
    "bad_argument": 400,
    "not_found": 404,
    "invalid_arguments": 422,
    "timeout": 504,
}


def error_response(status: int, kind: str, message: str, **extra) -> JSONResponse:
    body = {"kind": kind, "message": message, **extra}
    return JSONResponse({"error": body}, status_code=status)


def content_to_json(content: list) -> object:
    """The body mcpo would send for these content blocks.

    mcpo decodes each text block as JSON where it can and unwraps a single
    block. Every tool here returns one JSON text block; the general case is
    kept so the two surfaces cannot drift.
    """
    out = []
    for block in content:
        if isinstance(block, TextContent):
            try:
                out.append(json.loads(block.text))
            except json.JSONDecodeError:
                out.append(block.text)
    return out[0] if len(out) == 1 else out


def _call_blocking(name: str, args: dict):
    """Run the tool to completion on this (worker) thread.

    FastMCP calls a sync tool directly on the event loop, so an analysis would
    stall every other request on the process — /healthz included — for as
    long as it ran. A worker thread with a loop of its own keeps the server's
    loop free; Ghidra runs are serialised by headless.py's locks regardless.
    """
    return asyncio.run(mcp.call_tool(name, args))


def failure_response(name: str, exc: ToolError) -> JSONResponse:
    """Map a tool's failure onto a status, by the exception FastMCP wrapped."""
    cause = exc.__cause__
    # Only the arguments model is the caller's fault. A ValidationError from
    # inside the tool — a model built from an unexpected export — is ours.
    if isinstance(cause, ValidationError) and cause.title == f"{name}Arguments":
        return error_response(
            422,
            "invalid_arguments",
            f"invalid arguments for {name}",
            detail=json.loads(cause.json(include_url=False)),
        )
    if isinstance(cause, HeadlessError):
        status = STATUS_BY_KIND.get(cause.kind, 500)
        if status >= 500:
            log.error("%s failed: %s: %s", name, cause.kind, cause)
        return error_response(status, cause.kind, str(cause))
    log.error("%s failed unexpectedly", name, exc_info=cause or exc)
    return error_response(500, "error", str(cause or exc))


async def call_tool(request: Request) -> JSONResponse:
    name = request.path_params["tool"]
    if name not in {tool.name for tool in await mcp.list_tools()}:
        return error_response(404, "not_found", f"no tool named {name!r}")

    raw = await request.body()
    try:
        args = json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return error_response(400, "bad_argument", f"request body is not JSON: {exc}")
    if not isinstance(args, dict):
        return error_response(
            400, "bad_argument", "request body must be a JSON object of arguments"
        )

    try:
        content, _structured = await anyio.to_thread.run_sync(_call_blocking, name, args)
    except ToolError as exc:
        return failure_response(name, exc)
    return JSONResponse(content_to_json(content))


routes = [Route("/api/{tool}", call_tool, methods=["POST"])]
