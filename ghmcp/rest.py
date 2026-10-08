"""Plain HTTP/JSON tool calls, with status codes that say whose fault it was.

mcpo cannot do this. The MCP SDK turns every tool exception into an isError
result carrying only its message, and mcpo answers every isError with HTTP 500
— a missing file, an oversized upload and a crashed decompiler all look the
same, and a client that retries 5xx sends a bad 100 MiB upload three times.
Here the tool runs in-process, so the exception's type is still there to map.

    POST /api/<tool>     JSON object of arguments -> the tool's JSON result
    POST /api/upload     raw bytes, ?filename=… -> upload_binary's result

A success body is what mcpo returns for the same call, so a client moves
between the two by changing its base URL. A failure is

    {"error": {"kind": "<kind>", "message": "..."}}

with the kind from errors.py and the status below. Mounted inside the --http
app, so BearerAuthMiddleware guards it like /mcp.
"""

import asyncio
import hashlib
import json
import logging
import os
import tempfile
from pathlib import Path

import anyio
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import TextContent
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import config, tools
from .errors import BadArgument, HeadlessError
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


def headless_error_response(name: str, exc: HeadlessError) -> JSONResponse:
    status = STATUS_BY_KIND.get(exc.kind, 500)
    if status >= 500:
        log.error("%s failed: %s: %s", name, exc.kind, exc)
    return error_response(status, exc.kind, str(exc))


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
        return headless_error_response(name, cause)
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
        result = await anyio.to_thread.run_sync(_call_blocking, name, args)
    except ToolError as exc:
        return failure_response(name, exc)
    # A tool with an output schema yields (content, structured); one without —
    # clear_code_cache returns a bare dict — yields the content list alone.
    content = result[0] if isinstance(result, tuple) else result
    return JSONResponse(content_to_json(content))


# ------------------------------------------------------------------ upload

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off", ""}


def query_flag(request: Request, name: str, default: bool) -> bool:
    raw = request.query_params.get(name)
    if raw is None:
        return default
    if raw.lower() in _TRUE:
        return True
    if raw.lower() in _FALSE:
        return False
    raise BadArgument(f"{name} must be true or false, got {raw!r}")


class TooLarge(Exception):
    """The body passed MAX_STREAM_UPLOAD_BYTES."""


def _too_large(limit: int) -> JSONResponse:
    return error_response(
        413,
        "too_large",
        f"file exceeds the {limit}-byte upload limit (MAX_STREAM_UPLOAD_BYTES)",
    )


async def upload(request: Request) -> JSONResponse:
    """upload_binary for programs: raw bytes in the body, streamed to disk.

    No base64 and no JSON envelope, so nothing is inflated by a third, and the
    file is never held whole in memory: each chunk is hashed and written as it
    arrives. An oversized body is refused from its Content-Length before a byte
    is read, or as soon as it passes the cap when the length is not declared.
    The rest — storing, dedupe, keep=False, analysis — is upload_binary's own
    logic, so a file behaves the same whichever way it arrived.

        POST /api/upload?filename=<name>&analyze=true&keep=false
        Content-Type: application/octet-stream
    """
    limit = config.MAX_STREAM_UPLOAD_BYTES
    try:
        name = tools.sanitize_upload_name(request.query_params.get("filename", ""))
        overwrite = query_flag(request, "overwrite", False)
        analyze = query_flag(request, "analyze", False)
        keep = query_flag(request, "keep", True)
        tools.check_keep(analyze, keep)
        declared = request.headers.get("content-length")
        if declared is not None and not declared.isdigit():
            raise BadArgument(f"Content-Length is not a number: {declared!r}")
    except BadArgument as exc:
        return headless_error_response("upload", exc)
    if declared is not None and int(declared) > limit:
        return _too_large(limit)

    directory = tools.prepare_upload_dir()
    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=tools.UPLOAD_TMP_PREFIX)
    tmp = Path(tmp_name)
    md5, sha256, size = hashlib.md5(), hashlib.sha256(), 0
    try:
        with os.fdopen(fd, "wb") as fh:
            async for chunk in request.stream():
                size += len(chunk)
                if size > limit:
                    raise TooLarge
                md5.update(chunk)
                sha256.update(chunk)
                fh.write(chunk)
    except TooLarge:
        tmp.unlink(missing_ok=True)
        return _too_large(limit)
    except BaseException:
        # A client that disconnects mid-body, or anything else: no half file.
        tmp.unlink(missing_ok=True)
        raise
    if size == 0:
        tmp.unlink(missing_ok=True)
        return error_response(400, "bad_argument", "the request body is empty")

    try:
        result = await anyio.to_thread.run_sync(
            lambda: tools.store_upload(
                name,
                tmp,
                size=size,
                md5=md5.hexdigest(),
                sha256=sha256.hexdigest(),
                overwrite=overwrite,
                analyze=analyze,
                keep=keep,
            )
        )
    except HeadlessError as exc:
        return headless_error_response("upload", exc)
    return JSONResponse(json.loads(result.model_dump_json()))


# /api/upload first: it would otherwise match /api/{tool} as a tool named "upload".
routes = [
    Route("/api/upload", upload, methods=["POST"]),
    Route("/api/{tool}", call_tool, methods=["POST"]),
]
