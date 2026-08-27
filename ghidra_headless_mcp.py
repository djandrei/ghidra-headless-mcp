#!/usr/bin/env python3
"""Entry point for ghidra-headless-mcp.

The implementation lives in the ghmcp package; this stays a launcher so the
documented command line (`python ghidra_headless_mcp.py`, and the mcpo wrapper
around it) keeps working as the tool surface grows.

Two transports:

    python ghidra_headless_mcp.py            stdio, for a client that spawns us
    python ghidra_headless_mcp.py --http     native MCP over streamable-http

stdio is the default and is unchanged. It needs no authentication: the client
spawned this process, so it already has whatever this process has.

--http listens on a socket anyone can connect to, so it REQUIRES GHMCP_API_KEY
and refuses to start without one. See ghmcp/auth.py.

Transport for stdio is stdout, so ALL logging goes to stderr; anything on
stdout corrupts the JSON-RPC stream.
"""

import argparse
import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)

from ghmcp import auth, config  # noqa: E402  (configure logging before import chatter)
from ghmcp.tools import mcp  # noqa: E402

log = logging.getLogger("ghidra_headless_mcp")

DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 1351
"""Matches the url in opencode/opencode.json.

1341 is mcpo's; running both at once is the normal case, so they cannot share.
"""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ghidra_headless_mcp.py",
        description="Ghidra's headless analyzer as MCP tools.",
    )
    parser.add_argument(
        "--http",
        action="store_true",
        help="Serve native MCP over streamable-http instead of stdio. "
        "Requires GHMCP_API_KEY.",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("GHMCP_HTTP_HOST", DEFAULT_HTTP_HOST),
        help=f"Bind address for --http (default {DEFAULT_HTTP_HOST}, or GHMCP_HTTP_HOST).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("GHMCP_HTTP_PORT", DEFAULT_HTTP_PORT)),
        help=f"Port for --http (default {DEFAULT_HTTP_PORT}, or GHMCP_HTTP_PORT).",
    )
    return parser.parse_args(argv)


def build_http_app(key: str):
    """The streamable-http app, wrapped so every MCP request needs the token.

    /healthz is left open deliberately, matching the decision on the mcpo side
    that liveness checks stay reachable while tool calls do not. It reports
    nothing but that the process is up.
    """
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    app = mcp.streamable_http_app()
    app.router.routes.append(
        Route(
            "/healthz",
            lambda _request: JSONResponse({"ok": True, "auth": "required"}),
            methods=["GET"],
        )
    )
    return auth.BearerAuthMiddleware(app, key, exempt_paths={"/healthz"})


def run_http(host: str, port: int) -> None:
    import uvicorn

    # Before the banner, so a missing key is a clear message rather than a
    # server that comes up and then refuses everything.
    key = auth.require_api_key()

    log.info(
        "ghidra-headless-mcp serving native MCP on http://%s:%d%s (bearer auth required)",
        host,
        port,
        mcp.settings.streamable_http_path,
    )
    if host not in ("127.0.0.1", "localhost", "::1"):
        log.warning(
            "binding %s, not loopback: run_ghidra_script executes arbitrary "
            "Ghidra scripts, so reachability is the thing to be sure about here",
            host,
        )

    uvicorn.run(build_http_app(key), host=host, port=port, log_level="info")


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    log.info(
        "ghidra-headless-mcp starting: project=%s location=%s",
        config.PROJECT_NAME,
        config.PROJECT_LOCATION,
    )

    if not args.http:
        mcp.run()
        return

    try:
        run_http(args.host, args.port)
    except auth.MissingApiKey as exc:
        # The message is the whole point of failing here, so print it plainly
        # rather than as a traceback nobody reads to the bottom of.
        print(f"\n{exc}\n", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
