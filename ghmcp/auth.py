"""Bearer-token authentication for the HTTP surfaces.

stdio needs none of this. There the client spawns the process, so it already
has everything the process has and a token would only be checking the caller
against itself. Only the HTTP transports can be reached by someone who did not
start the server, so that is where a token means something and this module is
used.

Both HTTP surfaces read the SAME variable — mcpo's OpenAPI port via
`--api-key`, the native MCP port via `BearerAuthMiddleware` — so one token
works for both and there is no second secret to rotate.

Fail closed: `require_api_key` raises rather than defaulting to open. A server
that quietly serves `run_ghidra_script` to anyone who asks is the failure this
is here to prevent, so an unset key must stop the server, not warn in a log
nobody reads.
"""

from __future__ import annotations

import hmac
import logging
import os
from collections.abc import Iterable, Mapping

logger = logging.getLogger(__name__)

API_KEY_ENV = "GHMCP_API_KEY"

MIN_KEY_LENGTH = 16
"""Shortest key accepted.

Not a strength estimate — it is a typo guard. A key short enough to be typed
from memory is one somebody chose, and the generator below emits 43 characters.
"""

GENERATE_HINT = "python3 -c 'import secrets; print(secrets.token_urlsafe(32))'"

_UNSET_MESSAGE = f"""\
{API_KEY_ENV} is not set, so the HTTP server refuses to start.

Every tool is reachable over HTTP, run_ghidra_script included, and that one
executes arbitrary Ghidra scripts. Serving it unauthenticated is not a default
worth having.

Generate a key:
    {GENERATE_HINT}

Then put it in this directory's .env (gitignored) as
    {API_KEY_ENV}=<the key>
or export it in the environment that starts the server.

stdio needs no key: `python ghidra_headless_mcp.py` with no --http is
unaffected.\
"""


class MissingApiKey(RuntimeError):
    """No usable key in the environment, and the HTTP server will not start."""


def load_api_key(env: Mapping[str, str] | None = None) -> str | None:
    """Return the configured key, or None when there is none.

    Surrounding whitespace is stripped: a key pasted into a .env file tends to
    arrive with a trailing newline, and failing on that is unhelpful. A value
    that is only whitespace counts as unset rather than as a one-space key.
    """
    source = os.environ if env is None else env
    raw = source.get(API_KEY_ENV)
    if raw is None:
        return None
    key = raw.strip()
    return key or None


def require_api_key(env: Mapping[str, str] | None = None) -> str:
    """Return the configured key, or raise MissingApiKey explaining what to do.

    Raises on a key shorter than MIN_KEY_LENGTH too. Accepting a two-character
    key would satisfy the letter of "authentication required" while leaving the
    server brute-forceable in seconds, which is worse than refusing outright
    because it looks protected.
    """
    key = load_api_key(env)
    if key is None:
        raise MissingApiKey(_UNSET_MESSAGE)
    if len(key) < MIN_KEY_LENGTH:
        raise MissingApiKey(
            f"{API_KEY_ENV} is only {len(key)} characters; at least "
            f"{MIN_KEY_LENGTH} are required.\n\nGenerate one with:\n    {GENERATE_HINT}"
        )
    return key


def check_bearer(header: str | None, key: str) -> bool:
    """True when an Authorization header carries the expected bearer token.

    The comparison is constant-time. The scheme is matched case-insensitively
    because RFC 7235 says it is case-insensitive and clients disagree in
    practice — `Bearer`, `bearer` and `BEARER` are all sent by something.
    """
    if not header:
        return False
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer":
        return False
    token = token.strip()
    if not token:
        return False
    # Bytes, not str: compare_digest raises TypeError on a str holding
    # non-ASCII, and a header full of junk bytes must be a 401 rather than an
    # exception escaping into the transport.
    return hmac.compare_digest(token.encode("utf-8"), key.encode("utf-8"))


class BearerAuthMiddleware:
    """ASGI middleware demanding a bearer token on every guarded HTTP request.

    Pure ASGI rather than Starlette's BaseHTTPMiddleware on purpose: the
    streamable-http transport streams responses, and BaseHTTPMiddleware buffers
    them, which would break the transport this is protecting.

    Non-HTTP scopes (`lifespan`) pass straight through — there is no caller to
    authenticate and blocking them would stop the app from starting. A
    `websocket` scope is refused instead of passed: this transport does not use
    one, so anything arriving there is not a client we know about.
    """

    def __init__(self, app, key: str, exempt_paths: Iterable[str] = ()):
        self.app = app
        self.key = key
        self.exempt_paths = frozenset(exempt_paths)

    async def __call__(self, scope, receive, send) -> None:
        kind = scope.get("type")

        if kind == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return

        if kind != "http":
            await self.app(scope, receive, send)
            return

        if scope.get("path") in self.exempt_paths:
            await self.app(scope, receive, send)
            return

        if check_bearer(_authorization(scope), self.key):
            await self.app(scope, receive, send)
            return

        logger.warning(
            "rejected unauthenticated %s %s from %s",
            scope.get("method", "?"),
            scope.get("path", "?"),
            (scope.get("client") or ("?",))[0],
        )
        await _send_401(send)


def _authorization(scope) -> str | None:
    """Pull the Authorization header out of a raw ASGI scope.

    Header names arrive lowercased as bytes per the ASGI spec, but the value is
    decoded defensively: a malformed byte should be a 401, not a UnicodeError
    escaping into the transport.
    """
    for name, value in scope.get("headers") or ():
        if name == b"authorization":
            return value.decode("latin-1", "replace")
    return None


async def _send_401(send) -> None:
    body = b'{"error":"unauthorized","detail":"Bearer token required."}'
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                # RFC 7235 requires this on a 401; it is also what tells a
                # client the scheme rather than leaving it to guess.
                (b"www-authenticate", b'Bearer realm="ghidra-headless-mcp"'),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
