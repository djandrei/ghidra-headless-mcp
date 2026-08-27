"""Bearer authentication on the HTTP surfaces.

No JVM and no network: the middleware is exercised as an ASGI app over a stub,
so these run in the fast suite with everything else.
"""

import asyncio

import pytest

from ghmcp import auth


def _read(path):
    """Parse one .env the way _key_from_dotenv does, from an explicit path."""
    for raw in path.read_text().splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        name, sep, value = raw.partition("=")
        if sep and name.strip() == auth.API_KEY_ENV:
            return value.strip() or None
    return None


@pytest.fixture
def no_dotenv(monkeypatch):
    """Neutralise the real .env.

    Any test asserting the fail-closed path needs this. Without it the result
    depends on whether whoever runs the suite happens to have a key on disk,
    and a test that "passes" by starting a real server is worse than one that
    fails.
    """
    monkeypatch.setattr(auth, "_key_from_dotenv", lambda: None)


# ------------------------------------------------------------ key loading


def test_load_returns_none_when_unset():
    assert auth.load_api_key({}) is None


def test_load_strips_surrounding_whitespace():
    # A key pasted into .env usually arrives with a trailing newline.
    assert auth.load_api_key({auth.API_KEY_ENV: "  s3cret-token-value  \n"}) == "s3cret-token-value"


def test_load_treats_whitespace_only_as_unset():
    assert auth.load_api_key({auth.API_KEY_ENV: "   \n\t "}) is None


def test_load_treats_empty_as_unset():
    assert auth.load_api_key({auth.API_KEY_ENV: ""}) is None


# ------------------------------------------------------------ fail closed


def test_require_raises_when_unset():
    with pytest.raises(auth.MissingApiKey) as exc:
        auth.require_api_key({})
    message = str(exc.value)
    # The message is the feature: it has to say what to set and how to make one.
    assert auth.API_KEY_ENV in message
    assert "secrets.token_urlsafe" in message


def test_require_rejects_a_short_key():
    with pytest.raises(auth.MissingApiKey) as exc:
        auth.require_api_key({auth.API_KEY_ENV: "short"})
    assert str(auth.MIN_KEY_LENGTH) in str(exc.value)


def test_require_returns_a_long_enough_key():
    key = "k" * auth.MIN_KEY_LENGTH
    assert auth.require_api_key({auth.API_KEY_ENV: key}) == key


def test_require_reads_the_process_environment_by_default(monkeypatch):
    monkeypatch.setenv(auth.API_KEY_ENV, "environment-provided-key")
    assert auth.require_api_key() == "environment-provided-key"


# ------------------------------------------------------------ header check

KEY = "correct-horse-battery-staple"


@pytest.mark.parametrize(
    "header",
    [
        f"Bearer {KEY}",
        f"bearer {KEY}",  # RFC 7235: the scheme is case-insensitive.
        f"BEARER {KEY}",
        f"Bearer  {KEY} ",  # Stray whitespace around the token.
    ],
)
def test_accepts_a_valid_header(header):
    assert auth.check_bearer(header, KEY) is True


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "Bearer",
        "Bearer ",
        f"{KEY}",  # Bare token, no scheme.
        f"Basic {KEY}",  # mcpo accepts Basic; this surface does not.
        f"Bearer {KEY}x",
        f"Bearer {KEY[:-1]}",
        "Bearer wrong-token-entirely",
    ],
)
def test_rejects_everything_else(header):
    assert auth.check_bearer(header, KEY) is False


def test_rejection_is_not_a_prefix_match():
    """A token that merely starts with the key must not pass."""
    assert auth.check_bearer(f"Bearer {KEY}-and-more", KEY) is False


# ------------------------------------------------------------- middleware


class _Stub:
    """Minimal ASGI app recording whether the request reached it."""

    def __init__(self):
        self.calls = []

    async def __call__(self, scope, receive, send):
        self.calls.append(scope.get("path"))
        body = b'{"reached":true}'
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": body})


def _scope(path="/mcp", headers=(), kind="http", method="POST"):
    return {"type": kind, "path": path, "method": method, "headers": list(headers), "client": ("1.2.3.4", 5)}


def _drive(app, scope):
    """Run one ASGI request, returning (start_message, body_bytes, all_messages).

    Synchronous on purpose: no async pytest plugin is installed, and pulling one
    in for a handful of tests would cost the suite a dependency it does not
    otherwise need.
    """
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    start = next((m for m in sent if m["type"] == "http.response.start"), None)
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start, body, sent


@pytest.fixture
def stub():
    return _Stub()


@pytest.fixture
def guarded(stub):
    return auth.BearerAuthMiddleware(stub, KEY, exempt_paths={"/healthz"})


def test_valid_token_reaches_the_app(guarded, stub):
    scope = _scope(headers=[(b"authorization", f"Bearer {KEY}".encode())])
    start, body, _ = _drive(guarded, scope)
    assert start["status"] == 200
    assert body == b'{"reached":true}'
    assert stub.calls == ["/mcp"]


def test_missing_token_is_401_and_never_reaches_the_app(guarded, stub):
    start, body, _ = _drive(guarded, _scope())
    assert start["status"] == 401
    assert b"unauthorized" in body
    # The point of the middleware: the tool layer is not merely told to refuse,
    # it is never entered at all.
    assert stub.calls == []


def test_wrong_token_is_401_and_never_reaches_the_app(guarded, stub):
    scope = _scope(headers=[(b"authorization", b"Bearer not-the-key")])
    start, _, _ = _drive(guarded, scope)
    assert start["status"] == 401
    assert stub.calls == []


def test_401_carries_www_authenticate(guarded):
    """RFC 7235 requires it, and it tells a client which scheme to use."""
    start, _, _ = _drive(guarded, _scope())
    headers = {k.lower(): v for k, v in start["headers"]}
    assert b"Bearer" in headers[b"www-authenticate"]


def test_exempt_path_needs_no_token(guarded, stub):
    start, _, _ = _drive(guarded, _scope(path="/healthz", method="GET"))
    assert start["status"] == 200
    assert stub.calls == ["/healthz"]


def test_exemption_is_exact_not_a_prefix(guarded, stub):
    """/healthz must not open /healthz-and-more, nor anything mounted under it."""
    start, _, _ = _drive(guarded, _scope(path="/healthz/../mcp", method="GET"))
    assert start["status"] == 401
    assert stub.calls == []


def test_lifespan_passes_through(guarded, stub):
    """Blocking lifespan would stop the app from starting; there is no caller."""

    async def noop(*_args):
        return {"type": "lifespan.startup"}

    asyncio.run(guarded({"type": "lifespan"}, noop, noop))
    assert stub.calls == [None]


def test_websocket_is_refused(stub):
    """This transport uses none, so anything arriving there is unrecognised."""
    guarded = auth.BearerAuthMiddleware(stub, KEY)
    sent = []

    async def send(message):
        sent.append(message)

    asyncio.run(guarded({"type": "websocket", "path": "/mcp", "headers": []}, None, send))
    assert sent == [{"type": "websocket.close", "code": 1008}]
    assert stub.calls == []


def test_undecodable_header_is_a_401_not_a_crash(guarded, stub):
    scope = _scope(headers=[(b"authorization", b"Bearer \xff\xfe")])
    start, _, _ = _drive(guarded, scope)
    assert start["status"] == 401
    assert stub.calls == []


# ------------------------------------------------------- the app it guards


def test_build_http_app_wraps_in_auth():
    """The launcher must not hand out a bare, unguarded MCP app."""
    import ghidra_headless_mcp as entry

    app = entry.build_http_app(KEY)
    assert isinstance(app, auth.BearerAuthMiddleware)
    assert app.key == KEY
    assert "/healthz" in app.exempt_paths


def test_http_mode_exits_when_no_key(monkeypatch, capsys, no_dotenv):
    """--http must fail closed, and say why.

    no_dotenv matters: without it this test passes on a machine with no .env
    and, on a machine with one, sails past the check and binds a real port.
    """
    import ghidra_headless_mcp as entry

    monkeypatch.delenv(auth.API_KEY_ENV, raising=False)
    with pytest.raises(SystemExit) as exc:
        entry.main(["--http"])
    assert exc.value.code == 2
    assert auth.API_KEY_ENV in capsys.readouterr().err


# ------------------------------------------------------------ .env fallback


def test_dotenv_supplies_the_key_when_unexported(monkeypatch, tmp_path):
    """One .env has to serve compose, a host run and the devcontainer alike."""
    monkeypatch.delenv(auth.API_KEY_ENV, raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text(f"# a comment\n{auth.API_KEY_ENV}=from-the-dotenv-file\n")
    monkeypatch.setattr(auth, "_key_from_dotenv", lambda: _read(env_file))
    assert auth.require_api_key() == "from-the-dotenv-file"


@pytest.mark.parametrize(
    "line, expected",
    [
        ("GHMCP_API_KEY=plain-value-long-enough", "plain-value-long-enough"),
        ('GHMCP_API_KEY="double-quoted-value"', "double-quoted-value"),
        ("GHMCP_API_KEY='single-quoted-value'", "single-quoted-value"),
        ("  GHMCP_API_KEY  =  spaced-value  ", "spaced-value"),
        ("#GHMCP_API_KEY=commented-out", None),
        ("OTHER_KEY=not-ours", None),
        ("GHMCP_API_KEY=", None),
        ("no-equals-sign-at-all", None),
    ],
)
def test_dotenv_parsing(tmp_path, monkeypatch, line, expected):
    """Parsed, not sourced — .env is compose's format, not a shell script."""
    (tmp_path / ".env").write_text(line + "\n")
    monkeypatch.setattr(
        auth, "__file__", str(tmp_path / "pkg" / "auth.py")
    )
    assert auth._key_from_dotenv() == expected


def test_dotenv_is_ignored_when_an_env_mapping_is_passed(tmp_path, monkeypatch):
    """An explicit mapping is a test's environment; a real .env must not leak in."""
    monkeypatch.setattr(auth, "_key_from_dotenv", lambda: "from-disk")
    with pytest.raises(auth.MissingApiKey):
        auth.require_api_key({})


def test_missing_dotenv_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "__file__", str(tmp_path / "pkg" / "auth.py"))
    assert auth._key_from_dotenv() is None


def test_stdio_mode_needs_no_key(monkeypatch):
    """The default transport is unchanged: no key, no HTTP, no refusal."""
    import ghidra_headless_mcp as entry

    monkeypatch.delenv(auth.API_KEY_ENV, raising=False)
    ran = []
    monkeypatch.setattr(entry.mcp, "run", lambda: ran.append(True))
    entry.main([])
    assert ran == [True]
