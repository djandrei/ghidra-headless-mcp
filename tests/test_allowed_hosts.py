"""GHMCP_ALLOWED_HOSTS: extra Host headers /mcp accepts beyond loopback.

Without it, the MCP SDK's DNS-rebinding guard answers 421 to a client that
reaches the server under any other name — another container calling
host.docker.internal:1351, say. /api has no such guard and is unaffected.
"""

import pytest
from starlette.testclient import TestClient

import ghidra_headless_mcp as entry
from ghmcp import config
from ghmcp.tools import mcp

KEY = "correct-horse-battery-staple"
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-03-26", "capabilities": {},
    "clientInfo": {"name": "t", "version": "0"}}}


# ------------------------------------------------------------------ parsing


@pytest.mark.parametrize("raw, expected", [
    ("", []),
    ("  ", []),
    ("host.docker.internal", ["host.docker.internal:*"]),
    ("172.17.0.1:1351", ["172.17.0.1:1351"]),
    (" a.example , b.example:8080 ,", ["a.example:*", "b.example:8080"]),
    ("[::1]:1351", ["[::1]:1351"]),
    ("[fd00::5]", ["[fd00::5]:*"]),
    ("ghidra-headless-mcp-http", ["ghidra-headless-mcp-http:*"]),
])
def test_entries_become_sdk_patterns(monkeypatch, raw, expected):
    monkeypatch.setenv("GHMCP_ALLOWED_HOSTS", raw)
    assert config.extra_allowed_hosts() == expected


def test_unset_adds_nothing(monkeypatch):
    monkeypatch.delenv("GHMCP_ALLOWED_HOSTS", raising=False)
    assert config.extra_allowed_hosts() == []


@pytest.mark.parametrize("bad", [
    "*", "*:1351", "host:*", "http://host", "a/b", "two words", "host:0", "host:65536",
    "host:port", "-leading", "trailing-", "host:1351:1", "[not-ipv6]",
])
def test_a_malformed_entry_is_refused_by_name(monkeypatch, bad):
    monkeypatch.setenv("GHMCP_ALLOWED_HOSTS", f"ok.example,{bad}")
    with pytest.raises(config.InvalidSetting, match="GHMCP_ALLOWED_HOSTS"):
        config.extra_allowed_hosts()


# -------------------------------------------------------------- the effect


def initialize(monkeypatch, allowed, host, origin=None):
    """Build the --http app under GHMCP_ALLOWED_HOSTS and send one initialize."""
    if allowed is None:
        monkeypatch.delenv("GHMCP_ALLOWED_HOSTS", raising=False)
    else:
        monkeypatch.setenv("GHMCP_ALLOWED_HOSTS", allowed)
    mcp._session_manager = None  # a session manager runs once per app
    headers = {"Authorization": f"Bearer {KEY}", "Host": host,
               "Accept": "application/json, text/event-stream"}
    if origin:
        headers["Origin"] = origin
    try:
        with TestClient(entry.build_http_app(KEY)) as client:
            return client.post("/mcp", json=INIT, headers=headers).status_code
    finally:
        mcp._session_manager = None


@pytest.mark.parametrize("host", ["localhost:1351", "127.0.0.1:1351", "[::1]:1351"])
def test_loopback_is_always_accepted(monkeypatch, host):
    assert initialize(monkeypatch, "host.docker.internal", host) == 200
    assert initialize(monkeypatch, None, host) == 200


def test_unset_refuses_a_container_name(monkeypatch):
    assert initialize(monkeypatch, None, "host.docker.internal:1351") == 421


def test_a_listed_name_is_accepted_on_any_port(monkeypatch):
    for port in (1351, 9999):
        assert initialize(monkeypatch, "host.docker.internal",
                          f"host.docker.internal:{port}") == 200


def test_a_listed_port_is_the_only_port(monkeypatch):
    assert initialize(monkeypatch, "172.17.0.1:1351", "172.17.0.1:1351") == 200
    assert initialize(monkeypatch, "172.17.0.1:1351", "172.17.0.1:9999") == 421


def test_an_unlisted_name_is_still_refused(monkeypatch):
    assert initialize(monkeypatch, "host.docker.internal", "evil.example:1351") == 421


def test_a_browser_origin_on_a_listed_host_is_accepted(monkeypatch):
    for origin in ("http://host.docker.internal:1351", "https://host.docker.internal:1351"):
        assert initialize(monkeypatch, "host.docker.internal", "host.docker.internal:1351",
                          origin=origin) == 200


def test_a_browser_origin_elsewhere_is_refused(monkeypatch):
    assert initialize(monkeypatch, "host.docker.internal", "host.docker.internal:1351",
                      origin="http://evil.example") == 403


def test_removing_the_setting_takes_the_hosts_away_again(monkeypatch):
    """Each app starts from the SDK's loopback defaults; nothing accumulates."""
    assert initialize(monkeypatch, "host.docker.internal", "host.docker.internal:1351") == 200
    assert initialize(monkeypatch, None, "host.docker.internal:1351") == 421
    assert mcp.settings.transport_security.allowed_hosts == entry.LOOPBACK_HOSTS


def test_api_is_unaffected_either_way(monkeypatch):
    monkeypatch.delenv("GHMCP_ALLOWED_HOSTS", raising=False)
    client = TestClient(entry.build_http_app(KEY))
    r = client.post("/api/list_uploads", json={},
                    headers={"Authorization": f"Bearer {KEY}", "Host": "host.docker.internal:1351"})
    assert r.status_code == 200


# ----------------------------------------------------------------- startup


def test_http_mode_refuses_to_start_on_a_malformed_entry(monkeypatch, capsys):
    import uvicorn

    monkeypatch.setenv("GHMCP_API_KEY", KEY)
    monkeypatch.setenv("GHMCP_ALLOWED_HOSTS", "host.docker.internal,*")
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: pytest.fail("server started"))

    with pytest.raises(SystemExit) as exc:
        entry.main(["--http"])

    assert exc.value.code == 2
    assert "GHMCP_ALLOWED_HOSTS: '*'" in capsys.readouterr().err
