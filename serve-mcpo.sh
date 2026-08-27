#!/usr/bin/env bash
# Start the mcpo (HTTP/OpenAPI) surface with bearer authentication.
#
# This exists so the mcpo surface fails closed. `mcpo --api-key` is optional as
# far as mcpo is concerned, and a missing key there means "serve everything to
# everyone" — including run_ghidra_script, which executes arbitrary Ghidra
# scripts. Refusing to start is the better default, so the key is checked here
# before mcpo is execed.
#
# It is the container's CMD and is equally fine to run by hand on the host.
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

PORT="${MCPO_PORT:-1341}"
PYTHON="${PYTHON:-python}"

# mcpo sits next to the interpreter in a venv but on PATH in the container, so
# look beside $PYTHON first and fall back to PATH. Hardcoding either one breaks
# the other, and `mcpo: not found` from an exec is a poor way to learn that.
if [ -z "${MCPO:-}" ]; then
  _bindir="$(dirname "$PYTHON")"
  if [ -x "$_bindir/mcpo" ]; then MCPO="$_bindir/mcpo"; else MCPO="mcpo"; fi
fi

# mcpo's own default is 0.0.0.0, which puts every tool on the LAN. Loopback is
# the right default for a host-side run; the container overrides this to
# 0.0.0.0 via ENV in the Dockerfile, because binding loopback *inside* a
# container is unreachable through docker's published port. Auth is the lock on
# the door — this decides how many doors there are.
HOST="${MCPO_HOST:-127.0.0.1}"

# One source of truth for both "is this key usable" and "what is it": the same
# require_api_key() the native MCP surface calls, which also reads .env when the
# variable is not exported. So one .env serves compose, a host run and the
# devcontainer alike, and the shell needs no parser of its own.
err="$(mktemp)"
if KEY="$("$PYTHON" -c '
import sys
from ghmcp import auth
try:
    sys.stdout.write(auth.require_api_key())
except auth.MissingApiKey as exc:
    sys.exit(str(exc))
' 2>"$err")"; then
  rm -f "$err"
else
  printf '\n%s\n\n' "$(cat "$err")" >&2
  rm -f "$err"
  exit 2
fi

# --api-key protects the tool endpoints. /openapi.json and /docs stay readable
# without it, deliberately: the compose healthcheck and restart-server.sh both
# poll the schema, and the tool *surface* is not the thing being protected —
# the ability to *call* it is. `--strict-auth` would cover them too, at the
# cost of both of those needing the token.
#
# The key reaches mcpo on its command line because mcpo reads no environment
# variable for it. That makes it visible in `ps` to other users on the same
# host; see the README's Limitations.
if [ "$HOST" != "127.0.0.1" ] && [ "$HOST" != "localhost" ] && [ "$HOST" != "::1" ]; then
  echo "note: binding $HOST, not loopback — reachable beyond this machine." >&2
fi

exec "$MCPO" --host "$HOST" --port "$PORT" --api-key "$KEY" \
  -- "$PYTHON" ghidra_headless_mcp.py
