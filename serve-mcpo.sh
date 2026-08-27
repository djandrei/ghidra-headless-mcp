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

# mcpo's own default is 0.0.0.0, which puts every tool on the LAN. Loopback is
# the right default for a host-side run; the container overrides this to
# 0.0.0.0 via ENV in the Dockerfile, because binding loopback *inside* a
# container is unreachable through docker's published port. Auth is the lock on
# the door — this decides how many doors there are.
HOST="${MCPO_HOST:-127.0.0.1}"

# One source of truth for "is this key usable": the same require_api_key() the
# native MCP surface calls, so the two cannot drift on what they accept or on
# what they tell you when it is missing.
if ! why="$("$PYTHON" -c '
import sys
from ghmcp import auth
try:
    auth.require_api_key()
except auth.MissingApiKey as exc:
    sys.exit(str(exc))
' 2>&1)"; then
  printf '\n%s\n\n' "$why" >&2
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

exec mcpo --host "$HOST" --port "$PORT" --api-key "$GHMCP_API_KEY" \
  -- "$PYTHON" ghidra_headless_mcp.py
