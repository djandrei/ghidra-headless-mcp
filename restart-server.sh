#!/usr/bin/env bash
# Start or restart ghidra-headless-mcp in its container.
#
# Backs the "GhidraHeadlessMCP: Restart Server" VS Code task, and is fine to run
# by hand. Idempotent: it starts what is stopped and recreates what is running,
# which is what "restart" has to mean for a task you press twice.
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

PORT="${MCPO_PORT:-1341}"
DEADLINE=120

# The host-side `mcpo --port 1341` and this container want the same port, and
# docker's own error for that ("address already in use") never says who holds
# it. Ask docker which port our own service publishes rather than reading the
# listener's process name: docker-proxy runs as root, so an unprivileged `ss`
# prints the socket with no `users:(...)` field at all and a name match sees
# nothing to match on.
mine="$(docker compose port ghidra-headless-mcp 1341 2>/dev/null | head -1 | sed 's/.*://' || true)"
if [ "$mine" != "$PORT" ] && [ -n "$(ss -ltnH "sport = :$PORT" 2>/dev/null)" ]; then
  echo "Port $PORT is held by something other than this container:"
  ss -ltnpH "sport = :$PORT" 2>/dev/null | sed 's/^/  /'
  echo
  echo "Usually that is a host-side"
  echo "  mcpo --port $PORT -- python ghidra_headless_mcp.py"
  echo "(no pid shown means the socket belongs to another user, typically root.)"
  echo "Stop it, or set MCPO_PORT in .env to move the container elsewhere."
  exit 1
fi

echo "Building and (re)starting the container..."
docker compose up -d --build --force-recreate

# Poll rather than sleep: the build is cached and usually instant, but a changed
# requirements.txt makes this take a while, and a fixed sleep would be wrong in
# both directions.
echo -n "Waiting for the OpenAPI schema on :$PORT"
for _ in $(seq "$DEADLINE"); do
  if curl -fsS -o /dev/null "http://127.0.0.1:$PORT/openapi.json" 2>/dev/null; then
    # One operationId per operation, and mcpo gives every tool exactly one POST.
    # grep -c would count *lines*, and the whole schema is a single line.
    tools="$(curl -fsS "http://127.0.0.1:$PORT/openapi.json" | grep -o '"operationId"' | wc -l)"
    echo
    echo
    echo "ghidra-headless-mcp is up — $tools tools."
    echo "  from the host          http://127.0.0.1:$PORT"
    echo "  from OpenWebUI         http://host.docker.internal:$PORT"
    echo "  binary paths           /workspaces/building-agentic-re/... (valid on both sides)"
    exit 0
  fi
  echo -n "."
  sleep 1
done

echo
echo "No schema after ${DEADLINE}s. Container state and logs:"
docker compose ps
docker compose logs --tail 40
exit 1
