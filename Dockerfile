# ghidra-headless-mcp, containerised.
#
# The base image is the one the course devcontainer runs, so the Ghidra here is
# 12.0.4 — matching the course container rather than the host's 12.1.2. Ghidra
# projects are not portable across versions, which is why PROJECT_LOCATION
# points somewhere other than the repo's own ./projects.
FROM ghcr.io/clearbluejar/ghidra-python:12.0.4ghidra3.13python-bookworm

# The base image's unprivileged account is called `vscode` — a devcontainer
# naming convention with nothing to do with this server, and confusing in a
# container that never involves an editor. Rename it to `ghidra`.
#
# uid/gid stay 1000, so every path the base image already chowned (/ghidra,
# /usr/local/sdkman, /usr/local/py-utils) and anything in a bind- or named volume
# keeps its ownership: only the name attached to the id changes.
#
# NOTE for an existing /projects volume: Ghidra records the creating user in
# `<project>.rep/project.prp` as OWNER and refuses to open a private project
# owned by somebody else (NotOwnerException). A project only this container
# uses can have that value updated to `ghidra`. One the devcontainer's copy
# also opens — it runs as `vscode` over the same ./projects-docker — cannot,
# so give this container its own PROJECT_NAME instead: see README, *Run in
# Docker*, the "Project owner" row.
USER root
RUN groupmod -n ghidra vscode \
 && usermod -l ghidra -d /home/ghidra -m vscode \
 && if [ -f /etc/sudoers.d/vscode ]; then \
      sed -i 's/\bvscode\b/ghidra/g' /etc/sudoers.d/vscode \
      && mv /etc/sudoers.d/vscode /etc/sudoers.d/ghidra; \
    fi

# uv, pinned to the version the course devcontainer ships. The course convention
# is `uv pip`, never bare pip, and the base image carries no uv.
COPY --from=ghcr.io/astral-sh/uv:0.12.3 /uv /uvx /usr/local/bin/

# JAVA_TOOL_OPTIONS mirrors the devcontainer: Ghidra must never reach for a
# display. GHIDRA_INSTALL_DIR is set explicitly rather than left to config.py's
# probe, so a misplaced install fails loudly instead of silently finding another.
# MCPO_HOST overrides serve-mcpo.sh's loopback default: inside a container,
# binding 127.0.0.1 would make docker's published port unreachable. Confinement
# here is compose's `ports:`, which publishes to 127.0.0.1 and the bridge only.
ENV JAVA_TOOL_OPTIONS=-Djava.awt.headless=true \
    PYTHONUNBUFFERED=1 \
    GHIDRA_INSTALL_DIR=/ghidra \
    PROJECT_LOCATION=/projects \
    MCPO_HOST=0.0.0.0

WORKDIR /srv/ghidra-headless-mcp

# Dependencies first: editing the server then does not re-resolve them.
COPY requirements.txt .
RUN uv pip install --system --no-cache -r requirements.txt

# Source is baked in so `docker run` works on its own; compose bind-mounts over
# this for edit-and-restart.
COPY . .

# /projects must be writable by the runtime user. ~/.config/ghidra is Ghidra's
# per-user state — creating it here with the right owner means a named volume
# mounted there inherits that ownership instead of arriving root-owned.
RUN mkdir -p /projects /home/ghidra/.config/ghidra \
 && chown -R ghidra:ghidra /projects /home/ghidra/.config /srv/ghidra-headless-mcp

# uid/gid 1000, the same as the devcontainer's user and the host account, so
# files written into a bind-mounted /projects belong to you and not to root.
USER ghidra

EXPOSE 1341

# serve-mcpo.sh wraps the stdio server as HTTP/OpenAPI with bearer auth,
# exactly as the documented host-side command does. It refuses to start without
# GHMCP_API_KEY. Override with `python ghidra_headless_mcp.py` for a client that
# speaks stdio directly, or `--http` for the native MCP surface on 1351.
CMD ["./serve-mcpo.sh"]
