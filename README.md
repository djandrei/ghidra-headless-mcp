# ghidra-headless-mcp

An MCP server that exposes Ghidra's **headless analyzer** as tools. Unlike
GhidraMCP or `pyghidra-mcp`, it needs no running Ghidra GUI and no bridge
plugin — only a Ghidra install on disk.

## Why it is shaped this way

`analyzeHeadless` is a batch tool: every invocation cold-starts a JVM. A naive
server that re-analysed the binary per tool call would take minutes per
question. So the work is split in two:

| Phase | Tool | Cost | What runs |
|---|---|---|---|
| **Analyse once** | `analyze_binary` | seconds to minutes | `-import` + full auto-analysis, saved into a persistent project |
| **Query many times** | everything else | ~3 s each | `-process -noanalysis -readOnly` + a postScript that dumps JSON |

`ghidra_scripts/HeadlessJsonExport.java` is that postScript. Ghidra compiles
`.java` scripts on the fly, so there is no build step. It writes JSON to a file
the server passes in — never to stdout, which belongs to the JSON-RPC transport.

## Install

```bash
uv pip install -r requirements.txt
```

Configuration is by environment variable, matching the course's other
Ghidra-backed servers:

| Variable | Default | Meaning |
|---|---|---|
| `GHIDRA_INSTALL_DIR` | auto-detected | Ghidra root containing `support/analyzeHeadless`. Probes `/ghidra` (devcontainer), `~/bin/ghidra_*`, `/opt/ghidra*`. |
| `PROJECT_LOCATION` | `./projects` | Where the Ghidra project lives. |
| `PROJECT_NAME` | `headless-mcp` | Project name. |
| `ANALYZE_TIMEOUT_S` | `1800` | Timeout for `analyze_binary`. |
| `QUERY_TIMEOUT_S` | `600` | Timeout for every other tool. |

## Run

```bash
# stdio, for an MCP client that spawns it directly. No key needed.
python ghidra_headless_mcp.py

# HTTP/OpenAPI for OpenWebUI or notebook `requests` calls, on 1341
export GHMCP_API_KEY=...   # or put it in .env; see Authentication
./serve-mcpo.sh

# native MCP over streamable-http for an MCP client that connects, on 1351
python ghidra_headless_mcp.py --http
```

Both HTTP forms **require `GHMCP_API_KEY` and refuse to start without one** —
see **Authentication** below. `serve-mcpo.sh` is the wrapper that enforces that
and then runs the `mcpo --port 1341 -- python ghidra_headless_mcp.py` this used
to document; calling mcpo directly still works but leaves the port open to
anyone who can reach it.

**Port 1341** is chosen because 1337–1340 are taken by the course notebooks
(see the port map in the workspace `CLAUDE.md`). **1351** is the native MCP
port, matching `opencode/opencode.json`.

## Authentication

Every HTTP surface requires a bearer token and **refuses to start without
one**. stdio does not and cannot: there the client spawns the process, so it
already has whatever the process has and a token would check the caller against
itself.

The reason to fail closed rather than warn is `run_ghidra_script`, which
executes arbitrary Ghidra scripts against any program in the project. An
unauthenticated port serving that is remote code execution wearing an OpenAPI
schema.

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'   # generate
echo 'GHMCP_API_KEY=<the key>' >> .env                          # .env is gitignored
```

`GHMCP_API_KEY` is the only secret, and both surfaces read it, so there is one
token to distribute and one to rotate. Rotating it means restarting the server;
nothing caches it.

**`.env` is enough everywhere.** compose reads it by itself, and for a host or
devcontainer run `require_api_key()` falls back to reading the same file, so the
key does not also have to be exported in whatever shell starts the server —
which is how a file and an export drift apart. It is parsed, never sourced:
`.env` is compose's format, not a shell script, and sourcing it to read one
variable would run whatever else it contains. An exported variable still wins.

| Surface | Started by | Auth |
|---|---|---|
| stdio | `python ghidra_headless_mcp.py` | none — the client spawned it |
| mcpo, HTTP/OpenAPI, :1341 | `./serve-mcpo.sh` (the container's CMD) | mcpo `--api-key` |
| native MCP, streamable-http, :1351 | `python ghidra_headless_mcp.py --http` | `BearerAuthMiddleware` |

```bash
curl -X POST http://127.0.0.1:1341/list_programs \
  -H "Authorization: Bearer $GHMCP_API_KEY" \
  -H 'Content-Type: application/json' -d '{}'
```

`--http` is the surface `opencode/opencode.json` points at, which is why it
defaults to **1351** — mcpo holds 1341 and the two normally run together. It
serves MCP at `/mcp` and takes `--host` / `--port` (or `GHMCP_HTTP_HOST` /
`GHMCP_HTTP_PORT`).

**The schema is deliberately public; the tools are not.** `/openapi.json` and
`/docs` answer without a token, and so does `/healthz` on the native surface, so
the compose healthcheck and `restart-server.sh`'s schema poll keep working
untouched. What is protected is the ability to *call* a tool, not the ability to
read that one exists. `mcpo --strict-auth` covers the schema too if you want
that; both of those pollers then need the token.

**Both surfaces now bind loopback by default.** mcpo's own default is `0.0.0.0`,
which puts all 31 tools on the LAN, so `serve-mcpo.sh` passes `--host 127.0.0.1`
unless `MCPO_HOST` says otherwise. The container sets `MCPO_HOST=0.0.0.0`
because binding loopback *inside* a container makes docker's published port
unreachable — confinement there is compose's `ports:`, which publishes only to
127.0.0.1 and the docker bridge. A token is the lock on the door; the bind
address decides how many doors there are, and neither substitutes for the other.

### Registering an authenticated client

- **OpenWebUI** — the tool server's entry takes a bearer token; paste the key
  there alongside `http://host.docker.internal:1341`. A registered server whose
  key is wrong still appears in the integrations panel and simply loads no
  tools, exactly as a dead port does, so the panel is no evidence either way.
- **OpenCode** — `opencode.json`'s `mcp` entries take a `headers` object:
  `"headers": {"Authorization": "Bearer <key>"}` next to the `url`. That file is
  tracked in the workspace repo, so put the key in it only if you are content
  for it to be committed — otherwise keep that entry pointing at a loopback port
  and rely on the bind address.
- **Notebook `requests`** — add the header to the session, not to each call:
  `s.headers["Authorization"] = f"Bearer {os.environ['GHMCP_API_KEY']}"`.

### What this does not do

- **The key is visible in `ps`.** mcpo reads no environment variable for it, so
  `serve-mcpo.sh` has to pass `--api-key` on the command line, where any other
  user on the host can read it out of the process list. The native `--http`
  surface takes the key from the environment and does not have this problem. On
  a single-user workstation it does not matter; on a shared host, prefer
  `--http`.
- **One shared token, no identities.** There are no per-client keys, no scopes
  and no revocation short of rotating the one key and restarting. Every
  authenticated caller can do everything, writes and `run_ghidra_script`
  included. This is authentication, not authorization.
- **No transport encryption.** The token crosses the wire in a header, so it is
  only as private as the link. Over loopback and the docker bridge that is
  fine; anywhere else, terminate TLS in front of it (mcpo takes
  `--ssl-certfile` / `--ssl-keyfile`).
- **No rate limiting or lockout.** A 43-character `token_urlsafe` key is not
  brute-forceable, which is why `require_api_key` refuses anything under 16
  characters rather than trusting you to pick well.
- **Tool arguments are unchanged.** No tool takes a token, and none should:
  authentication belongs at the transport, where it can refuse a request before
  the tool layer is entered at all.

## Run in Docker

The course devcontainer already carries everything this server needs — Ghidra
12.0.4 at `/ghidra`, Java 21, Python 3.13 — so it runs there as happily as on
the host. `compose.yaml` starts it as a **sidecar** to that devcontainer rather
than inside it, because `claude/` is not mounted into the course container and
the course clone is read-only, so its `devcontainer.json` is not ours to edit.

```bash
# GHMCP_API_KEY must be in .env first — compose refuses to start without it.
docker compose up -d --build
curl -s http://127.0.0.1:1341/openapi.json | head -c 80   # schema: no token
```

The point of doing this is not packaging, it is **paths**. The clone is mounted
at the same `/workspaces/building-agentic-re` the devcontainer uses, so one
binary path is now valid on both sides:

```bash
curl -X POST http://127.0.0.1:1341/analyze_binary \
  -H "Authorization: Bearer $GHMCP_API_KEY" -H 'Content-Type: application/json' \
  -d '{"binary_path": "/workspaces/building-agentic-re/exercises/ai-assisted-re/assets/crackme2.x86_64"}'
```

The same path works in OpenWebUI's code interpreter, which is what made
host-versus-container path labelling necessary while this ran on the host.

| Concern | How compose settles it |
|---|---|
| **Ghidra version** | The image is the devcontainer's own, so 12.0.4 — not the host's 12.1.2. |
| **Projects** | `PROJECT_LOCATION=/projects`, bind-mounted from `./projects-docker`. Kept apart from `./projects`, which 12.1.2 wrote and 12.0.4 cannot open. |
| **File ownership** | Runs as `ghidra`, uid/gid 1000, matching the host account. Files in `./projects-docker` come back owned by you. |
| **Project owner** | Set `PROJECT_NAME=headless-mcp-docker` in `.env`. `./projects-docker` is also where the devcontainer's copy keeps its project (`GhidraHeadlessMCP: Restart Server` there runs as `vscode`), and Ghidra records the *username* that created a project and refuses every other one: `NotOwnerException: Project is owned by vscode`. The shared uid does not help — Ghidra checks the name, not the file mode. A separate name gives this container a project of its own in the same directory; binaries imported through one copy are not visible to the other. |
| **Reachability** | Published on `127.0.0.1` and on the docker bridge gateway, so both host tools and the devcontainer can reach it — but nothing on the LAN can. mcpo binds `0.0.0.0` *inside* the container (`MCPO_HOST`), which it must for a published port to work; compose's `ports:` is what confines it. `run_ghidra_script` executes arbitrary Ghidra scripts; this server does not belong on the LAN. |
| **The key** | `GHMCP_API_KEY` is passed through from `.env` with no default, so compose fails by name rather than starting an unauthenticated server. |
| **Editing** | The source is bind-mounted over the baked-in copy. `docker compose restart` picks up an edit; only a `requirements.txt` change needs `--build`. |

`restart-server.sh` wraps the start: it refuses to fight a host-side `mcpo` for
port 1341 and says which process holds it, then polls for the schema instead of
sleeping. The workspace's VS Code window exposes it as the task
**GhidraHeadlessMCP: Restart Server**, alongside *Stop Server* and *Server Logs*
(`../../../.vscode/tasks.json`). Those tasks run on the host: the course
devcontainer has neither the docker CLI nor `/var/run/docker.sock`, so it cannot
start this container itself.

Register it in OpenWebUI as **`http://host.docker.internal:1341`** — OpenWebUI
runs in the devcontainer, so `localhost` there is not this container.

To get the same task inside the *devcontainer's* window instead, the server has
to run there as a process rather than in this container, which takes two edits
to the course clone: see `../ghidra_headless_mcp_devcontainer_task.md`.

Copy `.env.example` to `.env` to move the port, point at a clone elsewhere, or
correct the bridge address if `ip -4 addr show docker0` disagrees with
`172.17.0.1`.

Tests run in the container too, and the image already has pytest:

```bash
docker compose exec ghidra-headless-mcp python -m pytest -q                 # unit
docker compose exec ghidra-headless-mcp python -m pytest -m integration -q  # real Ghidra
```

Sample paths in `tests/conftest.py` follow the same rule as the server: the
workspace layout when this repo sits under `claude/mcp-servers/`, the mounted
`/workspaces/building-agentic-re` when it does not, and `COURSE_CLONE` when you
say so outright.

**Running both copies at once does not work** — the host-side `mcpo --port 1341`
and this container want the same port. Stop one first.

### Two images: course-matched, or purpose-built

| | `Dockerfile` (default) | `Dockerfile.slim` |
|---|---|---|
| Base | `ghcr.io/clearbluejar/ghidra-python` | `eclipse-temurin:21-jdk` |
| Ghidra | **12.0.4** — identical to the course devcontainer | **12.1.3**, pinned by sha256 |
| Size | 5.01 GB | **1.84 GB** |
| Carries | SDKMAN, gradle, maven, ant, nvm, node, pipx, Jupyter | a JDK, a Python, Ghidra |
| Build | `docker build -t ghidra-headless-mcp:local .` | `docker build -f Dockerfile.slim -t ghidra-headless-mcp:12.1.3 .` |

Both run as `ghidra` at uid/gid 1000 and behave identically: when the slim image
was added, **all 650 unit and 170 integration tests passed on each**. The suite
has grown since (`upload_binary`); it has been re-run on the default image only.

Pick the default when a project has to be interchangeable with the course
devcontainer. Pick the slim one otherwise — it is a third the size, tracks the
current Ghidra, and contains nothing a headless analyzer does not use. Ghidra
projects are **not portable across versions**, so a `/projects` volume created by
one image cannot be reused by the other; re-import the binaries instead.

The slim image installs Python packages into a venv at `/opt/venv` (PEP 668 marks
the distro Python externally managed) and drops the base account's supplementary
groups — Ubuntu's `ubuntu` user at uid 1000 is renamed to `ghidra`, and `sudo`,
`adm` and the rest go with it.

Three directories Ghidra ships are removed, taking `/ghidra` from 847 MB to
590 MB and the image to 1.84 GB:

| Removed | Size | What it is |
|---|---|---|
| `docs/` | 112 MB | javadoc zip, IDE typestubs, the bundled training course |
| `Extensions/` | 100 MB | ten packaged-but-**not-installed** extension `.zip`s (Jython, MachineLearning, SleighDevTools…), plus Eclipse and IDA Pro plugins |
| `Ghidra/Debug/` | 81 MB | the interactive debugger — 67 MB of it the dbgeng Python bridge for attaching to live Windows processes |

None is reachable from a static analyzer: this server imports a file and answers
questions about the result, and none of its 31 tools launches or attaches to
anything. That reasoning was **checked rather than trusted** — the trim was made
in a separate tag and the full 170-test integration suite run against it before it
became the default. Re-run that suite before trimming anything further; Ghidra's
module system is interconnected enough that the next guess may not be free.

#### Running the integration suite in a container

The samples must be on a **writable** filesystem. Ghidra writes a `.lock` file
*next to* a `.gzf` while importing it, so a course clone mounted `:ro` fails with
`IOException: Read-only file system` followed by `FileInUseException` — and
`import_packed` then reports an empty project rather than an import error, which
looks exactly like a Ghidra version incompatibility and is not one. Copy the
assets in rather than relaxing the mount:

```bash
docker run --rm \
  -v "$COURSE_CLONE:/src-clone:ro" -v "$PWD:/srv/src:ro" \
  --tmpfs /projects:uid=1000,gid=1000,size=6g \
  --tmpfs /work:uid=1000,gid=1000,size=6g \
  -e COURSE_CLONE=/work/clone \
  --entrypoint sh ghidra-headless-mcp:12.1.3 -c '
    for d in starters ai-assisted-re multi-binary-analysis; do
      mkdir -p /work/clone/exercises/$d
      cp -r /src-clone/exercises/$d/assets /work/clone/exercises/$d/
    done
    cp -r /srv/src /work/code && cd /work/code && python3 -m pytest -q -m integration'
```

## Getting a binary to the server

`analyze_binary` and `analyze_binaries` take a **path**, and the only check is
that it resolves to a file *in the server's own filesystem* — the server's path,
never the host's. So a binary has to be somewhere the server can read before it
can be analysed. There are two ways to get it there: send it through the tool
surface with `upload_binary`, or put it in a directory the server already sees.

The file only has to exist for the import. Ghidra copies the bytes into the
project, so the source can be deleted afterwards and every tool still answers
for the program.

### `upload_binary`: through the tool surface

The one route an agent can take on its own, with no shell on the server's side:

```
upload_binary(filename="crackme.x86_64", content_base64="f0VMRgIBAQ…", analyze=True)
→ {"path": "/projects/samples/crackme.x86_64", "size": 15984, "sha256": "…",
   "written": true, "analysis": {"program": "crackme.x86_64", …}}
```

| Rule | Why |
|---|---|
| Lands in **one directory**: `UPLOAD_DIR`, default `<PROJECT_LOCATION>/samples` — `/projects/samples` in the container, `projects-docker/samples/` on the host | The only writable place every deployment shares; the course clone is read-only. `projects/` and `projects-docker/` are gitignored, so a sample cannot be committed by accident. |
| `filename` is a **bare name**. Path separators, NUL and a leading `.` are refused; characters outside `[A-Za-z0-9._+-]` become `_` | `../../etc/x` is an attempt to choose a directory, so it fails loudly rather than being quietly flattened. |
| Capped at **`MAX_UPLOAD_BYTES`**, 4 MiB by default, checked before decoding | The bytes pass through the model's context first, as base64 — 4 characters per 3 bytes, and base64 tokenises poorly. Fine for a crackme, wasteful for a DLL. |
| Stored **non-executable** (mode 644), written to a temp file and renamed into place, never through a symlink | Samples are analysed, never run, and a reader never sees half a file. |
| Same name, same content: nothing is written. Same name, different content: refused unless `overwrite=True`, which also re-analyses when `analyze=True` | Re-sending is safe; silently replacing a sample is not. |

This adds no new kind of access. Every HTTP surface already demands
`GHMCP_API_KEY`, and `run_ghidra_script` already runs arbitrary code; the upload
writes data into one directory and nothing else.

For anything larger than a few hundred KB, copy the file in instead: that keeps
it out of the model's context entirely.

### Copying a file in

What the compose container can read:

| Container path | Backed by | Use it for |
|---|---|---|
| `/workspaces/building-agentic-re/…` | the course clone, **read-only** | course samples in `exercises/*/assets/`; OpenWebUI chat uploads (below) |
| `/projects/…` | `./projects-docker`, read-write, gitignored | binaries you want to keep — put them in `projects-docker/samples/`, where `upload_binary` writes too, so they stay apart from Ghidra's project files |
| `/tmp/…` | the container's own filesystem | one-off imports via `docker cp`; gone when the container is recreated |
| `/srv/ghidra-headless-mcp/…` | this directory | readable, but tracked by git — keep samples out of it |

**`docker cp`** leaves nothing behind on the host:

```bash
docker cp ./sample.bin ghidra-headless-mcp:/tmp/sample.bin
# analyze_binary(binary_path="/tmp/sample.bin")
docker exec -u root ghidra-headless-mcp rm /tmp/sample.bin   # optional, see above
```

`docker cp` writes the file as root. `ghidra` can read it but not delete it from
the sticky `/tmp`, hence `-u root` on the cleanup.

**OpenWebUI chat attachments** are already reachable. OpenWebUI stores them in
the clone's `.openwebui-data/uploads/` as `<uuid>_<filename>` (gitignored by the
course repo), which is
`/workspaces/building-agentic-re/.openwebui-data/uploads/` in this container and
in the devcontainer alike. The model needs the full name, uuid included —
`container-workspace-mcp`'s `find_files` will find it.

The other two ways of running the server see different filesystems:

- **Devcontainer copy** (`GhidraHeadlessMCP: Restart Server` in the course
  window): everything under `/workspaces/` — the clone, `capstone`, the three
  MCP server directories — plus the devcontainer's own `/tmp`
  (`docker cp sample.bin <devcontainer>:/tmp/`).
- **On the host** (stdio or `serve-mcpo.sh`): any host path. This is the one
  arrangement where a prompt has to say which namespace its paths belong to.

Samples are analysed, never executed. Nothing here runs the binary, and nothing
should: keep malware in `.gzf` form, as the course does with Vidar.

## Tools

31 tools, at parity with GhidraMCP and pyghidra-mcp on everything that does not
require a GUI, and past both on project scope: several tools answer for the
whole project in one JVM start, and `resolve_symbol` links a symbol across
binaries — something neither of them offers. See `../ghidra_mcp_api_reference.md` for the comparison and
`../ghidra_headless_mcp_roadmap.md` for how they were staged.

**Project**

| Tool | Returns |
|---|---|
| `upload_binary(filename, content_base64, overwrite, analyze)` | Stores a binary sent as base64 in the upload directory, returning the path to import it from. `analyze=True` imports it too. See *Getting a binary to the server*. |
| `analyze_binary(binary_path, force, processor, cspec, max_cpu)` | Import + auto-analyse. `processor`/`cspec` override detection for raw firmware. Skips work if already analysed unless `force`. |
| `analyze_binaries(paths, force, recursive, processor, cspec, max_cpu)` | The same for many binaries, or a directory, in **one** import run. How you load a program together with its libraries. |
| `list_programs(refresh)` | Program names. `refresh=True` asks Ghidra itself, finding programs imported elsewhere and repairing the index. |
| `get_program_info(program)` | Hashes, architecture, image base, function/symbol counts, memory blocks. |
| `list_memory_blocks(program)` | Section map with read/write/execute permissions. |
| `delete_program(program)` | Removes a program, its cache and its index entry. |

**Reading**

| Tool | Returns |
|---|---|
| `list_functions(program, pattern, limit, offset, …)` | Paged function list with signatures; `pattern` is a regex applied inside Ghidra. |
| `decompile_function(program, function)` | Decompiled C, by name or entry-point address. |
| `disassemble(program, target, count, include_bytes)` | Aligned listing for a function body, or N instructions from any address. |
| `read_bytes(program, address, size)` | Raw bytes as hex plus a printable rendering. |
| `list_strings(program, pattern, min_length, limit, offset)` | Defined strings with addresses. |
| `list_symbols(program, kind, pattern, limit, offset)` | Imports, exports, data, classes, namespaces, labels or functions. |
| `list_symbols_project(kind, pattern, programs, limit, offset)` | The same inventory across **every binary in the project**, one JVM start. |
| `resolve_symbol(name, programs)` | Traces a symbol across binaries: who imports it, who forwards it, where the implementation lives. Follows apiset redirection. |

**Graph**

| Tool | Returns |
|---|---|
| `list_xrefs_to(program, target, limit, offset)` | Who references a function, symbol or address. Batched over targets **and programs**; each hit names its containing function. |
| `list_xrefs_from(program, target, limit, offset)` | What a function or address references. A function target sweeps its whole body. |
| `get_function_at(program, address)` | The function at, or containing, an address. |
| `gen_callgraph(program, function, direction, depth, max_nodes)` | MermaidJS call graph, callers or callees. |

**Search**

| Tool | Returns |
|---|---|
| `search_code(program, query, mode, limit, context, refresh)` | Searches decompiled C: `literal` regex or `semantic` ranking. |
| `search_code_project(query, programs, mode, limit, context, refresh)` | The same search across **every binary in the project** at once. `programs` defaults to all. `limit` is per program. |
| `search_memory(program, text, hex, limit)` | Scans the raw bytes, not what the analyser defined. `text` is tried as ASCII, UTF-16LE and UTF-16BE; `hex` takes a byte pattern. Each hit names its encoding, block and containing function. |
| `clear_code_cache(program)` | Drops the cached decompilation so the next search rebuilds it. |

**Writing** — these persist to the program database

| Tool | Returns |
|---|---|
| `apply_edits(program, edits)` | Applies many edits in one JVM start. The primitive the singles wrap. |
| `rename_function(program, target, new_name)` | Records what a function does. |
| `rename_variable(program, function, variable, new_name)` | Works on decompiler-synthesised locals too. |
| `rename_data(program, address, new_name)` | Names a global; creates the label if absent. |
| `set_function_prototype(program, target, prototype)` | Fixes a signature, improving every caller's decompilation. |
| `set_variable_type(program, function, variable, type)` | Applies a type to a parameter or local. |
| `set_comment(program, address, comment, comment_type)` | decompiler / pre / eol / post / plate / repeatable. |
| `run_ghidra_script(program, script_name, script_args, stage, read_only)` | Escape hatch onto Ghidra's ~190 bundled scripts. |

### Batch where you can

Every call cold-starts a JVM (~3 s). `apply_edits` applies 200 renames in one
start where 200 single calls take minutes, and `list_xrefs_to` / `list_xrefs_from`
accept a list of targets. Edits and xref targets are isolated: one failure
reports at its index and the rest still succeed.

### Project scope

Several tools answer for the whole project rather than one binary, in a single
JVM start. `search_code_project`, `list_symbols_project`, and `list_xrefs_to` /
`list_xrefs_from` when `program` is a list or `"*"`.

Measured on the four Windows DLLs from the course's multi-binary exercise:
**3.8 s for all four against 11.1 s as four single calls, a 2.9x speedup.** The
saving is the JVM start — opening a second program inside a live JVM costs
milliseconds.

`resolve_symbol` goes further than fan-out: it *joins* the results. Given
`notepad.exe` and its DLLs it reports

```
CreateFileW   terminal=KERNELBASE.DLL
   notepad.exe      import                 lib=API-MS-WIN-CORE-FILE-L1-1-0.DLL -> KERNELBASE.DLL
   KERNEL32.DLL     export,import,function lib=API-MS-WIN-CORE-FILE-L1-1-0.DLL -> KERNELBASE.DLL
   KERNELBASE.DLL   export,function                                               TERMINAL
   absent from: NTDLL.DLL
```

in **one call, 3.0 s**. Exporting *and* importing a name is what identifies
kernel32 as a forwarder; exporting without importing is what identifies
kernelbase as the implementation. Apiset libraries name a DLL no binary
provides, so the bare export name is matched against the project instead and
every such hop is recorded in `notes` rather than presented as fact. Where two
binaries both qualify, it says so instead of picking.

Three properties hold across all of them.

- **Failures are isolated.** A program that cannot be served appears in
  `failures` with its own error; the others still return. Only an argument
  error that is identical for every program — a malformed regex, an unknown
  mode — fails the whole call.
- **`limit` is per program, not across the batch.** A shared cap would let one
  large binary crowd out the rest. Defaults are lower than the single-program
  tools' because output multiplies by the program count.
- **Fan-out is read-only.** A headless run saves only the program it attached
  to, so the write tools stay single-program by design.
- **Single-program output is unchanged.** Passing a plain string to
  `list_xrefs_to` returns exactly what it always did; the per-row `program`
  field appears only when several programs were asked for.

`search_code_project` costs no JVM start of its own: it reads the same
decompilation cache `search_code` builds. The first search of a program still
decompiles it, so fanning out over four never-searched binaries pays that four
times, and every later search is free. `from_cache` on each result says which
happened.

### Response types

Every tool returns a pydantic model from `ghmcp/models.py` rather than a dict,
so the MCP client receives a typed schema and a change in the Java side's output
fails loudly here instead of silently reaching the caller. `clear_code_cache` is
the one exception and returns a bare dict.

| Tool | Returns |
|---|---|
| `analyze_binary` / `analyze_binaries` | `AnalysisResult` / `AnalysisBatchResult` |
| `list_programs` / `get_program_info` | `ProgramList` / `ProgramInfo` |
| `list_memory_blocks` / `delete_program` | `MemoryBlockList` / `DeleteResult` |
| `list_functions` / `get_function_at` | `FunctionList` / `FunctionDetail` |
| `decompile_function` | `Decompilation` or `DecompilationBatch` |
| `disassemble` / `read_bytes` | `Disassembly` / `BytesRead` or `BytesReadBatch` |
| `list_strings` / `list_symbols` | `StringList` / `SymbolList` |
| `list_symbols_project` / `resolve_symbol` | `SymbolListProject` / `SymbolResolution` |
| `list_xrefs_to` / `list_xrefs_from` | `XrefList` |
| `gen_callgraph` | `CallGraph` |
| `search_code` / `search_code_project` | `CodeSearchResults` / `CodeSearchProjectResults` |
| `search_memory` | `MemorySearchResults` |
| `apply_edits` / the six single edit tools | `EditBatchResult` / `EditResult` |
| `run_ghidra_script` | `ScriptResult` |

Four shapes recur, and knowing them is most of knowing the API.

- **Container plus leaf.** A list result carries `total`, `returned` and
  `truncated` around a list of rows: `FunctionList`/`FunctionSummary`,
  `StringList`/`StringHit`, `SymbolList`/`SymbolEntry`,
  `MemoryBlockList`/`MemoryBlock`, `CallGraph`/`CallGraphNode`,
  `CodeSearchResults`/`CodeMatch`, `MemorySearchResults`/`MemoryHit`, and
  `XrefList`/`XrefTargetResult`/`XrefEntry` at three levels. `total` counts
  matches before `limit`/`offset`; `truncated` is a different thing from paging
  — it means more matched than the Java side would emit at all, so paging cannot
  reach every match and the pattern needs narrowing.
- **A union where the tool batches.** `decompile_function` and `read_bytes`
  return the singular model for one target and the `…Batch` model for a list.
  Passing a string returns exactly what it always did.
- **Per-item failure, in the type.** `DecompilationResult`, `BytesReadResult`
  and `EditResult` each carry `error` and `error_kind` beside their success
  fields, so one bad item reports itself and the rest still succeed;
  `EditResult.index` is the batch position, for retrying just that one.
  `XrefTargetResult` does the same per target.
- **`ProgramFailure` for fan-out.** Project-scope results — `XrefList`,
  `SymbolListProject`, `SymbolResolution`, `CodeSearchProjectResults`,
  `AnalysisBatchResult` — carry a `failures` list of these rather than raising,
  so one unanalysed program does not discard every other program's results.

`resolve_symbol`'s triple is the richest of them.
`SymbolResolution` → `SymbolChain` → `SymbolLocation`, where a chain holds
`layers` ordered consumer to implementation, plus `terminal_program`,
`absent_from` and `notes`. `SymbolLocation.roles` is deliberately not exclusive:
exporting *and* importing a name is what identifies a forwarder, exporting
without importing is what identifies the implementation. Anything inferred
rather than read — an apiset hop, an ambiguity left unresolved — goes in `notes`
instead of being presented as fact.

Two fields exist to contradict an assumption Ghidra would otherwise let you
keep. `ScriptResult.exit_code` is analyzeHeadless's, which is 0 even when the
script threw, so `script_error` is the field to check. `Disassembly.skipped_bytes`
says how far the listing jumped over bytes Ghidra never defined as code; when it
is non-zero the listing is not contiguous and `read_bytes` is the way to see
what was passed over.

Errors arrive as typed exceptions, not formatted strings. The Java side's
`{"ok": false, "error": {"kind", "message"}}` envelope maps onto a
`HeadlessError` hierarchy in `ghmcp/errors.py` — `NotFound`, `BadArgument`,
`GhidraError`, `HeadlessTimeout`, `ExportFailure` — and an unrecognised kind
degrades to the base class, so a newer Java side can add kinds without breaking
an older Python side. Over mcpo they arrive nested — see *Limitations*.

## Tests

```bash
pytest                  # 676 unit tests, no JVM, ~15 s
pytest -m integration   # 174 integration tests against real Ghidra, ~12 minutes
```

Almost all of the unit suite's wall time is two tests: `test_projectlock.py`'s
deadline and exclusion cases wait out real timeouts (8 s and 4 s). The other
632 tests finish in 0.8 s — `pytest --ignore=tests/test_projectlock.py` is the
fast inner loop.

Unit tests never spawn a JVM: a fake intercepts `run_headless` and writes an
envelope into the out-file the real code chose, so genuine command
construction and file plumbing are exercised in-process. `test_auth.py`'s 34
cases need no socket either: the middleware is driven as a bare ASGI app, which
is also how they assert the thing that matters most — that an unauthenticated
request never reaches the tool layer at all, rather than reaching it and being
refused. Integration tests are
deselected by default (`pytest.ini`) and run against Ghidra 12.1.2 over four
projects and eight binaries:

| Fixture | Binaries | Why |
|---|---|---|
| the base suite | `starter05.x86_64`, `crackme.x86_64` (ELF x86-64) | single-binary tools, `check_key @ 00401146` as ground truth |
| `test_integration_multiprogram.py` | the same two | fan-out mechanics and the one-JVM-start assertion |
| `test_integration_windows_layering.py` | `notepad.exe` + `KERNEL32`/`KERNELBASE`/`NTDLL` (PE64, 15,218 functions) | the only fixture with a **real cross-binary relationship**; expected values come from NB 15 and from the syscall stub itself |
| `test_integration_mixed_arch.py` | KiTTY (Mach-O arm64), Vidar (PE32 x86), a crackme (ELF x86-64) | three formats and two architectures in one project, so nothing can assume ELF conventions |

The last two skip when their samples are absent — both are untracked in the
course clone. They import pre-analysed `.gzf` with `-noanalysis`, since a packed
program already carries Ghidra's analysis and re-running it on KERNELBASE alone
takes minutes. Write and project tests use their own
projects so they cannot disturb the read-only suite's assertions.

## Limitations, by design

- **An unsupported architecture fails at import, with an explanation.** Ghidra
  ships ~40 processor modules; Alpha, IA-64 and S/390 are not among them.
  analyzeHeadless exits 0 on a failed import, so the log is checked for
  "No load spec found" and the error says so rather than letting a later query
  report a missing program.
- **mcpo nests tool errors.** The real message is in `detail.error`; the
  `detail.message` field just says "Unexpected error". Read the former. A
  missing or wrong bearer token is the exception: mcpo answers 401 and 403
  itself, before a tool runs, with the reason in `detail`.
- **Authentication is one shared token, not identities.** Any authenticated
  caller can do everything, writes and `run_ghidra_script` included, and
  revocation means rotating the key and restarting. The mcpo surface also
  exposes that key in `ps`, since mcpo takes it only as a command-line
  argument. See *Authentication → What this does not do*.
- **Two binaries with the same basename get distinct program names.** Ghidra's
  project cannot hold two programs of one name, so the second is imported as
  `name_<md5prefix>`. `analyze_binary` verifies identity by comparing the file's
  MD5 with the one Ghidra recorded, rather than trusting the name — without
  that check it silently served the wrong program.
- **`list_programs` reads a local index by default** for speed; pass
  `refresh=True` to ask Ghidra itself and repair any drift.
- **Semantic search ranks by TF-IDF, not embeddings.** pyghidra-mcp uses
  ChromaDB; that pulls in onnxruntime and roughly half a gigabyte of
  dependencies, which is a poor trade for a server whose point is needing
  nothing but Ghidra. The response reports which backend ran, and the query
  interface would not change if an embedding backend were added.
- **Edits are isolated, not atomic.** One failure in a batch reports at its
  index and the rest still apply, rather than discarding good work over one
  stale name.
- **`disassemble` lists only *defined* instructions.** Where Ghidra has not
  disassembled the bytes — a computed jump table, inline data — the listing
  resumes at the next defined instruction. `skipped_bytes` says how far it
  jumped; when it is non-zero, use `read_bytes` and decode by hand.
- **Calls are serialised across processes** by an `flock` file beside the
  project, not just by an in-process lock. A single stdio server is not
  guaranteed: a long call can lead to a second one being spawned, and two
  processes racing Ghidra's project lock fail every import until someone
  notices. `PROJECT_LOCK_WAIT_S` bounds the wait.
- **Calls are serialised** by a lock. Ghidra locks a project for the duration
  of a headless run, so concurrent calls would fail rather than queue.
- **A project open in the Ghidra GUI blocks headless access** to it. Use a
  separate `PROJECT_LOCATION` from any project you open interactively.
- **`list_strings` returns *defined* strings**, not what `strings(1)` finds.
  Packed or encrypted regions stay invisible until something defines them.
- **When a string is missing, reach for `search_memory`.** `list_strings` and
  `list_symbols` report what Ghidra's analyser *defined*; length-prefixed wide
  strings (Delphi, VB) and text in undefined data are invisible to both.
  `search_memory` scans the raw bytes in ASCII and UTF-16 instead. It searches
  *loaded memory*, so data in unmapped regions (resources, overlays) is still
  out of reach.
- **`list_symbols(kind="data")` also only sees *defined* data.** A named array
  whose bytes Ghidra never typed is a `label`, not a data item, so it does not
  appear — `kind="label"` finds it. This bites in practice: `ENCODED` is data in
  `crackme2.x86_64` but only a label in `crackme.x86_64`, so the same query
  works on one and returns nothing on the other. When locating a named array,
  either try both kinds or take the address straight out of the decompilation.
- **Auto-analysis is a first pass, not a finished analysis.** Stripped binaries
  come back as `FUN_<address>`; the point of putting this behind MCP is to let a
  model do the iterating a human would otherwise do in the GUI.
- **A packed program is locked where it lies.** Ghidra writes a `.lock` file
  *next to* a `.gzf`/`.gar` while importing it, so one sitting on a read-only
  mount cannot be imported in place — which is exactly the container's case,
  since the course clone is mounted `ro`. `analyze_binary` stages such a file
  into a temporary directory first. Raw binaries load from bytes, take no lock,
  and are imported where they are.
- **Version skew**: the host install is 12.1.2; the devcontainer's and the
  container image's is 12.0.4. Open a project with the version that created it,
  and keep a `PROJECT_LOCATION` per version — which is why the container writes
  to `./projects-docker` and not `./projects`.

## Note on log noise

Runs on this host print `Module manifest file error … Extensions/GhidraMCP/
Module.manifest`. That is a pre-existing problem with the GhidraMCP extension
installed under `~/.config/ghidra/`, unrelated to this server, and harmless —
analysis and scripts complete normally.
