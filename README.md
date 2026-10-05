# ghidra-headless-mcp

An MCP server that exposes Ghidra's **headless analyzer** as tools. Unlike
GhidraMCP or `pyghidra-mcp`, it needs no running Ghidra GUI and no bridge
plugin — only a Ghidra install on disk.

34 tools: import and auto-analyse binaries, then list, decompile, disassemble,
cross-reference, search and annotate them — one binary at a time or a whole
project of them in a single call.

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

## Requirements

| | Supported | Tested |
|---|---|---|
| Ghidra | 12.x, with the JDK it requires (21) | 12.0.4, 12.1.2, 12.1.3 |
| Python | 3.12+ | 3.12, 3.13, 3.14 |
| OS | Linux; anywhere Ghidra's `analyzeHeadless` runs should work | Linux x86-64 |

Ghidra 12 replaced the integer comment-type constants with a `CommentType` enum,
so Ghidra 11 and earlier will not compile the export script.

## Quick start

```bash
git clone <this repository> && cd ghidra-headless-mcp
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.3_PUBLIC
```

**As a stdio server** — for an MCP client that launches it (no key needed):

```json
{
  "mcpServers": {
    "ghidra-headless": {
      "command": "/path/to/ghidra-headless-mcp/.venv/bin/python",
      "args": ["/path/to/ghidra-headless-mcp/ghidra_headless_mcp.py"],
      "env": { "GHIDRA_INSTALL_DIR": "/path/to/ghidra_12.1.3_PUBLIC" }
    }
  }
}
```

**Over HTTP** — for a client that connects to it. Both HTTP surfaces refuse to
start without a key (see *Authentication*):

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'   # generate a key
echo 'GHMCP_API_KEY=<the key>' >> .env                          # .env is gitignored

./serve-mcpo.sh                                # HTTP/OpenAPI via mcpo, on 127.0.0.1:1341
.venv/bin/python ghidra_headless_mcp.py --http # native MCP (streamable-http), on 127.0.0.1:1351/mcp
```

Then, from the client: `analyze_binary("/path/to/sample")` once, and any other
tool against the program name it returns.

## Configuration

Everything is an environment variable; a host run also reads `GHMCP_API_KEY`
from `.env` beside the server, and compose reads `.env` for all of them.

| Variable | Default | Meaning |
|---|---|---|
| `GHIDRA_INSTALL_DIR` | auto-detected | Ghidra root containing `support/analyzeHeadless`. Probes `/ghidra`, `~/bin/ghidra_*`, `/opt/ghidra*`. |
| `PROJECT_LOCATION` | `./projects` | Where the Ghidra project lives. |
| `PROJECT_NAME` | `headless-mcp` | Project name. |
| `ANALYZE_TIMEOUT_S` | `1800` | Timeout for `analyze_binary`. |
| `QUERY_TIMEOUT_S` | `600` | Timeout for every other tool. |
| `GHMCP_API_KEY` | — | Bearer token; **required** by both HTTP surfaces. |
| `MCPO_HOST` / `MCPO_PORT` | `127.0.0.1` / `1341` | mcpo surface (`serve-mcpo.sh`). |
| `GHMCP_HTTP_HOST` / `GHMCP_HTTP_PORT` | `127.0.0.1` / `1351` | Native MCP surface (`--http`). |
| `UPLOAD_DIR` | `<PROJECT_LOCATION>/samples` | Where `upload_binary` stores files. |
| `MAX_UPLOAD_BYTES` | `4194304` | Largest file `upload_binary` accepts. |
| `OPENWEBUI_UPLOADS_DIR` | course layout, probed | Where `list_chat_uploads` looks for OpenWebUI chat attachments. |
| `PROJECT_LOCK_WAIT_S` | `3600` | How long a call waits for another process holding the project. |

Port 1341 and 1351 are arbitrary; two surfaces normally run side by side, so
they differ.

## Run

```bash
# stdio, for an MCP client that spawns it directly. No key needed.
python ghidra_headless_mcp.py

# HTTP/OpenAPI — for OpenWebUI, scripts using `requests` — on 1341
./serve-mcpo.sh

# native MCP over streamable-http, for an MCP client that connects, on 1351
python ghidra_headless_mcp.py --http
```

`serve-mcpo.sh` is a wrapper around `mcpo --port 1341 -- python
ghidra_headless_mcp.py` that refuses to start without `GHMCP_API_KEY` and binds
loopback; calling mcpo directly still works but leaves the port open to anyone
who can reach it.

## Authentication

Every HTTP surface requires a bearer token and **refuses to start without
one**. stdio does not and cannot: there the client spawns the process, so it
already has whatever the process has and a token would check the caller against
itself.

The reason to fail closed rather than warn is `run_ghidra_script`, which
executes arbitrary Ghidra scripts against any program in the project. An
unauthenticated port serving that is remote code execution wearing an OpenAPI
schema.

`GHMCP_API_KEY` is the only secret, and both surfaces read it, so there is one
token to distribute and one to rotate. Rotating it means restarting the server;
nothing caches it.

**`.env` is enough everywhere.** compose reads it by itself, and for a host run
`require_api_key()` falls back to reading the same file, so the key does not
also have to be exported in whatever shell starts the server — which is how a
file and an export drift apart. It is parsed, never sourced: `.env` is
compose's format, not a shell script, and sourcing it to read one variable
would run whatever else it contains. An exported variable still wins.

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

`--http` serves MCP at `/mcp` and takes `--host` / `--port` (or
`GHMCP_HTTP_HOST` / `GHMCP_HTTP_PORT`).

**The schema is deliberately public; the tools are not.** `/openapi.json` and
`/docs` answer without a token, and so does `/healthz` on the native surface, so
the compose healthcheck and `restart-server.sh`'s schema poll keep working
untouched. What is protected is the ability to *call* a tool, not the ability to
read that one exists. `mcpo --strict-auth` covers the schema too if you want
that; both of those pollers then need the token.

**Both surfaces bind loopback by default.** mcpo's own default is `0.0.0.0`,
which puts all 34 tools on the LAN, so `serve-mcpo.sh` passes `--host 127.0.0.1`
unless `MCPO_HOST` says otherwise. The container sets `MCPO_HOST=0.0.0.0`
because binding loopback *inside* a container makes docker's published port
unreachable — confinement there is compose's `ports:`, which publishes only to
127.0.0.1 and the docker bridge. A token is the lock on the door; the bind
address decides how many doors there are, and neither substitutes for the other.

### Registering an authenticated client

- **OpenWebUI** — the tool server's entry takes a bearer token; paste the key
  there alongside the server's URL (`http://host.docker.internal:1341` when
  OpenWebUI runs in a container on the same host). A registered server whose key
  is wrong still appears in the integrations panel and simply loads no tools,
  exactly as a dead port does, so the panel is no evidence either way.
- **MCP clients over HTTP** (OpenCode and the like) — point them at
  `http://127.0.0.1:1351/mcp` with a header
  `"Authorization": "Bearer <key>"`. Keep the key out of any config file you
  commit.
- **Python `requests`** — add the header to the session, not to each call:
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

```bash
# GHMCP_API_KEY must be in .env first — compose refuses to start without it.
cp -n .env.example .env     # then set GHMCP_API_KEY, and SAMPLES_DIR if needed
docker compose up -d --build
curl -s http://127.0.0.1:1341/openapi.json | head -c 80   # schema: no token
```

Binaries to analyse come from **`SAMPLES_DIR`** on the host (default
`./samples`), mounted read-only at **`SAMPLES_MOUNT`** in the container (default
`/samples`):

```bash
cp ~/Downloads/crackme ./samples/
curl -X POST http://127.0.0.1:1341/analyze_binary \
  -H "Authorization: Bearer $GHMCP_API_KEY" -H 'Content-Type: application/json' \
  -d '{"binary_path": "/samples/crackme"}'
```

Set `SAMPLES_MOUNT` to the path another container already uses for the same
files, and one binary path is valid in both — prompts then never have to say
which filesystem a path belongs to.

| Concern | How compose settles it |
|---|---|
| **Projects** | `PROJECT_LOCATION=/projects`, bind-mounted from `./projects-docker`. Kept apart from `./projects`, which a host-side run uses: Ghidra projects are not portable across versions. |
| **File ownership** | Runs as `ghidra`, uid/gid 1000. Files in `./projects-docker` come back owned by uid 1000 on the host. |
| **Project owner** | Ghidra records the *username* that created a project and refuses every other one (`NotOwnerException`), whatever the file mode says. If another copy of this server, running as a different user, shares `./projects-docker`, give each its own `PROJECT_NAME`. |
| **Reachability** | Published on `127.0.0.1` and on the docker bridge gateway (`DOCKER_BRIDGE_IP`, default `172.17.0.1`), so host tools and other containers can reach it — but nothing on the LAN can. mcpo binds `0.0.0.0` *inside* the container (`MCPO_HOST`), which it must for a published port to work; compose's `ports:` is what confines it. `run_ghidra_script` executes arbitrary Ghidra scripts; this server does not belong on the LAN. |
| **The key** | `GHMCP_API_KEY` is passed through from `.env` with no default, so compose fails by name rather than starting an unauthenticated server. |
| **Editing** | The source is bind-mounted over the baked-in copy. `docker compose restart` picks up an edit; only a `requirements.txt` change needs `--build`. |

`restart-server.sh` wraps the start: it refuses to fight a host-side `mcpo` for
the port and says which process holds it, then polls for the schema instead of
sleeping. Copy `.env.example` to `.env` to move the port, change the samples
mount, or correct the bridge address if `ip -4 addr show docker0` disagrees
with `172.17.0.1`. A host-side `mcpo --port 1341` and this container want the
same port unless `MCPO_PORT` moves one of them.

### Running with Keystone

Keystone — a multi-user web app for AI-assisted RE/VR, in a repository of its
own — is a companion project that uses this server as its Ghidra
backend. Set this one up first; Keystone joins it. With both checked out side by
side:

```
work/
  ghidra-headless-mcp/   this repository — configured and started first
  keystone/              joins its network, shares its samples directory
```

1. Here, in `.env`: a `GHMCP_API_KEY`, and leave `SAMPLES_DIR` at `./samples` —
   Keystone writes each uploaded binary there.
2. `docker compose up -d`. The compose network is named `ghidra-headless-mcp`
   (`GHMCP_NETWORK`); Keystone's worker joins it and calls
   `http://ghidra-headless-mcp:1341`.
3. In Keystone's `infra/.env`, set `KEYSTONE_MCP_API_KEY` to the **same** key,
   then start Keystone as its README says.

Both stacks mount the shared directory at `/samples`, so the path Keystone hands
to `analyze_binary` is the same file here. Keystone needs only the tools it
calls to keep their shape; its README states which version of this server it
was tested against.

### Two images

| | `Dockerfile` (default) | `Dockerfile.slim` |
|---|---|---|
| Base | `ghcr.io/clearbluejar/ghidra-python` | `eclipse-temurin:21-jdk` |
| Ghidra | **12.0.4** | **12.1.3**, pinned by sha256 |
| Python | 3.13 | 3.14 |
| Size | 5.01 GB | **1.84 GB** |
| Carries | SDKMAN, gradle, maven, ant, nvm, node, pipx, Jupyter | a JDK, a Python, Ghidra |
| Build | `docker build -t ghidra-headless-mcp:local .` | `docker build -f Dockerfile.slim -t ghidra-headless-mcp:12.1.3 .` |

Both run as `ghidra` at uid/gid 1000 and pass the full test suite. Pick the
default to share projects with a `ghidra-python`-based devcontainer, such as the
Building Agentic RE course's (see below). Pick the slim one otherwise — it is a
third the size, tracks the current Ghidra, and contains nothing a headless
analyzer does not use. Ghidra projects are **not portable across versions**, so
a `/projects` volume created by one image cannot be reused by the other;
re-import the binaries instead.

The slim image installs Python packages into a venv at `/opt/venv` (PEP 668 marks
the distro Python externally managed) and drops the base account's supplementary
groups — Ubuntu's `ubuntu` user at uid 1000 is renamed to `ghidra`, and `sudo`,
`adm` and the rest go with it.

Three directories Ghidra ships are removed, taking `/ghidra` from 847 MB to
590 MB:

| Removed | Size | What it is |
|---|---|---|
| `docs/` | 112 MB | javadoc zip, IDE typestubs, the bundled training course |
| `Extensions/` | 100 MB | ten packaged-but-**not-installed** extension `.zip`s (Jython, MachineLearning, SleighDevTools…), plus Eclipse and IDA Pro plugins |
| `Ghidra/Debug/` | 81 MB | the interactive debugger — 67 MB of it the dbgeng Python bridge for attaching to live Windows processes |

None is reachable from a static analyzer: this server imports a file and answers
questions about the result, and none of its 34 tools launches or attaches to
anything. That reasoning was **checked rather than trusted** — the trim was made
separately and the full integration suite run against it before it became the
default. Re-run that suite before trimming anything further; Ghidra's module
system is interconnected enough that the next guess may not be free.

## Getting a binary to the server

`analyze_binary` and `analyze_binaries` take a **path**, and the only check is
that it resolves to a file *in the server's own filesystem* — the server's path,
never the client's. So a binary has to be somewhere the server can read before
it can be analysed. Which way depends on where the file is:

| The file is… | Route | Calls |
|---|---|---|
| already readable by the server (a host path, or under `SAMPLES_MOUNT`) | `analyze_binary(path)` | 1 |
| attached to an **OpenWebUI chat** | `list_chat_uploads` → `analyze_binary(path)` | 2 |
| only on the **client's side**, or made during the session | `upload_binary(…, analyze=True)` | 1 |

The file only has to exist for the import. Ghidra copies the bytes into the
project, so the source can be deleted afterwards and every tool still answers
for the program.

### `list_chat_uploads`: a file attached in OpenWebUI

OpenWebUI saves every chat attachment to disk, in its data directory's
`uploads/` as `<uuid>_<filename>`. When the server can see that directory —
set `OPENWEBUI_UPLOADS_DIR` to it — `list_chat_uploads(pattern)` lists it newest
first, with the uuid split off the name, and returns each file's path for
`analyze_binary`:

```
list_chat_uploads(pattern="keycheck")
→ {"uploads": [{"name": "demo_keycheck.aarch64", "size": 70744,
                "path": "/…/uploads/6eb39c47-…_demo_keycheck.aarch64", …}]}
analyze_binary(binary_path=<that path>)   → program "demo_keycheck.aarch64"
```

The program is named after what the user attached, not OpenWebUI's
`<uuid>_` storage name, so later calls use `demo_keycheck.aarch64` rather than
a 50-character id. That applies only to a file directly inside the uploads
directory; a uuid-shaped prefix anywhere else is part of the name. Two
different attachments of the same name get distinct programs, as any other
name clash does; the same attachment twice is recognised by MD5 and not
re-imported.

**Never re-encode an attachment from the chat.** What a model sees of an
attached binary is OpenWebUI's *text extraction* of it — for a 70 KB ELF, about
1,200 characters, a third of them non-ASCII. That is not the file, and no
encoding of it is. A model once spent a whole session base64-ing that text into
`upload_binary`, uploading a 5-byte test stub under the real name, and finally
asking the user to paste base64 by hand — while the file sat in the directory
above. `upload_binary` now names such a payload for what it is and points here,
and both tools' descriptions say so up front. The tool only lists; it never
opens a file.

### `upload_binary`: through the tool surface

The one route an agent can take on its own, with no shell on the server's side:

```
upload_binary(filename="crackme.x86_64", content_base64="f0VMRgIBAQ…", analyze=True)
→ {"path": "/projects/samples/crackme.x86_64", "size": 15984, "sha256": "…",
   "written": true, "analysis": {"program": "crackme.x86_64", …}}
```

| Rule | Why |
|---|---|
| Lands in **one directory**: `UPLOAD_DIR`, default `<PROJECT_LOCATION>/samples` — `/projects/samples` in the container | A writable place every deployment has, while the samples mount is read-only. `projects/` and `projects-docker/` are gitignored, so a sample cannot be committed by accident. |
| `filename` is a **bare name**. Path separators, NUL and a leading `.` are refused; characters outside `[A-Za-z0-9._+-]` become `_` | `../../etc/x` is an attempt to choose a directory, so it fails loudly rather than being quietly flattened. |
| Capped at **`MAX_UPLOAD_BYTES`**, 4 MiB by default, checked before decoding | The bytes travel as base64, 4 characters per 3 bytes. When a model makes the call they pass through its context as well, and base64 tokenises poorly: fine for a crackme, wasteful for a DLL. A program calling the tool pays only the size overhead. |
| Stored **non-executable** (mode 644), written to a temp file and renamed into place, never through a symlink | Samples are analysed, never run, and a reader never sees half a file. |
| Same name, same content: nothing is written. Same name, different content: refused unless `overwrite=True`, which also re-analyses when `analyze=True` | Re-sending is safe; silently replacing a sample is not. |
| `keep=False` (with `analyze=True`) imports the file from a private directory and deletes it in the same call; nothing is left in `UPLOAD_DIR` and the result has no `path` | A client that only wants the program needs no follow-up `delete_upload`, and no lock of its own: no other call can see or remove the file between storing and importing it. |
| Temporary entries (`.upload-*`, `.import-*`) older than twice `ANALYZE_TIMEOUT_S` are removed by the next upload | Every call cleans up after itself; only a process killed outright leaves one, and a `keep=False` import can leave a whole binary. |
| A payload with non-ASCII or control characters is refused as **"not base64"**, with a pointer to `list_chat_uploads` | It is a text rendering of a file, not damaged base64; retrying cannot help. |

`list_uploads` shows what is stored and `delete_upload(filename)` removes one —
a mistaken or test upload, say — under the same bare-name rules, so it can
never reach outside the directory. It removes the file only; `delete_program`
removes what was imported from it.

This adds no new kind of access. Every HTTP surface already demands
`GHMCP_API_KEY`, and `run_ghidra_script` already runs arbitrary code; the upload
writes data into one directory and nothing else. For anything larger than a few
hundred KB, copy the file in instead: that keeps it out of the model's context
entirely.

### Copying a file in

- **Host run**: any path the server's user can read.
- **Container**: put it in `SAMPLES_DIR`, or `docker cp` it in —

  ```bash
  docker cp ./sample.bin ghidra-headless-mcp:/tmp/sample.bin
  # analyze_binary(binary_path="/tmp/sample.bin")
  docker exec -u root ghidra-headless-mcp rm /tmp/sample.bin   # optional, see above
  ```

  `docker cp` writes the file as root. `ghidra` can read it but not delete it
  from the sticky `/tmp`, hence `-u root` on the cleanup.

Samples are analysed, never executed. Nothing here runs the binary, and nothing
should: keep malware in Ghidra's `.gzf` form where you can.

## Tools

34 tools, at parity with GhidraMCP and pyghidra-mcp on everything that does not
require a GUI, and past both on project scope: several tools answer for the
whole project in one JVM start, and `resolve_symbol` links a symbol across
binaries — something neither of them offers. See
[`docs/api-reference.md`](docs/api-reference.md) for the comparison and
[`docs/roadmap.md`](docs/roadmap.md) for how they were staged.

**Project**

| Tool | Returns |
|---|---|
| `list_chat_uploads(pattern, limit)` | Files the user attached in OpenWebUI, already on disk: name, size, and the path to hand `analyze_binary`. The route for a chat attachment — never `upload_binary`. |
| `upload_binary(filename, content_base64, overwrite, analyze, keep)` | Stores a binary sent as base64 in the upload directory, returning the path to import it from. `analyze=True` imports it too; adding `keep=False` deletes the file once imported. See *Getting a binary to the server*. |
| `list_uploads()` / `delete_upload(filename)` | What `upload_binary` has stored; remove one. Files only — `delete_program` removes an imported program. |
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
| `set_function_prototype(program, target, prototype)` | Fixes a signature, improving every caller's decompilation. No calling-convention keyword: the function keeps its convention, and an `unknown` one becomes the compiler default so the decompiler does not warn about locked storage. |
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

Measured on `notepad.exe` and three of the Windows DLLs it loads:
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
pip install -r requirements.txt
pytest                  # 713 unit tests, no JVM, no samples, ~15 s
pytest -m integration   # integration tests against real Ghidra, ~25 minutes
```

**The unit suite runs anywhere** — no Ghidra, no sample binaries. A fake
intercepts `run_headless` and writes an envelope into the out-file the real code
chose, so genuine command construction and file plumbing are exercised
in-process. `test_auth.py`'s cases need no socket either: the middleware is
driven as a bare ASGI app, which is also how they assert the thing that matters
most — that an unauthenticated request never reaches the tool layer at all,
rather than reaching it and being refused. Almost all of the wall time is
`test_projectlock.py` waiting out real deadlines; `pytest
--ignore=tests/test_projectlock.py` is the fast inner loop.

**The integration suite needs Ghidra**, and analyses binaries built from the
C sources in `tests/fixtures/src` and committed beside them — see
[`tests/fixtures/README.md`](tests/fixtures/README.md). They cover four formats
in five projects:

| Module | Fixtures | Why |
|---|---|---|
| `test_integration.py`, `…_edits.py`, `…_upload.py` | `keycheck.x86_64` (ELF x86-64) | single-binary tools, with `check_key @ 00401176` as ground truth |
| `test_integration_multiprogram.py`, `…_project.py` | `keycheck.x86_64`, `crackme.x86_64` | fan-out mechanics and the one-JVM-start assertion |
| `test_integration_mixed_arch.py` | `sample-macho.gzf` (Mach-O arm64), `sample-pe32.exe.gzf` (PE32 i386), `crackme.x86_64` | three formats and two architectures in one project, so nothing can assume ELF conventions |
| `test_integration_chain.py` | `chainapp.exe` → `chainfwd.dll` → `chainimpl.dll` (PE32+) | `resolve_symbol` across a real import → forwarder → implementation chain |

The packed fixtures are pre-analysed `.gzf`, imported with `-noanalysis` as one
imports a Ghidra database. Write and project tests use their own projects so
they cannot disturb the read-only suite's assertions. A read-only samples
directory is fine: Ghidra writes a `.lock` file *next to* a `.gzf` while
importing it, so the tests stage such files into a temp directory first, as
`analyze_binary` does.

**One module needs more than fixtures can give.**
`test_integration_windows_layering.py` checks the same join on the real
`notepad.exe`, `KERNEL32`, `KERNELBASE` and `NTDLL` (PE64, 15,218 functions):
apiset redirection, the syscall stub, the scale. Those binaries are Microsoft's
and cannot be redistributed; the tests find them through `COURSE_CLONE`, a
checkout of the *Building Agentic RE* course that downloads them, and **skip**
without it.

CI runs both suites: the unit suite on Python 3.12, 3.13 and 3.14, and the
integration suite inside the slim image.

In a container:

```bash
docker compose exec ghidra-headless-mcp python -m pytest -q                 # unit
docker compose exec ghidra-headless-mcp python -m pytest -m integration -q  # real Ghidra
```

or, for an image with no compose service — the slim one, say — mount the
source read-only and work on a copy (this is what CI does):

```bash
docker build -f Dockerfile.slim -t ghidra-headless-mcp:12.1.3 .
docker run --rm -v "$PWD:/src:ro" \
  --tmpfs /work:uid=1000,gid=1000,size=4g \
  --tmpfs /projects:uid=1000,gid=1000,size=4g \
  --entrypoint sh ghidra-headless-mcp:12.1.3 -c \
  'cp -r /src /work/code && cd /work/code && python3 -m pytest -q -m integration'
```

Add `-v "$COURSE_CLONE:/course:ro" -e COURSE_CLONE=/course` to include the
Windows-layering module.

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
- **A decompiler comment shows only on an address that becomes a statement.**
  `set_comment(..., "decompiler")` stores the comment wherever it is put, but the
  decompiler prints comments beside the statements their address produces. An
  instruction that produces none — the `endbr64` modern gcc puts at every
  function's entry, most prologue — keeps its comment invisible in the C. To
  annotate a function as a whole use `plate`; to annotate a line, use the
  address of an instruction in it (a call, a store).
- **Auto-analysis is a first pass, not a finished analysis.** Stripped binaries
  come back as `FUN_<address>`; the point of putting this behind MCP is to let a
  model do the iterating a human would otherwise do in the GUI.
- **A packed program is locked where it lies.** Ghidra writes a `.lock` file
  *next to* a `.gzf`/`.gar` while importing it, so one sitting on a read-only
  mount cannot be imported in place — which is exactly compose's case, since
  the samples directory is mounted `ro`. `analyze_binary` stages such a file
  into a temporary directory first. Raw binaries load from bytes, take no lock,
  and are imported where they are.
- **Projects are tied to a Ghidra version.** Open a project with the version
  that created it, and keep a `PROJECT_LOCATION` per version — which is why the
  container writes to `./projects-docker` and not `./projects`.
- **A stale Ghidra extension makes every run noisy, harmlessly.** An extension
  installed under `~/.config/ghidra/` for a different Ghidra version prints
  `Module manifest file error …` on every headless run. Analysis and scripts
  complete normally.

## Using it with the Building Agentic RE course

This server was written alongside the DEF CON 34 course *Building Agentic RE:
Automating Reverse Engineering & Vulnerability Research with AI*, whose
devcontainer (`ghcr.io/clearbluejar/ghidra-python`, Ghidra 12.0.4) runs
OpenWebUI, JupyterLab and the course's own MCP servers. Three ways to run it
alongside:

- **In the devcontainer**, as a process — a bind mount and a VS Code task in the
  course's `devcontainer.json`/`tasks.json` run `serve-mcpo.sh` there. OpenWebUI
  then reaches it as `http://localhost:1341`, and every path is a container
  path.
- **As a compose sidecar** — the default `Dockerfile` *is* the devcontainer's
  image, so projects stay compatible. Set in `.env`:

  ```bash
  SAMPLES_DIR=../building-agentic-re          # the course checkout, on the host
  SAMPLES_MOUNT=/workspaces/building-agentic-re
  MCPO_PORT=1342                              # the devcontainer copy holds 1341
  PROJECT_NAME=headless-mcp-docker            # see "Project owner" above
  ```

  The clone is then mounted at the same path the devcontainer uses, so a binary
  path such as
  `/workspaces/building-agentic-re/exercises/ai-assisted-re/assets/crackme2.x86_64`
  is valid on both sides. Register it in OpenWebUI as
  `http://host.docker.internal:1342`: OpenWebUI runs in the devcontainer, so
  `localhost` there is not this container. The devcontainer copy runs as
  `vscode` and this one as `ghidra`, which is why the two need different
  `PROJECT_NAME`s if they share `./projects-docker`.
- **On the host** — any host path works, but OpenWebUI's code interpreter sees
  container paths, so a prompt has to say which namespace each path belongs to.

The course OpenWebUI keeps its data in the clone's `.openwebui-data/`, which is
where `list_chat_uploads` looks when `OPENWEBUI_UPLOADS_DIR` is unset. Port 1341
was picked because the course notebooks use 1337–1340.

## Related projects

- [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) — Ghidra's GUI behind
  MCP through a plugin and a Python bridge.
- [pyghidra-mcp](https://github.com/clearbluejar/pyghidra-mcp) — in-process
  PyGhidra behind MCP, with a project of many binaries.

[`docs/api-reference.md`](docs/api-reference.md) compares the two tool by tool,
and [`docs/roadmap.md`](docs/roadmap.md) is the staged plan this server was
built to. Ghidra itself is developed by the NSA and released under the
Apache License 2.0; it is not distributed here.

## License

Copyright 2026 Andrei Dimitrief-Jianu. Licensed under the
[Apache License, Version 2.0](LICENSE).
