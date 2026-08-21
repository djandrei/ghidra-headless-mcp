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
# stdio, for an MCP client that spawns it directly
python ghidra_headless_mcp.py

# wrapped as HTTP/OpenAPI for OpenWebUI or notebook `requests` calls
mcpo --port 1341 -- python ghidra_headless_mcp.py
```

**Port 1341** is chosen because 1337–1340 are taken by the course notebooks
(see the port map in the workspace `CLAUDE.md`).

## Run in Docker

The course devcontainer already carries everything this server needs — Ghidra
12.0.4 at `/ghidra`, Java 21, Python 3.13 — so it runs there as happily as on
the host. `compose.yaml` starts it as a **sidecar** to that devcontainer rather
than inside it, because `claude/` is not mounted into the course container and
the course clone is read-only, so its `devcontainer.json` is not ours to edit.

```bash
docker compose up -d --build
curl -s http://127.0.0.1:1341/openapi.json | head -c 80
```

The point of doing this is not packaging, it is **paths**. The clone is mounted
at the same `/workspaces/building-agentic-re` the devcontainer uses, so one
binary path is now valid on both sides:

```bash
curl -X POST http://127.0.0.1:1341/analyze_binary -H 'Content-Type: application/json' \
  -d '{"binary_path": "/workspaces/building-agentic-re/exercises/ai-assisted-re/assets/crackme2.x86_64"}'
```

The same path works in OpenWebUI's code interpreter, which is what made
host-versus-container path labelling necessary while this ran on the host.

| Concern | How compose settles it |
|---|---|
| **Ghidra version** | The image is the devcontainer's own, so 12.0.4 — not the host's 12.1.2. |
| **Projects** | `PROJECT_LOCATION=/projects`, bind-mounted from `./projects-docker`. Kept apart from `./projects`, which 12.1.2 wrote and 12.0.4 cannot open. |
| **File ownership** | Runs as `vscode`, uid/gid 1000, matching the host account. Files in `./projects-docker` come back owned by you. |
| **Reachability** | Published on `127.0.0.1` and on the docker bridge gateway, so both host tools and the devcontainer can reach it — but nothing on the LAN can. `run_ghidra_script` executes arbitrary Ghidra scripts; this server does not belong on `0.0.0.0`. |
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

## Tools

26 tools, at parity with GhidraMCP and pyghidra-mcp on everything that does not
require a GUI. See `../ghidra_mcp_api_reference.md` for the comparison and
`../ghidra_headless_mcp_roadmap.md` for how they were staged.

**Project**

| Tool | Returns |
|---|---|
| `analyze_binary(binary_path, force, processor, cspec, max_cpu)` | Import + auto-analyse. `processor`/`cspec` override detection for raw firmware. Skips work if already analysed unless `force`. |
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

**Graph**

| Tool | Returns |
|---|---|
| `list_xrefs_to(program, target, limit, offset)` | Who references a function, symbol or address. Batched; each hit names its containing function. |
| `list_xrefs_from(program, target, limit, offset)` | What a function or address references. A function target sweeps its whole body. |
| `get_function_at(program, address)` | The function at, or containing, an address. |
| `gen_callgraph(program, function, direction, depth, max_nodes)` | MermaidJS call graph, callers or callees. |

**Search**

| Tool | Returns |
|---|---|
| `search_code(program, query, mode, limit, context, refresh)` | Searches decompiled C: `literal` regex or `semantic` ranking. |
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

## Tests

```bash
pytest                  # 504 unit tests, no JVM, ~13 s
pytest -m integration   # 117 integration tests against real Ghidra, ~7 minutes
```

Almost all of the unit suite's wall time is two tests: `test_projectlock.py`'s
deadline and exclusion cases wait out real timeouts (8 s and 4 s). The other
497 tests finish in 0.6 s — `pytest --ignore=tests/test_projectlock.py` is the
fast inner loop.

Unit tests never spawn a JVM: a fake intercepts `run_headless` and writes an
envelope into the out-file the real code chose, so genuine command
construction and file plumbing are exercised in-process. Integration tests are
deselected by default (`pytest.ini`) and run against Ghidra 12.1.2 using
`starter05.x86_64` and `crackme.x86_64` from the course assets, with
`check_key @ 00401146` as ground truth. Write and project tests use their own
projects so they cannot disturb the read-only suite's assertions.

## Limitations, by design

- **An unsupported architecture fails at import, with an explanation.** Ghidra
  ships ~40 processor modules; Alpha, IA-64 and S/390 are not among them.
  analyzeHeadless exits 0 on a failed import, so the log is checked for
  "No load spec found" and the error says so rather than letting a later query
  report a missing program.
- **mcpo nests tool errors.** The real message is in `detail.error`; the
  `detail.message` field just says "Unexpected error". Read the former.
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
