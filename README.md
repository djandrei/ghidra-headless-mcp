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

## Tools

24 tools, at parity with GhidraMCP and pyghidra-mcp on everything that does not
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
pytest                  # 381 unit tests, no JVM, under a second
pytest -m integration   # 107 integration tests against real Ghidra, ~7 minutes
```

Unit tests never spawn a JVM: a fake intercepts `run_headless` and writes an
envelope into the out-file the real code chose, so genuine command
construction and file plumbing are exercised in-process. Integration tests are
deselected by default (`pytest.ini`) and run against Ghidra 12.1.2 using
`starter05.x86_64` and `crackme.x86_64` from the course assets, with
`check_key @ 00401146` as ground truth. Write and project tests use their own
projects so they cannot disturb the read-only suite's assertions.

## Limitations, by design

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
- **Calls are serialised** by a lock. Ghidra locks a project for the duration
  of a headless run, so concurrent calls would fail rather than queue.
- **A project open in the Ghidra GUI blocks headless access** to it. Use a
  separate `PROJECT_LOCATION` from any project you open interactively.
- **`list_strings` returns *defined* strings**, not what `strings(1)` finds.
  Packed or encrypted regions stay invisible until something defines them.
- **`list_symbols(kind="data")` also only sees *defined* data.** A named array
  whose bytes Ghidra never typed is a `label`, not a data item, so it does not
  appear — `kind="label"` finds it. This bites in practice: `ENCODED` is data in
  `crackme2.x86_64` but only a label in `crackme.x86_64`, so the same query
  works on one and returns nothing on the other. When locating a named array,
  either try both kinds or take the address straight out of the decompilation.
- **Auto-analysis is a first pass, not a finished analysis.** Stripped binaries
  come back as `FUN_<address>`; the point of putting this behind MCP is to let a
  model do the iterating a human would otherwise do in the GUI.
- **Version skew**: the host install is 12.1.2, the devcontainer's is 12.0.4.
  Open a project with the version that created it.

## Note on log noise

Runs on this host print `Module manifest file error … Extensions/GhidraMCP/
Module.manifest`. That is a pre-existing problem with the GhidraMCP extension
installed under `~/.config/ghidra/`, unrelated to this server, and harmless —
analysis and scripts complete normally.
