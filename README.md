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

| Tool | Returns |
|---|---|
| `analyze_binary(binary_path, force, processor, cspec, max_cpu)` | Import + auto-analyse. `processor`/`cspec` override detection for raw firmware. Skips work if already analysed unless `force`. |
| `list_programs()` | Program names to pass to the other tools. |
| `get_program_info(program)` | Hashes, architecture, image base, function/symbol counts, memory blocks. |
| `list_functions(program, name_contains, limit, offset, …)` | Paged function list with signatures. Thunks and externals excluded by default. |
| `decompile_function(program, function)` | Decompiled C. Accepts a name or an entry-point address. |
| `list_strings(program, contains, min_length, limit, offset)` | Defined strings with addresses. |
| `run_ghidra_script(program, script_name, script_args, stage, read_only)` | Escape hatch: runs any of Ghidra's ~190 bundled scripts, or your own from `ghidra_scripts/`. |

## Verified

Smoke-tested against Ghidra 12.1.2 on the host, using
`exercises/starters/assets/starter05.x86_64`:

```
analyze_binary : starter05.x86_64 in 4.8s, 24 functions, x86:LE:64:default
list_functions : total=10 after filtering thunks/externals
decompile_function("check_key") : 43 lines of C @ 00401146
list_strings(contains="key")    : 4 hits, incl. "== starter05 :: keygen-me =="
re-analyze     : short-circuits (already_analyzed=True)
```

`check_key @ 00401146` agrees with the address recorded in
`claude/ctf-challenges/starter05_keygen.py`.

## Limitations, by design

- **`list_programs` reads an index this server maintains**, not the Ghidra
  project itself. Programs imported by an external `analyzeHeadless` run or by
  the GUI will not appear. Analyse through `analyze_binary` and they will.
- **Calls are serialised** by a lock. Ghidra locks a project for the duration
  of a headless run, so concurrent calls would fail rather than queue.
- **A project open in the Ghidra GUI blocks headless access** to it. Use a
  separate `PROJECT_LOCATION` from any project you open interactively.
- **`list_strings` returns *defined* strings**, not what `strings(1)` finds.
  Packed or encrypted regions stay invisible until something defines them.
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
