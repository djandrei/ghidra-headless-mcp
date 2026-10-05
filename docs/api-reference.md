# GhidraMCP vs pyghidra-mcp — consolidated API reference

Both projects put Ghidra behind MCP, and their tool lists look similar at a
glance. They are not interchangeable: the difference in *where Ghidra lives*
decides what each API can express.

Both were read from source, not from documentation, at the versions below:

| | GhidraMCP | pyghidra-mcp |
|---|---|---|
| Author | LaurieWired (created 2025-03-22) | clearbluejar + notoriousrip |
| Version here | **11.3.2** extension + `bridge_mcp_ghidra.py` | **0.2.5**, on `pyghidra` 3.1.0 |
| Where Ghidra runs | Inside a **running Ghidra GUI**; a Java plugin serves HTTP on 8080 | **In-process** via PyGhidra/JPype; no GUI needed |
| MCP layer | Python bridge translating MCP → HTTP | Native Python MCP server |
| Scope | **One program** — whatever the GUI has open | **A project of many binaries**; every tool takes `binary_name` |
| Tool count | **27** | **20**, plus **5** GUI-only tools behind `--gui` |
| Source read | `bridge_mcp_ghidra.py` from the GhidraMCP 1.4 release | `pyghidra_mcp/{server,mcp_tools}.py` from the installed 0.2.5 package |

The consequence worth internalising: **GhidraMCP is a remote control for a human's
Ghidra session; pyghidra-mcp is a headless analysis service that can optionally
open a GUI.** GhidraMCP can ask "what is the user looking at right now"
(`get_current_address`), which pyghidra-mcp cannot answer without `--gui`.
pyghidra-mcp can ask "which of these forty binaries defines this symbol", which
GhidraMCP cannot express at all.

---

## GhidraMCP — 27 tools

Every tool operates on the single program open in the GUI. Addresses are hex
strings (`"0x1400010a0"`). Listing tools take `offset`/`limit` for pagination.

### Orientation — what is in this binary

| Tool | Purpose |
|---|---|
| `list_functions()` | Every function in the database. No pagination — the blunt one. |
| `list_methods(offset, limit)` | The same function names, paginated. Use this on real binaries. |
| `list_classes(offset, limit)` | Namespace/class names — the OO structure Ghidra recovered (C++ RTTI, Java). |
| `list_namespaces(offset, limit)` | Non-global namespaces; separates library code from program code. |
| `list_segments(offset, limit)` | Memory segments — the map of where code, data, and headers sit. |
| `list_imports(offset, limit)` | Imported symbols: what the binary asks of the OS. The fastest capability read. |
| `list_exports(offset, limit)` | Exported symbols: what it offers to others. Central for DLL/SO triage. |
| `list_data_items(offset, limit)` | Defined data labels and values — where the constants and tables live. |
| `list_strings(offset, limit, filter)` | Defined strings with addresses. `filter` matches content; default limit is 2000. |

### Locating — finding the thing you care about

| Tool | Purpose |
|---|---|
| `search_functions_by_name(query, offset, limit)` | Substring match over function names. The usual entry point into a stripped binary once symbols exist. |
| `get_function_by_address(address)` | Resolve an address to its containing function. |
| `get_current_address()` | **The address the human has selected in the GUI.** No headless equivalent exists. |
| `get_current_function()` | **The function the human is looking at.** Lets an agent work on "this" without being told which. |

### Reading — turning bytes into meaning

| Tool | Purpose |
|---|---|
| `decompile_function(name)` | Pseudo-C by name. The workhorse: this is what gets fed to a model. |
| `decompile_function_by_address(address)` | Same, for functions with no useful name — the stripped-binary case. |
| `disassemble_function(address)` | Assembly as `address: instruction; comment`. Use when decompiler output is untrustworthy (obfuscation, hand-written asm). |

### Cross-references — following the flow

| Tool | Purpose |
|---|---|
| `get_xrefs_to(address, offset, limit)` | Who reaches this address. The core question of impact analysis: who can call this sink. |
| `get_xrefs_from(address, offset, limit)` | What this address reaches. Used to walk outward from an entry point. |
| `get_function_xrefs(name, offset, limit)` | Callers of a named function, without resolving the address first. |

### Writing back — the part that makes it an RE loop

These mutate the Ghidra database, which is what separates an agent that
*analyses* from one that *does the work*. Each recovered fact becomes context
for the next decompilation.

| Tool | Purpose |
|---|---|
| `rename_function(old_name, new_name)` | Record what a function actually does. `FUN_0041d000` → `rc4_decrypt_config`. |
| `rename_function_by_address(function_address, new_name)` | Same by address — the reliable form when names are auto-generated. |
| `rename_variable(function_name, old_name, new_name)` | `local_10` → `key_len`. Compounds: re-decompiling shows the new name throughout. |
| `rename_data(address, new_name)` | Name a global or table. |
| `set_function_prototype(function_address, prototype)` | Fix the signature. The highest-leverage write: a corrected prototype changes argument recovery in **every caller's** decompilation. |
| `set_local_variable_type(function_address, variable_name, new_type)` | Apply a type to a local. Turns `undefined8 *` plus arithmetic into readable struct field access. |
| `set_decompiler_comment(address, comment)` | Annotate the pseudo-C. Where an agent leaves its reasoning for the human. |
| `set_disassembly_comment(address, comment)` | Annotate the listing view. |

---

## pyghidra-mcp — 20 tools (+5 GUI)

Every tool takes `binary_name`, because the server holds a **project** of
binaries. Several accept a list for batch work — one MCP round trip instead of
twenty.

### Project management — no equivalent in GhidraMCP

| Tool | Purpose |
|---|---|
| `import_binary(binary_path)` | Add a binary to the project and analyse it. The server can grow its own corpus at runtime. |
| `list_project_binaries()` | Every binary in the project, with analysis status. |
| `list_project_binary_metadata(binary_name)` | Architecture, compiler, endianness, hashes, analysis counts. |
| `delete_project_binary(binary_name)` | Remove one. |
| `save()` | Persist all programs. **Renames and comments are not durable until this runs.** |

### Search — the real differentiator

| Tool | Purpose |
|---|---|
| `search_symbols_by_name(binary_name, query, functions_only, offset, limit)` | **Regex**, case-insensitive (`^main$`, `func.*init`). GhidraMCP offers substring only. `functions_only` excludes labels, variables, classes, namespaces. |
| `search_code(binary_name, query, limit, offset, search_mode, …)` | **Searches decompiled pseudo-C.** `semantic` mode (default) is vector similarity — "find code that validates a licence key" matches without any literal token. `literal` mode for exact text. Nothing in GhidraMCP is comparable. |
| `search_strings(binary_name, query, limit)` | String search within a binary. |
| `list_exports(binary_name, query, offset, limit)` | Exports, regex-filterable. |
| `list_imports(binary_name, query, offset, limit)` | Imports, regex-filterable. |

### Reading

| Tool | Purpose |
|---|---|
| `decompile_function(…)` | Pseudo-C **by name or address, single or batch**. Flags attach callees, strings, and xrefs to each result — one call returns the function plus its context, instead of three round trips. `timeout_sec` applies per target. |
| `disassemble(binary_name, address, count, include_bytes)` | Up to 200 instructions from **any address** — no function entry point needed, which matters for shellcode and mid-function analysis. Returns aligned text; `include_bytes` adds raw hex. |
| `read_bytes(binary_name, address, size)` | Raw bytes. The tool that lets an agent extract an encrypted blob or a key table itself. |
| `list_xrefs(binary_name, name_or_address)` | Cross-references, **single or batch**, and suggests near matches when nothing hits exactly. Collapses GhidraMCP's three xref tools into one. |
| `gen_callgraph(binary_name, function_name, direction, display_type)` | **A MermaidJS call graph**, callers or callees. Output is a diagram a model can emit straight into a report. No GhidraMCP equivalent. |

### Writing back

| Tool | Purpose |
|---|---|
| `rename_function(binary_name, name_or_address, new_name)` | Rename by name *or* address — one tool where GhidraMCP has two. |
| `rename_variable(binary_name, function_name_or_address, variable_name, new_name)` | Rename a parameter or local by exact name. |
| `set_variable_type(binary_name, function_name_or_address, variable_name, type_name)` | Apply a type to a parameter or local. |
| `set_function_prototype(binary_name, function_name_or_address, prototype)` | Set a signature; invalid input returns Ghidra's own error rather than a generic failure. |
| `set_comment(binary_name, target, comment, comment_type)` | One tool, six comment types: `decompiler`, `plate`, `pre`, `eol`, `post`, `repeatable`. GhidraMCP exposes two. |

### GUI tools — only with `--gui`

Registered by `register_gui_tools()` and gated: `--gui` **requires**
`--transport streamable-http` or `http`, and it launches Ghidra **in-process**.
It cannot attach to an already-running external Ghidra — the opposite of how
GhidraMCP works.

| Tool | Purpose |
|---|---|
| `list_open_programs()` | Programs open in the CodeBrowser. |
| `open_program_in_gui(binary_name, new_window)` | Open a project binary in the GUI. |
| `set_current_program(binary_name)` | Switch the active program. |
| `goto(binary_name, target, target_type)` | Drive the CodeBrowser to an address or function — the agent moves the human's view. |
| `get_gui_context()` | Current user location and metadata. Documented as volatile: assume it changed since the last call. |

---

## Capability matrix

| Capability | GhidraMCP | pyghidra-mcp |
|---|---|---|
| Multiple binaries in one session | ✗ | ✓ (`binary_name` everywhere) |
| **A tool that joins two binaries** | ✗ | ✗ (the model does the pivot) |
| Import a binary at runtime | ✗ | ✓ `import_binary` |
| Decompile by name | ✓ | ✓ |
| Decompile by address | ✓ | ✓ (same tool) |
| Batch decompile | ✗ | ✓ (list argument) |
| Decompile + callees/strings/xrefs in one call | ✗ | ✓ (response flags) |
| Disassemble at an arbitrary address | ✗ (function entry only) | ✓ `disassemble` |
| Read raw bytes | ✗ | ✓ `read_bytes` |
| Regex symbol search | ✗ (substring) | ✓ |
| **Semantic search over decompiled code** | ✗ | ✓ `search_code` |
| String search | ✓ (`filter`) | ✓ |
| Xrefs to / from | ✓ (3 tools) | ✓ (1 tool, batch) |
| Call graph generation | ✗ | ✓ MermaidJS |
| Rename function / variable / data | ✓ / ✓ / ✓ | ✓ / ✓ / ✗ |
| Set prototype / variable type | ✓ / ✓ | ✓ / ✓ |
| Comments | 2 types | 6 types |
| Explicit save | ✗ (GUI owns it) | ✓ `save` |
| **Read the human's current selection** | ✓ `get_current_*` | only with `--gui` |
| Drive the GUI view | ✗ | ✓ with `--gui` (`goto`) |
| List segments / classes / namespaces | ✓ | ✗ |
| Runs without a GUI | ✗ | ✓ |

---

## Choosing between them

- **Pair-analysis with a human in Ghidra** → GhidraMCP. `get_current_function`
  plus the rename/comment tools let a model annotate what the analyst is looking
  at, live. Nothing else offers that.
- **Corpus work, batch triage, or anything unattended** → pyghidra-mcp. Multi-
  binary scope, batch decompile, semantic code search, and call graphs are all
  built for the case where no human is watching.
- **Neither needs to stay resident** → the local `ghidra-headless-mcp/` shells
  out to `analyzeHeadless` per call: nothing to keep alive, ~3 s per query,
  since it shells out to `analyzeHeadless` per call: nothing to keep alive,
  ~3 s per query. It writes back to the database (`apply_edits`), and **it now
  has the cross-binary view neither of the others does** — `resolve_symbol`
  links a symbol across binaries, and the project-scope tools answer for every
  binary in one JVM start. Note that `list_project_xrefs`, which pyghidra-mcp is sometimes
  credited with, does not exist in pyghidra-mcp's source.

Two gaps neither closes: **no data-type/struct creation API** (both can apply an
existing type, neither can define a new struct from a decompiled access pattern
— the single most common manual step in real RE), and **no analysis-option
control** (you cannot ask either to re-run a specific analyzer with different
settings).
