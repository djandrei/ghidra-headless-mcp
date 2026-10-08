# Changelog

## Unreleased

- **Data types.** `list_types` and `get_type` read the program's types;
  six new `apply_edits` kinds write them: `define_type` (a C declaration,
  with an explicit `on_conflict`), `apply_type`, `struct_field` (add, rename,
  replace, comment, clear), `enum_member`, `delete_type`, and `fill_struct`,
  which builds a struct from how a pointer is used and retypes the variable.
  Type names accept a full category path, with pointer and array suffixes.
- **Control flow.** `get_cfg` returns basic blocks and the edges between them
  (fall-through, conditional, unconditional, indirect) for one or more
  functions; `find_call_paths` lists every call chain from one function to
  another, bounded by depth and path count.
- **Instruction search.** `search_constants` finds scalar operands equal to a
  value or inside a range (signed or unsigned reading); `search_instructions`
  finds instructions by mnemonic or by a regex over their text. Both scan an
  optional address window, page per program, and take one program, a list,
  or `"*"` for the whole project in one JVM start.
- **Analysis options.** `list_analysis_options` shows every analyzer switch
  and setting; `analyze_binary(..., analyzer_options=...)` sets options before
  the first analysis and `reanalyze(program, analyzer_options)` runs it again.
  A new pre-script, `SetAnalysisOptions.java`, validates every option before
  setting any: a bad name or value fails the call and nothing is imported or
  changed.
- `upload_binary(..., analyze=True, keep=False)` imports the file and deletes it
  in the same call, from a private directory no other call can see, so a
  client needs neither a follow-up `delete_upload` nor a lock of its own.
  `UploadResult` gains `kept`, and its `path` is absent when the file was not
  kept. Stale temporary upload entries left by a killed process are swept up.
- `POST /api/<tool>` on the `--http` surface: the tools as plain HTTP/JSON,
  with mcpo's success bodies but status codes that distinguish a caller's
  mistake (400 / 404 / 422) from a server failure (500 / 504). mcpo answers
  every tool error with 500, so a client retrying 5xx resent bad requests.
- `POST /api/upload` on the `--http` surface: raw bytes in the body, streamed
  to disk and hashed as they arrive, so a large binary is neither inflated by
  base64 nor held in memory. Same rules and result as `upload_binary`, capped
  by the new `MAX_STREAM_UPLOAD_BYTES` (128 MiB); 413 over it.
- Compose runs the `--http` surface as a second service,
  `ghidra-headless-mcp-http`, on 1351 (`GHMCP_HTTP_PORT`), over the same
  project as the mcpo service; the project lock file serialises the two.
- README: "Running with Keystone" is now a client-neutral "Using it from
  another service" — key, upload cap, published port, `/api/upload`, retry
  rules — with no shared samples directory or shared network.
- The unit suite covers 100% of lines and branches, and CI fails below that.
- **Changed:** `OPENWEBUI_UPLOADS_DIR` has no default. The server no longer
  probes one particular deployment's layout for OpenWebUI's uploads; unset,
  `list_chat_uploads` reports that it is not configured. Set it to OpenWebUI's
  `DATA_DIR/uploads` as the server sees it.
- **Changed:** the Windows-layering integration tests find their binaries
  through `WINDOWS_SAMPLES_DIR` (a directory of the four `.gzf` files, default
  `tests/windows-samples/`, gitignored), replacing `COURSE_CLONE`.
- Docs, comments and test data no longer refer to the training course this
  server was first written alongside.

## 0.1.0 — first public release

- **34 tools** over Ghidra's headless analyzer: import and auto-analysis
  (`analyze_binary`, `analyze_binaries`), reading (functions, decompilation,
  disassembly, bytes, strings, symbols, memory blocks), cross-references and
  call graphs, code and memory search, and annotation (renames, prototypes,
  types, comments, batched through `apply_edits`), plus `run_ghidra_script`.
- **Project scope**: several tools answer for every binary in a project in one
  JVM start, and `resolve_symbol` traces a symbol across binaries.
- **Getting binaries in**: `upload_binary` (base64 through the tool surface),
  `list_chat_uploads` (OpenWebUI chat attachments already on disk),
  `list_uploads` / `delete_upload`.
- **Three surfaces**: stdio, HTTP/OpenAPI via mcpo, and native MCP over
  streamable-http; both HTTP surfaces require a bearer token and bind loopback.
- **Two container images**: one on `ghidra-python` (Ghidra 12.0.4), a slim one on
  `eclipse-temurin:21-jdk` (Ghidra 12.1.3, 1.84 GB).
- **Self-contained test fixtures**: the integration suite analyses binaries
  built from C sources in `tests/fixtures/src` — ELF x86-64, PE32, Mach-O arm64
  and an import → forwarder → implementation chain of DLLs — so it runs from a
  plain clone and in CI. Only the Windows-layering module still needs real
  Windows binaries, and skips without them.
- Tested on Ghidra 12.0.4, 12.1.2 and 12.1.3, and Python 3.12, 3.13 and 3.14.
  CI runs the unit suite on all three Pythons and the integration suite in the
  slim image.
