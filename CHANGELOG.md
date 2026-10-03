# Changelog

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
- Tested on Ghidra 12.0.4, 12.1.2 and 12.1.3, and Python 3.12, 3.13 and 3.14:
  713 unit and 181 integration tests.
