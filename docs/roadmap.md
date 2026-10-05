# ghidra-headless-mcp — staged plan for the remaining 36 tools

> **Historical.** This is the plan the server was built to, kept for the
> reasoning behind its shape. All eight stages are implemented; the README is
> the reference for what exists now.

Target: reach functional parity with GhidraMCP and pyghidra-mcp on everything
that does not require a Ghidra GUI (45 of their 52 endpoints; the 7 GUI ones
are unreachable by construction). 9 are already covered by the current 7 tools,
leaving **36 endpoints to absorb**.

## The shaping decision

**36 source endpoints should not become 36 tools.** Two forces collapse them:

1. **The two projects duplicate each other.** GhidraMCP splits by-name and
   by-address into separate tools (`rename_function` / `rename_function_by_address`);
   pyghidra-mcp merges them behind one `name_or_address` parameter. Merge.
2. **Every call costs a ~3 s JVM cold start** (measured on a typical workstation). A
   per-call `rename_function` makes a 200-function renaming pass take ~10
   minutes. Fine-grained mutation tools are the wrong shape for this backend.

So the 36 land as **~22 tools**, several of which take lists. That is not a
compromise — batching is what makes a headless backend competitive, because one
JVM start amortises across the whole work unit.

Ordering is by value-per-unit-effort: xrefs first because nothing in the current
server answers "who calls this", writes before search because writes are what
turn a reader into an RE loop.

---

## Stage 0 — Foundations

Prerequisite refactor. Everything after this is additive; skipping it means
rewriting stages 1–7 later.

**Java side (`HeadlessJsonExport.java`)**

- Replace the `switch` in `run()` with a **mode registry** (`Map<String, Mode>`),
  so a new mode is one entry instead of an edit to the dispatcher.
- **Accept a JSON spec file instead of positional args.** Command-line length
  limits and quoting make positional args unworkable for batch calls
  (a list of 200 renames will not fit). New contract:
  `-postScript HeadlessJsonExport.java <specFile> <outFile>`, where the spec is
  `{"mode": "...", "args": {...}}`. Keep the positional form working for the
  four existing modes during migration.
- **Uniform error envelope.** Every mode returns
  `{"ok": true, "data": {...}}` or `{"ok": false, "error": {"kind": "...", "message": "..."}}`
  rather than today's ad-hoc `{"error": "..."}`. Kinds: `not_found`,
  `bad_argument`, `ghidra_error`, `timeout`.

**Python side (`ghidra_headless_mcp.py`)**

- `_export()` writes the spec file, invokes, parses the envelope, and raises a
  typed error. One place to change, not per tool.
- `_export_write()` — same but **drops `-readOnly`**, so changes persist.
  Verified: a rename in one headless run is visible to a fresh JVM afterwards.
  Route every mutation through this one function so read/write intent is never
  ambiguous at a call site.

**Testing**

- Add `tests/test_tools.py` (pytest) driving the server module against
  a small static ELF crackme, asserting known ground truth: `check_key` at `00401146`,
  24 functions, the `keygen-me` string. There is no test suite today; adding
  one now makes stages 1–7 verifiable instead of hopeful.
- Add a second fixture binary with imports/exports/classes — the crackme is a
  static ELF and will not exercise stages 3 and 6 meaningfully.

Effort: **M**. ~250 lines Java refactor, ~120 Python, ~150 test.
Risk: low. Nothing user-visible changes.

---

## Stage 1 — Cross-references (4 endpoints → 3 tools)

The biggest hole. Impact analysis ("who can reach this sink") is unanswerable
without it.

| New tool | Absorbs |
|---|---|
| `list_xrefs_to(program, target, limit, offset)` | GhidraMCP `get_xrefs_to`, `get_function_xrefs`; pyghidra `list_xrefs` |
| `list_xrefs_from(program, target, limit, offset)` | GhidraMCP `get_xrefs_from` |
| `get_function_at(program, address)` | GhidraMCP `get_function_by_address` |

`target` accepts a name **or** an address, and a **list** of either — batch
lookup in one JVM start, matching pyghidra-mcp's behaviour.

**Ghidra API**: `currentProgram.getReferenceManager()` →
`getReferencesTo(Address)` / `getReferencesFrom(Address)`. Each `Reference`
yields `getFromAddress()`, `getToAddress()`, `getReferenceType()`,
`isPrimary()`. Confirmed present: `ReferenceManager` is used by 21 bundled
scripts in 12.1.2.

Enrich each hit with the **containing function** (`getFunctionContaining`) —
a bare address is nearly useless to a model, "called from `main+0x40`" is not.

New mode: `xrefs`. Effort: **S**.

---

## Stage 2 — Raw views (3 endpoints → 2 tools)

For when the decompiler cannot be trusted: obfuscation, hand-written assembly,
shellcode, or data misidentified as code.

| New tool | Absorbs |
|---|---|
| `disassemble(program, target, count=20, include_bytes=False)` | GhidraMCP `disassemble_function`; pyghidra `disassemble` |
| `read_bytes(program, address, size=32)` | pyghidra `read_bytes` |

`target` accepts a function name (disassemble its whole body, GhidraMCP's
behaviour) or a bare address (disassemble `count` instructions from there,
pyghidra's behaviour). Cap `count` at 200 as pyghidra does.

**Ghidra API**: `Listing.getInstructionAt(addr)` then `instr.getNext()`, or
`getInstructions(AddressSetView, true)` for a function body. Per instruction:
`getAddress()`, `getMnemonicString()`, `getDefaultOperandRepresentation(i)`,
`getBytes()`. For `read_bytes`: `Memory.getBytes(Address, byte[])`.

Return the aligned text listing as one string, not a list of objects — models
read a listing better than JSON rows, and it is far fewer tokens.

New modes: `disassemble`, `read_bytes`. Effort: **S**.

---

## Stage 3 — Symbol inventory (6 endpoints → 2 tools)

Cheap, pure Program API, high triage value: imports alone often answer "what
does this thing do".

| New tool | Absorbs |
|---|---|
| `list_symbols(program, kind, query, limit, offset)` | GhidraMCP `list_imports`, `list_exports`, `list_data_items`, `list_classes`, `list_namespaces`; pyghidra `list_imports`, `list_exports` |
| `list_memory_blocks(program)` | GhidraMCP `list_segments` |

One tool with `kind: Literal["import","export","data","class","namespace","label"]`
rather than five near-identical tools. Fewer tools is better for a model's tool
selection, and the response models are the same shape anyway.

**Ghidra API**: `SymbolTable.getExternalSymbols()` (imports),
`getSymbolIterator()` filtered on `isExternalEntryPoint()` (exports),
`Listing.getDefinedData(true)` (data), `SymbolTable.getClassNamespaces()`
(classes). Memory blocks already exist in `get_program_info` — expose
standalone and stop duplicating them in the info payload.

New mode: `symbols`. Effort: **S**.

---

## Stage 4 — Search (2 endpoints → 2 tool upgrades)

| Change | Absorbs |
|---|---|
| `list_functions(name_contains=…)` → `search_symbols(program, pattern, kind, functions_only, …)` with **regex** | GhidraMCP `search_functions_by_name`; pyghidra `search_symbols_by_name` |
| `list_strings(contains=…)` → regex + `min_length` | pyghidra `search_strings` |

Today's filters are Python-side substring matches over a full export — the JVM
serialises every function, then Python throws most away. Push the regex **into
the Java side** so the JVM emits only matches. On a large binary this is the
difference between a 40 MB export and a 4 KB one.

Keep `name_contains` as a deprecated alias for one release; a plain substring is
a valid regex, so the migration is a rename, not a behaviour change.

Effort: **S**. Mostly moving existing filtering across the boundary.

---

## Stage 5 — Writes (10 endpoints → 6 tools + 1 batch)

The stage that changes what the server *is*. Everything before this reads; this
lets an agent record what it learned, and each recorded fact improves the next
decompilation.

| New tool | Absorbs |
|---|---|
| `rename_function(program, target, new_name)` | GhidraMCP `rename_function`, `rename_function_by_address`; pyghidra `rename_function` |
| `rename_variable(program, function, variable, new_name)` | both projects' `rename_variable` |
| `rename_data(program, address, new_name)` | GhidraMCP `rename_data` |
| `set_function_prototype(program, target, prototype)` | both |
| `set_variable_type(program, function, variable, type_name)` | GhidraMCP `set_local_variable_type`; pyghidra `set_variable_type` |
| `set_comment(program, address, comment, comment_type)` | GhidraMCP `set_decompiler_comment`, `set_disassembly_comment`; pyghidra `set_comment` |
| **`apply_edits(program, edits: list[Edit])`** | the batch form of all six |

`apply_edits` is the one that matters. A single JVM start applies an arbitrary
list of renames, retypes and comments in one transaction — the difference
between ~10 minutes and ~5 seconds for a 200-function pass. **Build it first**
and implement the six singles as one-element wrappers over it, not the reverse.

`save()` from pyghidra-mcp needs no tool: headless saves automatically unless
`-readOnly` is passed. Document that; do not add a no-op tool.

**Three verified API hazards:**

1. **Comment constants changed in Ghidra 12.** It is now a `CommentType` **enum**
   (`ghidra.program.model.listing.CommentType`, confirmed in 12.1.2's
   SoftwareModeling.jar) — `setComment(CommentType.EOL, …)`. Code copied from
   GhidraMCP or older tutorials uses the int constants `CodeUnit.EOL_COMMENT`
   and **will not compile**. Map the six pyghidra comment types onto the enum:
   `decompiler`→`PRE`, plus `PLATE`, `PRE`, `EOL`, `POST`, `REPEATABLE`.
2. **Renaming a decompiler-visible local is not `Variable.setName()`.** Locals
   the decompiler synthesises (`local_10`, `uVar1`) do not exist as database
   variables until committed. Use `HighFunctionDBUtil` (present in 12.1.2;
   `Ghidra/Features/Decompiler/ghidra_scripts/StringParameterPropagator.java`
   demonstrates the idiom). Expect this to be the single most fiddly item in
   the plan — budget accordingly and test against a stripped binary, not
   the crackme.
3. **Prototype strings need a parser.** `CParserUtils` exists in 12.1.2 but the
   bundled scripts only exercise `parseHeaderFiles`. The signature-parsing path
   (`FunctionSignatureParser` + `ApplyFunctionSignatureCmd`) appears in **no**
   bundled script, so treat its exact 12.x API as **unverified** — spike it
   before committing to the interface, and fall back to returning Ghidra's own
   parse error to the caller the way pyghidra-mcp does.

**Transactions**: `GhidraScript` manages one per script run. Wrap `apply_edits`
so a mid-list failure rolls back cleanly rather than leaving a half-renamed
program — and report which edit failed by index.

New modes: `edit` (batch). Effort: **L**. This is the stage that will overrun.

---

## Stage 6 — Call graph (1 endpoint → 1 tool)

| New tool | Absorbs |
|---|---|
| `gen_callgraph(program, function, direction, depth)` | pyghidra `gen_callgraph` |

**Ghidra API**: `Function.getCalledFunctions(monitor)` /
`getCallingFunctions(monitor)`, walked breadth-first with a depth cap and a
visited set (recursion is the default case in real binaries, not the exception).

Emit **MermaidJS**, matching pyghidra-mcp — a model can paste it straight into
a report, and most Markdown renderers draw it.

Effort: **S**. Cap depth and node count; an unbounded call graph on a large
binary is both useless and enormous.

---

## Stage 7 — Code search (2 endpoints → 1 tool)

| New tool | Absorbs |
|---|---|
| `search_code(program, query, mode, limit)` | pyghidra `search_code` |

Two modes, very different costs:

- **`literal`** — decompile every function once, cache the C to disk, grep it.
  The cache is the point: a second query costs no JVM start at all.
- **`semantic`** — pyghidra-mcp indexes decompiled code into a **persistent
  on-disk ChromaDB collection** (`chromadb>=1.3.5`, confirmed in its
  dependencies). That design ports cleanly: build the index during
  `analyze_binary`, and queries then need **no Ghidra at all** — a headless
  semantic search would actually be *faster* than pyghidra-mcp's, which still
  holds a JVM.

Adds the first heavyweight dependency. Keep it an **extra**
(`pip install .[semantic]`) so the core server stays dependency-light.

Effort: **M** literal, **L** semantic. Sequence literal first — it is most of
the value for a fraction of the work.

---

## Stage 8 — Project management (2 endpoints → 1 tool + docs)

| New tool | Absorbs |
|---|---|
| `delete_program(program)` | pyghidra `delete_project_binary` |
| — | pyghidra `save` — document as implicit, add no tool |

Also replace the `programs.json` index with a real project listing, so programs
imported by an external `analyzeHeadless` run or the GUI are visible. That is a
documented limitation today; this stage retires it.

Effort: **S**.

---

## Summary

| Stage | Endpoints | New tools | Effort | Blocking risk |
|---|---|---|---|---|
| 0 Foundations | — | — | M | none |
| 1 Xrefs | 4 | 3 | S | none |
| 2 Raw views | 3 | 2 | S | none |
| 3 Symbol inventory | 6 | 2 | S | needs a dynamic fixture binary |
| 4 Search | 2 | 2 (upgrades) | S | none |
| 5 Writes | 10 | 7 | **L** | prototype parser API unverified; decompiler-local renames |
| 6 Call graph | 1 | 1 | S | none |
| 7 Code search | 2 | 1 | M–L | chromadb dependency |
| 8 Project mgmt | 2 | 1 | S | none |
| **Total** | **30 + 6 batch forms = 36** | **~19–22** | | |

Stages 1–4 are a weekend and deliver most of the read-side value. Stage 5 is the
one to budget seriously. Stages 6–8 are optional polish.

## Cross-cutting

- **Token budget.** Every new tool needs `limit`/`offset` and a sane default.
  A `list_symbols` with no cap on a real binary will blow a model's context —
  the current `list_functions` default of 200 is the right precedent.
- **Batch everywhere it is cheap.** Any tool taking a `target` should take a
  list of targets. The JVM start is the cost; the work rarely is.
- **Version skew.** Ghidra 12 replaced the integer comment-type constants with
  a `CommentType` enum, so Stage 5 code has to be checked against every Ghidra
  version it claims to support (now 12.0.4, 12.1.2 and 12.1.3).
