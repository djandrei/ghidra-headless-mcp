"""Pydantic response models.

Every tool returns a model rather than a dict so the MCP client receives a
typed schema, and so a change in the Java side's output fails loudly here
instead of silently reaching the caller.
"""

from pydantic import BaseModel, Field


class MemoryBlock(BaseModel):
    name: str
    start: str
    end: str
    size: int
    readable: bool
    writable: bool
    executable: bool


class ProgramInfo(BaseModel):
    name: str
    executable_path: str | None = None
    executable_format: str | None = None
    md5: str | None = None
    sha256: str | None = None
    language_id: str
    compiler_spec_id: str
    image_base: str
    function_count: int
    symbol_count: int
    memory_blocks: list[MemoryBlock] = Field(default_factory=list)


class FunctionSummary(BaseModel):
    name: str
    address: str
    size: int
    signature: str
    calling_convention: str | None = None
    is_thunk: bool = False
    is_external: bool = False


class FunctionList(BaseModel):
    program: str
    total: int = Field(description="Matches before limit/offset were applied.")
    returned: int
    truncated: bool = Field(
        default=False,
        description="True when more matched than the Java side would emit, so "
        "paging cannot reach every match. Narrow the pattern.",
    )
    functions: list[FunctionSummary]


class Decompilation(BaseModel):
    program: str
    name: str
    address: str
    signature: str | None = None
    c: str


class DecompilationResult(BaseModel):
    """One function's slot in a batched decompilation.

    Failures are per-target: a name that does not resolve reports its own error
    and leaves the rest of the batch intact.
    """

    target: str
    name: str | None = None
    address: str | None = None
    signature: str | None = None
    c: str | None = None
    error: str | None = None
    error_kind: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


class DecompilationBatch(BaseModel):
    program: str
    total: int
    succeeded: int
    failed: int
    results: list[DecompilationResult]


class StringHit(BaseModel):
    address: str
    length: int
    value: str


class StringList(BaseModel):
    program: str
    total: int
    returned: int
    truncated: bool = False
    strings: list[StringHit]


class AnalysisResult(BaseModel):
    program: str
    already_analyzed: bool = Field(
        description="True when the program was already in the project and "
        "re-analysis was skipped because force=False."
    )
    duration_seconds: float
    info: ProgramInfo


class UploadResult(BaseModel):
    path: str | None = Field(
        default=None,
        description="Where the file now is, as this server sees it. Pass it to "
        "analyze_binary. Absent when keep=False, since the file is gone.",
    )
    filename: str = Field(description="The stored name, after sanitising.")
    size: int
    md5: str
    sha256: str
    written: bool = Field(
        description="False when an identical file was already there, so nothing "
        "was written."
    )
    replaced: bool = Field(
        default=False,
        description="True when overwrite=True replaced a different file of the "
        "same name.",
    )
    kept: bool = Field(
        default=True,
        description="False when keep=False: the file was imported and deleted.",
    )
    analysis: AnalysisResult | None = Field(
        default=None, description="Present when analyze=True."
    )


class ChatUpload(BaseModel):
    name: str = Field(description="The filename the user attached.")
    path: str = Field(description="Where it is on disk. Pass it to analyze_binary.")
    size: int
    modified: str = Field(description="When OpenWebUI stored it, UTC, ISO 8601.")
    upload_id: str | None = Field(
        default=None, description="OpenWebUI's file id, the uuid prefix of the stored name."
    )


class ChatUploadList(BaseModel):
    directory: str
    total: int = Field(description="Matches before limit was applied.")
    returned: int
    uploads: list[ChatUpload] = Field(description="Newest first.")


class StoredUpload(BaseModel):
    filename: str
    path: str
    size: int
    modified: str = Field(description="UTC, ISO 8601.")


class UploadList(BaseModel):
    directory: str
    uploads: list[StoredUpload]


class UploadDeleteResult(BaseModel):
    filename: str
    path: str
    deleted: bool
    detail: str


class ProgramFailure(BaseModel):
    """One program that could not be served, in an otherwise successful fan-out.

    A project-scope call reports these rather than raising: one unanalysed or
    corrupt program must not discard the results from every other program in
    the batch. Same isolation habit as EditResult per edit and
    XrefTargetResult per target.
    """

    program: str
    error: str
    error_kind: str | None = Field(
        default=None, description="Error kind from the Ghidra side, when there was one."
    )


class AnalysisBatchResult(BaseModel):
    """Several binaries imported by one analyzeHeadless run."""

    results: list["AnalysisResult"] = Field(
        description="One per binary that is now in the project. Check each "
        "already_analyzed to tell a fresh import from a skipped one."
    )
    failures: list[ProgramFailure] = Field(
        default_factory=list,
        description="Binaries that could not be imported. Named by file path, "
        "since they have no program name.",
    )
    imported: int = Field(description="Binaries this call actually imported.")
    skipped: int = Field(description="Binaries already in the project, unchanged.")
    duration_seconds: float
    jvm_starts: int = Field(
        description="analyzeHeadless invocations this call actually made, "
        "counted rather than estimated. Two for a plain batch - one to import, "
        "one to read the metadata back - against two per binary if each were "
        "analysed on its own."
    )


class ProgramList(BaseModel):
    project: str
    project_location: str
    programs: list[str]


class ScriptResult(BaseModel):
    program: str
    script: str
    exit_code: int = Field(
        description="analyzeHeadless's exit code. It is 0 even when the script "
        "itself threw, so check script_error rather than trusting this."
    )
    script_error: str | None = Field(
        default=None,
        description="The script's own error, extracted from the log. Set when "
        "the script failed despite a zero exit code — most often because it "
        "calls a GUI-only method such as askFile().",
    )
    stdout_tail: str = Field(description="Last 200 lines of the headless log.")


# ----------------------------------------------------------------- xrefs


class XrefEntry(BaseModel):
    from_address: str
    to_address: str
    ref_type: str = Field(description="Ghidra reference type, e.g. UNCONDITIONAL_CALL, DATA.")
    is_primary: bool = False
    from_function: str | None = Field(
        default=None,
        description="Function containing the referencing address, when there is one.",
    )
    from_function_address: str | None = None


class XrefTargetResult(BaseModel):
    target: str = Field(description="The caller's string, echoed back.")
    program: str | None = Field(
        default=None,
        description="Program this result came from. Set only when several "
        "programs were queried, so single-program output is unchanged.",
    )
    resolved_address: str | None = None
    resolved_kind: str | None = Field(
        default=None, description="How the target resolved: address, function, or symbol."
    )
    error: str | None = Field(
        default=None, description="Set when this target alone could not be resolved."
    )
    total: int = 0
    returned: int = 0
    xrefs: list[XrefEntry] = Field(default_factory=list)


class XrefList(BaseModel):
    program: str = Field(
        description='The program queried, or "*" when several were. Each result '
        "then names its own program."
    )
    direction: str
    results: list[XrefTargetResult]
    failures: list[ProgramFailure] = Field(default_factory=list)


class FunctionDetail(BaseModel):
    name: str
    address: str
    size: int
    signature: str
    calling_convention: str | None = None
    is_thunk: bool = False
    is_external: bool = False
    queried_address: str
    is_entry_point: bool = Field(
        description="True when the queried address is the function's entry point "
        "rather than an address inside its body."
    )


# ------------------------------------------------------------ raw views


class Disassembly(BaseModel):
    program: str
    target: str
    resolved_address: str
    listing_starts_at: str | None = Field(
        default=None,
        description="Address of the first instruction actually listed. Differs "
        "from resolved_address when undefined bytes were stepped over.",
    )
    skipped_bytes: int = Field(
        default=0,
        description="Bytes between the requested address and the first listed "
        "instruction. Non-zero means Ghidra has not defined code there — use "
        "read_bytes to see those bytes.",
    )
    scope: str = Field(
        description="'function' when the target named a function and its whole "
        "body was disassembled, 'address' when N instructions were read forward."
    )
    instruction_count: int
    truncated: bool = Field(
        description="True when the instruction cap stopped the listing early."
    )
    listing: str = Field(
        description="Aligned text, one instruction per line: address, optional "
        "raw bytes, mnemonic and operands."
    )


class BytesRead(BaseModel):
    program: str
    address: str
    requested_size: int
    size: int = Field(description="Bytes actually read; short at a block boundary.")
    hex: str
    ascii: str = Field(description="Printable rendering, non-printables as '.'.")


class BytesReadResult(BaseModel):
    """One span's slot in a batched read."""

    target: str
    address: str | None = None
    requested_size: int | None = None
    size: int | None = None
    hex: str | None = None
    ascii: str | None = None
    error: str | None = None
    error_kind: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


class BytesReadBatch(BaseModel):
    program: str
    total: int
    succeeded: int
    failed: int
    results: list[BytesReadResult]


# ------------------------------------------------------ symbol inventory


class SymbolEntry(BaseModel):
    name: str
    address: str | None = None
    kind: str
    namespace: str | None = Field(
        default=None, description="Parent namespace; null for global symbols."
    )
    is_external: bool = False
    source_type: str | None = Field(
        default=None,
        description="Symbol source (IMPORTED, USER_DEFINED, ANALYSIS…), or the "
        "data type name for data entries.",
    )
    value: str | None = Field(
        default=None, description="Rendered value, for data entries only."
    )


class SymbolList(BaseModel):
    program: str
    kind: str
    total: int
    returned: int
    truncated: bool = False
    symbols: list[SymbolEntry]


class SymbolLocation(BaseModel):
    """What one program does with a symbol."""

    program: str = Field(description="Project file name, as list_programs returns it.")
    internal_name: str | None = Field(
        default=None,
        description="The program's own name, which a PE reports as kernel32.dll "
        "while the project file is KERNEL32.DLL. Import tables name this one.",
    )
    roles: list[str] = Field(
        description="Any of import, export, function. Not exclusive: a forwarder "
        "both exports a name and imports it from somewhere else, and that "
        "combination is what identifies it."
    )
    address: str | None = None
    library: str | None = Field(
        default=None, description="Library this program imports the symbol from."
    )
    library_program: str | None = Field(
        default=None,
        description="Program in this project that provides `library`, when one "
        "matches. Null when the library is not loaded here.",
    )
    thunk_target: str | None = None
    thunk_library: str | None = None
    is_thunk: bool = False
    is_terminal: bool = Field(
        default=False,
        description="Exports the symbol and does not import it, so the real "
        "implementation is here rather than one layer further down.",
    )


class SymbolChain(BaseModel):
    """One symbol's path through the project's binaries."""

    name: str
    layers: list[SymbolLocation] = Field(
        description="Ordered consumer to implementation: programs that only "
        "import, then forwarders that both export and import, then the "
        "implementation that only exports."
    )
    terminal_program: str | None = Field(
        default=None,
        description="Where the implementation lives. Null when no program in "
        "the project provides it, or when several do — see `notes`.",
    )
    absent_from: list[str] = Field(
        default_factory=list, description="Programs that do not mention the symbol."
    )
    notes: list[str] = Field(
        default_factory=list,
        description="How the chain was resolved, including any apiset "
        "redirection followed and any ambiguity left unresolved.",
    )


class SymbolResolution(BaseModel):
    programs_searched: int
    results: list[SymbolChain]
    failures: list[ProgramFailure] = Field(default_factory=list)


class SymbolListProject(BaseModel):
    kind: str
    programs_searched: int = Field(
        description="Programs that returned symbols. Excludes any in `failures`."
    )
    total: int = Field(description="Matching symbols summed across every program.")
    results: list[SymbolList] = Field(
        description="One entry per program, each naming its own program."
    )
    failures: list[ProgramFailure] = Field(default_factory=list)


class MemoryBlockList(BaseModel):
    program: str
    total: int
    blocks: list[MemoryBlock]


# ------------------------------------------------------------- edits


# ------------------------------------------------------------ data types


class TypeSummary(BaseModel):
    name: str
    path: str = Field(description="Full category path, e.g. /recovered/record. "
                      "Unambiguous where a name is not.")
    kind: str = Field(description="struct, union, enum, typedef, pointer, array, "
                      "function, builtin or other.")
    size: int = Field(description="Length in bytes; -1 or 0 for dynamic or undefined sizes.")
    category: str


class TypeList(BaseModel):
    program: str
    total: int
    returned: int
    truncated: bool = False
    types: list[TypeSummary]


class TypeField(BaseModel):
    offset: int
    size: int
    type: str
    name: str | None = None
    comment: str | None = None
    bitfield: bool = False


class EnumMember(BaseModel):
    name: str
    value: int


class TypeDetail(TypeSummary):
    description: str | None = None
    packed: bool | None = Field(default=None, description="Composites only: whether "
                                "the compiler's packing rules place the fields.")
    fields: list[TypeField] | None = None
    members: list[EnumMember] | None = None
    base_type: str | None = Field(default=None, description="Typedefs only.")


class TypeLookup(BaseModel):
    target: str
    ok: bool
    type: TypeDetail | None = None
    error: str | None = None
    error_kind: str | None = None


class TypeInfoBatch(BaseModel):
    program: str
    total: int
    succeeded: int
    failed: int
    results: list[TypeLookup]


class EditResult(BaseModel):
    index: int = Field(description="Position in the submitted batch, for retrying.")
    kind: str
    ok: bool
    detail: str | None = Field(default=None, description="What changed, on success.")
    error: str | None = None
    error_kind: str | None = None


class EditBatchResult(BaseModel):
    program: str
    applied: int
    failed: int
    results: list[EditResult]


# --------------------------------------------------------- call graph


class CallGraphNode(BaseModel):
    id: str = Field(description="Mermaid node id, e.g. n0.")
    name: str


class CallGraph(BaseModel):
    program: str
    function: str
    address: str
    direction: str
    requested_depth: int
    reached_depth: int = Field(
        description="Levels actually traversed; lower than requested when the "
        "graph ran out before the depth limit."
    )
    node_count: int
    edge_count: int
    truncated: bool = Field(description="True when the node cap stopped expansion.")
    nodes: list[CallGraphNode]
    mermaid: str = Field(description="MermaidJS flowchart source, ready to render.")


# ---------------------------------------------------------- control flow


class BasicBlock(BaseModel):
    start: str
    end: str = Field(description="Last address in the block, inclusive.")
    size: int


class CfgEdge(BaseModel):
    source: str = Field(description="Start of the block the edge leaves.")
    target: str = Field(description="Start of the block it enters.")
    kind: str = Field(description="fall_through, conditional, unconditional or indirect.")


class FunctionCfg(BaseModel):
    target: str
    ok: bool
    function: str | None = None
    address: str | None = None
    block_count: int | None = None
    edge_count: int | None = None
    blocks: list[BasicBlock] = Field(default_factory=list)
    edges: list[CfgEdge] = Field(default_factory=list)
    error: str | None = None
    error_kind: str | None = None


class CfgBatch(BaseModel):
    program: str
    total: int
    succeeded: int
    failed: int
    results: list[FunctionCfg]


class PathStep(BaseModel):
    name: str
    address: str


class CallPaths(BaseModel):
    program: str
    source: str
    target: str
    max_depth: int
    path_count: int
    truncated: bool = Field(description="True when max_paths stopped the search; "
                            "more paths may exist.")
    paths: list[list[PathStep]] = Field(description="Each path runs from source to "
                                        "target, both included.")


# -------------------------------------------------------- code search


class CodeMatch(BaseModel):
    function: str
    address: str
    score: float | None = Field(
        default=None, description="Cosine similarity, semantic mode only."
    )
    line_number: int | None = Field(
        default=None, description="First matching line, literal mode only."
    )
    line: str | None = None
    match_count: int | None = Field(
        default=None, description="Matching lines in this function, literal mode only."
    )
    snippet: str | None = None


class CodeSearchResults(BaseModel):
    program: str
    query: str
    mode: str
    backend: str = Field(
        description="Ranking backend: 'regex' for literal, 'tfidf' for semantic."
    )
    indexed_functions: int
    from_cache: bool = Field(
        description="False when this call had to decompile the binary first."
    )
    returned: int
    matches: list[CodeMatch]


class CodeSearchProjectResults(BaseModel):
    query: str
    mode: str
    backend: str = Field(
        description="Ranking backend: 'regex' for literal, 'tfidf' for semantic."
    )
    programs_searched: int = Field(
        description="Programs that returned a result. Excludes any in `failures`."
    )
    total_matches: int
    results: list[CodeSearchResults] = Field(
        description="One entry per program, each naming its own program."
    )
    failures: list[ProgramFailure] = Field(default_factory=list)


# --------------------------------------------------- project management


class ProjectFile(BaseModel):
    name: str
    pathname: str
    content_type: str | None = None
    is_busy: bool = False


class DeleteResult(BaseModel):
    program: str
    deleted: bool
    deleted_project: bool = Field(
        default=False,
        description="True when the program was the project's last, so the whole "
        "project was removed to delete it.",
    )
    detail: str


# ------------------------------------------------------ raw memory search


class MemoryHit(BaseModel):
    address: str
    encoding: str = Field(description="ascii, utf16le, utf16be, or hex.")
    block: str | None = None
    in_function: str | None = None


class MemorySearchResults(BaseModel):
    program: str
    query: str
    count: int
    truncated: bool = False
    hits: list[MemoryHit]
