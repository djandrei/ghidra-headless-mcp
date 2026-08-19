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
    program: str
    direction: str
    results: list[XrefTargetResult]


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


class MemoryBlockList(BaseModel):
    program: str
    total: int
    blocks: list[MemoryBlock]


# ------------------------------------------------------------- edits


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
