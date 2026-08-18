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
    exit_code: int
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
    symbols: list[SymbolEntry]


class MemoryBlockList(BaseModel):
    program: str
    total: int
    blocks: list[MemoryBlock]
