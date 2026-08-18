"""Typed errors mirroring the Java side's error envelope.

The export script returns {"ok": false, "error": {"kind": ..., "message": ...}}.
`from_envelope` maps each kind onto a Python exception so tools can fail
precisely instead of raising bare RuntimeError with a formatted string.
"""


class HeadlessError(RuntimeError):
    """Base for every failure reaching the caller from the Ghidra side."""

    kind = "error"


class NotFound(HeadlessError):
    """A named function, symbol, program or address does not exist."""

    kind = "not_found"


class BadArgument(HeadlessError):
    """The caller supplied an argument Ghidra could not use."""

    kind = "bad_argument"


class GhidraError(HeadlessError):
    """Ghidra itself failed: decompiler error, analysis error, IO error."""

    kind = "ghidra_error"


class HeadlessTimeout(HeadlessError):
    """analyzeHeadless exceeded its deadline."""

    kind = "timeout"


class ExportFailure(HeadlessError):
    """The export script produced no output, or output we cannot parse."""

    kind = "export_failure"


_BY_KIND = {
    cls.kind: cls for cls in (NotFound, BadArgument, GhidraError, HeadlessTimeout, ExportFailure)
}


def from_envelope(kind: str, message: str) -> HeadlessError:
    """Build the exception matching an envelope's error kind.

    Unknown kinds degrade to HeadlessError rather than raising, so a newer
    Java side can add kinds without breaking an older Python side.
    """
    return _BY_KIND.get(kind, HeadlessError)(message)
