"""Shared support for the surface tests: every tool, called through every door.

The tools' own logic is tested elsewhere, function by function. What the
surface tests check is the wiring each transport adds on top: the published
schema, how JSON arguments are coerced into Python, how a result is
serialised, and how a failure is reported. So each registered tool's function
is swapped for a fake that records what it received and returns an example of
its real return type. The tool's argument model, built from the real
signature at registration, is untouched.

VALID_ARGS must name every registered tool: test_surfaces checks that, so a new
tool cannot ship without passing through every surface.
"""

import contextlib
import inspect
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import types
import typing
from pathlib import Path
from typing import Any, Literal, Union, get_args, get_origin, get_type_hints

import httpx
from pydantic import BaseModel

from ghmcp.tools import mcp

# One valid call per tool. Values exercise the coercions that matter: lists
# where a parameter takes str | list[str], dicts, ints, hex strings, booleans.
VALID_ARGS: dict[str, dict[str, Any]] = {
    "analyze_binaries": {"paths": ["/samples/a.bin", "/samples/b.bin"], "recursive": False},
    "analyze_binary": {"binary_path": "/samples/a.bin", "force": True,
                       "analyzer_options": {"Decompiler Parameter ID": True, "X.Timeout": 30}},
    "apply_edits": {"program": "p", "edits": [
        {"kind": "rename_function", "target": "FUN_1", "new_name": "check"},
        {"kind": "define_type", "c": "struct s { int a; };"}]},
    "clear_code_cache": {"program": "p"},
    "decompile_function": {"program": "p", "function": ["main", "00401000"]},
    "delete_program": {"program": "p"},
    "delete_upload": {"filename": "a.bin"},
    "disassemble": {"program": "p", "target": "main", "count": 20, "include_bytes": True},
    "find_call_paths": {"program": "p", "source": "main", "target": "sink", "max_depth": 4},
    "gen_callgraph": {"program": "p", "function": "main", "direction": "calling", "depth": 2},
    "get_cfg": {"program": "p", "function": ["main", "classify"]},
    "get_function_at": {"program": "p", "address": "00401010"},
    "get_program_info": {"program": "p"},
    "get_type": {"program": "p", "name": ["record", "/fixture/color"]},
    "list_analysis_options": {"program": "p", "pattern": "decompiler", "analyzers_only": True},
    "list_chat_uploads": {"pattern": "keycheck", "limit": 5},
    "list_functions": {"program": "p", "pattern": "^check", "limit": 10, "offset": 5},
    "list_memory_blocks": {"program": "p"},
    "list_programs": {"refresh": True},
    "list_strings": {"program": "p", "pattern": "https?://", "min_length": 6},
    "list_symbols": {"program": "p", "kind": "import", "pattern": "Crypt"},
    "list_symbols_project": {"kind": "export", "programs": ["a.dll", "b.dll"]},
    "list_types": {"program": "p", "category": "/fixture", "kind": "struct"},
    "list_uploads": {},
    "list_xrefs_from": {"program": "p", "target": "main"},
    "list_xrefs_to": {"program": ["p", "q"], "target": ["check_key", "00401176"]},
    "read_bytes": {"program": "p", "address": "00401000", "size": 16},
    "reanalyze": {"program": "p", "analyzer_options": {"Decompiler Parameter ID": False}},
    "rename_data": {"program": "p", "address": "00402000", "new_name": "g_key"},
    "rename_function": {"program": "p", "target": "FUN_1", "new_name": "check"},
    "rename_variable": {"program": "p", "function": "check", "variable": "local_10",
                        "new_name": "length"},
    "resolve_symbol": {"name": ["CreateFileW", "ReadFile"], "programs": "*"},
    "run_ghidra_script": {"program": "p", "script_name": "CountInstructions.java",
                          "script_args": ["a", "b"], "read_only": True},
    "search_code": {"program": "p", "query": "validate key", "mode": "semantic", "limit": 3},
    "search_code_project": {"query": "xor", "programs": "*", "mode": "literal"},
    "search_constants": {"program": "*", "value": "0xC0FFEE42"},
    "search_instructions": {"program": ["p", "q"], "mnemonic": "syscall"},
    "search_memory": {"program": "p", "hex": "deadbeef"},
    "set_comment": {"program": "p", "address": "00401000", "comment": "note",
                    "comment_type": "plate"},
    "set_function_prototype": {"program": "p", "target": "check",
                               "prototype": "int check(char *key)"},
    "set_variable_type": {"program": "p", "function": "check", "variable": "param_1",
                          "type": "char *"},
    "upload_binary": {"filename": "a.bin", "content_base64": "f0VMRg==", "analyze": True,
                      "keep": False},
}

# A wrongly-typed value per tool that has an integer or boolean parameter:
# the surface must refuse it before the tool runs.
WRONG_TYPE: dict[str, dict[str, Any]] = {
    "read_bytes": {"program": "p", "address": "00401000", "size": "sixteen"},
    "list_functions": {"program": "p", "limit": "many"},
    "find_call_paths": {"program": "p", "source": "a", "target": "b", "max_depth": [1]},
    "list_programs": {"refresh": {"yes": 1}},
    "disassemble": {"program": "p", "target": "main", "count": "lots"},
}


def registered_tools() -> dict:
    return dict(mcp._tool_manager._tools)


# The real functions, captured before any test swaps them for fakes: their
# signatures and return annotations are what the surfaces must honour.
ORIGINAL_FNS = {name: tool.fn for name, tool in registered_tools().items()}


def required_params(name: str) -> set[str]:
    sig = inspect.signature(ORIGINAL_FNS[name])
    return {p.name for p in sig.parameters.values() if p.default is inspect.Parameter.empty}


# --------------------------------------------------------- example results


def example(tp: Any) -> Any:
    """A minimal valid value of a type annotation, models included.

    Every field gets a value — optional ones too — so serialisation is
    exercised for each, not skipped as null.
    """
    origin = get_origin(tp)
    if origin in (Union, types.UnionType):
        first = next(a for a in get_args(tp) if a is not type(None))
        return example(first)
    if origin is Literal:
        return get_args(tp)[0]
    if origin in (list, typing.List):
        (item,) = get_args(tp) or (str,)
        return [example(item)]
    if origin in (dict, typing.Dict):
        key, value = get_args(tp) or (str, str)
        return {example(key): example(value)}
    if isinstance(tp, type) and issubclass(tp, BaseModel):
        hints = get_type_hints(tp)
        data = {}
        for name, field in tp.model_fields.items():
            data[field.alias or name] = example(hints[name])
        return tp.model_validate(data)
    return {str: "x", int: 1, float: 1.5, bool: True, dict: {"k": "v"}, Any: "x"}.get(tp, "x")


def return_example(name: str) -> Any:
    hints = get_type_hints(ORIGINAL_FNS[name])
    return example(hints["return"])


def as_json(value: Any) -> Any:
    """What a result looks like on the wire."""
    return value.model_dump(mode="json") if isinstance(value, BaseModel) else value


class FakeTools:
    """Swaps every registered tool function for a recorder; restores on undo().

    `calls[name]` holds the keyword arguments each call received, after the
    surface parsed and coerced them. `raises[name]` makes that tool raise.
    """

    def __init__(self, monkeypatch):
        self.calls: dict[str, list[dict]] = {}
        self.raises: dict[str, Exception] = {}
        self.results = {name: return_example(name) for name in registered_tools()}
        for name, tool in registered_tools().items():
            monkeypatch.setattr(tool, "fn", self._fake(name))

    def _fake(self, name):
        def fake(**kwargs):
            self.calls.setdefault(name, []).append(kwargs)
            if name in self.raises:
                raise self.raises[name]
            return self.results[name]
        return fake


# ------------------------------------------------------------------- mcpo

ROOT = Path(__file__).resolve().parents[1]
MCPO = Path(sys.executable).parent / "mcpo"
MCPO_AVAILABLE = MCPO.exists() or shutil.which("mcpo") is not None


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def serve_mcpo(tmp: Path, key: str, env: dict[str, str]):
    """serve-mcpo.sh — the container's CMD — on a free loopback port.

    Yields the base URL. The whole process group is stopped afterwards: the
    script execs mcpo, which spawns the server.
    """
    port = free_port()
    full_env = {**os.environ, "GHMCP_API_KEY": key, "MCPO_PORT": str(port),
                "MCPO_HOST": "127.0.0.1", "PYTHON": sys.executable, **env}
    full_env.pop("OPENWEBUI_UPLOADS_DIR", None)
    if MCPO.exists():
        full_env["MCPO"] = str(MCPO)
    log_path = tmp / "mcpo.log"
    with open(log_path, "w") as log:
        proc = subprocess.Popen([str(ROOT / "serve-mcpo.sh")], cwd=ROOT, env=full_env,
                                stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        base = f"http://127.0.0.1:{port}"
        try:
            deadline = time.monotonic() + 60
            while True:
                try:
                    if httpx.get(f"{base}/openapi.json", timeout=2).is_success:
                        break
                except httpx.TransportError:
                    pass
                if proc.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("serve-mcpo.sh did not come up:\n" + log_path.read_text())
                time.sleep(0.3)
            yield base
        finally:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=20)
