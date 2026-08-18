"""Tests that the response models accept real payloads and reject broken ones."""

import pytest
from pydantic import ValidationError

from ghmcp import models

INFO = {
    "name": "starter05.x86_64",
    "executable_path": "/tmp/starter05.x86_64",
    "executable_format": "Executable and Linking Format (ELF)",
    "md5": "aa" * 16,
    "sha256": "bb" * 32,
    "language_id": "x86:LE:64:default",
    "compiler_spec_id": "gcc",
    "image_base": "00400000",
    "function_count": 24,
    "symbol_count": 100,
    "memory_blocks": [
        {
            "name": ".text",
            "start": "00401000",
            "end": "00401fff",
            "size": 4096,
            "readable": True,
            "writable": False,
            "executable": True,
        }
    ],
}


def test_program_info_accepts_a_full_payload():
    info = models.ProgramInfo(**INFO)
    assert info.function_count == 24
    assert info.memory_blocks[0].executable is True


def test_program_info_tolerates_null_hashes():
    """Ghidra leaves these null for some formats; that must not be fatal."""
    payload = {**INFO, "md5": None, "sha256": None, "executable_path": None}
    assert models.ProgramInfo(**payload).md5 is None


def test_program_info_defaults_memory_blocks_to_empty():
    payload = {k: v for k, v in INFO.items() if k != "memory_blocks"}
    assert models.ProgramInfo(**payload).memory_blocks == []


@pytest.mark.parametrize("missing", ["name", "language_id", "image_base", "function_count"])
def test_program_info_requires_its_core_fields(missing):
    payload = {k: v for k, v in INFO.items() if k != missing}
    with pytest.raises(ValidationError):
        models.ProgramInfo(**payload)


def test_function_summary_defaults_flags_to_false():
    f = models.FunctionSummary(
        name="main", address="00401146", size=10, signature="int main(void)"
    )
    assert f.is_thunk is False and f.is_external is False


def test_function_count_must_be_an_integer():
    with pytest.raises(ValidationError):
        models.ProgramInfo(**{**INFO, "function_count": "many"})


def test_decompilation_requires_c_text():
    with pytest.raises(ValidationError):
        models.Decompilation(program="p", name="f", address="0")


def test_string_hit_round_trips_control_characters():
    hit = models.StringHit(address="004020a8", length=5, value="a\nb\tc")
    assert hit.value == "a\nb\tc"


def test_analysis_result_nests_program_info():
    res = models.AnalysisResult(
        program="p", already_analyzed=False, duration_seconds=4.8,
        info=models.ProgramInfo(**INFO),
    )
    assert res.info.language_id == "x86:LE:64:default"
