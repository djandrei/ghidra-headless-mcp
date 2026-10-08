"""Data types against real Ghidra: define, apply, edit and infer structures.

The fixture's score_record reads struct record through its parameter, so the
proof that a type took is the decompiler printing p->field instead of pointer
arithmetic. Tests share one project and run in file order: fill_struct first,
while the parameter is still untyped.

Run with: pytest -m integration
"""

import pytest

from ghmcp import tools
from tests.conftest import LAYOUT_STRUCT_FN, analyse_layout

pytestmark = pytest.mark.integration

RECORD = """struct record {
    int id; short flags; short kind; int weight; char tag[12]; long long total;
};"""
COLOR = "enum color { RED = 1, GREEN = 2, BLUE = 4, ALPHA = 8 };"


@pytest.fixture(scope="module")
def prog(tmp_path_factory):
    return analyse_layout(tmp_path_factory, "types").program


def edits(prog, *batch):
    return tools.apply_edits(prog, list(batch))


def fields(prog, name):
    [r] = tools.get_type(prog, name).results
    assert r.ok, r.error
    return r.type


def test_fill_struct_infers_the_layout_from_pointer_use(prog):
    out = edits(prog, {"kind": "fill_struct", "function": LAYOUT_STRUCT_FN,
                       "variable": "param_1", "name": "inferred_record"})
    assert out.applied == 1, out.results[0].error
    t = fields(prog, "inferred_record")
    offsets = {f.offset for f in t.fields}
    assert {0, 4, 6, 8, 12, 0x18} <= offsets
    assert "->" in tools.decompile_function(prog, LAYOUT_STRUCT_FN).c


def test_fill_struct_on_a_missing_variable_fails_alone(prog):
    out = edits(prog, {"kind": "fill_struct", "function": LAYOUT_STRUCT_FN, "variable": "nope"})
    assert out.failed == 1 and out.results[0].error_kind == "not_found"


def test_define_types_from_c(prog):
    out = edits(prog,
                {"kind": "define_type", "c": COLOR, "category": "/fixture"},
                {"kind": "define_type", "c": RECORD, "category": "/fixture"})
    assert out.applied == 2, [r.error for r in out.results]
    t = fields(prog, "/fixture/record")
    assert t.kind == "struct" and t.size == 32 and t.packed
    assert [(f.offset, f.name) for f in t.fields] == [
        (0, "id"), (4, "flags"), (6, "kind"), (8, "weight"), (12, "tag"), (24, "total")]
    color = fields(prog, "/fixture/color")
    assert {(m.name, m.value) for m in color.members} == {
        ("RED", 1), ("GREEN", 2), ("BLUE", 4), ("ALPHA", 8)}


def test_redefining_is_refused_by_default_and_the_batch_continues(prog):
    out = edits(prog,
                {"kind": "define_type", "c": RECORD, "category": "/fixture"},
                {"kind": "define_type", "c": "typedef int score_t;", "category": "/fixture"})
    assert [r.ok for r in out.results] == [False, True]
    assert out.results[0].error_kind == "bad_argument"
    assert "on_conflict" in out.results[0].error


def test_on_conflict_replace_and_rename(prog):
    out = edits(prog,
                {"kind": "define_type", "c": "struct scratch { int a; };", "category": "/fixture"},
                {"kind": "define_type", "c": "struct scratch { int a; int b; };",
                 "category": "/fixture", "on_conflict": "replace"},
                {"kind": "define_type", "c": "struct scratch { char c; };",
                 "category": "/fixture", "on_conflict": "rename"})
    assert out.applied == 3, [r.error for r in out.results]
    assert fields(prog, "/fixture/scratch").size == 8
    renamed = tools.list_types(prog, pattern="scratch", category="/fixture").types
    assert len(renamed) == 2


def test_a_bad_declaration_is_a_bad_argument(prog):
    out = edits(prog, {"kind": "define_type", "c": "struct { int ; garbage", "category": "/fixture"})
    assert out.results[0].error_kind == "bad_argument"


def test_typing_the_parameter_turns_offsets_into_fields(prog):
    out = edits(prog, {"kind": "set_variable_type", "function": LAYOUT_STRUCT_FN,
                       "variable": "param_1", "type": "/fixture/record *"})
    assert out.applied == 1, out.results[0].error
    c = tools.decompile_function(prog, LAYOUT_STRUCT_FN).c
    assert "->weight" in c and "->total" in c


def test_struct_field_edits(prog):
    out = edits(prog,
                {"kind": "struct_field", "struct": "/fixture/record", "action": "rename",
                 "offset": 8, "new_name": "importance"},
                {"kind": "struct_field", "struct": "/fixture/record", "action": "comment",
                 "name": "flags", "comment": "bit 0: kind counts"},
                {"kind": "struct_field", "struct": "/fixture/record", "action": "replace",
                 "offset": "0x6", "type": "ushort"},
                {"kind": "struct_field", "struct": "/fixture/record", "action": "add",
                 "type": "int", "name": "appended"},
                {"kind": "struct_field", "struct": "/fixture/record", "action": "rename",
                 "offset": 99, "new_name": "x"})
    assert [r.ok for r in out.results] == [True, True, True, True, False]
    assert out.results[4].error_kind == "not_found"
    t = {f.offset: f for f in fields(prog, "/fixture/record").fields}
    assert t[8].name == "importance"
    assert t[4].comment == "bit 0: kind counts"
    assert t[6].type == "ushort" and t[6].name == "kind"
    assert any(f.name == "appended" for f in t.values())
    assert "->importance" in tools.decompile_function(prog, LAYOUT_STRUCT_FN).c


def test_clearing_a_packed_field_removes_it(prog):
    out = edits(prog, {"kind": "struct_field", "struct": "/fixture/record",
                       "action": "clear", "name": "appended"})
    assert out.applied == 1, out.results[0].error
    assert all(f.name != "appended" for f in fields(prog, "/fixture/record").fields)


def test_adding_at_an_offset_of_a_packed_struct_is_refused(prog):
    out = edits(prog, {"kind": "struct_field", "struct": "/fixture/record", "action": "add",
                       "offset": 4, "type": "int", "name": "x"})
    assert out.results[0].error_kind == "bad_argument" and "packed" in out.results[0].error


def test_enum_members(prog):
    out = edits(prog,
                {"kind": "enum_member", "enum": "/fixture/color", "action": "add",
                 "name": "CYAN", "value": 16},
                {"kind": "enum_member", "enum": "/fixture/color", "action": "remove",
                 "name": "ALPHA"},
                {"kind": "enum_member", "enum": "/fixture/color", "action": "remove",
                 "name": "MAGENTA"})
    assert [r.ok for r in out.results] == [True, True, False]
    names = {m.name for m in fields(prog, "/fixture/color").members}
    assert "CYAN" in names and "ALPHA" not in names


def test_apply_type_respects_existing_data_unless_cleared(prog):
    hit = tools.list_strings(prog, pattern="licensed").strings[0]
    kept = edits(prog, {"kind": "apply_type", "address": hit.address, "type": "dword"})
    assert kept.results[0].error_kind == "bad_argument" and "clear=true" in kept.results[0].error
    cleared = edits(prog, {"kind": "apply_type", "address": hit.address, "type": "dword",
                           "clear": True})
    assert cleared.applied == 1, cleared.results[0].error


def test_list_types_filters_by_kind_and_category(prog):
    out = tools.list_types(prog, category="/fixture", kind="enum")
    assert [t.path for t in out.types] == ["/fixture/color"]


def test_delete_type(prog):
    out = edits(prog, {"kind": "delete_type", "type": "/fixture/score_t"})
    assert out.applied == 1, out.results[0].error
    [r] = tools.get_type(prog, "/fixture/score_t").results
    assert not r.ok and r.error_kind == "not_found"


def test_get_type_isolates_a_missing_name(prog):
    out = tools.get_type(prog, ["/fixture/record", "no_such_type_anywhere"])
    assert (out.succeeded, out.failed) == (1, 1)
