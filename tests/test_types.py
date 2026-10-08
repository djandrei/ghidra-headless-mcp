"""Data types: edit validation, and list_types / get_type over a faked export.

No JVM. The Java half is exercised for real in test_integration_types.py.
"""

import pytest

from ghmcp import tools
from ghmcp.errors import BadArgument
from ghmcp.tools import validate_edits


def _one(**edit):
    return validate_edits([edit])


# --------------------------------------------------------------- validation


class TestDefineType:
    def test_a_declaration_is_enough(self):
        assert _one(kind="define_type", c="struct s { int a; };")

    @pytest.mark.parametrize("policy", ["error", "replace", "rename"])
    def test_each_conflict_policy_is_accepted(self, policy):
        assert _one(kind="define_type", c="struct s { int a; };", on_conflict=policy)

    def test_an_unknown_conflict_policy_is_refused(self):
        with pytest.raises(BadArgument, match="on_conflict"):
            _one(kind="define_type", c="struct s { int a; };", on_conflict="merge")


class TestStructField:
    def test_add_needs_a_type_but_no_location(self):
        assert _one(kind="struct_field", struct="s", action="add", type="int", name="x")
        with pytest.raises(BadArgument, match="'type'"):
            _one(kind="struct_field", struct="s", action="add", name="x")

    @pytest.mark.parametrize("action, extra", [
        ("rename", {"new_name": "y"}),
        ("replace", {"type": "int"}),
        ("comment", {"comment": "note"}),
        ("clear", {}),
    ])
    def test_other_actions_locate_a_field_by_offset_or_name(self, action, extra):
        assert _one(kind="struct_field", struct="s", action=action, offset=0, **extra)
        assert _one(kind="struct_field", struct="s", action=action, name="x", **extra)
        with pytest.raises(BadArgument, match="offset or name"):
            _one(kind="struct_field", struct="s", action=action, **extra)

    def test_offset_zero_counts_as_given(self):
        """0 is falsy; a truthiness check would wrongly demand a name."""
        assert _one(kind="struct_field", struct="s", action="clear", offset=0)

    def test_an_action_missing_its_field_is_refused(self):
        with pytest.raises(BadArgument, match="'new_name'"):
            _one(kind="struct_field", struct="s", action="rename", offset=4)

    def test_an_unknown_action_is_refused(self):
        with pytest.raises(BadArgument, match="action must be one of"):
            _one(kind="struct_field", struct="s", action="move", offset=4)


class TestEnumMember:
    def test_add_with_a_value_and_remove_without(self):
        assert _one(kind="enum_member", enum="e", action="add", name="A", value=0)
        assert _one(kind="enum_member", enum="e", action="remove", name="A")

    @pytest.mark.parametrize("value", [None, "3", 1.5])
    def test_add_needs_an_integer_value(self, value):
        with pytest.raises(BadArgument, match="integer value"):
            _one(kind="enum_member", enum="e", action="add", name="A", value=value)

    def test_an_unknown_action_is_refused(self):
        with pytest.raises(BadArgument, match="add or remove"):
            _one(kind="enum_member", enum="e", action="rename", name="A")


@pytest.mark.parametrize("edit", [
    {"kind": "apply_type", "address": "00401000", "type": "int"},
    {"kind": "delete_type", "type": "/recovered/s"},
    {"kind": "fill_struct", "function": "f", "variable": "param_1"},
])
def test_the_simple_kinds_validate(edit):
    assert validate_edits([edit])


def test_a_type_batch_reaches_the_edit_mode_as_a_write(fake_headless):
    fake_headless.envelope = {"ok": True, "mode": "edit", "data": {
        "applied": 1, "failed": 0,
        "results": [{"index": 0, "kind": "define_type", "ok": True,
                     "detail": "defined struct /s (4 bytes)"}]}}

    out = tools.apply_edits("p", [{"kind": "define_type", "c": "struct s { int a; };"}])

    assert out.applied == 1
    assert fake_headless.last_spec["mode"] == "edit"
    assert "-readOnly" not in fake_headless.last


# --------------------------------------------------------------- list_types


TYPES = [
    {"name": "color", "path": "/fixture/color", "kind": "enum", "size": 4, "category": "/fixture"},
    {"name": "record", "path": "/fixture/record", "kind": "struct", "size": 32,
     "category": "/fixture"},
]


def test_list_types_pages_and_passes_the_filters(fake_headless):
    fake_headless.envelope = {"ok": True, "mode": "types",
                              "data": {"matched": 2, "truncated": False, "types": TYPES}}

    out = tools.list_types("p", pattern="o", category="/fixture", kind="struct",
                           limit=1, offset=1)

    assert fake_headless.last_spec["args"] == {"pattern": "o", "category": "/fixture",
                                               "kind": "struct"}
    assert (out.total, out.returned) == (2, 1)
    assert out.types[0].name == "record"
    assert "-readOnly" in fake_headless.last


# ----------------------------------------------------------------- get_type


def test_get_type_reports_each_name(fake_headless):
    fake_headless.envelope = {"ok": True, "mode": "type_info", "data": {"results": [
        {"target": "record", "ok": True, "type": {
            **TYPES[1], "packed": True,
            "fields": [{"offset": 0, "size": 4, "type": "int", "name": "id",
                        "comment": None, "bitfield": False}]}},
        {"target": "color", "ok": True, "type": {
            **TYPES[0], "members": [{"name": "RED", "value": 1}]}},
        {"target": "nope", "ok": False, "error": "unknown data type: nope",
         "error_kind": "bad_argument"},
    ]}}

    out = tools.get_type("p", ["record", "color", "nope"])

    assert fake_headless.last_spec["args"] == {"names": ["record", "color", "nope"]}
    assert (out.total, out.succeeded, out.failed) == (3, 2, 1)
    assert out.results[0].type.fields[0].name == "id"
    assert out.results[1].type.members[0].value == 1
    assert out.results[2].error_kind == "bad_argument"


def test_get_type_takes_a_single_name(fake_headless):
    fake_headless.envelope = {"ok": True, "mode": "type_info", "data": {"results": []}}

    tools.get_type("p", "record")

    assert fake_headless.last_spec["args"] == {"names": ["record"]}


def test_get_type_refuses_no_names():
    with pytest.raises(BadArgument):
        tools.get_type("p", [])
