"""Unit tests for Stage 5: the write path."""

import pytest

from ghmcp import tools
from ghmcp.errors import BadArgument, GhidraError, NotFound
from ghmcp.tools import COMMENT_TYPES, EDIT_KINDS, validate_edits

RENAME = {"kind": "rename_function", "target": "FUN_1", "new_name": "check_key"}


def _ok(index=0, kind="rename_function", detail="renamed"):
    return {"index": index, "kind": kind, "ok": True, "detail": detail,
            "error": None, "error_kind": None}


def _fail(index=0, kind="rename_function", error="boom", error_kind="not_found"):
    return {"index": index, "kind": kind, "ok": False, "detail": None,
            "error": error, "error_kind": error_kind}


def _batch(results):
    return {
        "applied": sum(1 for r in results if r["ok"]),
        "failed": sum(1 for r in results if not r["ok"]),
        "results": results,
    }


class TestValidation:
    def test_accepts_a_well_formed_edit(self):
        assert validate_edits([RENAME]) == [RENAME]

    def test_rejects_an_empty_batch(self):
        with pytest.raises(BadArgument, match="at least one edit"):
            validate_edits([])

    def test_rejects_a_non_object_edit(self):
        with pytest.raises(BadArgument, match="not an object"):
            validate_edits(["rename please"])

    @pytest.mark.parametrize("kind", [None, "", "rename", "RENAME_FUNCTION", "delete_all"])
    def test_rejects_an_unknown_kind(self, kind):
        with pytest.raises(BadArgument, match="unknown kind"):
            validate_edits([{"kind": kind, "target": "a", "new_name": "b"}])

    @pytest.mark.parametrize("kind,fields", list(EDIT_KINDS.items()))
    def test_every_kind_requires_each_of_its_fields(self, kind, fields):
        # A field that takes one of a fixed set of values gets a valid one.
        valid = {"struct_field": {"action": "clear", "name": "f"},
                 "enum_member": {"action": "remove"}}.get(kind, {})
        complete = {"kind": kind, **{f: "value" for f in fields}, **valid}
        assert validate_edits([complete])
        for missing in fields:
            partial = {k: v for k, v in complete.items() if k != missing}
            with pytest.raises(BadArgument, match=missing):
                validate_edits([partial])

    @pytest.mark.parametrize("empty", ["", None, 0])
    def test_empty_field_values_are_rejected(self, empty):
        with pytest.raises(BadArgument, match="new_name"):
            validate_edits([{**RENAME, "new_name": empty}])

    def test_error_names_the_offending_index(self):
        with pytest.raises(BadArgument, match="edit 2"):
            validate_edits([RENAME, RENAME, {"kind": "nope"}])

    @pytest.mark.parametrize("ctype", COMMENT_TYPES)
    def test_every_documented_comment_type_is_accepted(self, ctype):
        validate_edits([{"kind": "set_comment", "address": "0", "comment": "c",
                         "comment_type": ctype}])

    def test_unknown_comment_type_is_rejected(self):
        with pytest.raises(BadArgument, match="comment_type"):
            validate_edits([{"kind": "set_comment", "address": "0", "comment": "c",
                             "comment_type": "sidebar"}])

    def test_comment_type_defaults_to_decompiler(self):
        validate_edits([{"kind": "set_comment", "address": "0", "comment": "c"}])


class TestApplyEdits:
    def test_uses_write_mode_so_changes_persist(self, captured_specs):
        captured_specs.stub["edit"] = _batch([_ok()])
        tools.apply_edits("p", [RENAME])
        assert captured_specs.calls[0][3] is True, "edits must not be -readOnly"

    def test_sends_the_batch_intact(self, captured_specs):
        captured_specs.stub["edit"] = _batch([_ok(0), _ok(1)])
        edits = [RENAME, {**RENAME, "new_name": "other"}]
        tools.apply_edits("p", edits)
        assert captured_specs.calls[0][2] == {"edits": edits}

    def test_reports_applied_and_failed_counts(self, captured_specs):
        captured_specs.stub["edit"] = _batch([_ok(0), _fail(1), _ok(2)])
        out = tools.apply_edits("p", [RENAME] * 3)
        assert out.applied == 2 and out.failed == 1

    def test_one_failure_does_not_discard_the_others(self, captured_specs):
        """The whole point of per-edit isolation."""
        captured_specs.stub["edit"] = _batch([_ok(0), _fail(1), _ok(2)])
        out = tools.apply_edits("p", [RENAME] * 3)
        assert [r.ok for r in out.results] == [True, False, True]

    def test_failures_carry_an_index_for_retry(self, captured_specs):
        captured_specs.stub["edit"] = _batch([_ok(0), _fail(1, error="gone")])
        out = tools.apply_edits("p", [RENAME] * 2)
        failed = [r for r in out.results if not r.ok]
        assert failed[0].index == 1 and failed[0].error == "gone"

    def test_validation_runs_before_any_jvm_start(self, captured_specs):
        with pytest.raises(BadArgument):
            tools.apply_edits("p", [{"kind": "bogus"}])
        assert captured_specs.calls == []

    def test_a_large_batch_is_one_call(self, captured_specs):
        """200 renames must cost one JVM start, not 200."""
        edits = [{**RENAME, "new_name": f"n{i}"} for i in range(200)]
        captured_specs.stub["edit"] = _batch([_ok(i) for i in range(200)])
        out = tools.apply_edits("p", edits)
        assert len(captured_specs.calls) == 1
        assert out.applied == 200


class TestSingleEditWrappers:
    @pytest.mark.parametrize(
        "call,expected_kind",
        [
            (lambda: tools.rename_function("p", "f", "g"), "rename_function"),
            (lambda: tools.rename_variable("p", "f", "v", "w"), "rename_variable"),
            (lambda: tools.rename_data("p", "0", "g"), "rename_data"),
            (lambda: tools.set_function_prototype("p", "f", "int f(void)"), "set_prototype"),
            (lambda: tools.set_variable_type("p", "f", "v", "int"), "set_variable_type"),
            (lambda: tools.set_comment("p", "0", "note"), "set_comment"),
        ],
    )
    def test_each_wrapper_sends_its_kind(self, captured_specs, call, expected_kind):
        captured_specs.stub["edit"] = _batch([_ok(kind=expected_kind)])
        call()
        sent = captured_specs.calls[0][2]["edits"]
        assert len(sent) == 1 and sent[0]["kind"] == expected_kind

    def test_wrappers_go_through_the_batch_path(self, captured_specs):
        captured_specs.stub["edit"] = _batch([_ok()])
        tools.rename_function("p", "f", "g")
        assert captured_specs.calls[0][1] == "edit"

    def test_rename_function_fields(self, captured_specs):
        captured_specs.stub["edit"] = _batch([_ok()])
        tools.rename_function("p", "FUN_1", "check_key")
        assert captured_specs.calls[0][2]["edits"][0] == RENAME

    def test_set_comment_defaults_to_decompiler(self, captured_specs):
        captured_specs.stub["edit"] = _batch([_ok(kind="set_comment")])
        tools.set_comment("p", "0", "note")
        assert captured_specs.calls[0][2]["edits"][0]["comment_type"] == "decompiler"

    def test_a_failed_single_edit_raises_its_typed_error(self, captured_specs):
        captured_specs.stub["edit"] = _batch([_fail(error_kind="not_found",
                                                    error="function not found: f")])
        with pytest.raises(NotFound, match="function not found"):
            tools.rename_function("p", "f", "g")

    def test_error_kind_selects_the_exception_class(self, captured_specs):
        captured_specs.stub["edit"] = _batch([_fail(error_kind="ghidra_error",
                                                    error="apply failed")])
        with pytest.raises(GhidraError):
            tools.set_function_prototype("p", "f", "int f(void)")

    def test_a_successful_single_edit_returns_its_detail(self, captured_specs):
        captured_specs.stub["edit"] = _batch([_ok(detail="renamed FUN_1 -> check_key")])
        out = tools.rename_function("p", "FUN_1", "check_key")
        assert out.ok is True and "check_key" in out.detail

    def test_wrapper_validation_rejects_empty_names_locally(self, captured_specs):
        with pytest.raises(BadArgument, match="new_name"):
            tools.rename_function("p", "f", "")
        assert captured_specs.calls == []
