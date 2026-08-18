"""End-to-end tests for the write path, against a real Ghidra install.

These mutate the program database, so they use their own project rather than
the read-only suite's — a rename here would otherwise invalidate the ground
truth the other module asserts.

Run with: pytest -m integration
"""

import re

import pytest

from ghmcp import config, tools
from ghmcp.errors import BadArgument, HeadlessError, NotFound
from tests.conftest import KNOWN_ADDRESS, KNOWN_FUNCTION, STARTER05

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def writable(tmp_path_factory):
    loc = tmp_path_factory.mktemp("editproj")
    config.PROJECT_LOCATION = loc
    config.PROJECT_NAME = "edit-test"
    if not STARTER05.is_file():
        pytest.skip(f"fixture binary missing: {STARTER05}")
    return tools.analyze_binary(str(STARTER05)).program


class TestPersistence:
    def test_a_rename_survives_a_fresh_jvm(self, writable):
        """The property the whole write path depends on."""
        tools.rename_function(writable, KNOWN_ADDRESS, "verify_license_key")
        # A separate call is a separate JVM; nothing is cached between them.
        found = tools.list_functions(writable, pattern="^verify_license_key$")
        assert found.total == 1
        assert found.functions[0].address == KNOWN_ADDRESS

    def test_the_old_name_is_gone(self, writable):
        assert tools.list_functions(writable, pattern=f"^{KNOWN_FUNCTION}$").total == 0

    def test_rename_back_restores_it(self, writable):
        tools.rename_function(writable, KNOWN_ADDRESS, KNOWN_FUNCTION)
        assert tools.list_functions(writable, pattern=f"^{KNOWN_FUNCTION}$").total == 1

    def test_read_only_tools_do_not_persist_anything(self, writable):
        before = tools.list_functions(writable, limit=1000).total
        tools.decompile_function(writable, KNOWN_FUNCTION)
        tools.disassemble(writable, KNOWN_FUNCTION)
        assert tools.list_functions(writable, limit=1000).total == before


class TestComments:
    @pytest.mark.parametrize(
        "ctype", ["decompiler", "pre", "eol", "post", "plate", "repeatable"]
    )
    def test_every_comment_type_applies(self, writable, ctype):
        """Ghidra 12 replaced the int constants with a CommentType enum."""
        out = tools.set_comment(writable, KNOWN_ADDRESS, f"note-{ctype}", ctype)
        assert out.ok is True
        assert ctype in out.detail

    def test_a_decompiler_comment_reaches_the_pseudo_c(self, writable):
        marker = "MARKER_COMMENT_FOR_TEST"
        tools.set_comment(writable, KNOWN_ADDRESS, marker, "decompiler")
        assert marker in tools.decompile_function(writable, KNOWN_FUNCTION).c

    def test_an_unknown_comment_type_is_rejected_by_java(self, writable):
        """Reported per-edit, not raised: edits are isolated from each other.

        Bypasses the Python validator to check the Java side guards it too,
        since export() is callable directly.
        """
        from ghmcp import headless as hl

        out = hl.export(
            writable, "edit",
            {"edits": [{"kind": "set_comment", "address": KNOWN_ADDRESS,
                        "comment": "x", "comment_type": "sidebar"}]},
            write=True,
        )
        assert out["failed"] == 1 and out["applied"] == 0
        assert out["results"][0]["error_kind"] == "bad_argument"
        assert "comment_type" in out["results"][0]["error"]

    def test_the_python_validator_rejects_it_before_a_jvm_starts(self, writable):
        with pytest.raises(BadArgument, match="comment_type"):
            tools.set_comment(writable, KNOWN_ADDRESS, "x", "sidebar")


class TestVariables:
    def _a_decompiler_local(self, program):
        """Find a synthesised local name in the decompiled output."""
        c = tools.decompile_function(program, KNOWN_FUNCTION).c
        names = re.findall(r"\b(local_[0-9a-f]+|[iu]Var\d+)\b", c)
        if not names:
            pytest.skip("no decompiler-synthesised local found in this function")
        return names[0]

    def test_renaming_a_decompiler_local_works(self, writable):
        """Variable.setName alone cannot touch these; HighFunctionDBUtil can."""
        original = self._a_decompiler_local(writable)
        out = tools.rename_variable(writable, KNOWN_FUNCTION, original, "renamed_local")
        assert out.ok is True

        c = tools.decompile_function(writable, KNOWN_FUNCTION).c
        assert "renamed_local" in c

    def test_renaming_a_missing_variable_reports_not_found(self, writable):
        with pytest.raises(NotFound, match="no variable named"):
            tools.rename_variable(writable, KNOWN_FUNCTION, "no_such_var", "x")

    def test_setting_a_variable_type_works(self, writable):
        original = self._a_decompiler_local(writable)
        out = tools.set_variable_type(writable, KNOWN_FUNCTION, original, "int")
        assert out.ok is True

    def test_an_unparseable_type_is_rejected(self, writable):
        original = self._a_decompiler_local(writable)
        with pytest.raises(HeadlessError):
            tools.set_variable_type(writable, KNOWN_FUNCTION, original,
                                    "struct NoSuchTypeAnywhere")


class TestPrototype:
    def test_setting_a_prototype_changes_the_signature(self, writable):
        tools.set_function_prototype(
            writable, KNOWN_FUNCTION, "int check_key(char *key)"
        )
        found = tools.list_functions(writable, pattern=f"^{KNOWN_FUNCTION}$")
        assert "char *" in found.functions[0].signature

    def test_an_unparseable_prototype_returns_ghidras_own_error(self, writable):
        with pytest.raises(HeadlessError) as exc:
            tools.set_function_prototype(writable, KNOWN_FUNCTION, "this is not a prototype")
        assert str(exc.value)


class TestData:
    def test_naming_a_data_address_works(self, writable):
        strings = tools.list_strings(writable, pattern="keygen-me", limit=1)
        addr = strings.strings[0].address
        out = tools.rename_data(writable, addr, "g_banner_text")
        assert out.ok is True
        found = tools.list_symbols(writable, kind="data", pattern="^g_banner_text$",
                                   limit=10)
        assert found.total == 1


class TestBatch:
    def test_a_batch_applies_every_edit_in_one_call(self, writable):
        out = tools.apply_edits(writable, [
            {"kind": "set_comment", "address": KNOWN_ADDRESS, "comment": "batch-1"},
            {"kind": "set_comment", "address": KNOWN_ADDRESS, "comment": "batch-2",
             "comment_type": "eol"},
            {"kind": "rename_function", "target": KNOWN_ADDRESS,
             "new_name": "batch_renamed"},
        ])
        assert out.applied == 3 and out.failed == 0
        assert tools.list_functions(writable, pattern="^batch_renamed$").total == 1
        tools.rename_function(writable, KNOWN_ADDRESS, KNOWN_FUNCTION)

    def test_one_bad_edit_does_not_discard_the_good_ones(self, writable):
        out = tools.apply_edits(writable, [
            {"kind": "set_comment", "address": KNOWN_ADDRESS, "comment": "survives"},
            {"kind": "rename_function", "target": "no_such_function_at_all",
             "new_name": "x"},
            {"kind": "set_comment", "address": KNOWN_ADDRESS, "comment": "also survives",
             "comment_type": "eol"},
        ])
        assert out.applied == 2 and out.failed == 1
        assert [r.ok for r in out.results] == [True, False, True]
        assert out.results[1].index == 1
        assert out.results[1].error_kind == "not_found"

    def test_an_empty_batch_is_rejected_by_java_too(self, writable):
        from ghmcp import headless as hl

        with pytest.raises(BadArgument, match="at least one edit"):
            hl.export(writable, "edit", {"edits": []}, write=True)

    def test_an_unknown_edit_kind_is_rejected_by_java(self, writable):
        from ghmcp import headless as hl

        out = hl.export(
            writable, "edit", {"edits": [{"kind": "drop_database"}]}, write=True
        )
        assert out["failed"] == 1
        assert "unknown edit kind" in out["results"][0]["error"]
