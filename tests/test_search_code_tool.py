"""Unit tests for the search_code tool and the decompilation cache."""

import json

import pytest

from ghmcp import headless, tools
from ghmcp.errors import BadArgument

CORPUS = {
    "attempted": 2, "decompiled": 2, "failed": 0, "truncated": False,
    "functions": [
        {"name": "rc4_decrypt_config", "address": "0041d000",
         "c": "void rc4_decrypt_config(byte *key){ swap_bytes(key); }"},
        {"name": "main", "address": "00401267",
         "c": "int main(void){ puts(\"hi\"); }"},
    ],
}


@pytest.fixture
def corpus(monkeypatch, project):
    """Stub the expensive decompile_all export."""
    calls = []

    def fake_export(program, mode, args=None, *, write=False, timeout=None):
        calls.append(mode)
        assert mode == "decompile_all"
        return CORPUS

    monkeypatch.setattr(headless, "export", fake_export)
    return calls


class TestValidation:
    @pytest.mark.parametrize("mode", ["fuzzy", "SEMANTIC", "", "vector"])
    def test_unknown_mode_is_rejected_before_decompiling(self, corpus, mode):
        with pytest.raises(BadArgument, match="mode must be"):
            tools.search_code("p", "x", mode=mode)
        assert corpus == []

    def test_empty_query_is_rejected(self, corpus):
        with pytest.raises(BadArgument, match="query must not be empty"):
            tools.search_code("p", "")
        assert corpus == []

    def test_invalid_regex_becomes_a_bad_argument(self, corpus):
        with pytest.raises(BadArgument, match="invalid regex"):
            tools.search_code("p", "(unclosed", mode="literal")


class TestLiteralMode:
    def test_finds_a_token(self, corpus):
        out = tools.search_code("p", "swap_bytes", mode="literal")
        assert out.returned == 1
        assert out.matches[0].function == "rc4_decrypt_config"
        assert out.matches[0].line_number == 1

    def test_reports_the_regex_backend(self, corpus):
        assert tools.search_code("p", "puts", mode="literal").backend == "regex"

    def test_limit_is_honoured(self, corpus):
        out = tools.search_code("p", r"\w+", mode="literal", limit=1)
        assert out.returned == 1

    def test_no_match_is_not_an_error(self, corpus):
        out = tools.search_code("p", "nothing_here", mode="literal")
        assert out.returned == 0 and out.matches == []


class TestSemanticMode:
    def test_ranks_the_related_function_first(self, corpus):
        out = tools.search_code("p", "decrypt configuration key", mode="semantic")
        assert out.matches[0].function == "rc4_decrypt_config"
        assert out.matches[0].score > 0

    def test_reports_the_tfidf_backend(self, corpus):
        assert tools.search_code("p", "decrypt", mode="semantic").backend == "tfidf"

    def test_semantic_hits_carry_no_line_number(self, corpus):
        out = tools.search_code("p", "decrypt", mode="semantic")
        assert out.matches[0].line_number is None


class TestCaching:
    def test_first_call_decompiles_and_reports_it(self, corpus):
        out = tools.search_code("p", "puts")
        assert out.from_cache is False
        assert corpus == ["decompile_all"]

    def test_second_call_reads_the_cache(self, corpus):
        tools.search_code("p", "puts")
        out = tools.search_code("p", "puts")
        assert out.from_cache is True
        assert corpus == ["decompile_all"], "must not decompile twice"

    def test_refresh_forces_a_rebuild(self, corpus):
        tools.search_code("p", "puts")
        out = tools.search_code("p", "puts", refresh=True)
        assert out.from_cache is False
        assert corpus == ["decompile_all", "decompile_all"]

    def test_indexed_function_count_is_reported(self, corpus):
        assert tools.search_code("p", "puts").indexed_functions == 2

    def test_cache_is_per_program(self, corpus):
        tools.search_code("a.bin", "puts")
        tools.search_code("b.bin", "puts")
        assert corpus == ["decompile_all", "decompile_all"]

    @pytest.mark.parametrize(
        "program",
        ["weird/../name .bin", "../../etc/passwd", "a/b/c", "..", "with space.bin"],
    )
    def test_a_hostile_program_name_cannot_escape_the_cache_directory(
        self, project, program
    ):
        """Containment is the property that matters, not the exact spelling."""
        path = headless.corpus_path(program)
        assert path.parent == headless.cache_dir()
        assert path.resolve().is_relative_to(headless.cache_dir().resolve())
        assert "/" not in path.name

    def test_a_corrupt_cache_is_rebuilt_not_fatal(self, corpus, project):
        tools.search_code("p", "puts")
        headless.corpus_path("p").write_text("{ truncated json")
        out = tools.search_code("p", "puts")
        assert out.from_cache is False
        assert out.returned == 1

    def test_clear_code_cache_removes_it(self, corpus):
        tools.search_code("p", "puts")
        assert tools.clear_code_cache("p") == {"program": "p", "cleared": True}
        assert tools.search_code("p", "puts").from_cache is False

    def test_clearing_an_absent_cache_reports_false(self, project):
        assert tools.clear_code_cache("never-cached")["cleared"] is False

    def test_cache_is_valid_json_on_disk(self, corpus, project):
        tools.search_code("p", "puts")
        assert json.loads(headless.corpus_path("p").read_text())["functions"]
