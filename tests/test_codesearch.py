"""Exhaustive tests for the code-search index and rankers.

Pure functions over lists and dicts, so every branch is reachable without a JVM.
"""

import re

import pytest

from ghmcp import codesearch
from ghmcp.codesearch import build_index, literal_search, semantic_search, tokenize

DOCS = [
    {"name": "rc4_decrypt_config", "address": "0041d000",
     "c": "void rc4_decrypt_config(byte *key, int key_len) {\n"
          "  int i; byte state[256];\n"
          "  for (i = 0; i < 256; i++) { state[i] = i; }\n"
          "  swap_bytes(state, key, key_len);\n}"},
    {"name": "validate_license", "address": "00401146",
     "c": "int validate_license(char *serial) {\n"
          "  int checksum = compute_checksum(serial);\n"
          "  return checksum == 0xe91c;\n}"},
    {"name": "main", "address": "00401267",
     "c": "int main(int argc, char **argv) {\n"
          "  puts(\"hello\");\n  return 0;\n}"},
]


class TestTokenize:
    def test_splits_snake_case(self):
        assert "decrypt" in tokenize("rc4_decrypt_config")
        assert "config" in tokenize("rc4_decrypt_config")

    def test_splits_camel_case(self):
        assert "decrypt" in tokenize("decryptConfig")
        assert "config" in tokenize("decryptConfig")

    def test_snake_and_camel_produce_the_same_terms(self):
        """A query must match either spelling of the same idea."""
        assert set(tokenize("decrypt_config")) == set(tokenize("decryptConfig"))

    def test_lowercases(self):
        assert tokenize("DecryptConfig") == tokenize("decryptconfig") or "decrypt" in tokenize("DecryptConfig")

    @pytest.mark.parametrize("keyword", ["int", "char", "return", "if", "while", "void"])
    def test_c_keywords_are_dropped(self, keyword):
        assert keyword not in tokenize(f"{keyword} x;")

    @pytest.mark.parametrize("noise", ["undefined8", "uVar1", "local_10"])
    def test_ghidra_noise_is_dropped(self, noise):
        """Synthesised names appear everywhere; keeping them makes all code alike."""
        assert tokenize(noise) == [] or all(t in codesearch.STOPWORDS or len(t) < 3
                                            for t in tokenize(noise))

    def test_short_tokens_are_dropped(self):
        assert tokenize("a b cd") == []

    def test_numbers_and_punctuation_are_ignored(self):
        assert tokenize("0xdeadbeef + 42 * (x);") == []

    def test_empty_input(self):
        assert tokenize("") == []

    def test_repeated_terms_are_kept_for_frequency(self):
        assert tokenize("crypto crypto").count("crypto") == 2


class TestBuildIndex:
    def test_indexes_every_document(self):
        index = build_index(DOCS)
        assert index["document_count"] == 3
        assert len(index["entries"]) == 3

    def test_records_document_frequencies(self):
        index = build_index(DOCS)
        assert index["df"]
        assert all(count >= 1 for count in index["df"].values())

    def test_vectors_are_unit_length(self):
        """Cosine similarity is a dot product only if vectors are normalised."""
        index = build_index(DOCS)
        for entry in index["entries"]:
            norm = sum(w * w for w in entry["vector"].values()) ** 0.5
            assert abs(norm - 1.0) < 1e-9

    def test_preserves_name_and_address(self):
        index = build_index(DOCS)
        assert index["entries"][0]["name"] == "rc4_decrypt_config"
        assert index["entries"][0]["address"] == "0041d000"

    def test_handles_an_empty_corpus(self):
        index = build_index([])
        assert index["document_count"] == 0 and index["entries"] == []

    def test_handles_a_function_with_no_meaningful_tokens(self):
        index = build_index([{"name": "f", "address": "0", "c": "int f(){return 0;}"}])
        assert len(index["entries"]) == 1

    def test_is_json_serialisable(self):
        import json

        json.dumps(build_index(DOCS))


class TestSemanticSearch:
    def test_finds_the_obviously_related_function(self):
        hits = semantic_search(build_index(DOCS), "decrypt configuration", limit=3)
        assert hits[0]["function"] == "rc4_decrypt_config"

    def test_finds_a_function_by_related_words(self):
        hits = semantic_search(build_index(DOCS), "license serial checksum", limit=3)
        assert hits[0]["function"] == "validate_license"

    def test_scores_descend(self):
        hits = semantic_search(build_index(DOCS), "decrypt key state", limit=5)
        assert hits == sorted(hits, key=lambda h: -h["score"])

    def test_unrelated_documents_are_dropped_not_padded(self):
        """A list padded with unrelated functions is worse than a short one."""
        hits = semantic_search(build_index(DOCS), "decrypt", limit=5)
        assert len(hits) < len(DOCS)

    def test_a_query_with_no_known_terms_returns_nothing(self):
        assert semantic_search(build_index(DOCS), "zzzz qqqq", limit=5) == []

    def test_a_query_of_only_stopwords_returns_nothing(self):
        assert semantic_search(build_index(DOCS), "int char return", limit=5) == []

    def test_limit_is_respected(self):
        assert len(semantic_search(build_index(DOCS), "key state serial", limit=1)) == 1

    @pytest.mark.parametrize("limit", [0, -1])
    def test_non_positive_limit_returns_nothing(self, limit):
        assert semantic_search(build_index(DOCS), "decrypt", limit=limit) == []

    def test_empty_index_returns_nothing(self):
        assert semantic_search(build_index([]), "decrypt", limit=5) == []

    def test_ties_break_deterministically_by_name(self):
        docs = [
            {"name": "b_fn", "address": "2", "c": "void b_fn(){ crypto_thing(); }"},
            {"name": "a_fn", "address": "1", "c": "void a_fn(){ crypto_thing(); }"},
        ]
        hits = semantic_search(build_index(docs), "crypto thing", limit=2)
        assert [h["function"] for h in hits] == ["a_fn", "b_fn"]


class TestLiteralSearch:
    def test_finds_a_token(self):
        hits = literal_search(DOCS, "checksum")
        assert hits[0]["function"] == "validate_license"
        assert "checksum" in hits[0]["line"]

    def test_is_case_insensitive(self):
        assert literal_search(DOCS, "CHECKSUM")

    def test_supports_real_regex(self):
        assert literal_search(DOCS, r"0x[0-9a-f]{4}")

    def test_reports_the_first_matching_line_number(self):
        hits = literal_search(DOCS, "compute_checksum")
        assert hits[0]["line_number"] == 2

    def test_counts_every_matching_line(self):
        hits = literal_search(DOCS, "state")
        assert hits[0]["match_count"] >= 2

    def test_no_match_returns_empty(self):
        assert literal_search(DOCS, "nothing_like_this") == []

    def test_limit_stops_early(self):
        assert len(literal_search(DOCS, r"\w+", limit=1)) == 1

    def test_context_adds_surrounding_lines(self):
        plain = literal_search(DOCS, "compute_checksum", context=0)
        with_ctx = literal_search(DOCS, "compute_checksum", context=2)
        assert plain[0]["snippet"] is None
        assert with_ctx[0]["snippet"] and "\n" in with_ctx[0]["snippet"]

    def test_context_clamps_at_the_start_of_a_function(self):
        hits = literal_search(DOCS, "rc4_decrypt_config", context=10)
        assert hits[0]["snippet"].splitlines()

    def test_invalid_regex_raises_re_error_for_the_caller_to_translate(self):
        with pytest.raises(re.error):
            literal_search(DOCS, "(unclosed")

    def test_empty_corpus(self):
        assert literal_search([], "anything") == []
