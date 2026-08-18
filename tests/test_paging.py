"""Exhaustive boundary tests for filtering and paging.

These are pure functions, so every edge worth worrying about is cheap to cover
here rather than through a subprocess.
"""

import pytest

from ghmcp.paging import page, substring_filter

ITEMS = ["alpha", "Beta", "gamma", "DELTA", "epsilon"]


class TestSubstringFilter:
    def test_matches_case_insensitively(self):
        assert substring_filter(ITEMS, "BET", key=str) == ["Beta"]
        assert substring_filter(ITEMS, "delta", key=str) == ["DELTA"]

    @pytest.mark.parametrize("needle", [None, ""])
    def test_empty_needle_matches_everything(self, needle):
        assert substring_filter(ITEMS, needle, key=str) == ITEMS

    def test_no_match_returns_empty(self):
        assert substring_filter(ITEMS, "zzz", key=str) == []

    def test_preserves_input_order(self):
        assert substring_filter(ITEMS, "a", key=str) == ["alpha", "Beta", "gamma", "DELTA"]

    def test_returns_a_copy_not_the_original_list(self):
        out = substring_filter(ITEMS, None, key=str)
        out.append("mutated")
        assert "mutated" not in ITEMS

    def test_uses_the_key_function(self):
        pairs = [("x", "alpha"), ("y", "beta")]
        assert substring_filter(pairs, "alp", key=lambda p: p[1]) == [("x", "alpha")]

    def test_empty_input(self):
        assert substring_filter([], "a", key=str) == []


class TestPage:
    def test_returns_the_requested_window(self):
        assert page(ITEMS, limit=2, offset=1) == ["Beta", "gamma"]

    def test_offset_past_the_end_returns_empty(self):
        assert page(ITEMS, limit=10, offset=99) == []

    def test_limit_larger_than_the_set_returns_all_remaining(self):
        assert page(ITEMS, limit=100, offset=3) == ["DELTA", "epsilon"]

    @pytest.mark.parametrize("limit", [0, -1, -100])
    def test_non_positive_limit_returns_nothing(self, limit):
        assert page(ITEMS, limit=limit, offset=0) == []

    @pytest.mark.parametrize("offset", [-1, -100])
    def test_negative_offset_clamps_to_zero_instead_of_wrapping(self, offset):
        """A bare slice would count from the end and return the wrong rows."""
        assert page(ITEMS, limit=2, offset=offset) == ["alpha", "Beta"]

    def test_empty_input(self):
        assert page([], limit=10, offset=0) == []

    def test_exact_boundary(self):
        assert page(ITEMS, limit=5, offset=0) == ITEMS
        assert page(ITEMS, limit=1, offset=4) == ["epsilon"]
        assert page(ITEMS, limit=1, offset=5) == []

    def test_returns_a_list_even_for_tuple_input(self):
        assert page(("a", "b"), limit=1, offset=0) == ["a"]
