"""Exhaustive tests for the typed error mapping."""

import pytest

from ghmcp import errors


@pytest.mark.parametrize(
    "kind,expected",
    [
        ("not_found", errors.NotFound),
        ("bad_argument", errors.BadArgument),
        ("ghidra_error", errors.GhidraError),
        ("timeout", errors.HeadlessTimeout),
        ("export_failure", errors.ExportFailure),
    ],
)
def test_every_known_kind_maps_to_its_class(kind, expected):
    exc = errors.from_envelope(kind, "boom")
    assert isinstance(exc, expected)
    assert str(exc) == "boom"


@pytest.mark.parametrize("kind", ["", "error", "unheard_of", "NOT_FOUND", None])
def test_unknown_kind_degrades_to_base_rather_than_raising(kind):
    """A newer Java side must be able to add kinds without breaking us."""
    exc = errors.from_envelope(kind, "msg")
    assert isinstance(exc, errors.HeadlessError)
    assert type(exc) is errors.HeadlessError


def test_kind_lookup_is_case_sensitive():
    assert type(errors.from_envelope("Not_Found", "m")) is errors.HeadlessError


@pytest.mark.parametrize(
    "cls",
    [
        errors.NotFound,
        errors.BadArgument,
        errors.GhidraError,
        errors.HeadlessTimeout,
        errors.ExportFailure,
    ],
)
def test_all_errors_share_the_base_so_callers_can_catch_broadly(cls):
    assert issubclass(cls, errors.HeadlessError)
    assert issubclass(cls, RuntimeError)


def test_kinds_are_unique_across_classes():
    kinds = [
        c.kind
        for c in (
            errors.NotFound,
            errors.BadArgument,
            errors.GhidraError,
            errors.HeadlessTimeout,
            errors.ExportFailure,
        )
    ]
    assert len(kinds) == len(set(kinds))


def test_class_kind_round_trips_through_from_envelope():
    for cls in (errors.NotFound, errors.BadArgument, errors.GhidraError):
        assert type(errors.from_envelope(cls.kind, "x")) is cls
