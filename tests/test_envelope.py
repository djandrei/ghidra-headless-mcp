"""Exhaustive tests for envelope parsing — the Java/Python contract."""

import json

import pytest

from ghmcp import errors
from ghmcp.headless import parse_envelope


def test_success_returns_the_data_payload():
    assert parse_envelope(json.dumps({"ok": True, "data": {"a": 1}})) == {"a": 1}


@pytest.mark.parametrize("payload", [{}, [], "text", 0, False, None])
def test_success_passes_any_json_data_type_through(payload):
    assert parse_envelope(json.dumps({"ok": True, "data": payload})) == payload


@pytest.mark.parametrize(
    "kind,expected",
    [
        ("not_found", errors.NotFound),
        ("bad_argument", errors.BadArgument),
        ("ghidra_error", errors.GhidraError),
    ],
)
def test_failure_raises_the_typed_error(kind, expected):
    text = json.dumps({"ok": False, "error": {"kind": kind, "message": "detail here"}})
    with pytest.raises(expected, match="detail here"):
        parse_envelope(text)


def test_failure_with_unknown_kind_still_raises_base():
    text = json.dumps({"ok": False, "error": {"kind": "novel", "message": "m"}})
    with pytest.raises(errors.HeadlessError):
        parse_envelope(text)


def test_failure_with_no_error_object_still_raises():
    with pytest.raises(errors.HeadlessError, match="unknown failure"):
        parse_envelope(json.dumps({"ok": False}))


def test_ok_without_data_is_a_protocol_violation():
    with pytest.raises(errors.ExportFailure, match="carried no data"):
        parse_envelope(json.dumps({"ok": True}))


@pytest.mark.parametrize("text", ["", "not json", "{", '{"ok":', "\x00"])
def test_invalid_json_raises_export_failure(text):
    with pytest.raises(errors.ExportFailure, match="invalid JSON"):
        parse_envelope(text)


@pytest.mark.parametrize("text", ['{"data": 1}', "[]", '"a string"', "42", "null"])
def test_missing_ok_field_is_an_unrecognised_envelope(text):
    with pytest.raises(errors.ExportFailure, match="unrecognised envelope"):
        parse_envelope(text)


def test_truncates_the_offending_payload_in_the_message():
    """A megabyte of bad output must not become a megabyte-long exception."""
    text = json.dumps({"junk": "x" * 5000})
    with pytest.raises(errors.ExportFailure) as exc:
        parse_envelope(text)
    assert len(str(exc.value)) < 400


def test_falsy_ok_values_are_treated_as_failure():
    with pytest.raises(errors.HeadlessError):
        parse_envelope(json.dumps({"ok": 0, "error": {"kind": "x", "message": "m"}}))


def test_unicode_and_control_characters_survive_the_round_trip():
    payload = {"c": 'line\nnext\ttab "quoted" \\ backslash ünïcode'}
    assert parse_envelope(json.dumps({"ok": True, "data": payload})) == payload
