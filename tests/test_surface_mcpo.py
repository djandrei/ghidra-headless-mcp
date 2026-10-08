"""The mcpo (HTTP/OpenAPI) surface, end to end: serve-mcpo.sh as a subprocess.

This is the surface OpenWebUI uses, launched exactly as the container's CMD
launches it. No JVM: the calls are the tools that never reach Ghidra, and
failures decided before it would. Some assertions pin mcpo's own behaviour —
every tool error is HTTP 500, a wrong key is 403 — so an mcpo upgrade that
changes it is noticed.
"""

import httpx
import pytest

from tests.surfaces import MCPO_AVAILABLE, registered_tools, required_params, serve_mcpo

KEY = "surface-test-key-" + "k" * 32

pytestmark = pytest.mark.skipif(not MCPO_AVAILABLE, reason="mcpo is not installed")


@pytest.fixture(scope="module")
def mcpo(tmp_path_factory):
    """serve-mcpo.sh on a free loopback port; yields its base URL."""
    tmp = tmp_path_factory.mktemp("mcpo")
    with serve_mcpo(tmp, KEY, {"PROJECT_LOCATION": str(tmp / "proj"),
                               "UPLOAD_DIR": str(tmp / "uploads")}) as base:
        yield base


def post(base, tool, body, key=KEY):
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    return httpx.post(f"{base}/{tool}", json=body, headers=headers, timeout=60)


def test_the_schema_lists_every_tool_with_its_required_fields(mcpo):
    spec = httpx.get(f"{mcpo}/openapi.json", timeout=10).json()
    schemas = spec["components"]["schemas"]

    paths = {p.lstrip("/"): ops for p, ops in spec["paths"].items()}
    assert set(paths) == set(registered_tools())
    for name, ops in paths.items():
        if "requestBody" not in ops["post"]:
            # mcpo publishes no body for a tool that takes no arguments.
            assert required_params(name) == set(), name
            continue
        ref = ops["post"]["requestBody"]["content"]["application/json"]["schema"]["$ref"]
        body = schemas[ref.rsplit("/", 1)[1]]
        assert set(body.get("required", [])) == required_params(name), name


def test_the_schema_is_public_and_the_tools_are_not(mcpo):
    assert httpx.get(f"{mcpo}/openapi.json", timeout=10).status_code == 200
    assert post(mcpo, "list_uploads", {}, key=None).status_code == 401
    assert post(mcpo, "list_uploads", {}, key="wrong").status_code == 403


def test_a_file_round_trips_through_the_upload_tools(mcpo):
    stored = post(mcpo, "upload_binary", {"filename": "a.bin", "content_base64": "f0VMRg=="})
    assert stored.status_code == 200 and stored.json()["size"] == 4
    assert [u["filename"] for u in post(mcpo, "list_uploads", {}).json()["uploads"]] == ["a.bin"]
    assert post(mcpo, "delete_upload", {"filename": "a.bin"}).json()["deleted"] is True
    assert post(mcpo, "list_uploads", {}).json()["uploads"] == []


def test_a_missing_required_field_is_422(mcpo):
    r = post(mcpo, "get_cfg", {"function": "main"})
    assert r.status_code == 422
    assert any(d["loc"][-1] == "program" for d in r.json()["detail"])


def test_a_wrongly_typed_field_is_422(mcpo):
    assert post(mcpo, "list_functions", {"program": "p", "limit": "many"}).status_code == 422


def test_every_tool_error_is_500_with_the_message(mcpo):
    """mcpo's behaviour, not ours: /api/<tool> on --http maps these properly."""
    r = post(mcpo, "analyze_binary", {"binary_path": "/nope/missing.bin"})
    assert r.status_code == 500
    assert "binary not found" in r.text


def test_an_unknown_tool_is_404(mcpo):
    assert post(mcpo, "no_such_tool", {}).status_code == 404
