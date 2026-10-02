"""End-to-end: a binary sent through upload_binary is analysed by real Ghidra.

The point is the hand-off — the bytes arrive base64-encoded, land in the upload
directory, and analyze_binary imports them from there — so one sample suffices.

Run with: pytest -m integration
"""

import base64

import pytest

from ghmcp import config, tools
from tests.conftest import KNOWN_FUNCTION, STARTER05

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def uploaded(tmp_path_factory):
    if not STARTER05.is_file():
        pytest.skip(f"fixture missing: {STARTER05}")
    loc = tmp_path_factory.mktemp("uploadtest")
    config.PROJECT_LOCATION = loc
    config.PROJECT_NAME = "upload-test"
    encoded = base64.b64encode(STARTER05.read_bytes()).decode()
    return tools.upload_binary("uploaded-starter05", encoded, analyze=True)


def test_the_upload_lands_beside_the_project(uploaded):
    assert uploaded.path == str(config.PROJECT_LOCATION / "samples" / "uploaded-starter05")
    assert uploaded.written


def test_analyze_true_imports_the_uploaded_file(uploaded):
    assert uploaded.analysis is not None
    assert uploaded.analysis.program == "uploaded-starter05"
    assert uploaded.analysis.info.md5 == uploaded.md5


def test_the_uploaded_program_answers_queries(uploaded):
    out = tools.decompile_function(uploaded.analysis.program, KNOWN_FUNCTION)
    assert KNOWN_FUNCTION in out.c


def test_reuploading_reuses_the_existing_analysis(uploaded):
    encoded = base64.b64encode(STARTER05.read_bytes()).decode()
    again = tools.upload_binary("uploaded-starter05", encoded, analyze=True)
    assert not again.written
    assert again.analysis.already_analyzed
