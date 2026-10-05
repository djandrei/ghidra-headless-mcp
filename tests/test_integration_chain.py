"""resolve_symbol over a real import -> forwarder -> implementation chain.

Three x86-64 PEs built from tests/fixtures/src, the same shape as Windows' own
layering of notepad.exe -> kernel32 -> kernelbase, small enough to ship:

    chainapp.exe    imports do_work from chainfwd.dll           (consumer)
    chainfwd.dll    exports do_work, implemented by a call into
                    chainimpl.dll, so it imports do_work too    (forwarder)
    chainimpl.dll   exports and implements do_work              (terminal)

test_integration_windows_layering.py checks the same join on the real Windows
binaries, including apiset redirection, when WINDOWS_SAMPLES_DIR provides them.

Run with: pytest -m integration
"""

import pytest

from ghmcp import config, headless, tools
from tests.conftest import CHAIN

pytestmark = pytest.mark.integration

APP, FWD, IMPL = (path.name for path in CHAIN)


@pytest.fixture(scope="module")
def chain_project(tmp_path_factory):
    for path in CHAIN:
        if not path.is_file():
            pytest.skip(f"fixture missing: {path}")
    loc = tmp_path_factory.mktemp("chain")
    config.PROJECT_LOCATION = loc
    config.PROJECT_NAME = "chain-test"
    result = tools.analyze_binaries([str(path) for path in CHAIN])
    assert result.failures == [], result.failures
    return [r.program for r in result.results]


@pytest.fixture
def count_runs(monkeypatch):
    real = headless.run_headless
    calls: list[list[str]] = []

    def counting(args, timeout):
        calls.append(list(args))
        return real(args, timeout)

    monkeypatch.setattr(headless, "run_headless", counting)
    return calls


@pytest.fixture(scope="module")
def do_work(chain_project):
    return tools.resolve_symbol("do_work").results[0]


def test_the_three_binaries_import_in_one_run(chain_project):
    assert sorted(chain_project) == sorted([APP, FWD, IMPL])


def test_the_chain_runs_consumer_to_implementation(do_work):
    assert [layer.program for layer in do_work.layers] == [APP, FWD, IMPL]


def test_the_implementation_is_the_terminal(do_work):
    assert do_work.terminal_program == IMPL
    impl = do_work.layers[-1]
    assert impl.is_terminal is True
    assert "export" in impl.roles and "function" in impl.roles
    assert "import" not in impl.roles
    assert impl.address


def test_the_forwarder_both_exports_and_imports(do_work):
    """Exporting *and* importing a name is what identifies a forwarder."""
    fwd = do_work.layers[1]
    assert {"export", "import"} <= set(fwd.roles)
    assert fwd.is_terminal is False
    assert fwd.library_program == IMPL


def test_the_consumer_only_imports_and_its_library_is_resolved(do_work):
    """The import names a DLL (CHAINFWD.DLL, upper-cased by the PE loader);
    the join maps it to the program that is that DLL."""
    app = do_work.layers[0]
    assert app.roles == ["import"]
    assert app.library.lower() == FWD
    assert app.library_program == FWD


def test_nothing_is_absent_and_nothing_is_inferred(do_work):
    """Every library name matches a program directly: no apiset hop, so no
    notes — anything inferred would have to say so there."""
    assert do_work.absent_from == []
    assert do_work.notes == []


def test_the_join_costs_one_jvm_start(chain_project, count_runs):
    tools.resolve_symbol(["do_work", "main"])
    assert len(count_runs) == 1


def test_exports_are_listed_across_the_project(chain_project):
    out = tools.list_symbols_project(kind="export", pattern="^do_work$")
    by_program = {r.program: [s.name for s in r.symbols] for r in out.results}

    assert out.failures == []
    assert by_program[FWD] == ["do_work"]
    assert by_program[IMPL] == ["do_work"]
    assert by_program[APP] == []


def test_a_missing_symbol_is_absent_everywhere(chain_project):
    chain = tools.resolve_symbol("no_such_symbol_anywhere").results[0]
    assert chain.layers == []
    assert sorted(chain.absent_from) == sorted([APP, FWD, IMPL])
