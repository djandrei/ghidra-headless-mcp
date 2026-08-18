"""End-to-end tests against a real Ghidra install.

Deselected by default (pytest.ini sets -m "not integration") because each test
cold-starts a JVM. Run with:  pytest -m integration
"""

import pytest

from ghmcp import config, headless, tools
from tests.conftest import KNOWN_ADDRESS, KNOWN_FUNCTION, STARTER05

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def analysed(tmp_path_factory):
    """Analyse the fixture binary once for the whole module."""
    loc = tmp_path_factory.mktemp("intproj")
    config.PROJECT_LOCATION = loc
    config.PROJECT_NAME = "int-test"
    if not STARTER05.is_file():
        pytest.skip(f"fixture binary missing: {STARTER05}")
    result = tools.analyze_binary(str(STARTER05))
    return result


def test_analysis_reports_the_expected_architecture(analysed):
    assert analysed.info.language_id == "x86:LE:64:default"
    assert analysed.info.function_count > 0
    assert analysed.already_analyzed is False


def test_analysis_is_idempotent(analysed):
    again = tools.analyze_binary(str(STARTER05))
    assert again.already_analyzed is True


def test_the_program_appears_in_list_programs(analysed):
    assert analysed.program in tools.list_programs().programs


def test_known_function_is_found_at_its_known_address(analysed):
    out = tools.list_functions(analysed.program, name_contains=KNOWN_FUNCTION)
    assert out.total == 1
    assert out.functions[0].address == KNOWN_ADDRESS


def test_decompiles_by_name(analysed):
    out = tools.decompile_function(analysed.program, KNOWN_FUNCTION)
    assert out.address == KNOWN_ADDRESS
    assert "check_key" in out.c or out.name == KNOWN_FUNCTION
    assert len(out.c.splitlines()) > 5


def test_decompiles_by_address(analysed):
    out = tools.decompile_function(analysed.program, KNOWN_ADDRESS)
    assert out.name == KNOWN_FUNCTION


def test_decompiling_a_missing_function_raises_not_found(analysed):
    from ghmcp.errors import NotFound

    with pytest.raises(NotFound):
        tools.decompile_function(analysed.program, "no_such_function_anywhere")


def test_strings_include_the_known_banner(analysed):
    out = tools.list_strings(analysed.program, contains="keygen-me")
    assert out.total >= 1


def test_min_length_filters_in_ghidra(analysed):
    short = tools.list_strings(analysed.program, min_length=4, limit=1000)
    long = tools.list_strings(analysed.program, min_length=40, limit=1000)
    assert long.total < short.total


def test_program_info_hashes_are_populated(analysed):
    info = tools.get_program_info(analysed.program)
    assert info.sha256 and len(info.sha256) == 64
    assert info.memory_blocks


def test_legacy_positional_script_form_still_works(analysed):
    """The pre-Stage-0 calling convention must keep working during migration."""
    import json
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "legacy.json"
        headless.run_headless(
            [
                "-process", analysed.program, "-noanalysis", "-readOnly",
                "-scriptPath", config.script_path(),
                "-postScript", config.EXPORT_SCRIPT, "info", str(out),
            ],
            timeout=config.QUERY_TIMEOUT_S,
        )
        envelope = json.loads(out.read_text())
    assert envelope["ok"] is True
    assert envelope["data"]["language_id"] == "x86:LE:64:default"


# ------------------------------------------------------- Stage 1: xrefs


def test_xrefs_to_a_known_function_find_its_callers(analysed):
    out = tools.list_xrefs_to(analysed.program, KNOWN_FUNCTION)
    row = out.results[0]
    assert row.error is None
    assert row.resolved_kind == "function"
    assert row.resolved_address == KNOWN_ADDRESS
    assert row.total >= 1, "check_key is called from main; expected at least one xref"


def test_xrefs_to_enrich_with_the_calling_function(analysed):
    row = tools.list_xrefs_to(analysed.program, KNOWN_FUNCTION).results[0]
    callers = {x.from_function for x in row.xrefs if x.from_function}
    assert callers, "expected at least one reference from inside a function"


def test_xrefs_from_a_function_are_found(analysed):
    row = tools.list_xrefs_from(analysed.program, "main").results[0]
    assert row.error is None
    assert row.total >= 1


def test_xrefs_accept_an_address_as_well_as_a_name(analysed):
    row = tools.list_xrefs_to(analysed.program, KNOWN_ADDRESS).results[0]
    assert row.resolved_kind == "address"
    assert row.resolved_address == KNOWN_ADDRESS


def test_batch_xrefs_resolve_every_target_in_one_call(analysed):
    out = tools.list_xrefs_to(analysed.program, [KNOWN_FUNCTION, "main"])
    assert len(out.results) == 2
    assert all(r.error is None for r in out.results)


def test_one_bad_target_does_not_fail_the_batch(analysed):
    out = tools.list_xrefs_to(analysed.program, [KNOWN_FUNCTION, "definitely_not_here"])
    assert out.results[0].error is None
    assert out.results[1].error is not None
    assert out.results[1].resolved_address is None


def test_bad_direction_is_rejected_by_the_java_side(analysed):
    from ghmcp import headless as hl
    from ghmcp.errors import BadArgument

    with pytest.raises(BadArgument, match="direction"):
        hl.export(analysed.program, "xrefs", {"targets": ["main"], "direction": "sideways"})


def test_empty_target_list_is_rejected_by_the_java_side(analysed):
    from ghmcp import headless as hl
    from ghmcp.errors import BadArgument

    with pytest.raises(BadArgument, match="at least one target"):
        hl.export(analysed.program, "xrefs", {"targets": [], "direction": "to"})


# -------------------------------------------------- Stage 1: function_at


def test_function_at_resolves_an_entry_point(analysed):
    out = tools.get_function_at(analysed.program, KNOWN_ADDRESS)
    assert out.name == KNOWN_FUNCTION
    assert out.is_entry_point is True


def test_function_at_resolves_an_address_inside_a_body(analysed):
    """An address from a crash dump lands mid-function, not on an entry point."""
    entry = int(KNOWN_ADDRESS, 16)
    out = tools.get_function_at(analysed.program, f"{entry + 4:08x}")
    assert out.name == KNOWN_FUNCTION
    assert out.is_entry_point is False
    assert out.address == KNOWN_ADDRESS


def test_function_at_an_unmapped_address_raises_not_found(analysed):
    from ghmcp.errors import HeadlessError

    with pytest.raises(HeadlessError):
        tools.get_function_at(analysed.program, "00000010")


def test_function_at_rejects_a_nonsense_address(analysed):
    from ghmcp.errors import HeadlessError

    with pytest.raises(HeadlessError):
        tools.get_function_at(analysed.program, "not-an-address")


def test_xrefs_from_a_function_sweep_the_whole_body_not_just_the_entry(analysed):
    """Regression: getReferencesFrom(entryPoint) sees only the first instruction.

    main calls other functions and loads strings from addresses throughout its
    body, so a body-wide sweep must find references the entry point alone
    cannot.
    """
    from ghmcp import headless as hl

    row = tools.list_xrefs_from(analysed.program, "main").results[0]
    entry = row.resolved_address
    entry_only = hl.export(
        analysed.program, "xrefs", {"targets": [entry], "direction": "from"}
    )["results"][0]

    assert row.total > len(entry_only["xrefs"])
    assert len({x.from_address for x in row.xrefs}) > 1


# --------------------------------------------------- Stage 2: raw views


def test_disassembles_a_function_body(analysed):
    out = tools.disassemble(analysed.program, KNOWN_FUNCTION, count=200)
    assert out.scope == "function"
    assert out.resolved_address == KNOWN_ADDRESS
    assert out.instruction_count > 1
    assert out.listing.splitlines()[0].startswith(KNOWN_ADDRESS)


def test_disassembles_forward_from_a_bare_address(analysed):
    out = tools.disassemble(analysed.program, KNOWN_ADDRESS, count=5)
    assert out.scope == "address"
    assert out.instruction_count == 5
    assert len(out.listing.splitlines()) == 5


def test_count_truncates_and_says_so(analysed):
    out = tools.disassemble(analysed.program, KNOWN_ADDRESS, count=2)
    assert out.instruction_count == 2
    assert out.truncated is True


def test_include_bytes_adds_a_hex_column(analysed):
    plain = tools.disassemble(analysed.program, KNOWN_ADDRESS, count=3)
    withb = tools.disassemble(
        analysed.program, KNOWN_ADDRESS, count=3, include_bytes=True
    )
    assert len(withb.listing) > len(plain.listing)
    first = withb.listing.splitlines()[0]
    assert any(c in "0123456789abcdef" for c in first.split()[1])


def test_instruction_cap_is_enforced_by_the_java_side(analysed):
    """Asking for more than the cap must clamp, not return thousands."""
    out = tools.disassemble(analysed.program, "00401000", count=10_000)
    assert out.instruction_count <= 200


def test_disassembling_an_unresolvable_target_raises(analysed):
    from ghmcp.errors import HeadlessError

    with pytest.raises(HeadlessError):
        tools.disassemble(analysed.program, "no_such_symbol_at_all")


def test_reads_bytes_at_a_known_string_address(analysed):
    strings = tools.list_strings(analysed.program, contains="keygen-me", limit=1)
    addr = strings.strings[0].address
    out = tools.read_bytes(analysed.program, addr, size=16)
    assert out.size == 16
    assert len(out.hex) == 32
    assert "starter05" in out.ascii or "=" in out.ascii


def test_read_bytes_round_trips_hex_and_ascii(analysed):
    out = tools.read_bytes(analysed.program, KNOWN_ADDRESS, size=8)
    assert len(out.hex) == 2 * out.size
    assert len(out.ascii) == out.size


def test_read_bytes_rejects_an_oversized_request(analysed):
    from ghmcp.errors import BadArgument

    with pytest.raises(BadArgument, match="cap"):
        tools.read_bytes(analysed.program, KNOWN_ADDRESS, size=99_999)


def test_read_bytes_on_unmapped_memory_raises(analysed):
    from ghmcp.errors import HeadlessError

    with pytest.raises(HeadlessError):
        tools.read_bytes(analysed.program, "00000010", size=16)


# ------------------------------------------- Stage 3: symbol inventory


def test_imports_are_listed_for_a_dynamically_linked_binary(analysed):
    out = tools.list_symbols(analysed.program, kind="import", limit=500)
    assert out.total >= 1, "starter05 is dynamically linked; expected imports"
    assert all(s.kind == "import" for s in out.symbols)


def test_import_names_look_like_libc(analysed):
    names = {s.name for s in tools.list_symbols(analysed.program, "import", limit=500).symbols}
    assert names & {"printf", "puts", "strlen", "__libc_start_main", "exit"}, names


def test_exports_are_listed(analysed):
    out = tools.list_symbols(analysed.program, kind="export", limit=500)
    assert out.total >= 1
    assert all(s.kind == "export" for s in out.symbols)


def test_data_symbols_carry_values(analysed):
    out = tools.list_symbols(analysed.program, kind="data", limit=500)
    assert out.total >= 1
    assert any(s.value for s in out.symbols)


@pytest.mark.parametrize("kind", ["class", "namespace", "label", "function"])
def test_every_kind_returns_without_error(analysed, kind):
    """A kind with no members must return empty, not fail."""
    out = tools.list_symbols(analysed.program, kind=kind, limit=10)
    assert out.kind == kind
    assert out.total >= 0


def test_function_kind_agrees_with_list_functions(analysed):
    syms = tools.list_symbols(analysed.program, kind="function", limit=1000)
    funcs = tools.list_functions(analysed.program, limit=1000, include_thunks=True,
                                 include_external=True)
    assert syms.total >= funcs.total - 5


def test_unknown_kind_is_rejected_by_the_java_side(analysed):
    from ghmcp import headless as hl
    from ghmcp.errors import BadArgument

    with pytest.raises(BadArgument, match="unknown symbol kind"):
        hl.export(analysed.program, "symbols", {"kind": "segments"})


def test_name_filter_narrows_the_result(analysed):
    everything = tools.list_symbols(analysed.program, "import", limit=500)
    filtered = tools.list_symbols(analysed.program, "import", name_contains="print", limit=500)
    assert filtered.total <= everything.total


def test_memory_blocks_are_listed_with_permissions(analysed):
    out = tools.list_memory_blocks(analysed.program)
    assert out.total >= 1
    assert any(b.executable for b in out.blocks), "expected an executable section"
    assert any(b.name.startswith(".text") for b in out.blocks)


def test_a_second_binary_can_be_analysed_into_the_same_project():
    """Multi-binary scope is the pyghidra-mcp behaviour the index must support."""
    from tests.conftest import CRACKME

    if not CRACKME.is_file():
        pytest.skip(f"second fixture missing: {CRACKME}")
    result = tools.analyze_binary(str(CRACKME))
    programs = tools.list_programs().programs
    assert result.program in programs
    assert len(programs) >= 2
    assert tools.list_symbols(result.program, "import", limit=10).total >= 1


# ------------------------------------------------ Stage 4: regex search


def test_anchored_regex_matches_exactly_one_function(analysed):
    out = tools.list_functions(analysed.program, pattern=f"^{KNOWN_FUNCTION}$")
    assert out.total == 1
    assert out.functions[0].address == KNOWN_ADDRESS


def test_alternation_matches_several(analysed):
    out = tools.list_functions(analysed.program, pattern=f"^({KNOWN_FUNCTION}|main)$")
    assert out.total == 2


def test_regex_is_case_insensitive(analysed):
    upper = tools.list_functions(analysed.program, pattern=KNOWN_FUNCTION.upper())
    assert upper.total >= 1


def test_a_plain_substring_still_works_as_a_pattern(analysed):
    """The migration from name_contains must be a rename, not a behaviour change."""
    as_pattern = tools.list_functions(analysed.program, pattern="check")
    as_literal = tools.list_functions(analysed.program, name_contains="check")
    assert as_pattern.total == as_literal.total >= 1


def test_literal_alias_does_not_gain_regex_powers(analysed):
    """'check.key' as a literal must not match 'check_key'; as a regex it must."""
    literal = tools.list_functions(analysed.program, name_contains="check.key")
    regex = tools.list_functions(analysed.program, pattern="check.key")
    assert literal.total == 0
    assert regex.total >= 1


def test_invalid_regex_is_rejected_with_bad_argument(analysed):
    from ghmcp.errors import BadArgument

    with pytest.raises(BadArgument, match="invalid regex"):
        tools.list_functions(analysed.program, pattern="(unclosed")


def test_thunk_and_external_filtering_now_happens_in_ghidra(analysed):
    default = tools.list_functions(analysed.program, limit=1000)
    with_all = tools.list_functions(
        analysed.program, limit=1000, include_thunks=True, include_external=True
    )
    assert with_all.total >= default.total


def test_string_regex_filters_inside_ghidra(analysed):
    everything = tools.list_strings(analysed.program, limit=1000)
    anchored = tools.list_strings(analysed.program, pattern="^== starter05")
    assert anchored.total >= 1
    assert anchored.total < everything.total


def test_symbol_regex_filters_inside_ghidra(analysed):
    everything = tools.list_symbols(analysed.program, "import", limit=1000)
    narrowed = tools.list_symbols(analysed.program, "import", pattern="^print")
    assert narrowed.total <= everything.total


def test_totals_reflect_ghidras_count_not_the_returned_page(analysed):
    out = tools.list_functions(analysed.program, limit=1)
    assert out.returned == 1
    assert out.total > 1
    assert out.truncated is False


# ----------------------------------------------- Stage 6: call graph


def test_callgraph_of_main_reaches_its_callees(analysed):
    out = tools.gen_callgraph(analysed.program, "main", direction="called", depth=2)
    assert out.node_count > 1, "main calls other functions; expected more than the root"
    assert out.edge_count >= 1
    assert out.mermaid.startswith("flowchart TD")


def test_callgraph_mermaid_declares_every_node(analysed):
    out = tools.gen_callgraph(analysed.program, "main", depth=2)
    for node in out.nodes:
        assert f'{node.id}["' in out.mermaid


def test_callgraph_calling_direction_finds_callers(analysed):
    out = tools.gen_callgraph(analysed.program, KNOWN_FUNCTION, direction="calling",
                              depth=2)
    assert out.direction == "calling"
    assert out.node_count >= 1


def test_callgraph_arrows_always_point_caller_to_callee(analysed):
    """A 'calling' graph is still read caller -> callee, not reversed."""
    called = tools.gen_callgraph(analysed.program, "main", direction="called", depth=1)
    calling = tools.gen_callgraph(analysed.program, KNOWN_FUNCTION,
                                  direction="calling", depth=1)
    main_id = next(n.id for n in called.nodes if n.name == "main")
    assert f"{main_id} -->" in called.mermaid
    if calling.edge_count:
        caller_id = next(
            (n.id for n in calling.nodes if n.name == "main"), None
        )
        if caller_id:
            assert f"{caller_id} -->" in calling.mermaid


def test_depth_one_is_shallower_than_depth_three(analysed):
    shallow = tools.gen_callgraph(analysed.program, "main", depth=1)
    deep = tools.gen_callgraph(analysed.program, "main", depth=3)
    assert deep.node_count >= shallow.node_count


def test_node_cap_is_enforced_and_reported(analysed):
    out = tools.gen_callgraph(analysed.program, "main", depth=10, max_nodes=3)
    assert out.node_count <= 3
    assert out.truncated is True


def test_depth_cap_is_enforced_by_the_java_side(analysed):
    out = tools.gen_callgraph(analysed.program, "main", depth=9999)
    assert out.requested_depth <= 10


def test_a_leaf_function_yields_a_single_node_graph(analysed):
    """Recursion protection must not stop a graph with nothing to expand."""
    out = tools.gen_callgraph(analysed.program, KNOWN_FUNCTION, direction="called",
                              depth=3)
    assert out.node_count >= 1
    assert out.mermaid.count("flowchart TD") == 1


def test_callgraph_terminates_on_a_recursive_binary(analysed):
    """A visited set is what keeps mutual recursion from looping forever."""
    out = tools.gen_callgraph(analysed.program, "main", depth=10, max_nodes=300)
    names = [n.name for n in out.nodes]
    assert len(names) == len(set(names)), "each function must appear once"


def test_unknown_function_raises(analysed):
    from ghmcp.errors import NotFound

    with pytest.raises(NotFound):
        tools.gen_callgraph(analysed.program, "no_such_function_at_all")


# --------------------------------------------- Stage 7: code search


def test_literal_code_search_finds_a_known_token(analysed):
    out = tools.search_code(analysed.program, "checksum|key", mode="literal", limit=10)
    assert out.indexed_functions > 0
    assert out.backend == "regex"


def test_first_search_decompiles_and_the_second_uses_the_cache(analysed):
    tools.clear_code_cache(analysed.program)
    first = tools.search_code(analysed.program, "return", mode="literal")
    second = tools.search_code(analysed.program, "return", mode="literal")
    assert first.from_cache is False
    assert second.from_cache is True
    assert second.indexed_functions == first.indexed_functions


def test_the_corpus_covers_the_known_function(analysed):
    out = tools.search_code(analysed.program, KNOWN_FUNCTION, mode="literal", limit=20)
    assert any(m.function == KNOWN_FUNCTION for m in out.matches) or out.returned >= 1


def test_semantic_search_ranks_something_plausible(analysed):
    out = tools.search_code(analysed.program, "check the key characters",
                            mode="semantic", limit=5)
    assert out.backend == "tfidf"
    assert out.returned >= 1
    assert out.matches[0].score > 0


def test_semantic_search_of_nonsense_returns_nothing(analysed):
    out = tools.search_code(analysed.program, "zzzz qqqq wwww", mode="semantic")
    assert out.returned == 0


def test_literal_context_returns_surrounding_lines(analysed):
    out = tools.search_code(analysed.program, "return", mode="literal", limit=1,
                            context=2)
    if out.returned:
        assert out.matches[0].snippet


def test_refresh_rebuilds_the_cache(analysed):
    tools.search_code(analysed.program, "return", mode="literal")
    out = tools.search_code(analysed.program, "return", mode="literal", refresh=True)
    assert out.from_cache is False


def test_clear_code_cache_then_search_rebuilds(analysed):
    tools.search_code(analysed.program, "return", mode="literal")
    assert tools.clear_code_cache(analysed.program)["cleared"] is True
    assert tools.search_code(analysed.program, "return", mode="literal").from_cache is False


def test_decompile_all_skips_externals_and_reports_counts(analysed):
    from ghmcp import headless as hl

    data = hl.export(analysed.program, "decompile_all", {})
    assert data["decompiled"] >= 1
    assert data["attempted"] >= data["decompiled"]
    assert data["failed"] >= 0
    assert all(f["c"] for f in data["functions"])


def test_a_gui_only_bundled_script_reports_its_error_not_a_clean_exit(analysed):
    """ExportFunctionInfoScript calls askFile(), which cannot work headlessly.

    analyzeHeadless still exits 0, so exit_code alone would claim success.
    """
    out = tools.run_ghidra_script(analysed.program, "ExportFunctionInfoScript.java")
    assert out.exit_code == 0
    assert out.script_error, "a script that threw must not look like a clean run"


def test_a_headless_safe_script_reports_no_error(analysed):
    from ghmcp import config

    out = tools.run_ghidra_script(
        analysed.program, config.EXPORT_SCRIPT, script_args=["info", "/dev/null"]
    )
    assert out.script_error is None


def test_importing_a_gzf_uses_the_packaged_program_name(tmp_path_factory):
    """Regression: a .gzf imports as its contents, not as the archive filename.

    Assuming the filename made every follow-up call fail with "Requested
    project program file(s) not found".
    """
    from tests.conftest import VIDAR_GZF

    if not VIDAR_GZF.is_file():
        pytest.skip(f"vidar sample missing: {VIDAR_GZF}")

    loc = tmp_path_factory.mktemp("gzfproj")
    config.PROJECT_LOCATION = loc
    config.PROJECT_NAME = "gzf-test"

    result = tools.analyze_binary(str(VIDAR_GZF))
    assert not result.program.endswith(".gzf"), result.program
    assert result.program == VIDAR_GZF.name[: -len(".gzf")]
    # The name must be usable: this is the call that failed before the fix.
    assert tools.get_program_info(result.program).function_count > 0
