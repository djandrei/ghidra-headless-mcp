/* Emit program facts as JSON for ghidra_headless_mcp.py.
 *
 * Run as a headless postScript. Ghidra compiles this on the fly, so there is
 * no build step:
 *
 *   analyzeHeadless <loc> <proj> -process <prog> -noanalysis [-readOnly] \
 *       -scriptPath <dir> -postScript HeadlessJsonExport.java <specFile> <outFile>
 *
 * The spec file is JSON: {"mode": "<name>", "args": {...}}. Args travel in a
 * file rather than on the command line because batch payloads (a list of 200
 * renames) exceed argv limits and defeat shell quoting.
 *
 * A spec may also carry a top-level "programs": [...] list. The mode then runs
 * once per named program inside the same JVM, and the data is
 *   {"multi": true, "results": [{"program", "ok", "data"|"error"}, ...]}
 * Modes never see the key; the dispatcher rebinds currentProgram around each
 * one, so every mode is project-capable without knowing it.
 *
 * A legacy positional form is still accepted for the four original modes:
 *   ... -postScript HeadlessJsonExport.java <mode> <outFile> [arg]
 *
 * Output is always an envelope, written to <outFile>:
 *   {"ok": true,  "mode": "...", "data": {...}}
 *   {"ok": false, "mode": "...", "error": {"kind": "...", "message": "..."}}
 * Error kinds: not_found | bad_argument | ghidra_error
 *
 * Output never goes to stdout: the MCP server that invokes this speaks
 * JSON-RPC on stdout, and analyzeHeadless log noise would corrupt it.
 *
 * Gson is bundled with Ghidra (Framework/Generic/lib/gson-2.13.2.jar) and is on
 * the script classpath, so this still depends on nothing beyond Ghidra itself.
 *
 * @category Headless
 */
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.util.FillOutStructureHelper;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

public class HeadlessJsonExport extends GhidraScript {

    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;

    /* ------------------------------------------------------------ framework */

    /** One exportable operation. Implementations read `args` and return data. */
    @FunctionalInterface
    private interface Mode {
        JsonElement run(JsonObject args) throws Exception;
    }

    /** Failure with a machine-readable kind, surfaced in the error envelope. */
    private static class ModeError extends Exception {
        final String kind;

        ModeError(String kind, String message) {
            super(message);
            this.kind = kind;
        }
    }

    private final Map<String, Mode> modes = new LinkedHashMap<>();

    private void registerModes() {
        modes.put("info", this::modeInfo);
        modes.put("functions", this::modeFunctions);
        modes.put("decompile", this::modeDecompile);
        modes.put("strings", this::modeStrings);
        modes.put("xrefs", this::modeXrefs);
        modes.put("function_at", this::modeFunctionAt);
        modes.put("disassemble", this::modeDisassemble);
        modes.put("read_bytes", this::modeReadBytes);
        modes.put("symbols", this::modeSymbols);
        modes.put("search_memory", this::modeSearchMemory);
        modes.put("edit", this::modeEdit);
        modes.put("callgraph", this::modeCallgraph);
        modes.put("decompile_all", this::modeDecompileAll);
        modes.put("project_files", this::modeProjectFiles);
        modes.put("delete_program", this::modeDeleteProgram);
        modes.put("link_symbols", this::modeLinkSymbols);
        modes.put("types", this::modeTypes);
        modes.put("type_info", this::modeTypeInfo);
        modes.put("cfg", this::modeCfg);
        modes.put("call_paths", this::modeCallPaths);
        modes.put("search_constants", this::modeSearchConstants);
        modes.put("search_instructions", this::modeSearchInstructions);
    }

    @Override
    public void run() throws Exception {
        registerModes();

        String[] argv = getScriptArgs();
        if (argv.length < 2) {
            throw new IllegalArgumentException(
                "usage: HeadlessJsonExport <specFile|mode> <outFile> [arg]");
        }

        String outFile = argv[1];
        String mode;
        JsonObject args;
        JsonArray programs = null;

        if (modes.containsKey(argv[0])) {
            // Legacy positional form: <mode> <outFile> [arg]
            mode = argv[0];
            args = new JsonObject();
            if (argv.length > 2) {
                args.addProperty("arg", argv[2]);
            }
        }
        else {
            // Spec-file form: <specFile> <outFile>
            String specText =
                new String(Files.readAllBytes(Paths.get(argv[0])), StandardCharsets.UTF_8);
            JsonObject spec = JsonParser.parseString(specText).getAsJsonObject();
            mode = spec.get("mode").getAsString();
            args = spec.has("args") && spec.get("args").isJsonObject()
                ? spec.getAsJsonObject("args")
                : new JsonObject();
            programs = spec.has("programs") && spec.get("programs").isJsonArray()
                ? spec.getAsJsonArray("programs")
                : null;
        }

        JsonObject envelope = new JsonObject();
        envelope.addProperty("mode", mode);
        try {
            Mode impl = modes.get(mode);
            if (impl == null) {
                throw new ModeError("bad_argument", "unknown mode: " + mode);
            }
            envelope.addProperty("ok", true);
            envelope.add("data", programs == null
                ? impl.run(args)
                : runOverPrograms(impl, args, programs));
        }
        catch (ModeError e) {
            envelope.addProperty("ok", false);
            envelope.add("error", error(e.kind, e.getMessage()));
        }
        catch (Exception e) {
            envelope.addProperty("ok", false);
            envelope.add("error", error("ghidra_error",
                e.getClass().getSimpleName() + ": " + e.getMessage()));
        }

        try (PrintWriter out = new PrintWriter(outFile, "UTF-8")) {
            out.print(new Gson().toJson(envelope));
        }
    }

    private JsonObject error(String kind, String message) {
        JsonObject e = new JsonObject();
        e.addProperty("kind", kind);
        e.addProperty("message", message == null ? "" : message);
        return e;
    }

    /**
     * Run one mode against several programs inside a single JVM start.
     *
     * This is what makes fan-out cheap: opening a second program costs
     * milliseconds, while starting analyzeHeadless again costs seconds. The
     * mode bodies are untouched - rebinding currentProgram (a protected field
     * of FlatProgramAPI) retargets the inherited flat API too, so a mode
     * written against currentProgram works here without knowing it.
     *
     * Four things this must get right:
     *
     * - The program analyzeHeadless attached to is already open. Reopening it
     *   would contend with ourselves, so it is borrowed rather than opened.
     * - Names are DomainFile names, not Program names. A PE reports its
     *   internal name (kernel32.dll) while the project holds the file name
     *   (KERNEL32.DLL); comparing the wrong one breaks the borrow check and
     *   returns a program field that does not match list_programs.
     * - currentProgram is restored in a finally, because analyzeHeadless tears
     *   down against whatever it attached to.
     * - A failing program produces an error entry, not an exception. One
     *   unanalysed binary must not discard the rest of the batch.
     *
     * getImmutableDomainObject rather than getReadOnlyDomainObject: measurably
     * faster, and isChangeable() is false, so read-only is structural instead
     * of a promise. The decompiler opens and completes on it either way.
     */
    private JsonElement runOverPrograms(Mode impl, JsonObject args, JsonArray programs)
            throws Exception {
        Program attached = currentProgram;
        String attachedName = attached == null ? null : attached.getDomainFile().getName();
        JsonArray results = new JsonArray();

        try {
            for (JsonElement element : programs) {
                String name = element.getAsString();
                JsonObject entry = new JsonObject();
                entry.addProperty("program", name);

                Program program = null;
                boolean borrowed = false;
                try {
                    if (name.equals(attachedName)) {
                        program = attached;
                        borrowed = true;
                    }
                    else {
                        DomainFile file = findFile(getProjectRootFolder(), name);
                        if (file == null) {
                            throw new ModeError("not_found",
                                "no program named " + name + " in the project");
                        }
                        program = (Program) file.getImmutableDomainObject(
                            this, DomainFile.DEFAULT_VERSION, monitor);
                    }

                    currentProgram = program;
                    state.setCurrentProgram(program);

                    entry.addProperty("ok", true);
                    entry.add("data", impl.run(args));
                }
                catch (ModeError e) {
                    entry.addProperty("ok", false);
                    entry.add("error", error(e.kind, e.getMessage()));
                }
                catch (Exception e) {
                    entry.addProperty("ok", false);
                    entry.add("error", error("ghidra_error",
                        e.getClass().getSimpleName() + ": " + e.getMessage()));
                }
                finally {
                    if (program != null && !borrowed) {
                        program.release(this);
                    }
                }
                results.add(entry);
            }
        }
        finally {
            currentProgram = attached;
            if (attached != null) {
                state.setCurrentProgram(attached);
            }
        }

        JsonObject data = new JsonObject();
        data.addProperty("multi", true);
        data.addProperty("count", results.size());
        data.add("results", results);
        return data;
    }

    /* ---------------------------------------------------------------- modes */

    private JsonElement modeInfo(JsonObject args) {
        JsonArray blocks = new JsonArray();
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            JsonObject o = new JsonObject();
            o.addProperty("name", b.getName());
            o.addProperty("start", b.getStart().toString());
            o.addProperty("end", b.getEnd().toString());
            o.addProperty("size", b.getSize());
            o.addProperty("readable", b.isRead());
            o.addProperty("writable", b.isWrite());
            o.addProperty("executable", b.isExecute());
            blocks.add(o);
        }

        JsonObject d = new JsonObject();
        d.addProperty("name", currentProgram.getName());
        d.addProperty("executable_path", currentProgram.getExecutablePath());
        d.addProperty("executable_format", currentProgram.getExecutableFormat());
        d.addProperty("md5", currentProgram.getExecutableMD5());
        d.addProperty("sha256", currentProgram.getExecutableSHA256());
        d.addProperty("language_id", currentProgram.getLanguageID().getIdAsString());
        d.addProperty("compiler_spec_id",
            currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
        d.addProperty("image_base", currentProgram.getImageBase().toString());
        d.addProperty("function_count", currentProgram.getFunctionManager().getFunctionCount());
        d.addProperty("symbol_count", currentProgram.getSymbolTable().getNumSymbols());
        d.add("memory_blocks", blocks);
        return d;
    }

    private JsonElement modeFunctions(JsonObject args) throws ModeError {
        Pattern pattern = compilePattern(args);
        boolean includeThunks = boolOr(args, "include_thunks", false);
        boolean includeExternal = boolOr(args, "include_external", false);
        int maxEmit = intOr(args, "max_emit", MAX_EMIT);

        JsonArray items = new JsonArray();
        int matched = 0;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            if (!includeThunks && f.isThunk()) {
                continue;
            }
            if (!includeExternal && f.isExternal()) {
                continue;
            }
            if (!matches(pattern, f.getName())) {
                continue;
            }
            matched++;
            if (items.size() >= maxEmit) {
                continue;
            }
            JsonObject o = new JsonObject();
            o.addProperty("name", f.getName());
            o.addProperty("address", f.getEntryPoint().toString());
            o.addProperty("size", f.getBody().getNumAddresses());
            o.addProperty("signature", f.getSignature().getPrototypeString());
            o.addProperty("calling_convention", f.getCallingConventionName());
            o.addProperty("is_thunk", f.isThunk());
            o.addProperty("is_external", f.isExternal());
            items.add(o);
        }
        JsonObject d = new JsonObject();
        d.addProperty("matched", matched);
        d.addProperty("truncated", matched > items.size());
        d.add("functions", items);
        return d;
    }

    private JsonElement modeDecompile(JsonObject args) throws Exception {
        JsonArray targets = args.getAsJsonArray("targets");
        boolean batch = targets != null;
        if (!batch) {
            String target = str(args, "target", str(args, "arg", null));
            if (target == null) {
                throw new ModeError("bad_argument",
                    "decompile requires a name or address");
            }
            targets = new JsonArray();
            targets.add(target);
        }
        if (targets.size() == 0) {
            throw new ModeError("bad_argument", "decompile requires at least one target");
        }

        // One DecompInterface for the whole batch: opening the program is the
        // expensive part, so re-opening it per function would throw away the
        // win that batching exists to capture.
        DecompInterface decomp = new DecompInterface();
        try {
            if (!decomp.openProgram(currentProgram)) {
                throw new ModeError("ghidra_error",
                    "decompiler failed to open program: " + decomp.getLastMessage());
            }

            // A single target keeps the flat legacy response; only an explicit
            // `targets` array gets the results envelope.
            if (!batch) {
                return decompileOne(decomp, targets.get(0).getAsString());
            }

            JsonArray results = new JsonArray();
            for (JsonElement t : targets) {
                String target = t.getAsString();
                JsonObject d = new JsonObject();
                d.addProperty("target", target);
                try {
                    JsonObject one = (JsonObject) decompileOne(decomp, target);
                    for (String k : one.keySet()) {
                        d.add(k, one.get(k));
                    }
                }
                catch (ModeError me) {
                    d.addProperty("error_kind", me.kind);
                    d.addProperty("error", me.getMessage());
                }
                results.add(d);
            }
            JsonObject out = new JsonObject();
            out.add("results", results);
            return out;
        }
        finally {
            decomp.dispose();
        }
    }

    /** Decompile one function on an already-open interface. */
    private JsonElement decompileOne(DecompInterface decomp, String target)
            throws ModeError {
        Function f = resolveFunction(target);
        if (f == null) {
            throw new ModeError("not_found", "function not found: " + target);
        }
        DecompileResults res =
            decomp.decompileFunction(f, DECOMPILE_TIMEOUT_SECONDS, monitor);
        if (!res.decompileCompleted()) {
            throw new ModeError("ghidra_error",
                "decompilation failed: " + res.getErrorMessage());
        }
        JsonObject d = new JsonObject();
        d.addProperty("name", f.getName());
        d.addProperty("address", f.getEntryPoint().toString());
        d.addProperty("signature", f.getSignature().getPrototypeString());
        d.addProperty("c", res.getDecompiledFunction().getC());
        return d;
    }

    private JsonElement modeStrings(JsonObject args) throws ModeError {
        int minLength = intOr(args, "min_length", intOr(args, "arg", 4));
        Pattern pattern = compilePattern(args);
        int maxEmit = intOr(args, "max_emit", MAX_EMIT);

        JsonArray items = new JsonArray();
        int matched = 0;
        DataIterator it = currentProgram.getListing().getDefinedData(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Data d = it.next();
            boolean isString = d.getDataType() instanceof StringDataType
                || d.getValue() instanceof String;
            if (!isString) {
                continue;
            }
            Object value = d.getValue();
            if (value == null) {
                continue;
            }
            String s = value.toString();
            if (s.length() < minLength) {
                continue;
            }
            if (!matches(pattern, s)) {
                continue;
            }
            matched++;
            if (items.size() >= maxEmit) {
                continue;
            }
            JsonObject o = new JsonObject();
            o.addProperty("address", d.getAddress().toString());
            o.addProperty("length", s.length());
            o.addProperty("value", s);
            items.add(o);
        }
        JsonObject d = new JsonObject();
        d.addProperty("matched", matched);
        d.addProperty("truncated", matched > items.size());
        d.add("strings", items);
        return d;
    }

    /**
     * Cross-references to or from one or more targets.
     *
     * Batch is per-target: one unresolvable name reports its own error rather
     * than failing the whole call, because a model asking about twenty symbols
     * should not lose nineteen answers to one typo.
     */
    private JsonElement modeXrefs(JsonObject args) throws Exception {
        String direction = str(args, "direction", "to");
        if (!direction.equals("to") && !direction.equals("from")) {
            throw new ModeError("bad_argument",
                "direction must be 'to' or 'from', got: " + direction);
        }

        JsonArray targets = args.getAsJsonArray("targets");
        if (targets == null || targets.size() == 0) {
            throw new ModeError("bad_argument", "xrefs requires at least one target");
        }

        ReferenceManager refs = currentProgram.getReferenceManager();
        JsonArray results = new JsonArray();

        for (JsonElement t : targets) {
            String target = t.getAsString();
            JsonObject result = new JsonObject();
            result.addProperty("target", target);

            Resolved resolved = resolve(target);
            if (resolved == null) {
                result.add("resolved_address", null);
                result.add("resolved_kind", null);
                result.addProperty("error", "not found: " + target);
                result.add("xrefs", new JsonArray());
                results.add(result);
                continue;
            }

            result.addProperty("resolved_address", resolved.address.toString());
            result.addProperty("resolved_kind", resolved.kind);
            result.add("error", null);

            JsonArray items = new JsonArray();
            if (direction.equals("to")) {
                ReferenceIterator it = refs.getReferencesTo(resolved.address);
                while (it.hasNext() && !monitor.isCancelled()) {
                    items.add(reference(it.next()));
                }
            }
            else if (resolved.function != null) {
                // References *from* a function means from anywhere in its body.
                // getReferencesFrom(entryPoint) would only ever see the first
                // instruction, which almost never references anything.
                AddressIterator sources = refs.getReferenceSourceIterator(
                    resolved.function.getBody(), true);
                while (sources.hasNext() && !monitor.isCancelled()) {
                    for (Reference r : refs.getReferencesFrom(sources.next())) {
                        items.add(reference(r));
                    }
                }
            }
            else {
                for (Reference r : refs.getReferencesFrom(resolved.address)) {
                    items.add(reference(r));
                }
            }
            result.add("xrefs", items);
            results.add(result);
        }

        JsonObject d = new JsonObject();
        d.addProperty("direction", direction);
        d.add("results", results);
        return d;
    }

    /** One reference, enriched with the function it sits in. */
    private JsonObject reference(Reference r) {
        JsonObject o = new JsonObject();
        o.addProperty("from_address", r.getFromAddress().toString());
        o.addProperty("to_address", r.getToAddress().toString());
        o.addProperty("ref_type", r.getReferenceType().getName());
        o.addProperty("is_primary", r.isPrimary());

        // A bare address is nearly useless to a caller; "called from main+0x40"
        // is not. Attach the containing function whenever there is one.
        Function containing = currentProgram.getFunctionManager()
            .getFunctionContaining(r.getFromAddress());
        if (containing != null) {
            o.addProperty("from_function", containing.getName());
            o.addProperty("from_function_address", containing.getEntryPoint().toString());
        }
        else {
            o.add("from_function", null);
            o.add("from_function_address", null);
        }
        return o;
    }

    /** The function at (or containing) an address. */
    private JsonElement modeFunctionAt(JsonObject args) throws Exception {
        String addrText = str(args, "address", null);
        if (addrText == null) {
            throw new ModeError("bad_argument", "function_at requires an address");
        }
        Address addr;
        try {
            addr = currentProgram.getAddressFactory().getAddress(addrText);
        }
        catch (Exception e) {
            throw new ModeError("bad_argument", "not a valid address: " + addrText);
        }
        if (addr == null) {
            throw new ModeError("bad_argument", "not a valid address: " + addrText);
        }

        Function f = currentProgram.getFunctionManager().getFunctionAt(addr);
        boolean isEntry = f != null;
        if (f == null) {
            f = currentProgram.getFunctionManager().getFunctionContaining(addr);
        }
        if (f == null) {
            throw new ModeError("not_found", "no function at or containing " + addrText);
        }

        JsonObject d = new JsonObject();
        d.addProperty("name", f.getName());
        d.addProperty("address", f.getEntryPoint().toString());
        d.addProperty("size", f.getBody().getNumAddresses());
        d.addProperty("signature", f.getSignature().getPrototypeString());
        d.addProperty("calling_convention", f.getCallingConventionName());
        d.addProperty("is_thunk", f.isThunk());
        d.addProperty("is_external", f.isExternal());
        d.addProperty("queried_address", addr.toString());
        d.addProperty("is_entry_point", isEntry);
        return d;
    }

    /**
     * Symbols of one kind.
     *
     * One mode covers what the reference projects spread over five tools
     * (imports, exports, data items, classes, namespaces): the payload shape is
     * identical, only the selection differs, and fewer tools makes a model's
     * choice easier.
     */
    private JsonElement modeSymbols(JsonObject args) throws Exception {
        String kind = str(args, "kind", "import");
        symbolPattern = compilePattern(args);
        symbolMaxEmit = intOr(args, "max_emit", MAX_EMIT);
        symbolMatched = 0;
        SymbolTable table = currentProgram.getSymbolTable();
        JsonArray items = new JsonArray();

        switch (kind) {
            case "import": {
                // Imports are external symbols: what the binary asks of the OS.
                SymbolIterator it = table.getExternalSymbols();
                while (it.hasNext() && !monitor.isCancelled()) {
                    addSymbol(items, it.next(), kind);
                }
                break;
            }
            case "export": {
                // Exports are entry points: what the binary offers to others.
                SymbolIterator it = table.getAllSymbols(true);
                while (it.hasNext() && !monitor.isCancelled()) {
                    Symbol sym = it.next();
                    if (sym.isExternalEntryPoint()) {
                        addSymbol(items, sym, kind);
                    }
                }
                break;
            }
            case "data": {
                DataIterator it = currentProgram.getListing().getDefinedData(true);
                while (it.hasNext() && !monitor.isCancelled()) {
                    Data d = it.next();
                    String label = d.getLabel() != null ? d.getLabel() : "";
                    if (!matches(symbolPattern, label)) {
                        continue;
                    }
                    symbolMatched++;
                    if (items.size() >= symbolMaxEmit) {
                        continue;
                    }
                    JsonObject o = new JsonObject();
                    o.addProperty("name", label);
                    o.addProperty("address", d.getAddress().toString());
                    o.addProperty("kind", "data");
                    o.addProperty("namespace", (String) null);
                    o.addProperty("is_external", false);
                    o.addProperty("source_type", d.getDataType().getName());
                    Object v = d.getValue();
                    o.addProperty("value", v == null ? null : v.toString());
                    items.add(o);
                }
                break;
            }
            case "class":
            case "namespace":
            case "label":
            case "function": {
                SymbolType wanted = symbolType(kind);
                SymbolIterator it = table.getAllSymbols(true);
                while (it.hasNext() && !monitor.isCancelled()) {
                    Symbol sym = it.next();
                    if (sym.getSymbolType() == wanted) {
                        addSymbol(items, sym, kind);
                    }
                }
                break;
            }
            default:
                throw new ModeError("bad_argument",
                    "unknown symbol kind: " + kind
                        + " (want import, export, data, class, namespace, label or function)");
        }

        JsonObject d = new JsonObject();
        d.addProperty("kind", kind);
        d.addProperty("matched", symbolMatched);
        d.addProperty("truncated", symbolMatched > items.size());
        d.add("symbols", items);
        return d;
    }

    private SymbolType symbolType(String kind) {
        switch (kind) {
            case "class":     return SymbolType.CLASS;
            case "namespace": return SymbolType.NAMESPACE;
            case "label":     return SymbolType.LABEL;
            default:          return SymbolType.FUNCTION;
        }
    }

    /** Apply the shared pattern and emission cap, then append. */
    private void addSymbol(JsonArray items, Symbol sym, String kind) {
        if (!matches(symbolPattern, sym.getName())) {
            return;
        }
        symbolMatched++;
        if (items.size() >= symbolMaxEmit) {
            return;
        }
        items.add(symbol(sym, kind));
    }

    private JsonObject symbol(Symbol sym, String kind) {
        JsonObject o = new JsonObject();
        o.addProperty("name", sym.getName());
        o.addProperty("address", sym.getAddress() == null ? null : sym.getAddress().toString());
        o.addProperty("kind", kind);
        String ns = sym.getParentNamespace() == null ? null : sym.getParentNamespace().getName();
        o.addProperty("namespace", "Global".equals(ns) ? null : ns);
        o.addProperty("is_external", sym.isExternal());
        o.addProperty("source_type", sym.getSource() == null ? null : sym.getSource().toString());
        o.add("value", null);
        return o;
    }

    /**
     * Ceiling on rows emitted by a list mode. Matching is still counted in
     * full, so the caller learns the true total and that it was truncated,
     * rather than silently receiving a prefix.
     */
    private static final int MAX_EMIT = 5000;

    // Shared by modeSymbols and its per-kind branches.
    private Pattern symbolPattern;
    private int symbolMaxEmit = MAX_EMIT;
    private int symbolMatched;

    /**
     * Compile the caller's regex, or null for "match everything".
     *
     * Case-insensitive and matched with find(), so a plain substring behaves as
     * it did before regex support - the migration is a rename, not a change of
     * behaviour.
     */
    private Pattern compilePattern(JsonObject args) throws ModeError {
        String p = str(args, "pattern", null);
        if (p == null || p.isEmpty()) {
            return null;
        }
        try {
            return Pattern.compile(p, Pattern.CASE_INSENSITIVE);
        }
        catch (PatternSyntaxException e) {
            throw new ModeError("bad_argument", "invalid regex: " + e.getMessage());
        }
    }

    private boolean matches(Pattern pattern, String value) {
        return pattern == null || (value != null && pattern.matcher(value).find());
    }

    private boolean boolOr(JsonObject args, String key, boolean fallback) {
        if (!args.has(key) || args.get(key).isJsonNull()) {
            return fallback;
        }
        try {
            return args.get(key).getAsBoolean();
        }
        catch (UnsupportedOperationException e) {
            return fallback;
        }
    }

    /**
     * Search raw memory for text, in several encodings.
     *
     * list_strings only reports what Ghidra's analyser *defined*, which misses
     * length-prefixed wide strings (Delphi and VB store them that way) and
     * anything in undefined data. This searches the bytes themselves, so it
     * finds text no amount of auto-analysis has typed.
     */
    private JsonElement modeSearchMemory(JsonObject args) throws Exception {
        String text = str(args, "text", null);
        String hex = str(args, "hex", null);
        if (text == null && hex == null) {
            throw new ModeError("bad_argument", "search_memory requires text or hex");
        }
        int limit = Math.max(1, intOr(args, "limit", 50));

        Map<String, byte[]> needles = new LinkedHashMap<>();
        if (hex != null) {
            needles.put("hex", parseHex(hex));
        }
        else {
            needles.put("ascii", text.getBytes(StandardCharsets.US_ASCII));
            needles.put("utf16le", text.getBytes(java.nio.charset.StandardCharsets.UTF_16LE));
            needles.put("utf16be", text.getBytes(java.nio.charset.StandardCharsets.UTF_16BE));
        }

        JsonArray hits = new JsonArray();
        for (Map.Entry<String, byte[]> e : needles.entrySet()) {
            byte[] needle = e.getValue();
            if (needle.length == 0) {
                continue;
            }
            Address at = currentProgram.getMinAddress();
            while (at != null && hits.size() < limit && !monitor.isCancelled()) {
                Address found = currentProgram.getMemory()
                    .findBytes(at, needle, null, true, monitor);
                if (found == null) {
                    break;
                }
                JsonObject o = new JsonObject();
                o.addProperty("address", found.toString());
                o.addProperty("encoding", e.getKey());
                MemoryBlock blk = currentProgram.getMemory().getBlock(found);
                o.addProperty("block", blk == null ? null : blk.getName());
                Function f = currentProgram.getFunctionManager().getFunctionContaining(found);
                o.addProperty("in_function", f == null ? null : f.getName());
                hits.add(o);
                try {
                    at = found.add(1);
                }
                catch (Exception ex) {
                    break;
                }
            }
        }

        JsonObject d = new JsonObject();
        d.addProperty("query", text != null ? text : hex);
        d.addProperty("count", hits.size());
        d.addProperty("truncated", hits.size() >= limit);
        d.add("hits", hits);
        return d;
    }

    private byte[] parseHex(String hex) throws ModeError {
        String clean = hex.replaceAll("[^0-9a-fA-F]", "");
        if (clean.length() % 2 != 0) {
            throw new ModeError("bad_argument", "hex needs an even number of digits");
        }
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    /** Hard cap on instructions per call, matching pyghidra-mcp's limit. */
    private static final int MAX_INSTRUCTIONS = 200;
    /** Hard cap on a byte read, to keep a response from blowing a context window. */
    private static final int MAX_READ_BYTES = 4096;

    /**
     * Disassembly of a function body, or of N instructions from an address.
     *
     * Returns an aligned text listing rather than JSON rows: a listing is what
     * an analyst reads, and it costs a fraction of the tokens per instruction.
     */
    private JsonElement modeDisassemble(JsonObject args) throws Exception {
        String target = str(args, "target", null);
        if (target == null) {
            throw new ModeError("bad_argument", "disassemble requires a target");
        }
        int count = Math.min(intOr(args, "count", 20), MAX_INSTRUCTIONS);
        if (count <= 0) {
            throw new ModeError("bad_argument", "count must be positive");
        }
        boolean includeBytes = args.has("include_bytes")
            && args.get("include_bytes").getAsBoolean();

        Resolved resolved = resolve(target);
        if (resolved == null) {
            throw new ModeError("not_found", "cannot resolve: " + target);
        }

        InstructionIterator it;
        String scope;
        if (resolved.function != null) {
            // A function target disassembles its whole body, as GhidraMCP does.
            it = currentProgram.getListing().getInstructions(resolved.function.getBody(), true);
            scope = "function";
        }
        else {
            // A bare address disassembles forward, which is what shellcode and
            // mid-function inspection need — no entry point required.
            it = currentProgram.getListing().getInstructions(resolved.address, true);
            scope = "address";
        }

        StringBuilder listing = new StringBuilder();
        int emitted = 0;
        boolean truncated = false;
        Address firstEmitted = null;
        while (it.hasNext() && !monitor.isCancelled()) {
            if (emitted >= count) {
                truncated = true;
                break;
            }
            Instruction instr = it.next();
            if (firstEmitted == null) {
                firstEmitted = instr.getAddress();
            }
            listing.append(String.format("%-12s", instr.getAddress().toString()));
            if (includeBytes) {
                listing.append(String.format("%-24s", hex(safeBytes(instr))));
            }
            listing.append(instr.toString()).append("\n");
            emitted++;
        }

        if (emitted == 0) {
            throw new ModeError("not_found",
                "no instructions at " + resolved.address
                    + " (undefined data, or outside initialised memory?)");
        }

        // The iterator yields only *defined* instructions, so it silently steps
        // over undefined bytes - a computed jump table, or data Ghidra never
        // typed. Saying where the listing really begins keeps a caller from
        // believing they are reading code at the address they asked for.
        long skipped = firstEmitted == null
            ? 0
            : firstEmitted.subtract(resolved.address);

        JsonObject d = new JsonObject();
        d.addProperty("target", target);
        d.addProperty("resolved_address", resolved.address.toString());
        d.addProperty("listing_starts_at", firstEmitted == null ? null : firstEmitted.toString());
        d.addProperty("skipped_bytes", skipped);
        d.addProperty("scope", scope);
        d.addProperty("instruction_count", emitted);
        d.addProperty("truncated", truncated);
        d.addProperty("listing", listing.toString());
        return d;
    }

    /** Raw bytes at an address, so a caller can extract blobs and key tables. */
    private JsonElement modeReadBytes(JsonObject args) throws Exception {
        JsonArray reads = args.getAsJsonArray("reads");
        if (reads == null) {
            String addrText = str(args, "address", null);
            if (addrText == null) {
                throw new ModeError("bad_argument", "read_bytes requires an address");
            }
            return readOne(addrText, intOr(args, "size", 32));
        }
        if (reads.size() == 0) {
            throw new ModeError("bad_argument", "read_bytes requires at least one read");
        }

        JsonArray results = new JsonArray();
        for (JsonElement e : reads) {
            JsonObject spec = e.getAsJsonObject();
            String addrText = str(spec, "address", null);
            JsonObject d = new JsonObject();
            d.addProperty("target", addrText == null ? "" : addrText);
            if (addrText == null) {
                d.addProperty("error_kind", "bad_argument");
                d.addProperty("error", "read is missing an address");
                results.add(d);
                continue;
            }
            try {
                JsonObject one = (JsonObject) readOne(addrText, intOr(spec, "size", 32));
                for (String k : one.keySet()) {
                    d.add(k, one.get(k));
                }
            }
            catch (ModeError me) {
                d.addProperty("error_kind", me.kind);
                d.addProperty("error", me.getMessage());
            }
            results.add(d);
        }
        JsonObject out = new JsonObject();
        out.add("results", results);
        return out;
    }

    /** Read one span, shared by the single and batch paths. */
    private JsonElement readOne(String addrText, int size) throws ModeError {
        if (size <= 0) {
            throw new ModeError("bad_argument", "size must be positive");
        }
        if (size > MAX_READ_BYTES) {
            throw new ModeError("bad_argument",
                "size exceeds the " + MAX_READ_BYTES + "-byte cap");
        }

        Resolved resolved = resolve(addrText);
        if (resolved == null) {
            throw new ModeError("not_found", "cannot resolve: " + addrText);
        }

        byte[] buf = new byte[size];
        int read;
        try {
            read = currentProgram.getMemory().getBytes(resolved.address, buf);
        }
        catch (MemoryAccessException e) {
            throw new ModeError("not_found",
                "cannot read " + size + " bytes at " + resolved.address
                    + ": " + e.getMessage());
        }

        byte[] actual = new byte[read];
        System.arraycopy(buf, 0, actual, 0, read);

        JsonObject d = new JsonObject();
        d.addProperty("address", resolved.address.toString());
        d.addProperty("requested_size", size);
        d.addProperty("size", read);
        d.addProperty("hex", hex(actual));
        d.addProperty("ascii", ascii(actual));
        return d;
    }

    /**
     * Every program in the project, walked from the root folder.
     *
     * This is what retires the server's hand-maintained index: the project
     * itself is authoritative, so programs imported by an external
     * analyzeHeadless run or by the Ghidra GUI are visible too.
     */
    private JsonElement modeProjectFiles(JsonObject args) throws Exception {
        JsonArray files = new JsonArray();
        collectFiles(getProjectRootFolder(), files);
        JsonObject d = new JsonObject();
        d.addProperty("count", files.size());
        d.add("files", files);
        return d;
    }

    private void collectFiles(DomainFolder folder, JsonArray out) {
        if (folder == null || monitor.isCancelled()) {
            return;
        }
        for (DomainFile f : folder.getFiles()) {
            JsonObject o = new JsonObject();
            o.addProperty("name", f.getName());
            o.addProperty("pathname", f.getPathname());
            o.addProperty("content_type", f.getContentType());
            o.addProperty("is_busy", f.isBusy());
            out.add(o);
        }
        for (DomainFolder sub : folder.getFolders()) {
            collectFiles(sub, out);
        }
    }

    /**
     * Delete one program from the project.
     *
     * Ghidra will not delete a file that is open, and the program this script
     * is attached to is by definition open - so the caller must attach to a
     * different program. The Python side arranges that; this reports plainly
     * when it has not.
     */
    private JsonElement modeDeleteProgram(JsonObject args) throws Exception {
        String name = str(args, "name", null);
        if (name == null) {
            throw new ModeError("bad_argument", "delete_program requires a name");
        }

        JsonArray files = new JsonArray();
        collectFiles(getProjectRootFolder(), files);

        DomainFile target = null;
        DomainFolder root = getProjectRootFolder();
        target = findFile(root, name);
        if (target == null) {
            throw new ModeError("not_found", "no program named " + name + " in the project");
        }
        if (target.isBusy()) {
            throw new ModeError("ghidra_error",
                "program " + name + " is open in this run; attach to a different "
                    + "program to delete it");
        }

        String pathname = target.getPathname();
        target.delete();

        JsonObject d = new JsonObject();
        d.addProperty("deleted", name);
        d.addProperty("pathname", pathname);
        return d;
    }

    private DomainFile findFile(DomainFolder folder, String name) {
        if (folder == null) {
            return null;
        }
        for (DomainFile f : folder.getFiles()) {
            if (f.getName().equals(name) || f.getPathname().equals(name)) {
                return f;
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            DomainFile found = findFile(sub, name);
            if (found != null) {
                return found;
            }
        }
        return null;
    }

    /**
     * Classify named symbols within this one program, for resolve_symbol.
     *
     * Single-program on purpose: the dispatcher fans it out and the join
     * happens in Python. That keeps the Java side a classifier rather than a
     * second project walker.
     *
     * The roles are not exclusive and that is the point. In a Windows
     * forwarder, kernel32 both *exports* CreateFileW and *imports* it from an
     * apiset; the implementing library exports it and imports nothing. Seeing
     * both roles on one program is what identifies the forwarder.
     */
    private JsonElement modeLinkSymbols(JsonObject args) throws Exception {
        JsonArray names = args.getAsJsonArray("names");
        if (names == null || names.size() == 0) {
            throw new ModeError("bad_argument", "link_symbols requires a names list");
        }

        SymbolTable table = currentProgram.getSymbolTable();
        JsonArray out = new JsonArray();

        for (JsonElement element : names) {
            String name = element.getAsString();
            JsonObject entry = new JsonObject();
            entry.addProperty("name", name);

            JsonArray roles = new JsonArray();
            String address = null;
            String library = null;
            String thunkTarget = null;
            String thunkLibrary = null;
            boolean isExternal = false;
            boolean isThunk = false;

            for (Symbol sym : table.getGlobalSymbols(name)) {
                if (sym.isExternalEntryPoint()) {
                    addRole(roles, "export");
                    if (address == null && sym.getAddress() != null) {
                        address = sym.getAddress().toString();
                    }
                }
            }

            // Imports are external symbols; the parent namespace names the
            // library the loader is expected to satisfy them from.
            SymbolIterator externals = table.getExternalSymbols(name);
            while (externals.hasNext() && !monitor.isCancelled()) {
                Symbol sym = externals.next();
                addRole(roles, "import");
                isExternal = true;
                if (library == null && sym.getParentNamespace() != null) {
                    String ns = sym.getParentNamespace().getName();
                    if (!"Global".equals(ns)) {
                        library = ns;
                    }
                }
            }

            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (monitor.isCancelled()) {
                    break;
                }
                if (!f.getName().equals(name)) {
                    continue;
                }
                addRole(roles, "function");
                if (address == null && f.getEntryPoint() != null) {
                    address = f.getEntryPoint().toString();
                }
                if (f.isThunk()) {
                    isThunk = true;
                    Function thunked = f.getThunkedFunction(true);
                    if (thunked != null) {
                        thunkTarget = thunked.getName();
                        if (thunked.isExternal() && thunked.getParentNamespace() != null) {
                            String ns = thunked.getParentNamespace().getName();
                            if (!"Global".equals(ns)) {
                                thunkLibrary = ns;
                            }
                        }
                    }
                }
                break;
            }

            entry.add("roles", roles);
            entry.addProperty("address", address);
            entry.addProperty("library", library);
            entry.addProperty("thunk_target", thunkTarget);
            entry.addProperty("thunk_library", thunkLibrary);
            entry.addProperty("is_external", isExternal);
            entry.addProperty("is_thunk", isThunk);
            out.add(entry);
        }

        JsonObject data = new JsonObject();
        // The internal name too: a PE reports kernel32.dll while the project
        // file is KERNEL32.DLL, and an import table names the former.
        data.addProperty("internal_name", currentProgram.getName());
        data.addProperty("count", out.size());
        data.add("symbols", out);
        return data;
    }

    private void addRole(JsonArray roles, String role) {
        for (JsonElement existing : roles) {
            if (existing.getAsString().equals(role)) {
                return;
            }
        }
        roles.add(role);
    }

    /**
     * Decompile every function once, for the code-search index.
     *
     * Expensive - it is the whole binary through the decompiler - which is
     * exactly why the result is cached on the Python side and this runs once
     * per program rather than once per query.
     */
    private JsonElement modeDecompileAll(JsonObject args) throws Exception {
        int maxFunctions = intOr(args, "max_functions", MAX_EMIT);
        boolean includeThunks = boolOr(args, "include_thunks", false);
        int timeout = intOr(args, "timeout_sec", DECOMPILE_TIMEOUT_SECONDS);

        DecompInterface decomp = new DecompInterface();
        JsonArray items = new JsonArray();
        int attempted = 0;
        int failed = 0;
        boolean truncated = false;

        try {
            if (!decomp.openProgram(currentProgram)) {
                throw new ModeError("ghidra_error",
                    "decompiler failed to open program: " + decomp.getLastMessage());
            }
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                if (f.isExternal() || (!includeThunks && f.isThunk())) {
                    continue;
                }
                if (items.size() >= maxFunctions) {
                    truncated = true;
                    break;
                }
                attempted++;
                DecompileResults res = decomp.decompileFunction(f, timeout, monitor);
                if (!res.decompileCompleted()) {
                    // One unlucky function must not lose the whole index.
                    failed++;
                    continue;
                }
                JsonObject o = new JsonObject();
                o.addProperty("name", f.getName());
                o.addProperty("address", f.getEntryPoint().toString());
                o.addProperty("c", res.getDecompiledFunction().getC());
                items.add(o);
            }
        }
        finally {
            decomp.dispose();
        }

        JsonObject d = new JsonObject();
        d.addProperty("attempted", attempted);
        d.addProperty("decompiled", items.size());
        d.addProperty("failed", failed);
        d.addProperty("truncated", truncated);
        d.add("functions", items);
        return d;
    }

    /** Depth and node ceilings: an unbounded call graph is enormous and useless. */
    private static final int MAX_DEPTH = 10;
    private static final int MAX_NODES = 300;

    /**
     * A call graph around one function, rendered as MermaidJS.
     *
     * Mermaid because a model can paste it straight into a report and it
     * renders in the places these reports land, matching pyghidra-mcp's choice.
     *
     * Breadth-first with a visited set: recursion and mutual recursion are the
     * normal case in real binaries, not an edge case, and a naive walk would
     * not terminate.
     */
    private JsonElement modeCallgraph(JsonObject args) throws Exception {
        String target = str(args, "function", null);
        if (target == null) {
            throw new ModeError("bad_argument", "callgraph requires a function");
        }
        String direction = str(args, "direction", "called");
        if (!direction.equals("called") && !direction.equals("calling")) {
            throw new ModeError("bad_argument",
                "direction must be 'called' or 'calling', got: " + direction);
        }
        int depth = Math.min(Math.max(intOr(args, "depth", 3), 1), MAX_DEPTH);
        int maxNodes = Math.min(intOr(args, "max_nodes", MAX_NODES), MAX_NODES);

        Function root = resolveFunction(target);
        if (root == null) {
            throw new ModeError("not_found", "function not found: " + target);
        }

        Map<String, String> ids = new LinkedHashMap<>();     // name -> node id
        java.util.Set<String> edges = new java.util.LinkedHashSet<>();
        java.util.List<Function> frontier = new java.util.ArrayList<>();
        frontier.add(root);
        ids.put(root.getName(), "n0");
        boolean truncated = false;
        int reachedDepth = 0;

        for (int level = 0; level < depth && !frontier.isEmpty(); level++) {
            java.util.List<Function> next = new java.util.ArrayList<>();
            for (Function f : frontier) {
                if (monitor.isCancelled()) {
                    break;
                }
                java.util.Set<Function> neighbours = direction.equals("called")
                    ? f.getCalledFunctions(monitor)
                    : f.getCallingFunctions(monitor);
                for (Function n : neighbours) {
                    if (!ids.containsKey(n.getName())) {
                        if (ids.size() >= maxNodes) {
                            truncated = true;
                            continue;
                        }
                        ids.put(n.getName(), "n" + ids.size());
                        next.add(n);
                    }
                    // Direction decides which way the arrow points, so a
                    // "calling" graph still reads caller -> callee.
                    String from = direction.equals("called") ? f.getName() : n.getName();
                    String to = direction.equals("called") ? n.getName() : f.getName();
                    edges.add(ids.get(from) + " --> " + ids.get(to));
                }
            }
            if (!next.isEmpty()) {
                reachedDepth = level + 1;
            }
            frontier = next;
        }

        StringBuilder mermaid = new StringBuilder("flowchart TD\n");
        for (Map.Entry<String, String> e : ids.entrySet()) {
            mermaid.append("    ").append(e.getValue())
                .append("[\"").append(mermaidLabel(e.getKey())).append("\"]\n");
        }
        for (String edge : edges) {
            mermaid.append("    ").append(edge).append("\n");
        }

        JsonArray nodes = new JsonArray();
        for (Map.Entry<String, String> e : ids.entrySet()) {
            JsonObject o = new JsonObject();
            o.addProperty("id", e.getValue());
            o.addProperty("name", e.getKey());
            nodes.add(o);
        }

        JsonObject d = new JsonObject();
        d.addProperty("function", root.getName());
        d.addProperty("address", root.getEntryPoint().toString());
        d.addProperty("direction", direction);
        d.addProperty("requested_depth", depth);
        d.addProperty("reached_depth", reachedDepth);
        d.addProperty("node_count", ids.size());
        d.addProperty("edge_count", edges.size());
        d.addProperty("truncated", truncated);
        d.add("nodes", nodes);
        d.addProperty("mermaid", mermaid.toString());
        return d;
    }

    /** Quotes and brackets break Mermaid node labels; C++ names are full of them. */
    private String mermaidLabel(String name) {
        return name.replace("\"", "'").replace("[", "(").replace("]", ")");
    }

    /* ---------------------------------------------------------------- edits */

    /**
     * Apply a batch of edits in one JVM start.
     *
     * Edits are isolated from each other: one failure reports at its index and
     * the rest still apply. All-or-nothing would discard nineteen good renames
     * because the twentieth named a variable that no longer exists, which is
     * the opposite of useful when a model is recording what it just learned.
     * The caller sees applied/failed counts and a per-edit verdict, so a retry
     * can target exactly what failed.
     */
    private JsonElement modeEdit(JsonObject args) throws Exception {
        JsonArray edits = args.getAsJsonArray("edits");
        if (edits == null || edits.size() == 0) {
            throw new ModeError("bad_argument", "edit requires at least one edit");
        }

        JsonArray results = new JsonArray();
        int applied = 0;
        int failed = 0;

        for (int i = 0; i < edits.size(); i++) {
            JsonObject edit = edits.get(i).getAsJsonObject();
            String kind = str(edit, "kind", "");
            JsonObject r = new JsonObject();
            r.addProperty("index", i);
            r.addProperty("kind", kind);
            try {
                r.addProperty("detail", applyEdit(kind, edit));
                r.addProperty("ok", true);
                r.add("error", null);
                r.add("error_kind", null);
                applied++;
            }
            catch (ModeError e) {
                r.addProperty("ok", false);
                r.addProperty("error_kind", e.kind);
                r.addProperty("error", e.getMessage());
                r.add("detail", null);
                failed++;
            }
            catch (Exception e) {
                r.addProperty("ok", false);
                r.addProperty("error_kind", "ghidra_error");
                r.addProperty("error", e.getClass().getSimpleName() + ": " + e.getMessage());
                r.add("detail", null);
                failed++;
            }
            results.add(r);
        }

        JsonObject d = new JsonObject();
        d.addProperty("applied", applied);
        d.addProperty("failed", failed);
        d.add("results", results);
        return d;
    }

    private String applyEdit(String kind, JsonObject e) throws Exception {
        switch (kind) {
            case "rename_function":   return editRenameFunction(e);
            case "rename_variable":   return editRenameVariable(e);
            case "rename_data":       return editRenameData(e);
            case "set_prototype":     return editSetPrototype(e);
            case "set_variable_type": return editSetVariableType(e);
            case "set_comment":       return editSetComment(e);
            case "define_type":       return editDefineType(e);
            case "apply_type":        return editApplyType(e);
            case "struct_field":      return editStructField(e);
            case "enum_member":       return editEnumMember(e);
            case "delete_type":       return editDeleteType(e);
            case "fill_struct":       return editFillStruct(e);
            default:
                throw new ModeError("bad_argument", "unknown edit kind: " + kind);
        }
    }

    private String editRenameFunction(JsonObject e) throws Exception {
        Function f = requireFunction(str(e, "target", null), "rename_function");
        String newName = requireArg(e, "new_name");
        String old = f.getName();
        f.setName(newName, SourceType.USER_DEFINED);
        return "renamed function " + old + " -> " + newName;
    }

    private String editRenameData(JsonObject e) throws Exception {
        Address addr = requireAddress(str(e, "address", null));
        String newName = requireArg(e, "new_name");
        Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(addr);
        if (sym != null) {
            String old = sym.getName();
            sym.setName(newName, SourceType.USER_DEFINED);
            return "renamed label " + old + " -> " + newName + " at " + addr;
        }
        currentProgram.getSymbolTable().createLabel(addr, newName, SourceType.USER_DEFINED);
        return "created label " + newName + " at " + addr;
    }

    private String editSetComment(JsonObject e) throws Exception {
        Address addr = requireAddress(str(e, "address", null));
        String comment = str(e, "comment", null);
        if (comment == null) {
            throw new ModeError("bad_argument", "set_comment requires a comment");
        }
        String typeName = str(e, "comment_type", "decompiler");
        currentProgram.getListing().setComment(addr, commentType(typeName), comment);
        return "set " + typeName + " comment at " + addr;
    }

    /**
     * pyghidra-mcp names a "decompiler" comment; Ghidra has no such constant.
     * PRE is the one the decompiler renders above the statement, so that is
     * what "decompiler" maps to.
     */
    private CommentType commentType(String name) throws ModeError {
        switch (name) {
            case "decompiler":
            case "pre":        return CommentType.PRE;
            case "eol":        return CommentType.EOL;
            case "post":       return CommentType.POST;
            case "plate":      return CommentType.PLATE;
            case "repeatable": return CommentType.REPEATABLE;
            default:
                throw new ModeError("bad_argument",
                    "unknown comment_type: " + name
                        + " (want decompiler, pre, eol, post, plate or repeatable)");
        }
    }

    private String editSetPrototype(JsonObject e) throws Exception {
        Function f = requireFunction(str(e, "target", null), "set_prototype");
        String prototype = requireArg(e, "prototype");

        FunctionSignatureParser parser =
            new FunctionSignatureParser(currentProgram.getDataTypeManager(), null);
        FunctionDefinitionDataType definition;
        try {
            definition = parser.parse(f.getSignature(), prototype);
        }
        catch (Exception ex) {
            // Hand Ghidra's own parse error back, as pyghidra-mcp does: it says
            // which token failed, which a generic message cannot.
            throw new ModeError("bad_argument",
                "could not parse prototype: " + ex.getMessage());
        }
        if (definition == null) {
            throw new ModeError("bad_argument", "could not parse prototype: " + prototype);
        }

        // The parser has no syntax for a calling convention ("void __cdecl
        // f(void)" fails to parse), and what it carries over from the old
        // signature is not reliable: processEntry comes back as unknown. So the
        // convention is decided here, from the function itself:
        //
        //  * a known one, default or not (processEntry, __thiscall, ...), is
        //    kept — a prototype edit is about types, not about how it is called;
        //  * "unknown", which auto-analysis leaves on many functions, becomes
        //    the compiler spec's default. Left unknown, a prototype locks the
        //    parameter storage and the decompiler opens every decompilation
        //    with "Unknown calling convention -- yet parameter storage is
        //    locked".
        String convention = f.getCallingConventionName();
        if (convention == null || convention.isEmpty()
                || Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(convention)) {
            convention = currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
        }
        definition.setCallingConvention(convention);

        ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
            f.getEntryPoint(), definition, SourceType.USER_DEFINED);
        if (!cmd.applyTo(currentProgram, monitor)) {
            throw new ModeError("ghidra_error",
                "failed to apply prototype: " + cmd.getStatusMsg());
        }
        return "set prototype of " + f.getName() + " to " + prototype;
    }

    private String editRenameVariable(JsonObject e) throws Exception {
        Function f = requireFunction(str(e, "function", null), "rename_variable");
        String varName = requireArg(e, "variable");
        String newName = requireArg(e, "new_name");
        return updateVariable(f, varName, newName, null);
    }

    private String editSetVariableType(JsonObject e) throws Exception {
        Function f = requireFunction(str(e, "function", null), "set_variable_type");
        String varName = requireArg(e, "variable");
        DataType dt = requireDataType(requireArg(e, "type"));
        return updateVariable(f, varName, null, dt);
    }

    /**
     * Rename and/or retype a parameter or local.
     *
     * Database variables are tried first. Names the decompiler synthesises
     * (local_10, uVar1) have no database variable until they are committed, so
     * those fall through to HighFunctionDBUtil - Variable.setName alone cannot
     * touch them, which is the trap this method exists to hide.
     */
    private String updateVariable(Function f, String varName, String newName, DataType dt)
            throws Exception {
        for (Variable v : allVariables(f)) {
            if (v.getName().equals(varName)) {
                if (dt != null) {
                    v.setDataType(dt, SourceType.USER_DEFINED);
                    return "set type of " + varName + " in " + f.getName()
                        + " to " + dt.getName();
                }
                v.setName(newName, SourceType.USER_DEFINED);
                return "renamed " + varName + " -> " + newName + " in " + f.getName();
            }
        }

        DecompInterface decomp = new DecompInterface();
        try {
            if (!decomp.openProgram(currentProgram)) {
                throw new ModeError("ghidra_error",
                    "decompiler failed to open program: " + decomp.getLastMessage());
            }
            DecompileResults res =
                decomp.decompileFunction(f, DECOMPILE_TIMEOUT_SECONDS, monitor);
            HighFunction high = res.getHighFunction();
            if (high == null) {
                throw new ModeError("ghidra_error",
                    "could not decompile " + f.getName() + " to resolve " + varName);
            }
            Iterator<HighSymbol> it = high.getLocalSymbolMap().getSymbols();
            while (it.hasNext()) {
                HighSymbol sym = it.next();
                if (sym.getName().equals(varName)) {
                    HighFunctionDBUtil.updateDBVariable(
                        sym,
                        newName != null ? newName : sym.getName(),
                        dt,
                        SourceType.USER_DEFINED);
                    return dt != null
                        ? "set type of decompiler variable " + varName + " in "
                            + f.getName() + " to " + dt.getName()
                        : "renamed decompiler variable " + varName + " -> " + newName
                            + " in " + f.getName();
                }
            }
            throw new ModeError("not_found",
                "no variable named " + varName + " in " + f.getName());
        }
        finally {
            decomp.dispose();
        }
    }

    /* ----------------------------------------------------- control flow */

    /**
     * Basic blocks and the control-flow edges between them, per function.
     *
     * Only edges that stay inside the function are reported: a call is not
     * control flow within it (gen_callgraph covers calls), and a jump out of
     * the body — a tail call — has no block here to land on.
     */
    private JsonElement modeCfg(JsonObject args) throws Exception {
        JsonArray targets = args.getAsJsonArray("targets");
        if (targets == null || targets.size() == 0) {
            throw new ModeError("bad_argument", "cfg requires at least one function");
        }
        BasicBlockModel model = new BasicBlockModel(currentProgram);
        JsonArray results = new JsonArray();
        for (JsonElement t : targets) {
            String target = t.getAsString();
            JsonObject r = new JsonObject();
            r.addProperty("target", target);
            try {
                Function f = requireFunction(target, "cfg");
                r.addProperty("function", f.getName());
                r.addProperty("address", f.getEntryPoint().toString());
                cfgOf(model, f, r);
                r.addProperty("ok", true);
            }
            catch (ModeError me) {
                r.addProperty("ok", false);
                r.addProperty("error_kind", me.kind);
                r.addProperty("error", me.getMessage());
            }
            results.add(r);
        }
        JsonObject d = new JsonObject();
        d.add("results", results);
        return d;
    }

    private void cfgOf(BasicBlockModel model, Function f, JsonObject out) throws Exception {
        JsonArray blocks = new JsonArray();
        JsonArray edges = new JsonArray();
        CodeBlockIterator it = model.getCodeBlocksContaining(f.getBody(), monitor);
        while (it.hasNext()) {
            CodeBlock block = it.next();
            JsonObject b = new JsonObject();
            b.addProperty("start", block.getMinAddress().toString());
            b.addProperty("end", block.getMaxAddress().toString());
            b.addProperty("size", block.getNumAddresses());
            blocks.add(b);

            CodeBlockReferenceIterator dests = block.getDestinations(monitor);
            while (dests.hasNext()) {
                CodeBlockReference ref = dests.next();
                FlowType flow = ref.getFlowType();
                Address to = ref.getDestinationAddress();
                if (flow.isCall() || !f.getBody().contains(to)) {
                    continue;
                }
                JsonObject e = new JsonObject();
                e.addProperty("source", block.getMinAddress().toString());
                e.addProperty("target", to.toString());
                e.addProperty("kind", edgeKind(flow));
                edges.add(e);
            }
        }
        out.addProperty("block_count", blocks.size());
        out.addProperty("edge_count", edges.size());
        out.add("blocks", blocks);
        out.add("edges", edges);
    }

    private String edgeKind(FlowType flow) {
        if (flow.isFallthrough()) return "fall_through";
        if (flow.isComputed()) return "indirect";
        if (flow.isConditional()) return "conditional";
        return "unconditional";
    }

    /**
     * Call paths from one function to another, each a list of functions.
     *
     * A depth-first walk over called functions that never revisits a function
     * already on the current path, so recursion cannot loop it. Both limits
     * matter in a large binary: the number of paths grows exponentially with
     * depth, and `truncated` says when max_paths cut the search short.
     */
    private JsonElement modeCallPaths(JsonObject args) throws Exception {
        Function source = requireFunction(str(args, "source", null), "call_paths");
        Function target = requireFunction(str(args, "target", null), "call_paths");
        int maxDepth = intOr(args, "max_depth", 8);
        int maxPaths = intOr(args, "max_paths", 20);

        JsonArray paths = new JsonArray();
        java.util.Deque<Function> path = new java.util.ArrayDeque<>();
        path.addLast(source);
        boolean truncated = walkCalls(source, target, maxDepth, maxPaths, path, paths);

        JsonObject d = new JsonObject();
        d.addProperty("source", source.getName());
        d.addProperty("target", target.getName());
        d.addProperty("truncated", truncated);
        d.add("paths", paths);
        return d;
    }

    /** Returns true when max_paths stopped the walk. */
    private boolean walkCalls(Function at, Function target, int depthLeft, int maxPaths,
            java.util.Deque<Function> path, JsonArray paths) throws Exception {
        if (at.equals(target) && path.size() > 1) {
            if (paths.size() >= maxPaths) {
                return true;
            }
            JsonArray steps = new JsonArray();
            for (Function step : path) {
                JsonObject s = new JsonObject();
                s.addProperty("name", step.getName());
                s.addProperty("address", step.getEntryPoint().toString());
                steps.add(s);
            }
            paths.add(steps);
            return false;
        }
        if (depthLeft == 0 || monitor.isCancelled()) {
            return false;
        }
        java.util.List<Function> callees = new java.util.ArrayList<>(at.getCalledFunctions(monitor));
        callees.sort((a, b) -> a.getEntryPoint().compareTo(b.getEntryPoint()));
        for (Function callee : callees) {
            if (path.contains(callee)) {
                continue;
            }
            path.addLast(callee);
            boolean stop = walkCalls(callee, target, depthLeft - 1, maxPaths, path, paths);
            path.removeLast();
            if (stop) {
                return true;
            }
        }
        return false;
    }

    /* -------------------------------------------- instruction search */

    /** The instructions to scan: all of them, or [start, end] when given. */
    private AddressSetView scanRange(JsonObject args) throws ModeError {
        String start = str(args, "start", null);
        String end = str(args, "end", null);
        if (start == null && end == null) {
            return currentProgram.getMemory().getLoadedAndInitializedAddressSet();
        }
        Address from = start != null ? requireAddress(start) : currentProgram.getMinAddress();
        Address to = end != null ? requireAddress(end) : currentProgram.getMaxAddress();
        if (from.compareTo(to) > 0) {
            throw new ModeError("bad_argument", "start " + from + " is after end " + to);
        }
        return new AddressSet(from, to);
    }

    private JsonObject instructionHit(Instruction ins) {
        JsonObject o = new JsonObject();
        o.addProperty("address", ins.getAddress().toString());
        Function f = currentProgram.getFunctionManager().getFunctionContaining(ins.getAddress());
        o.addProperty("function", f == null ? null : f.getName());
        o.addProperty("instruction", ins.toString());
        return o;
    }

    private java.math.BigInteger bigArg(JsonObject args, String key) throws ModeError {
        String raw = str(args, key, null);
        if (raw == null) {
            return null;
        }
        try {
            return new java.math.BigInteger(raw);
        }
        catch (NumberFormatException ex) {
            throw new ModeError("bad_argument", key + " is not an integer: " + raw);
        }
    }

    /**
     * Instructions with a scalar operand equal to a value, or inside a range.
     *
     * An operand matches on its signed or its unsigned reading, so -1 and
     * 0xffffffff both find "mov eax, 0xffffffff" whichever way the caller
     * thinks of it. Only scalars are compared: an address operand is a
     * reference, and list_xrefs_to finds those.
     */
    private JsonElement modeSearchConstants(JsonObject args) throws ModeError {
        java.math.BigInteger value = bigArg(args, "value");
        java.math.BigInteger min = value != null ? value : bigArg(args, "min");
        java.math.BigInteger max = value != null ? value : bigArg(args, "max");
        if (min == null || max == null) {
            throw new ModeError("bad_argument", "search_constants needs a value, or min and max");
        }
        int maxEmit = intOr(args, "max_emit", MAX_EMIT);

        JsonArray hits = new JsonArray();
        int matched = 0;
        InstructionIterator it = currentProgram.getListing().getInstructions(scanRange(args), true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            for (int op = 0; op < ins.getNumOperands(); op++) {
                Scalar scalar = matchingScalar(ins.getOpObjects(op), min, max);
                if (scalar == null) {
                    continue;
                }
                matched++;
                if (hits.size() < maxEmit) {
                    JsonObject o = instructionHit(ins);
                    o.addProperty("operand", op);
                    o.addProperty("value", "0x" + Long.toHexString(scalar.getUnsignedValue()));
                    hits.add(o);
                }
            }
        }
        JsonObject d = new JsonObject();
        d.addProperty("matched", matched);
        d.addProperty("truncated", matched > hits.size());
        d.add("hits", hits);
        return d;
    }

    private Scalar matchingScalar(Object[] objects, java.math.BigInteger min,
            java.math.BigInteger max) {
        for (Object o : objects) {
            if (!(o instanceof Scalar sc)) {
                continue;
            }
            java.math.BigInteger signed = java.math.BigInteger.valueOf(sc.getSignedValue());
            java.math.BigInteger unsigned =
                new java.math.BigInteger(Long.toUnsignedString(sc.getUnsignedValue()));
            if (within(signed, min, max) || within(unsigned, min, max)) {
                return sc;
            }
        }
        return null;
    }

    private boolean within(java.math.BigInteger v, java.math.BigInteger min,
            java.math.BigInteger max) {
        return v.compareTo(min) >= 0 && v.compareTo(max) <= 0;
    }

    /** Instructions by mnemonic, or by a regex over the rendered instruction. */
    private JsonElement modeSearchInstructions(JsonObject args) throws ModeError {
        String mnemonic = str(args, "mnemonic", null);
        Pattern pattern = compilePattern(args);
        if ((mnemonic == null) == (pattern == null)) {
            throw new ModeError("bad_argument", "search_instructions needs a mnemonic or a pattern");
        }
        int maxEmit = intOr(args, "max_emit", MAX_EMIT);

        JsonArray hits = new JsonArray();
        int matched = 0;
        InstructionIterator it = currentProgram.getListing().getInstructions(scanRange(args), true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            boolean hit = mnemonic != null
                ? ins.getMnemonicString().equalsIgnoreCase(mnemonic)
                : matches(pattern, ins.toString());
            if (!hit) {
                continue;
            }
            matched++;
            if (hits.size() < maxEmit) {
                hits.add(instructionHit(ins));
            }
        }
        JsonObject d = new JsonObject();
        d.addProperty("matched", matched);
        d.addProperty("truncated", matched > hits.size());
        d.add("hits", hits);
        return d;
    }

    /* ------------------------------------------------------- data types */

    /**
     * A data type by name or path: "int", "record *", "char[16]", or a full
     * category path such as "/layout/record". A path is looked up directly;
     * anything else goes through Ghidra's own type-string parser, which
     * understands pointers, arrays and every type the program already has.
     */
    private static final Pattern TYPE_SUFFIX = Pattern.compile("\\s*(\\*|\\[\\d+\\])[\\s*\\[\\]\\d]*$");
    private static final Pattern TYPE_SUFFIX_PART = Pattern.compile("(\\*)|\\[(\\d+)\\]");

    private DataType requireDataType(String typeName) throws ModeError {
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        if (typeName.startsWith("/")) {
            // A path may carry pointer and array suffixes, as a name can:
            // "/recovered/record *" or "/recovered/record[4]".
            java.util.regex.Matcher m = TYPE_SUFFIX.matcher(typeName);
            int cut = m.find() ? m.start() : typeName.length();
            String path = typeName.substring(0, cut).trim();
            DataType dt = dtm.getDataType(path);
            if (dt == null) {
                throw new ModeError("not_found", "no data type at path " + path);
            }
            java.util.regex.Matcher part = TYPE_SUFFIX_PART.matcher(typeName.substring(cut));
            while (part.find()) {
                dt = part.group(1) != null
                    ? new PointerDataType(dt, dtm)
                    : new ghidra.program.model.data.ArrayDataType(
                        dt, Integer.parseInt(part.group(2)), dt.getLength(), dtm);
            }
            return dt;
        }
        DataType dt;
        try {
            dt = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL).parse(typeName);
        }
        catch (Exception ex) {
            throw new ModeError("bad_argument",
                "could not parse data type '" + typeName + "': " + ex.getMessage());
        }
        if (dt == null) {
            throw new ModeError("bad_argument", "unknown data type: " + typeName);
        }
        return dt;
    }

    private Structure requireStructure(String name) throws ModeError {
        DataType dt = requireDataType(name);
        if (dt instanceof TypeDef td) {
            dt = td.getBaseDataType();
        }
        if (!(dt instanceof Structure st)) {
            throw new ModeError("bad_argument", name + " is not a structure");
        }
        return st;
    }

    private String typeKind(DataType dt) {
        if (dt instanceof Structure) return "struct";
        if (dt instanceof Union) return "union";
        if (dt instanceof ghidra.program.model.data.Enum) return "enum";
        if (dt instanceof TypeDef) return "typedef";
        if (dt instanceof ghidra.program.model.data.Pointer) return "pointer";
        if (dt instanceof ghidra.program.model.data.Array) return "array";
        if (dt instanceof ghidra.program.model.data.FunctionDefinition) return "function";
        if (dt instanceof ghidra.program.model.data.BuiltInDataType) return "builtin";
        return "other";
    }

    private JsonObject typeSummary(DataType dt) {
        JsonObject o = new JsonObject();
        o.addProperty("name", dt.getName());
        o.addProperty("path", dt.getPathName());
        o.addProperty("kind", typeKind(dt));
        o.addProperty("size", dt.getLength());
        o.addProperty("category", dt.getCategoryPath().getPath());
        return o;
    }

    /** Every data type the program's manager holds, filtered and capped. */
    private JsonElement modeTypes(JsonObject args) throws ModeError {
        Pattern pattern = compilePattern(args);
        String category = str(args, "category", null);
        String kind = str(args, "kind", null);
        int maxEmit = intOr(args, "max_emit", MAX_EMIT);

        java.util.List<DataType> found = new java.util.ArrayList<>();
        Iterator<DataType> it = currentProgram.getDataTypeManager().getAllDataTypes();
        while (it.hasNext()) {
            DataType dt = it.next();
            if (category != null && !dt.getCategoryPath().getPath().startsWith(category)) {
                continue;
            }
            if (kind != null && !kind.equals(typeKind(dt))) {
                continue;
            }
            if (!matches(pattern, dt.getPathName())) {
                continue;
            }
            found.add(dt);
        }
        found.sort((a, b) -> a.getPathName().compareTo(b.getPathName()));

        JsonArray items = new JsonArray();
        for (DataType dt : found) {
            if (items.size() >= maxEmit) {
                break;
            }
            items.add(typeSummary(dt));
        }
        JsonObject d = new JsonObject();
        d.addProperty("matched", found.size());
        d.addProperty("truncated", found.size() > items.size());
        d.add("types", items);
        return d;
    }

    /** Full definitions — fields, enum values, typedef targets — for each name. */
    private JsonElement modeTypeInfo(JsonObject args) throws ModeError {
        JsonArray names = args.getAsJsonArray("names");
        if (names == null || names.size() == 0) {
            throw new ModeError("bad_argument", "type_info requires at least one name");
        }
        JsonArray results = new JsonArray();
        for (JsonElement n : names) {
            String name = n.getAsString();
            JsonObject r = new JsonObject();
            r.addProperty("target", name);
            try {
                r.add("type", typeDetail(requireDataType(name)));
                r.addProperty("ok", true);
            }
            catch (ModeError ex) {
                r.addProperty("ok", false);
                r.addProperty("error", ex.getMessage());
                r.addProperty("error_kind", ex.kind);
            }
            results.add(r);
        }
        JsonObject d = new JsonObject();
        d.add("results", results);
        return d;
    }

    private JsonObject typeDetail(DataType dt) {
        JsonObject o = typeSummary(dt);
        String description = dt.getDescription();
        if (description != null && !description.isEmpty()) {
            o.addProperty("description", description);
        }
        if (dt instanceof Composite comp) {
            o.addProperty("packed", comp.isPackingEnabled());
            JsonArray fields = new JsonArray();
            for (DataTypeComponent c : comp.getDefinedComponents()) {
                JsonObject f = new JsonObject();
                f.addProperty("offset", c.getOffset());
                f.addProperty("size", c.getLength());
                f.addProperty("type", c.getDataType().getDisplayName());
                f.addProperty("name", c.getFieldName());
                f.addProperty("comment", c.getComment());
                f.addProperty("bitfield", c.isBitFieldComponent());
                fields.add(f);
            }
            o.add("fields", fields);
        }
        if (dt instanceof ghidra.program.model.data.Enum en) {
            JsonArray members = new JsonArray();
            for (String member : en.getNames()) {
                JsonObject m = new JsonObject();
                m.addProperty("name", member);
                m.addProperty("value", en.getValue(member));
                members.add(m);
            }
            o.add("members", members);
        }
        if (dt instanceof TypeDef td) {
            o.addProperty("base_type", td.getBaseDataType().getPathName());
        }
        return o;
    }

    /**
     * Parse one C declaration — a struct, union, enum or typedef — and add it.
     *
     * Parsed without storing, so an existing type of the same name is a
     * decision rather than an accident: on_conflict says whether that is an
     * error (the default), a replacement, or a reason to keep both under a
     * ".conflict" name. Replacing silently would retype every variable and
     * data item already using the old definition.
     */
    private String editDefineType(JsonObject e) throws Exception {
        String c = requireArg(e, "c");
        String onConflict = str(e, "on_conflict", "error");
        CategoryPath category = new CategoryPath(str(e, "category", "/"));
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        CParser parser = new CParser(dtm, false, null);
        DataType parsed;
        try {
            parsed = parser.parse(c.trim().endsWith(";") ? c : c + ";");
        }
        catch (Exception | Error ex) {
            throw new ModeError("bad_argument", "could not parse C declaration: " + ex.getMessage());
        }
        if (parsed == null) {
            throw new ModeError("bad_argument", "no type declared in: " + c);
        }
        parsed.setCategoryPath(category);

        DataTypeConflictHandler handler;
        switch (onConflict) {
            case "error":
                if (dtm.getDataType(category, parsed.getName()) != null) {
                    throw new ModeError("bad_argument", "type " + parsed.getName()
                        + " already exists in " + category.getPath()
                        + "; pass on_conflict=replace or rename");
                }
                handler = DataTypeConflictHandler.DEFAULT_HANDLER;
                break;
            case "replace":
                handler = DataTypeConflictHandler.REPLACE_HANDLER;
                break;
            case "rename":
                handler = DataTypeConflictHandler.DEFAULT_HANDLER;
                break;
            default:
                throw new ModeError("bad_argument",
                    "on_conflict must be error, replace or rename, got " + onConflict);
        }
        DataType added = dtm.addDataType(parsed, handler);
        return "defined " + typeKind(added) + " " + added.getPathName()
            + " (" + added.getLength() + " bytes)";
    }

    /** Lay a data type over the bytes at an address. */
    private String editApplyType(JsonObject e) throws Exception {
        Address addr = requireAddress(str(e, "address", null));
        DataType dt = requireDataType(requireArg(e, "type"));
        DataUtilities.ClearDataMode mode = boolOr(e, "clear", false)
            ? DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA
            : DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA;
        try {
            Data d = DataUtilities.createData(currentProgram, addr, dt, -1, mode);
            return "applied " + dt.getName() + " at " + addr + " (" + d.getLength() + " bytes)";
        }
        catch (ghidra.program.model.util.CodeUnitInsertionException ex) {
            throw new ModeError("bad_argument", "cannot apply " + dt.getName() + " at "
                + addr + ": " + ex.getMessage() + " (clear=true replaces existing data)");
        }
    }

    /** Add, rename, retype, comment or clear one field of a structure. */
    private String editStructField(JsonObject e) throws Exception {
        Structure st = requireStructure(requireArg(e, "struct"));
        String action = requireArg(e, "action");

        if (action.equals("add")) {
            DataType dt = requireDataType(requireArg(e, "type"));
            String name = str(e, "name", null);
            String comment = str(e, "comment", null);
            if (e.has("offset")) {
                if (st.isPackingEnabled()) {
                    throw new ModeError("bad_argument", st.getName()
                        + " is packed, so its fields have no free offsets: add without an "
                        + "offset to append, or replace an existing field");
                }
                int offset = offsetArg(e);
                st.replaceAtOffset(offset, dt, dt.getLength(), name, comment);
                return "added " + name + " at offset " + offset + " of " + st.getName();
            }
            st.add(dt, name, comment);
            return "appended " + name + " to " + st.getName();
        }

        DataTypeComponent comp = findComponent(st, e);
        switch (action) {
            case "rename":
                comp.setFieldName(requireArg(e, "new_name"));
                return "renamed field at offset " + comp.getOffset() + " of " + st.getName()
                    + " to " + comp.getFieldName();
            case "comment":
                comp.setComment(str(e, "comment", ""));
                return "set comment on field at offset " + comp.getOffset() + " of " + st.getName();
            case "replace": {
                DataType dt = requireDataType(requireArg(e, "type"));
                String name = str(e, "new_name", comp.getFieldName());
                String comment = str(e, "comment", comp.getComment());
                st.replace(comp.getOrdinal(), dt, dt.getLength(), name, comment);
                return "replaced field at offset " + comp.getOffset() + " of " + st.getName()
                    + " with " + dt.getName();
            }
            case "clear":
                if (st.isPackingEnabled()) {
                    st.delete(comp.getOrdinal());
                }
                else {
                    st.clearComponent(comp.getOrdinal());
                }
                return "cleared field at offset " + comp.getOffset() + " of " + st.getName();
            default:
                throw new ModeError("bad_argument",
                    "action must be add, rename, replace, comment or clear, got " + action);
        }
    }

    /** The field an edit names, by "offset" or by field "name". */
    private DataTypeComponent findComponent(Structure st, JsonObject e) throws ModeError {
        if (e.has("offset")) {
            int offset = offsetArg(e);
            DataTypeComponent c = st.getComponentAt(offset);
            if (c == null || c.getDataType() == DataType.DEFAULT) {
                throw new ModeError("not_found",
                    "no field starts at offset " + offset + " of " + st.getName());
            }
            return c;
        }
        String name = str(e, "name", null);
        if (name == null) {
            throw new ModeError("bad_argument", "struct_field needs an offset or a field name");
        }
        for (DataTypeComponent c : st.getDefinedComponents()) {
            if (name.equals(c.getFieldName())) {
                return c;
            }
        }
        throw new ModeError("not_found", "no field named " + name + " in " + st.getName());
    }

    /** "offset" as a JSON number or a string, decimal or 0x-hex. */
    private int offsetArg(JsonObject e) throws ModeError {
        String raw = e.get("offset").getAsString().trim();
        try {
            return raw.startsWith("0x") || raw.startsWith("0X")
                ? Integer.parseInt(raw.substring(2), 16)
                : Integer.parseInt(raw);
        }
        catch (NumberFormatException ex) {
            throw new ModeError("bad_argument", "offset is not a number: " + raw);
        }
    }

    private String editEnumMember(JsonObject e) throws Exception {
        DataType dt = requireDataType(requireArg(e, "enum"));
        if (!(dt instanceof ghidra.program.model.data.Enum en)) {
            throw new ModeError("bad_argument", dt.getName() + " is not an enum");
        }
        String action = requireArg(e, "action");
        String name = requireArg(e, "name");
        if (action.equals("add")) {
            if (!e.has("value")) {
                throw new ModeError("bad_argument", "enum_member add requires a value");
            }
            long value = e.get("value").getAsLong();
            en.add(name, value);
            return "added " + name + " = " + value + " to " + en.getName();
        }
        if (action.equals("remove")) {
            try {
                en.getValue(name);
            }
            catch (java.util.NoSuchElementException ex) {
                throw new ModeError("not_found", "no member " + name + " in " + en.getName());
            }
            en.remove(name);
            return "removed " + name + " from " + en.getName();
        }
        throw new ModeError("bad_argument", "action must be add or remove, got " + action);
    }

    private String editDeleteType(JsonObject e) throws Exception {
        DataType dt = requireDataType(requireArg(e, "type"));
        String path = dt.getPathName();
        if (dt.getDataTypeManager() != currentProgram.getDataTypeManager()
                || !currentProgram.getDataTypeManager().remove(dt)) {
            throw new ModeError("bad_argument", "cannot delete " + path
                + ": it is not a type this program owns");
        }
        return "deleted " + path;
    }

    /**
     * Build a structure from how a pointer variable is used, then retype the
     * variable as a pointer to it.
     *
     * The decompiler follows every load and store through the variable — into
     * callees too — and records the offset and size of each, which is the
     * field layout. Existing structure pointers are extended rather than
     * replaced.
     */
    private String editFillStruct(JsonObject e) throws Exception {
        Function f = requireFunction(str(e, "function", null), "fill_struct");
        String varName = requireArg(e, "variable");
        String structName = str(e, "name", null);

        FillOutStructureHelper helper = new FillOutStructureHelper(currentProgram, monitor);
        DecompInterface decomp = helper.setUpDecompiler(new DecompileOptions());
        try {
            DecompileResults res = decomp.decompileFunction(f, DECOMPILE_TIMEOUT_SECONDS, monitor);
            HighFunction high = res.getHighFunction();
            if (high == null) {
                throw new ModeError("ghidra_error", "could not decompile " + f.getName());
            }
            HighSymbol symbol = null;
            Iterator<HighSymbol> it = high.getLocalSymbolMap().getSymbols();
            while (it.hasNext()) {
                HighSymbol s = it.next();
                if (s.getName().equals(varName)) {
                    symbol = s;
                    break;
                }
            }
            if (symbol == null || symbol.getHighVariable() == null) {
                throw new ModeError("not_found", "no variable named " + varName + " in " + f.getName());
            }
            HighVariable var = symbol.getHighVariable();
            Structure st = helper.processStructure(var, f, false, false, decomp);
            if (st == null || st.getNumDefinedComponents() == 0) {
                throw new ModeError("bad_argument", varName + " in " + f.getName()
                    + " is not used as a pointer to fields, so there is no structure to build");
            }
            if (structName != null) {
                st.setName(structName);
            }
            DataType pointer = currentProgram.getDataTypeManager()
                .addDataType(new PointerDataType(st), DataTypeConflictHandler.DEFAULT_HANDLER);
            HighFunctionDBUtil.updateDBVariable(symbol, null, pointer, SourceType.USER_DEFINED);
            DataType built = ((ghidra.program.model.data.Pointer) pointer).getDataType();
            return "filled " + built.getPathName() + " (" + built.getLength() + " bytes, "
                + ((Structure) built).getNumDefinedComponents() + " fields) from " + varName
                + " in " + f.getName();
        }
        finally {
            decomp.dispose();
        }
    }

    private java.util.List<Variable> allVariables(Function f) {
        java.util.List<Variable> all = new java.util.ArrayList<>();
        for (Parameter p : f.getParameters()) {
            all.add(p);
        }
        for (Variable v : f.getLocalVariables()) {
            all.add(v);
        }
        return all;
    }

    private Function requireFunction(String target, String what) throws ModeError {
        if (target == null) {
            throw new ModeError("bad_argument", what + " requires a target function");
        }
        Function f = resolveFunction(target);
        if (f == null) {
            Resolved r = resolve(target);
            if (r != null && r.function != null) {
                return r.function;
            }
            throw new ModeError("not_found", "function not found: " + target);
        }
        return f;
    }

    private Address requireAddress(String text) throws ModeError {
        if (text == null) {
            throw new ModeError("bad_argument", "an address is required");
        }
        Resolved r = resolve(text);
        if (r == null) {
            throw new ModeError("not_found", "cannot resolve address: " + text);
        }
        return r.address;
    }

    private String requireArg(JsonObject e, String key) throws ModeError {
        String v = str(e, key, null);
        if (v == null || v.isEmpty()) {
            throw new ModeError("bad_argument", "missing required field: " + key);
        }
        return v;
    }

    /* ------------------------------------------------------------- helpers */

    /** Read a string arg, tolerating the legacy positional "arg" key. */
    private String str(JsonObject args, String key, String fallback) {
        if (args.has(key) && !args.get(key).isJsonNull()) {
            return args.get(key).getAsString();
        }
        return fallback;
    }

    /** Read an int arg; the legacy positional form delivers it as a string. */
    private int intOr(JsonObject args, String key, int fallback) {
        if (!args.has(key) || args.get(key).isJsonNull()) {
            return fallback;
        }
        try {
            return args.get(key).getAsInt();
        }
        catch (NumberFormatException | UnsupportedOperationException e) {
            return fallback;
        }
    }

    /** Instruction bytes, or an empty array where memory is unreadable. */
    private byte[] safeBytes(Instruction instr) {
        try {
            return instr.getBytes();
        }
        catch (MemoryAccessException e) {
            return new byte[0];
        }
    }

    private String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /** Printable rendering, non-printables as '.', as a hex dump would show. */
    private String ascii(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            int c = b & 0xff;
            sb.append(c >= 0x20 && c < 0x7f ? (char) c : '.');
        }
        return sb.toString();
    }

    /** An address plus what kind of thing the caller's string named. */
    private static class Resolved {
        final Address address;
        final String kind;
        /** Set when the target named a function, so its body can be swept. */
        final Function function;

        Resolved(Address address, String kind, Function function) {
            this.address = address;
            this.kind = kind;
            this.function = function;
        }
    }

    /**
     * Resolve a caller string to an address: literal address, then function
     * name, then any symbol. Symbols matter because xrefs to a string or a
     * global are as interesting as xrefs to a function.
     */
    private Resolved resolve(String target) {
        try {
            Address addr = currentProgram.getAddressFactory().getAddress(target);
            if (addr != null && currentProgram.getMemory().contains(addr)) {
                return new Resolved(addr, "address", null);
            }
        }
        catch (Exception e) {
            // not an address; fall through
        }

        Function f = resolveFunction(target);
        if (f != null) {
            return new Resolved(f.getEntryPoint(), "function", f);
        }

        for (Symbol sym : currentProgram.getSymbolTable().getGlobalSymbols(target)) {
            return new Resolved(sym.getAddress(), "symbol", null);
        }
        return null;
    }

    private Function resolveFunction(String target) {
        // address first, then exact name, then case-insensitive name
        try {
            Address addr = currentProgram.getAddressFactory().getAddress(target);
            if (addr != null) {
                Function f = currentProgram.getFunctionManager().getFunctionAt(addr);
                if (f != null) {
                    return f;
                }
            }
        }
        catch (Exception e) {
            // not an address; fall through to name lookup
        }

        Function fallback = null;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.getName().equals(target)) {
                return f;
            }
            if (fallback == null && f.getName().equalsIgnoreCase(target)) {
                fallback = f;
            }
        }
        return fallback;
    }
}
