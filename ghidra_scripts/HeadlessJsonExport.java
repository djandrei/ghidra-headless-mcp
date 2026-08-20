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
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.DataType;
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
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
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
        }

        JsonObject envelope = new JsonObject();
        envelope.addProperty("mode", mode);
        try {
            Mode impl = modes.get(mode);
            if (impl == null) {
                throw new ModeError("bad_argument", "unknown mode: " + mode);
            }
            envelope.addProperty("ok", true);
            envelope.add("data", impl.run(args));
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
        String typeName = requireArg(e, "type");

        DataType dt;
        try {
            DataTypeParser parser = new DataTypeParser(
                currentProgram.getDataTypeManager(), currentProgram.getDataTypeManager(),
                null, AllowedDataTypes.ALL);
            dt = parser.parse(typeName);
        }
        catch (Exception ex) {
            throw new ModeError("bad_argument",
                "could not parse data type '" + typeName + "': " + ex.getMessage());
        }
        if (dt == null) {
            throw new ModeError("bad_argument", "unknown data type: " + typeName);
        }
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
