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
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;

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

    private JsonElement modeFunctions(JsonObject args) {
        JsonArray items = new JsonArray();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
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
        d.add("functions", items);
        return d;
    }

    private JsonElement modeDecompile(JsonObject args) throws Exception {
        String target = str(args, "target", str(args, "arg", null));
        if (target == null) {
            throw new ModeError("bad_argument", "decompile requires a name or address");
        }
        Function f = resolveFunction(target);
        if (f == null) {
            throw new ModeError("not_found", "function not found: " + target);
        }

        DecompInterface decomp = new DecompInterface();
        try {
            if (!decomp.openProgram(currentProgram)) {
                throw new ModeError("ghidra_error",
                    "decompiler failed to open program: " + decomp.getLastMessage());
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
        finally {
            decomp.dispose();
        }
    }

    private JsonElement modeStrings(JsonObject args) {
        int minLength = intOr(args, "min_length", intOr(args, "arg", 4));

        JsonArray items = new JsonArray();
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
            JsonObject o = new JsonObject();
            o.addProperty("address", d.getAddress().toString());
            o.addProperty("length", s.length());
            o.addProperty("value", s);
            items.add(o);
        }
        JsonObject d = new JsonObject();
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
