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
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;

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
