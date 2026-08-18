/* Emit program facts as JSON for ghidra_headless_mcp.py.
 *
 * Run as a headless postScript. Ghidra compiles this on the fly, so there is
 * no build step:
 *
 *   analyzeHeadless <loc> <proj> -process <prog> -noanalysis -readOnly \
 *       -scriptPath <dir> -postScript HeadlessJsonExport.java <mode> <outFile> [arg]
 *
 * Modes: info | functions | decompile <nameOrAddress> | strings [minLength]
 *
 * Output goes to <outFile>, never to stdout: the MCP server that invokes this
 * speaks JSON-RPC on stdout, and analyzeHeadless log noise would corrupt it.
 *
 * @category Headless
 */
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

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

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "usage: HeadlessJsonExport <mode> <outFile> [arg]");
        }
        String mode = args[0];
        String outFile = args[1];
        String arg = args.length > 2 ? args[2] : null;

        String json;
        switch (mode) {
            case "info":       json = info();               break;
            case "functions":  json = functions();          break;
            case "decompile":  json = decompile(arg);       break;
            case "strings":    json = strings(arg);         break;
            default:
                throw new IllegalArgumentException("unknown mode: " + mode);
        }

        try (PrintWriter out = new PrintWriter(outFile, "UTF-8")) {
            out.print(json);
        }
    }

    /* ---------------------------------------------------------------- modes */

    private String info() {
        List<String> blocks = new ArrayList<>();
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            blocks.add(obj(
                kv("name", b.getName()),
                kv("start", b.getStart().toString()),
                kv("end", b.getEnd().toString()),
                num("size", b.getSize()),
                bool("readable", b.isRead()),
                bool("writable", b.isWrite()),
                bool("executable", b.isExecute())));
        }
        return obj(
            kv("name", currentProgram.getName()),
            kv("executable_path", currentProgram.getExecutablePath()),
            kv("executable_format", currentProgram.getExecutableFormat()),
            kv("md5", currentProgram.getExecutableMD5()),
            kv("sha256", currentProgram.getExecutableSHA256()),
            kv("language_id", currentProgram.getLanguageID().getIdAsString()),
            kv("compiler_spec_id", currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()),
            kv("image_base", currentProgram.getImageBase().toString()),
            num("function_count", currentProgram.getFunctionManager().getFunctionCount()),
            num("symbol_count", currentProgram.getSymbolTable().getNumSymbols()),
            raw("memory_blocks", arr(blocks)));
    }

    private String functions() {
        List<String> items = new ArrayList<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            items.add(obj(
                kv("name", f.getName()),
                kv("address", f.getEntryPoint().toString()),
                num("size", f.getBody().getNumAddresses()),
                kv("signature", f.getSignature().getPrototypeString()),
                kv("calling_convention", f.getCallingConventionName()),
                bool("is_thunk", f.isThunk()),
                bool("is_external", f.isExternal())));
        }
        return obj(raw("functions", arr(items)));
    }

    private String decompile(String target) throws Exception {
        if (target == null) {
            throw new IllegalArgumentException("decompile requires a name or address");
        }
        Function f = resolveFunction(target);
        if (f == null) {
            return obj(kv("error", "function not found: " + target));
        }

        DecompInterface decomp = new DecompInterface();
        try {
            if (!decomp.openProgram(currentProgram)) {
                return obj(kv("error", "decompiler failed to open program: "
                    + decomp.getLastMessage()));
            }
            DecompileResults res =
                decomp.decompileFunction(f, DECOMPILE_TIMEOUT_SECONDS, monitor);
            if (!res.decompileCompleted()) {
                return obj(
                    kv("name", f.getName()),
                    kv("address", f.getEntryPoint().toString()),
                    kv("error", "decompilation failed: " + res.getErrorMessage()));
            }
            return obj(
                kv("name", f.getName()),
                kv("address", f.getEntryPoint().toString()),
                kv("signature", f.getSignature().getPrototypeString()),
                kv("c", res.getDecompiledFunction().getC()));
        }
        finally {
            decomp.dispose();
        }
    }

    private String strings(String minLengthArg) {
        int minLength = 4;
        if (minLengthArg != null) {
            try {
                minLength = Integer.parseInt(minLengthArg);
            }
            catch (NumberFormatException e) {
                // keep the default rather than failing the whole export
            }
        }

        List<String> items = new ArrayList<>();
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
            items.add(obj(
                kv("address", d.getAddress().toString()),
                num("length", s.length()),
                kv("value", s)));
        }
        return obj(raw("strings", arr(items)));
    }

    /* ------------------------------------------------------------- helpers */

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

    /* ---------------------------------------------------- minimal JSON emit */
    // Hand-rolled so the script has no dependency beyond Ghidra itself.

    private String obj(String... fields) {
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < fields.length; i++) {
            if (i > 0) {
                sb.append(",");
            }
            sb.append(fields[i]);
        }
        return sb.append("}").toString();
    }

    private String arr(List<String> items) {
        return "[" + String.join(",", items) + "]";
    }

    private String kv(String key, String value) {
        return quote(key) + ":" + (value == null ? "null" : quote(value));
    }

    private String num(String key, long value) {
        return quote(key) + ":" + value;
    }

    private String bool(String key, boolean value) {
        return quote(key) + ":" + value;
    }

    private String raw(String key, String rawJson) {
        return quote(key) + ":" + rawJson;
    }

    private String quote(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\"");  break;
                case '\\': sb.append("\\\\");  break;
                case '\n': sb.append("\\n");   break;
                case '\r': sb.append("\\r");   break;
                case '\t': sb.append("\\t");   break;
                default:
                    if (c < 0x20 || c == 0x7f) {
                        sb.append(String.format("\\u%04x", (int) c));
                    }
                    else {
                        sb.append(c);
                    }
            }
        }
        return sb.append("\"").toString();
    }
}
