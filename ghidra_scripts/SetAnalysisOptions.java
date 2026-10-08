/* Set analysis options before auto-analysis runs, for ghidra_headless_mcp.py.
 *
 * Runs as a -preScript, so the options it sets are the ones the analysis that
 * follows uses. Arguments: <spec.json> <out.json>. The spec is
 *
 *     {"mode": "import" | "process", "options": {"<option name>": <value>}}
 *
 * Every option is validated before any is set: an unknown name, or a value of
 * the wrong type, fails the whole request and the analysis does not run. In
 * -import mode the import is then discarded; in -process mode the program is
 * left exactly as it was. Ghidra's own setAnalysisOption only logs such errors
 * and carries on, which would let an analysis run with half the options a
 * caller asked for.
 *
 * The result is written to <out.json> as {"ok": true, "data": {"applied": …}}
 * or {"ok": false, "error": {"kind", "message"}} — never to stdout, which the
 * headless log owns.
 */
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

public class SetAnalysisOptions extends HeadlessScript {

    /** One validated change, ready to apply. */
    private record Change(String name, OptionType type, Object value) {
    }

    private static class Invalid extends Exception {
        Invalid(String message) {
            super(message);
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args[1];
        JsonObject spec = JsonParser.parseString(
            Files.readString(Paths.get(args[0]), StandardCharsets.UTF_8)).getAsJsonObject();
        boolean importing = "import".equals(spec.get("mode").getAsString());

        Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        JsonObject result = new JsonObject();
        try {
            List<Change> changes = validate(options, spec.getAsJsonObject("options"));
            JsonObject applied = new JsonObject();
            for (Change c : changes) {
                apply(options, c);
                applied.add(c.name(), spec.getAsJsonObject("options").get(c.name()));
            }
            JsonObject data = new JsonObject();
            data.add("applied", applied);
            result.addProperty("ok", true);
            result.add("data", data);
        }
        catch (Invalid ex) {
            JsonObject error = new JsonObject();
            error.addProperty("kind", "bad_argument");
            error.addProperty("message", ex.getMessage());
            result.addProperty("ok", false);
            result.add("error", error);
            // Nothing was set. Stop before analysis: an import is discarded,
            // a processed program is left as it was (ABORT_AND_DELETE would
            // delete it in -process mode).
            setHeadlessContinuationOption(importing
                ? HeadlessContinuationOption.ABORT_AND_DELETE
                : HeadlessContinuationOption.ABORT);
        }
        try (PrintWriter w = new PrintWriter(outPath, StandardCharsets.UTF_8)) {
            w.write(result.toString());
        }
    }

    private List<Change> validate(Options options, JsonObject wanted) throws Invalid {
        List<Change> changes = new ArrayList<>();
        List<String> problems = new ArrayList<>();
        for (Map.Entry<String, JsonElement> e : wanted.entrySet()) {
            String name = e.getKey();
            if (!options.contains(name)) {
                problems.add("unknown analysis option: " + name);
                continue;
            }
            try {
                changes.add(new Change(name, options.getType(name),
                    convert(options, name, e.getValue())));
            }
            catch (Invalid ex) {
                problems.add(ex.getMessage());
            }
        }
        if (!problems.isEmpty()) {
            throw new Invalid(String.join("; ", problems)
                + " (list_analysis_options shows each option's name and type)");
        }
        return changes;
    }

    private Object convert(Options options, String name, JsonElement value) throws Invalid {
        OptionType type = options.getType(name);
        if (!value.isJsonPrimitive()) {
            throw new Invalid(name + " needs a " + describe(type) + " value");
        }
        JsonPrimitive p = value.getAsJsonPrimitive();
        try {
            switch (type) {
                case BOOLEAN_TYPE:
                    if (!p.isBoolean()) {
                        throw new Invalid(name + " is a boolean option; got " + p);
                    }
                    return p.getAsBoolean();
                case INT_TYPE:
                    return Integer.valueOf(wholeNumber(name, p));
                case LONG_TYPE:
                    return Long.valueOf(wholeNumber(name, p));
                case DOUBLE_TYPE:
                    return p.isNumber() ? p.getAsDouble() : Double.valueOf(p.getAsString());
                case FLOAT_TYPE:
                    return p.isNumber() ? p.getAsFloat() : Float.valueOf(p.getAsString());
                case STRING_TYPE:
                    return p.getAsString();
                case ENUM_TYPE:
                    return enumConstant(options, name, p.getAsString());
                default:
                    throw new Invalid(name + " is a " + type + " option, which cannot be set here");
            }
        }
        catch (NumberFormatException ex) {
            throw new Invalid(name + " needs a " + describe(type) + " value; got " + p);
        }
    }

    private String wholeNumber(String name, JsonPrimitive p) throws Invalid {
        String text = p.getAsString();
        if (p.isBoolean() || text.contains(".")) {
            throw new Invalid(name + " needs a whole number; got " + p);
        }
        return text;
    }

    @SuppressWarnings({ "rawtypes" })
    private Object enumConstant(Options options, String name, String wanted) throws Invalid {
        Enum current = options.getEnum(name, null);
        if (current == null) {
            throw new Invalid(name + " has no current value to take its choices from");
        }
        List<String> choices = new ArrayList<>();
        for (Object c : current.getDeclaringClass().getEnumConstants()) {
            Enum constant = (Enum) c;
            if (constant.name().equalsIgnoreCase(wanted)
                    || constant.toString().equalsIgnoreCase(wanted)) {
                return constant;
            }
            choices.add(constant.toString());
        }
        throw new Invalid(name + " must be one of " + choices + "; got " + wanted);
    }

    private String describe(OptionType type) {
        switch (type) {
            case BOOLEAN_TYPE: return "boolean";
            case INT_TYPE:
            case LONG_TYPE:    return "whole-number";
            case DOUBLE_TYPE:
            case FLOAT_TYPE:   return "numeric";
            case ENUM_TYPE:    return "choice";
            default:           return "string";
        }
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private void apply(Options options, Change c) {
        switch (c.type()) {
            case BOOLEAN_TYPE: options.setBoolean(c.name(), (Boolean) c.value()); break;
            case INT_TYPE:     options.setInt(c.name(), (Integer) c.value()); break;
            case LONG_TYPE:    options.setLong(c.name(), (Long) c.value()); break;
            case DOUBLE_TYPE:  options.setDouble(c.name(), (Double) c.value()); break;
            case FLOAT_TYPE:   options.setFloat(c.name(), (Float) c.value()); break;
            case ENUM_TYPE:    options.setEnum(c.name(), (Enum) c.value()); break;
            default:           options.setString(c.name(), (String) c.value()); break;
        }
    }
}
