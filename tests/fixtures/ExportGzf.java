// Packs the current program's saved project file into a .gzf, analysis
// included. Used by make-gzf.sh; takes the output path as its one argument.
//
// Run it in a -readOnly pass over a program an earlier pass imported and
// analysed. From the importing pass it cannot work: a post-script runs inside
// an open transaction ("Unable to lock due to active transaction"), and
// GzfExporter then just returns false. Packing the saved DomainFile sidesteps
// both, and packs exactly what the project stored.
//@category ghidra-headless-mcp

import java.io.File;

import ghidra.app.script.GhidraScript;

public class ExportGzf extends GhidraScript {
    @Override
    protected void run() throws Exception {
        File out = new File(getScriptArgs()[0]);
        currentProgram.getDomainFile().packFile(out, monitor);
        println("wrote " + out);
    }
}
