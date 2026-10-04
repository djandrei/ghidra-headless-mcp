#!/usr/bin/env bash
# Pack the fixtures the tests import pre-analysed (.gzf) from bin/:
# import, run full auto-analysis, and export with ExportGzf.java.
#
#   GHIDRA_INSTALL_DIR=/path/to/ghidra ./make-gzf.sh
#
# Build them with the OLDEST Ghidra the server supports (12.0.4, as in the
# default Dockerfile): newer Ghidra opens older packed files, not the reverse.
#   docker compose exec ghidra-headless-mcp tests/fixtures/make-gzf.sh
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to a Ghidra install}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for name in sample-pe32.exe sample-macho; do
  rm -f "bin/$name.gzf"
  # Two passes: the first imports, analyses and saves; the second packs the
  # saved file read-only (see ExportGzf.java for why it cannot be one).
  "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$work" pack -import "bin/$name" \
    > "$work/$name.log" 2>&1 || { tail -30 "$work/$name.log"; exit 1; }
  "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$work" pack -process "$name" \
    -noanalysis -readOnly -scriptPath "$PWD" \
    -postScript ExportGzf.java "$PWD/bin/$name.gzf" \
    >> "$work/$name.log" 2>&1 || { tail -30 "$work/$name.log"; exit 1; }
  grep -q "wrote $PWD/bin/$name.gzf" "$work/$name.log" \
    || { echo "no .gzf written for $name"; tail -30 "$work/$name.log"; exit 1; }
  chmod 0644 "bin/$name.gzf"
done
grep -h "application.version" "$GHIDRA_INSTALL_DIR/Ghidra/application.properties"
ls -l bin/*.gzf
