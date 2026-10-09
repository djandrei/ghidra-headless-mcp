#!/usr/bin/env bash
# Pack the fixtures the tests import pre-analysed (.gzf) from bin/:
# import, run full auto-analysis, and export with ExportGzf.java.
#
#   GHIDRA_INSTALL_DIR=/path/to/ghidra ./make-gzf.sh
#
# Pack them with the OLDEST Ghidra the server supports: newer Ghidra opens
# older packed files, not the reverse. The simplest way is the repository's
# Dockerfile built for that version (the command is in its header), from
# this directory:
#   docker run --rm -v "$PWD:/fx" --entrypoint bash ghidra-headless-mcp:12.0.4 /fx/make-gzf.sh
# Not the compose container: it runs the Dockerfile's default, a newer Ghidra.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to a Ghidra install}"

# Refuse any other Ghidra: fixtures packed by a newer one cannot be opened by
# the oldest supported version, which CI tests, and the failure would surface
# there as an import error far from its cause. Raise this together with the
# oldest version the server supports.
OLDEST_SUPPORTED=12.0.4
found="$(sed -n 's/^application.version=//p' "$GHIDRA_INSTALL_DIR/Ghidra/application.properties")"
if [ "$found" != "$OLDEST_SUPPORTED" ]; then
  echo "make-gzf.sh: this is Ghidra ${found:-unknown}; the fixtures must be packed with" >&2
  echo "Ghidra $OLDEST_SUPPORTED, the oldest supported. Build that image (see the" >&2
  echo "Dockerfile header) and run this script in it." >&2
  exit 2
fi

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
