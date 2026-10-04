#!/usr/bin/env bash
# Rebuild the fixture binaries in bin/ from src/.
#
#   ./build.sh            builds inside the toolchain image (needs docker only)
#   ./build.sh --native   builds with the compilers on PATH (what the image runs)
#
# The binaries are committed, so the tests never build anything: addresses such
# as check_key's entry are ground truth, and a different compiler would move
# them. Rebuild only when a source changes, then update KNOWN_ADDRESS in
# tests/conftest.py and re-run make-gzf.sh.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

if [ "${1:-}" != "--native" ]; then
  docker build -q -t ghmcp-fixture-builder . >/dev/null
  exec docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
    -v "$PWD:/fixtures" ghmcp-fixture-builder ./build.sh --native
fi

mkdir -p bin
# No -g anywhere: debug info would hand Ghidra prototypes the tests expect it
# to lack. -fno-pie/-no-pie keep the ELF at its classic 0x400000 base.
ELF_FLAGS=(-O0 -fno-pie -no-pie -fno-stack-protector)

gcc "${ELF_FLAGS[@]}" -o bin/keycheck.x86_64 src/keycheck.c
gcc "${ELF_FLAGS[@]}" -o bin/crackme.x86_64 src/crackme.c

i686-w64-mingw32-gcc -O0 -o bin/sample-pe32.exe src/sample-pe32.c

# Linked with the runtime left to dynamic lookup: no Apple SDK is needed.
zig cc -target aarch64-macos -O0 -Wl,-undefined,dynamic_lookup \
  -o bin/sample-macho src/sample-macho.c

# The import -> forwarder -> implementation chain, x86-64 PE.
x86_64-w64-mingw32-gcc -O0 -shared -o bin/chainimpl.dll src/chainimpl.c
x86_64-w64-mingw32-gcc -O0 -shared -o bin/chainfwd.dll \
  src/chainfwd.c src/chainfwd.def bin/chainimpl.dll
x86_64-w64-mingw32-gcc -O0 -o bin/chainapp.exe src/chainapp.c bin/chainfwd.dll

chmod 0644 bin/*
ls -l bin
