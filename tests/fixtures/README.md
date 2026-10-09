# Test fixtures

Binaries the integration suite analyses, **built from the sources in `src/`**
and committed. Every one is ours to publish under the repository's Apache-2.0
licence: no third-party program, no malware. None of them is
ever executed — the suite only analyses them.

| File | Format | Built with | What the tests rely on |
|---|---|---|---|
| `keycheck.x86_64` | ELF x86-64, non-PIE | gcc | `check_key` at `0x401176`, called from `main`; `.init` at `0x401000`; crt1 `_start`, crti `_init`; the string `== keycheck keygen-me ==` |
| `crackme.x86_64` | ELF x86-64, non-PIE | gcc | imports `strcmp`, `malloc`, `memcpy` |
| `layout.x86_64` | ELF x86-64, non-PIE | gcc | `score_record` (`0x401176`) reads a `struct record` through its parameter at offsets 0, 4, 6, 8, 12 and 0x18; `classify` (`0x4011e0`) is a 4-case switch, 13 basic blocks and 18 edges; the chain `main → stage_a → stage_b → stage_c → score_record`; `is_licensed` (`0x401296`) compares with `0xC0FFEE42` at `0x4012a1`, and its `jne` at `0x4012a8` (bytes `75 07`, file offset `0x12a8`) decides the result |
| `sample-pe32.exe(.gzf)` | PE32 i386 | i686-w64-mingw32-gcc | imports `GetModuleHandleA`, `GetProcAddress`, `CreateFileA` |
| `sample-macho(.gzf)` | Mach-O arm64 | zig cc | an `_objc_msgSend` import and stub |
| `chainapp.exe`, `chainfwd.dll`, `chainimpl.dll` | PE32+ x86-64 | x86_64-w64-mingw32-gcc | `do_work`: imported by the app, re-exported by `chainfwd`, implemented in `chainimpl` |

The `.gzf` files are the PE32 and Mach-O programs imported and auto-analysed
by **Ghidra 12.0.4** and packed, because the suite imports them the way one
imports a Ghidra database. 12.0.4 is the oldest Ghidra the server supports:
newer versions open older packed files, not the reverse. `SHA256SUMS` lists
every file.

The compilers' own runtime pieces are linked in as usual — gcc's crt objects
and libgcc under the GCC Runtime Library Exception, glibc dynamically, the
mingw-w64 runtime under its permissive licences — none of which restricts
distributing the result.

## Rebuilding

Only when a source changes; the committed binaries are the ground truth, and a
different compiler would move `check_key`.

```bash
./build.sh                       # compiles src/ -> bin/ in a toolchain container (docker only)
# re-pack the .gzf with Ghidra 12.0.4: build that image once (the command is in
# the repository Dockerfile's header), then from this directory
docker run --rm -v "$PWD:/fx" --entrypoint bash ghidra-headless-mcp:12.0.4 /fx/make-gzf.sh
(cd bin && sha256sum * > ../SHA256SUMS)
```

`make-gzf.sh` refuses to run on any other Ghidra. Do not use the compose
container for it: that runs the Dockerfile's default, a newer Ghidra, whose
packed files 12.0.4 cannot open.

Then update `KNOWN_ADDRESS` in `tests/conftest.py` from
`nm bin/keycheck.x86_64 | grep check_key`.

- `Dockerfile` is the toolchain image: Ubuntu 24.04's gcc and mingw-w64, and
  zig (pinned by the sha256 ziglang.org publishes) for Mach-O without an Apple
  SDK.
- Nothing is built with debug info: it would hand Ghidra prototypes the tests
  expect it to have to infer — `main`'s calling convention must start out
  `unknown`.
- `ExportGzf.java` packs a program in a second, read-only Ghidra pass; from
  the importing pass a post-script runs inside an open transaction and cannot.
