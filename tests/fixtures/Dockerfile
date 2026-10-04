# Toolchains for tests/fixtures/build.sh, so the fixture binaries can be rebuilt
# anywhere without installing cross-compilers on the host:
#   gcc                     ELF x86-64
#   mingw-w64               PE32+ executables and DLLs
#   zig                     Mach-O (arm64), no Apple SDK needed for plain C
FROM ubuntu:24.04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      gcc libc6-dev mingw-w64 \
      binutils make curl ca-certificates xz-utils \
 && rm -rf /var/lib/apt/lists/*

# Pinned to the sha256 ziglang.org publishes in its download index.
ARG ZIG_VERSION=0.17.0
ARG ZIG_SHA256=1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026
RUN curl -fsSL -o /tmp/zig.tar.xz \
      "https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz" \
 && echo "${ZIG_SHA256}  /tmp/zig.tar.xz" | sha256sum -c - \
 && mkdir /opt/zig && tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1 \
 && rm /tmp/zig.tar.xz \
 && ln -s /opt/zig/zig /usr/local/bin/zig

WORKDIR /fixtures
