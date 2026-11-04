#!/usr/bin/env bash
# Cross-builds Sideroute.exe on Linux with the system clang + lld and the llvm-mingw (UCRT) sysroot.
# Only llvm-mingw's libraries and headers are used, none of its programs. The result depends only on
# DLLs that ship with Windows 10/11.
#
# usage: scripts/build-windows.sh            -> dist/SiderouteSetup.exe (installer and app in one file)
# needs: clang, lld, llvm-ar, curl, rustup; LLVM_MINGW=<extracted llvm-mingw dir> skips the download
set -euo pipefail
export LC_ALL=C

LLVM_MINGW_VERSION=20261104
LLVM_MINGW_SHA256=919380403de87dca3c581c2053230cd298af5e891286628ba0613b7fed370926
TARGET=x86_64-pc-windows-gnullvm

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CACHE="$ROOT/target/llvm-mingw"
if [ -z "${LLVM_MINGW:-}" ]; then
    LLVM_MINGW="$CACHE/llvm-mingw-$LLVM_MINGW_VERSION-ucrt-ubuntu-22.04-x86_64"
    if [ ! -d "$LLVM_MINGW/x86_64-w64-mingw32" ]; then
        mkdir -p "$CACHE"
        tarball="$CACHE/llvm-mingw.tar.xz"
        curl -fL -o "$tarball" \
            "https://github.com/mstorsjo/llvm-mingw/releases/download/$LLVM_MINGW_VERSION/llvm-mingw-$LLVM_MINGW_VERSION-ucrt-ubuntu-22.04-x86_64.tar.xz"
        echo "$LLVM_MINGW_SHA256  $tarball" | sha256sum -c --quiet -
        tar -C "$CACHE" -xJf "$tarball" --wildcards '*/x86_64-w64-mingw32/*' '*/generic-w64-mingw32/*' '*/lib/clang/*/lib/windows/*x86_64*'
        rm -f "$tarball"
    fi
fi
SYSROOT="$LLVM_MINGW/x86_64-w64-mingw32"
RESOURCE="$(ls -d "$LLVM_MINGW"/lib/clang/* | head -1)"

# libunwind must be linked statically: Windows has no libunwind.dll
mkdir -p "$ROOT/target/mingw-static"
cp "$SYSROOT/lib/libunwind.a" "$ROOT/target/mingw-static/"
LINKER="$ROOT/target/mingw-link.sh"
cat > "$LINKER" <<EOF
#!/bin/sh
exec clang --target=x86_64-w64-mingw32 --sysroot="$SYSROOT" -resource-dir="$RESOURCE" -fuse-ld=lld \\
    -rtlib=compiler-rt -unwindlib=libunwind -L"$ROOT/target/mingw-static" "\$@"
EOF
chmod +x "$LINKER"

rustup target add "$TARGET" >/dev/null
export SIDEROUTE_PAYLOAD_DIR="$("$ROOT/scripts/fetch-windows-payload.sh")"
export RC_x86_64_pc_windows_gnullvm=llvm-windres
export CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER="$LINKER"
export CC_x86_64_pc_windows_gnullvm=clang
export CFLAGS_x86_64_pc_windows_gnullvm="--target=x86_64-w64-mingw32 --sysroot=$SYSROOT"
export AR_x86_64_pc_windows_gnullvm=llvm-ar
cd "$ROOT"
cargo build --release --locked --target "$TARGET" -p sideroute-windows

EXE="target/$TARGET/release/Sideroute.exe"
if llvm-readobj --coff-imports "$EXE" | grep -qi 'libunwind\|libc++\|libwinpthread'; then
    echo "error: $EXE depends on a DLL that Windows does not have" >&2
    exit 1
fi
OUT="$ROOT/dist"; mkdir -p "$OUT"
cp "$EXE" "$OUT/SiderouteSetup.exe"
ls -l "$OUT/SiderouteSetup.exe"
