#!/usr/bin/env bash
# Builds release archives into dist/:
#   sideroute-server-<arch>-linux-musl     static server binary
#   sideroute-linux-<arch>.tar.gz          client binaries + data files
#   SHA256SUMS
# usage: scripts/package.sh <rust-target>      e.g. x86_64-unknown-linux-musl
set -euo pipefail
export LC_ALL=C
TARGET="${1:?rust target, e.g. x86_64-unknown-linux-musl}"
ARCH="${TARGET%%-*}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
"${CARGO:-cargo}" build --release --locked --target "$TARGET" --workspace
OUT="$ROOT/dist"; mkdir -p "$OUT"
REL="target/$TARGET/release"
cp "$REL/sideroute-server" "$OUT/sideroute-server-$ARCH-linux-musl"
PKG="$OUT/sideroute-linux-$ARCH"
rm -rf "$PKG"; mkdir -p "$PKG/share"
cp "$REL/sideroute" "$REL/sideroute-helper" "$PKG/"
cp -r client/systemd client/dbus client/kwin "$PKG/share/"
cp LICENSE-MIT LICENSE-APACHE README.md "$PKG/"
tar -C "$OUT" -czf "$OUT/sideroute-linux-$ARCH.tar.gz" "sideroute-linux-$ARCH"
rm -rf "$PKG"
(cd "$OUT" && sha256sum sideroute-server-*-linux-musl sideroute-linux-*.tar.gz > SHA256SUMS)
ls -l "$OUT"
