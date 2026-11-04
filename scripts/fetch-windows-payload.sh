#!/usr/bin/env bash
# Downloads the third-party components bundled into Sideroute.exe (pinned versions and SHA-256)
# into target/payload, or the directory given as $1:
#   wireguard.dll + its license   https://download.wireguard.com/wireguard-nt/
#   ProxiFyre setup (x64)         https://github.com/wiresock/proxifyre (AGPL-3.0; installs the
#                                 Windows Packet Filter driver and the VC++ runtime)
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/target/payload}"
WGNT_URL=https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip
WGNT_SHA256=dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace
PFY_URL=https://github.com/wiresock/proxifyre/releases/download/v2.6.4/ProxiFyre-2.6.4-win-x64-setup.exe
PFY_SHA256=afaf3ac8a2069f9653adb1b4a63b31d1edd8aa109ccdc367cf0d4462e78f5027

mkdir -p "$OUT"
fetch() { # url sha256 file
    if [ -f "$3" ] && echo "$2  $3" | sha256sum -c --quiet - 2>/dev/null; then return; fi
    curl -fsSL -o "$3.part" "$1"
    echo "$2  $3.part" | sha256sum -c --quiet - || { echo "checksum mismatch: $1" >&2; rm -f "$3.part"; exit 1; }
    mv "$3.part" "$3"
}
fetch "$WGNT_URL" "$WGNT_SHA256" "$OUT/wireguard-nt.zip"
fetch "$PFY_URL" "$PFY_SHA256" "$OUT/ProxiFyre-setup.exe"
# python3 on Linux; on Windows (Git Bash) usually just "python"
PY=""
for p in python3 python; do
    if "$p" -c 'import zipfile' >/dev/null 2>&1; then PY="$p"; break; fi
done
[ -n "$PY" ] || { echo "python is needed" >&2; exit 1; }
"$PY" - "$OUT" <<'PY'
import sys, zipfile
out = sys.argv[1]
z = zipfile.ZipFile(f"{out}/wireguard-nt.zip")
open(f"{out}/wireguard.dll", "wb").write(z.read("wireguard-nt/bin/amd64/wireguard.dll"))
open(f"{out}/wireguard-nt-LICENSE.txt", "wb").write(z.read("wireguard-nt/LICENSE.txt"))
PY
echo "$OUT"
