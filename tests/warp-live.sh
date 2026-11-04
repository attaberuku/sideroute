#!/usr/bin/env bash
# Live test of the Cloudflare WARP mode (needs internet; registers a real WARP device and deletes
# it again at the end). No root needed and the host network is not changed:
#
#  * registration runs in a user namespace that still uses the host network,
#  * the tunnel runs in a private network namespace; its WireGuard UDP packets are relayed to
#    Cloudflare through a unix socket by a small relay in the host network namespace,
#  * a process in the tunnel cgroup then fetches https://www.cloudflare.com/cdn-cgi/trace and
#    must see "warp=on".
#
# usage: tests/warp-live.sh [BIN_DIR]     (default: target/debug)
set -euo pipefail
export LC_ALL=C
[ -n "${E2E_TRACE:-}" ] && set -x

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$(cd "${1:-$ROOT/target/debug}" && pwd)"
SELF="$ROOT/tests/warp-live.sh"
H="$BIN/sideroute-helper"

case "${E2E_STAGE:-0}" in
0)
    [ -x "$H" ] || { echo "missing $H (cargo build first)" >&2; exit 1; }
    exec systemd-run --user --scope --quiet --collect -p Delegate=yes --unit="sideroute-warp-$$" \
        env E2E_STAGE=1 "$SELF" "$BIN"
    ;;
1)
    CG="$(sed -n 's/^0:://p' /proc/self/cgroup)"; CG="${CG#/}"
    mkdir -p "/sys/fs/cgroup/$CG"/{main,tun}
    echo $$ > "/sys/fs/cgroup/$CG/main/cgroup.procs"
    T="$(mktemp -d)"; chmod 700 "$T"
    RELAY=""
    finish() {
        [ -n "$RELAY" ] && kill "$RELAY" 2>/dev/null || true
        # delete the WARP registration
        if [ -f "$T/cli-etc/warp.json" ]; then
            python3 - "$T/cli-etc/warp.json" <<'EOF' || echo "  (could not delete the WARP registration)"
import json, sys, urllib.request
a = json.load(open(sys.argv[1]))
r = urllib.request.Request(f"https://api.cloudflareclient.com/v0a5641/reg/{a['id']}", method="DELETE",
    headers={"Authorization": "Bearer " + a["token"], "User-Agent": "1.1.1.1/6.38.9-5641 (Android 16.0.0)",
             "CF-Client-Version": "a-6.38.9-5641"})
print("  WARP registration deleted:", urllib.request.urlopen(r, timeout=15).status)
EOF
        fi
        rm -rf "$T"
    }
    trap finish EXIT

    echo "registering a WARP device:"
    unshare --user --map-root-user env SIDEROUTE_CONFIG_DIR="$T/cli-etc" SIDEROUTE_NO_PROBE=1 "$H" pair warp
    REAL="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["endpoint"])' "$T/cli-etc/client.json")"

    # host side of the relay: unix datagram socket <-> real WARP endpoint
    python3 - "$T" "$REAL" <<'EOF' &
import os, socket, select, sys
d, real = sys.argv[1], sys.argv[2]
host, port = real.rsplit(":", 1)
u = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); u.bind(d + "/host.sock")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
while True:
    for r in select.select([u, s], [], [])[0]:
        if r is u:
            s.sendto(u.recv(65535), (host, int(port)))
        else:
            data = s.recv(65535)
            try: u.sendto(data, d + "/ns.sock")
            except OSError: pass
EOF
    RELAY=$!
    sleep 0.3
    unshare --user --map-root-user --net --mount env E2E_STAGE=2 E2E_CG="$CG" E2E_T="$T" "$SELF" "$BIN"
    exit $?
    ;;
esac

# ---- stage 2: private network namespace -----------------------------------------------------------
CG="$E2E_CG"; T="$E2E_T"
export SIDEROUTE_CONFIG_DIR="$T/cli-etc"
PIDS=()
trap 'for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done' EXIT
pass=0; fail=0
ok()  { echo "  ok   $*"; pass=$((pass + 1)); }
bad() { echo "  FAIL $*"; fail=$((fail + 1)); }

unshare --net sleep infinity </dev/null >/dev/null 2>&1 & INET=$!; PIDS+=($INET)
sleep 0.3
ip link set lo up
ip link add eth0 type veth peer name c-side
ip link set c-side netns "$INET"
ip addr add 192.0.2.2/24 dev eth0; ip link set eth0 up; ip route add default via 192.0.2.1
nsenter --net="/proc/$INET/ns/net" sh -c 'ip link set lo up; ip addr add 192.0.2.1/24 dev c-side; ip link set c-side up'

# namespace side of the relay: 192.0.2.1:2408 <-> unix socket
cat > "$T/ns-relay.py" <<'EOF'
import socket, select, sys
d = sys.argv[1]
u = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); u.bind(d + "/ns.sock")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("192.0.2.1", 2408))
peer = None
while True:
    for r in select.select([u, s], [], [])[0]:
        if r is s:
            data, peer = s.recvfrom(65535); u.sendto(data, d + "/host.sock")
        elif peer:
            s.sendto(u.recv(65535), peer)
        else:
            u.recv(65535)
EOF
nsenter --net="/proc/$INET/ns/net" python3 "$T/ns-relay.py" "$T" </dev/null >/dev/null 2>&1 &
PIDS+=($!)
sleep 0.3

# point the tunnel at the relay instead of Cloudflare's address
python3 - "$T/cli-etc/client.json" <<'EOF'
import json, sys
c = json.load(open(sys.argv[1])); c["endpoint"] = "192.0.2.1:2408"; json.dump(c, open(sys.argv[1], "w"))
EOF

echo "tunnel:"
"$H" up --cgroup "$CG/tun" >/dev/null && ok "up"
for _ in $(seq 50); do
    hs=$(wg show sroute0 latest-handshakes | awk '{print $2}')
    [ "${hs:-0}" -gt 0 ] && break; sleep 0.2
done
[ "${hs:-0}" -gt 0 ] && ok "WireGuard handshake with Cloudflare" || bad "no handshake with Cloudflare"
"$H" status | sed 's/^/       /'

trace=$(sh -c 'echo $$ > "/sys/fs/cgroup/$0/cgroup.procs" && exec curl -4 -sS --max-time 15 https://www.cloudflare.com/cdn-cgi/trace' "$CG/tun" 2>&1 || true)
grep -q '^warp=on' <<<"$trace" && ok "tunneled app goes through WARP ($(grep '^colo=' <<<"$trace"), $(grep '^ip=' <<<"$trace"))" \
    || bad "trace: $trace"
direct=$(curl -4 -sS --max-time 3 https://www.cloudflare.com/cdn-cgi/trace 2>&1 || echo unreachable)
grep -q -e unreachable -e 'Could not resolve' -e 'Failed to connect' -e 'Network is unreachable' <<<"$direct" \
    && ok "apps outside the tunnel cgroup do not use it" || bad "direct: $direct"
"$H" down >/dev/null

echo
echo "passed: $pass, failed: $fail"
[ "$fail" -eq 0 ]
