#!/usr/bin/env bash
# End-to-end test without root and without touching the host network.
#
# Builds three network namespaces inside an unprivileged user namespace:
#
#   client (192.0.2.2) ── inet (router, "internet", web+dns at 198.51.100.1) ── server (203.0.113.2)
#
# runs the real sideroute-server (init/up/serve/pair/list/revoke) in "server", pairs the real
# sideroute-helper in "client" over pinned TLS, and checks that only processes in the tunnel cgroup
# leave through the server, DNS included, with the kill switch and socket killing working.
#
# The cgroups come from a delegated systemd --user scope, so the host's slices are not touched.
#
# usage: tests/e2e-netns.sh [BIN_DIR]     (default: target/debug)
set -euo pipefail
[ -n "${E2E_TRACE:-}" ] && set -x
export LC_ALL=C

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$(cd "${1:-$ROOT/target/debug}" && pwd)"
SELF="$ROOT/tests/e2e-netns.sh"

case "${E2E_STAGE:-0}" in
0)
    for b in sideroute-server sideroute-helper; do
        [ -x "$BIN/$b" ] || { echo "missing $BIN/$b (cargo build first)" >&2; exit 1; }
    done
    for t in unshare nsenter wg nft ip ss iptables python3 curl systemd-run; do
        command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }
    done
    # a delegated scope gives us cgroups we may create and move processes between
    exec systemd-run --user --scope --quiet --collect -p Delegate=yes --unit="sideroute-e2e-$$" \
        env E2E_STAGE=1 "$SELF" "$BIN"
    ;;
1)
    CG="$(sed -n 's/^0:://p' /proc/self/cgroup)"; CG="${CG#/}"
    mkdir -p "/sys/fs/cgroup/$CG"/{main,tun,direct}
    echo $$ > "/sys/fs/cgroup/$CG/main/cgroup.procs"
    exec unshare --user --map-root-user --net --mount env E2E_STAGE=2 E2E_CG="$CG" "$SELF" "$BIN"
    ;;
esac

# ---- stage 2: root in a user namespace; this network namespace is the client --------------------
CG="$E2E_CG"
T="$(mktemp -d)"
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    rm -rf "$T"
}
trap cleanup EXIT

pass=0; fail=0
ok()  { echo "  ok   $*"; pass=$((pass + 1)); }
bad() { echo "  FAIL $*"; fail=$((fail + 1)); }
check() { # check "description" expected actual
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}

unshare --net sleep infinity </dev/null >/dev/null 2>&1 & INET=$!; PIDS+=($INET)
unshare --net sleep infinity </dev/null >/dev/null 2>&1 & SRV=$!; PIDS+=($SRV)
sleep 0.3
in_inet() { nsenter --net="/proc/$INET/ns/net" "$@"; }
in_srv()  { nsenter --net="/proc/$SRV/ns/net" "$@"; }

ip link set lo up
ip link add eth0 type veth peer name c-side
ip link set c-side netns "$INET"
ip link add s-side type veth peer name eth0 netns "$SRV"
ip link set s-side netns "$INET"
ip addr add 192.0.2.2/24 dev eth0; ip link set eth0 up; ip route add default via 192.0.2.1
in_inet sh -c '
    ip link set lo up
    ip addr add 192.0.2.1/24 dev c-side; ip link set c-side up
    ip addr add 203.0.113.1/24 dev s-side; ip link set s-side up
    ip link add web type dummy; ip addr add 198.51.100.1/32 dev web; ip link set web up
    echo 1 > /proc/sys/net/ipv4/ip_forward'
in_srv sh -c '
    ip link set lo up
    ip addr add 203.0.113.2/24 dev eth0; ip link set eth0 up; ip route add default via 203.0.113.1'

# "internet" services: HTTP and a DNS-like UDP service, both answer with the caller's address
cat > "$T/echo.py" <<'EOF'
import socket, threading, http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = self.client_address[0].encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("198.51.100.1", 53))
    while True:
        d, a = s.recvfrom(512); s.sendto(a[0].encode(), a)
threading.Thread(target=udp, daemon=True).start()
http.server.ThreadingHTTPServer(("198.51.100.1", 8080), H).serve_forever()
EOF
in_inet python3 "$T/echo.py" </dev/null >/dev/null 2>&1 & PIDS+=($!)

# ---- server ---------------------------------------------------------------------------------------
export SIDEROUTE_STATE_DIR="$T/srv-state"
SRVENV=(env SIDEROUTE_CONFIG_DIR="$T/srv-etc" SIDEROUTE_STATE_DIR="$T/srv-state")
echo "server:"
in_srv "${SRVENV[@]}" "$BIN/sideroute-server" init --endpoint 203.0.113.2 --dns 198.51.100.1 >/dev/null
in_srv "${SRVENV[@]}" "$BIN/sideroute-server" init >/dev/null   # idempotent
in_srv "${SRVENV[@]}" "$BIN/sideroute-server" up >/dev/null && ok "server up (WireGuard + iptables)"
in_srv iptables -w -t nat -S POSTROUTING | grep -q 'sideroute' && ok "masquerade rule present" || bad "masquerade rule"
n1=$(in_srv iptables -w -S | grep -c 'sideroute' || true)
in_srv "${SRVENV[@]}" "$BIN/sideroute-server" up >/dev/null
n2=$(in_srv iptables -w -S | grep -c 'sideroute' || true)
check "re-running up does not duplicate rules" "$n1" "$n2"
in_srv "${SRVENV[@]}" "$BIN/sideroute-server" serve </dev/null >/dev/null 2>"$T/serve.log" & PIDS+=($!)
sleep 0.5
CODE=$(in_srv "${SRVENV[@]}" "$BIN/sideroute-server" pair --no-qr | grep -o 'sr1:[^ ]*' | head -1)
[[ "$CODE" == sr1:*@203.0.113.2:51821 ]] && ok "pairing code issued" || bad "pairing code: $CODE"

# ---- client ---------------------------------------------------------------------------------------
echo "client:"
export SIDEROUTE_CONFIG_DIR="$T/cli-etc"
H="$BIN/sideroute-helper"

# a code with a wrong certificate fingerprint must be refused before anything is sent
WRONG=$(sed -E 's/^(sr1:[A-Z2-7]+:)[A-Z2-7]{26}/\1AAAAAAAAAAAAAAAAAAAAAAAAAA/' <<<"$CODE")
if out=$("$H" pair "$WRONG" 2>&1); then bad "pinned TLS accepted a wrong fingerprint"; else
    grep -q "does not match the pairing code" <<<"$out" && ok "wrong fingerprint refused" || bad "wrong fingerprint: $out"; fi

echo "$CODE" | "$H" pair >/dev/null && ok "paired (code via stdin)"
[ "$(stat -c %a "$T/cli-etc/private.key")" = 600 ] && ok "private key is 0600" || bad "private key mode"
if out=$("$H" pair "$CODE" 2>&1); then bad "a used code was accepted again"; else
    grep -q 403 <<<"$out" && ok "used code refused (single use)" || bad "reuse: $out"; fi

"$H" up --cgroup "$CG/tun" >/dev/null && ok "client up"
"$H" up --cgroup "$CG/tun" >/dev/null && ok "client up again (idempotent)"

in_cg() { local g="$1"; shift; sh -c 'echo $$ > "/sys/fs/cgroup/$0/cgroup.procs" && exec "$@"' "$CG/$g" "$@"; }
web() { in_cg "$1" curl -s --max-time 3 http://198.51.100.1:8080/ || echo "unreachable"; }
dns() { # $1 cgroup, $2 resolver address
    in_cg "$1" python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(b"q", (sys.argv[1], 53))
try: print(s.recvfrom(512)[0].decode())
except Exception: print("no answer")' "$2"
}

check "tunneled app leaves through the server" 203.0.113.2 "$(web tun)"
check "other apps connect directly" 192.0.2.2 "$(web direct)"
check "DNS to the local stub (127.0.0.53) goes through the tunnel" 203.0.113.2 "$(dns tun 127.0.0.53)"
check "DNS to a LAN resolver goes through the tunnel" 203.0.113.2 "$(dns tun 192.0.2.1)"
hs=$(wg show sroute0 latest-handshakes | awk '{print $2}')
[ "${hs:-0}" -gt 0 ] && ok "WireGuard handshake" || bad "no handshake"
st=$("$H" status)
grep -q "tunnel: connected" <<<"$st" && ok "helper status" || bad "helper status: $st"

# connections that existed before the move are closed so the app reconnects
in_cg direct python3 -c '
import socket, time
s = socket.create_connection(("198.51.100.1", 8080))
s.settimeout(10)
try: d = s.recv(1)
except Exception as e: print("error", e); raise SystemExit
print("closed" if d == b"" else "data")' > "$T/conn.out" &
CONN=$!
sleep 0.5
grep -q "closed 1" <<<"$("$H" kill-sockets "$CONN" $(pgrep -P "$CONN" || true))" && ok "kill-sockets closed the connection" || bad "kill-sockets"
wait "$CONN" || true
grep -q -e closed -e "error" "$T/conn.out" && ok "app saw its connection end" || bad "connection state: $(cat "$T/conn.out")"

# kill switch: without the interface, tunneled traffic fails instead of going direct
ip link del sroute0
check "kill switch: no leak when the tunnel is gone" unreachable "$(web tun)"
check "direct apps unaffected" 192.0.2.2 "$(web direct)"
"$H" up --cgroup "$CG/tun" >/dev/null
check "tunnel restored" 203.0.113.2 "$(web tun)"

# server-side management
echo "server management:"
in_srv "${SRVENV[@]}" "$BIN/sideroute-server" list | grep -q '10\.77\.0\.2' && ok "device listed" || bad "list"
in_srv "${SRVENV[@]}" "$BIN/sideroute-server" status | grep -q "1 paired" && ok "status" || bad "status"
# the tunnel may not be used to reach the server's private networks
check "private networks behind the server are blocked" unreachable \
    "$(in_cg tun curl -s --max-time 2 http://10.77.0.1:1/ >/dev/null 2>&1; in_cg tun curl -s --max-time 2 http://172.16.0.1:1/ || echo unreachable)"
in_srv "${SRVENV[@]}" "$BIN/sideroute-server" revoke 10.77.0.2 >/dev/null && ok "revoked"
check "revoked device cannot connect" unreachable "$(web tun)"
in_srv "${SRVENV[@]}" "$BIN/sideroute-server" down >/dev/null
n=$(in_srv iptables -w -S | grep -c 'sideroute' || true)
check "server down removes its firewall rules" 0 "$n"

"$H" down >/dev/null
nft list table inet sideroute >/dev/null 2>&1 && bad "client rules left behind" || ok "client down removes rules"

echo
echo "passed: $pass, failed: $fail"
[ "$fail" -eq 0 ]
