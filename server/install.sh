#!/usr/bin/env bash
# sideroute server installer for Debian / Ubuntu VPSes.
#
#   curl -fsSL https://raw.githubusercontent.com/attaberuku/sideroute/main/server/install.sh | sudo bash
#
# Safe to run again: it upgrades the binary and keeps keys, devices and settings.
# It adds its own WireGuard interface (sroute0) and iptables rules tagged "sideroute"; it does not
# touch existing WireGuard interfaces, Docker, Tailscale or other firewall rules.
#
# Options:
#   --endpoint HOST     address clients connect to (default: detected public IPv4)
#   --port N            WireGuard UDP port (default 51820)
#   --pair-port N       pairing HTTPS TCP port (default 51821)
#   --subnet CIDR       tunnel subnet (default: first free of 10.77.0.0/24, 10.78.0.0/24, ...)
#   --binary PATH       install this sideroute-server binary instead of downloading one
#   --from-source       build from source with cargo instead of downloading a release
#   --no-pair           do not print a pairing code at the end
#   --uninstall         remove the service (keeps /etc/sideroute and /var/lib/sideroute)
#   --purge             with --uninstall: also delete keys, devices and settings
set -euo pipefail
export LC_ALL=C   # stable command output and regex ranges in any locale

REPO="${SIDEROUTE_REPO:-attaberuku/sideroute}"
BIN=/usr/local/bin/sideroute-server
UNIT_DIR=/etc/systemd/system

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

INIT_ARGS=() BINARY="" FROM_SOURCE=0 PAIR=1 UNINSTALL=0 PURGE=0 ENDPOINT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --endpoint)    ENDPOINT="${2:?}"; shift ;;
        --port)        INIT_ARGS+=(--port "${2:?}"); shift ;;
        --pair-port)   INIT_ARGS+=(--pair-port "${2:?}"); shift ;;
        --subnet)      INIT_ARGS+=(--subnet "${2:?}"); shift ;;
        --binary)      BINARY="${2:?}"; shift ;;
        --from-source) FROM_SOURCE=1 ;;
        --no-pair)     PAIR=0 ;;
        --uninstall)   UNINSTALL=1 ;;
        --purge)       PURGE=1 ;;
        -h|--help)     sed -n '2,/^set -e/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
    shift
done

[ "$(id -u)" = 0 ] || die "run as root (curl ... | sudo bash)"
command -v systemctl >/dev/null || die "systemd is required"

if [ "$UNINSTALL" = 1 ]; then
    say "removing sideroute server"
    systemctl disable --now sideroute.service sideroute-wg.service 2>/dev/null || true
    rm -f "$UNIT_DIR/sideroute.service" "$UNIT_DIR/sideroute-wg.service" /etc/sysctl.d/99-sideroute.conf
    systemctl daemon-reload
    rm -f "$BIN"
    if [ "$PURGE" = 1 ]; then
        rm -rf /etc/sideroute /var/lib/sideroute
        say "removed, including keys and paired devices"
    else
        say "removed (keys and devices kept in /etc/sideroute and /var/lib/sideroute; --purge deletes them)"
    fi
    exit 0
fi

# ---- packages ------------------------------------------------------------------------------------
command -v apt-get >/dev/null || die "this installer supports Debian and Ubuntu (apt). Other distros: see README"
need=()
command -v wg >/dev/null       || need+=(wireguard-tools)
command -v iptables >/dev/null || need+=(iptables)
command -v qrencode >/dev/null || need+=(qrencode)
command -v curl >/dev/null     || need+=(curl ca-certificates)
command -v ip >/dev/null       || need+=(iproute2)
if [ ${#need[@]} -gt 0 ]; then
    say "installing packages: ${need[*]}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends "${need[@]}" >/dev/null
fi

# WireGuard is in the kernel since 5.6; containers (OpenVZ/LXC) usually cannot create interfaces
modprobe wireguard 2>/dev/null || true
if ! ip link show sroute0 >/dev/null 2>&1; then
    ip link add sroute0-probe type wireguard 2>/dev/null \
        || die "this server cannot create WireGuard interfaces (OpenVZ/LXC container?). A KVM VPS is needed."
    ip link del sroute0-probe
fi

# ---- binary --------------------------------------------------------------------------------------
case "$(uname -m)" in
    x86_64|amd64)  ARCH=x86_64 ;;
    aarch64|arm64) ARCH=aarch64 ;;
    *) die "unsupported CPU architecture: $(uname -m)" ;;
esac
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
SRC_DIR=""   # a source checkout, when the script is run from one (not via curl | bash)
if [ -f "${BASH_SOURCE[0]:-}" ]; then SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; fi

build_from_source() {
    local dir="$SRC_DIR"
    if [ ! -f "$dir/Cargo.toml" ] || ! grep -q sideroute "$dir/Cargo.toml" 2>/dev/null; then
        command -v git >/dev/null || apt-get install -y -qq git >/dev/null
        dir="$TMP/src"; git clone -q --depth 1 "https://github.com/$REPO.git" "$dir"
    fi
    if ! command -v cargo >/dev/null && [ ! -x "$HOME/.cargo/bin/cargo" ]; then
        say "installing the Rust toolchain (rustup, minimal profile)"
        apt-get install -y -qq build-essential >/dev/null
        curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
    fi
    say "building sideroute-server (this can take a few minutes on a small VPS)"
    (cd "$dir" && PATH="$HOME/.cargo/bin:$PATH" cargo build --release --locked -p sideroute-server)
    BINARY="$dir/target/release/sideroute-server"
}

if [ -n "$BINARY" ]; then
    [ -x "$BINARY" ] || die "$BINARY is not an executable"
elif [ "$FROM_SOURCE" = 1 ]; then
    build_from_source
else
    asset="sideroute-server-$ARCH-linux-musl"
    base="https://github.com/$REPO/releases/latest/download"
    say "downloading $asset"
    if curl -fsSL -o "$TMP/$asset" "$base/$asset" && curl -fsSL -o "$TMP/SHA256SUMS" "$base/SHA256SUMS"; then
        (cd "$TMP" && grep " $asset\$" SHA256SUMS | sha256sum -c --quiet -) || die "checksum mismatch for $asset"
        chmod +x "$TMP/$asset"; BINARY="$TMP/$asset"
    else
        warn "no release download available; building from source instead"
        build_from_source
    fi
fi
"$BINARY" version >/dev/null || die "$BINARY does not run on this system"
install -m 755 -o root -g root "$BINARY" "$BIN.new" && mv -f "$BIN.new" "$BIN"
say "installed $("$BIN" version)"

# ---- configuration -------------------------------------------------------------------------------
if [ -z "$ENDPOINT" ] && [ ! -f /etc/sideroute/server.json ]; then
    for u in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do
        ip4="$(curl -4 -fsS --max-time 5 "$u" 2>/dev/null | tr -d '[:space:]' || true)"
        if [[ "$ip4" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then ENDPOINT="$ip4"; break; fi
    done
    [ -n "$ENDPOINT" ] && say "public address: $ENDPOINT" || warn "could not detect the public address; using the local one"
fi
[ -n "$ENDPOINT" ] && INIT_ARGS+=(--endpoint "$ENDPOINT")
"$BIN" init "${INIT_ARGS[@]}"

echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-sideroute.conf
sysctl -q -w net.ipv4.ip_forward=1

# ---- services ------------------------------------------------------------------------------------
cat > "$UNIT_DIR/sideroute-wg.service" <<EOF
[Unit]
Description=sideroute WireGuard interface and firewall rules
After=network-online.target docker.service ufw.service firewalld.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$BIN up
ExecStop=$BIN down

[Install]
WantedBy=multi-user.target
EOF
cat > "$UNIT_DIR/sideroute.service" <<EOF
[Unit]
Description=sideroute pairing service (HTTPS)
After=sideroute-wg.service
Requires=sideroute-wg.service

[Service]
ExecStart=$BIN serve
Restart=on-failure
RestartSec=3
# least privilege: it only reads its config, writes its state and adds WireGuard peers
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/sideroute
ProtectHome=yes
PrivateTmp=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable -q sideroute-wg.service sideroute.service
systemctl restart sideroute-wg.service
systemctl restart sideroute.service
sleep 1
systemctl is-active -q sideroute.service || { journalctl -u sideroute.service -n 20 --no-pager; die "pairing service did not start"; }

# ---- firewall hints ------------------------------------------------------------------------------
PORTS="$(sed -n 's/.*"listen_port": *\([0-9]*\).*/UDP \1/p; s/.*"pair_port": *\([0-9]*\).*/TCP \1/p' /etc/sideroute/server.json | paste -sd, - | sed 's/,/ and /')"
if systemctl is-active -q firewalld 2>/dev/null; then
    warn "firewalld is active: allow $PORTS and enable masquerading there, or tunneled traffic will be dropped"
fi
say "server ready. If your VPS provider has a firewall in its web panel, allow $PORTS there."

if [ "$PAIR" = 1 ]; then
    echo
    "$BIN" pair
    echo
    echo "More devices later:  sudo sideroute-server pair      List / remove:  sudo sideroute-server list | revoke <name>"
fi
