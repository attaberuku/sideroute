#!/usr/bin/env bash
# sideroute Linux client installer. Run it as your normal user (it asks for sudo when needed):
#
#   curl -fsSL https://raw.githubusercontent.com/attaberuku/sideroute/main/client/install.sh | bash
#
# It installs sideroute + sideroute-helper to /usr/local/bin, a sudoers rule that lets you run
# only the helper's up/down/status/kill-sockets commands without a password, systemd user units,
# a D-Bus service and (on KDE Plasma) a KWin script, then pairs with your server.
#
# Options:
#   --code CODE       pairing code (otherwise you are asked for it)
#   --warp            use Cloudflare WARP instead of your own server (nothing to ask)
#   --from-source     build with cargo instead of downloading a release (default inside a checkout)
#   --no-pair         skip pairing
#   --uninstall       remove sideroute (keeps the pairing in /etc/sideroute)
#   --purge           with --uninstall: also forget the pairing and the private key
set -euo pipefail
export LC_ALL=C   # stable command output and regex ranges in any locale

REPO="${SIDEROUTE_REPO:-attaberuku/sideroute}"
PREFIX=/usr/local/bin
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
DBUS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/dbus-1/services"
DBUS_NAME=io.github.attaberuku.Sideroute

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

CODE="${SIDEROUTE_CODE:-}" FROM_SOURCE="" PAIR=1 UNINSTALL=0 PURGE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --code)        CODE="${2:?}"; shift ;;
        --warp)        CODE=warp ;;
        --from-source) FROM_SOURCE=1 ;;
        --no-pair)     PAIR=0 ;;
        --uninstall)   UNINSTALL=1 ;;
        --purge)       PURGE=1 ;;
        -h|--help)     sed -n '2,/^set -e/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
    shift
done

[ "$(id -u)" != 0 ] || die "run this as your normal user, not root (it uses sudo itself)"
command -v sudo >/dev/null || die "sudo is required"
[ -f /sys/fs/cgroup/cgroup.controllers ] || die "cgroup v2 is required (any current distribution has it)"
systemctl --user show-environment >/dev/null 2>&1 || die "no systemd user session found (run this from your desktop session)"
USER_NAME="$(id -un)"
SUDOERS="/etc/sudoers.d/sideroute-$(printf '%s' "$USER_NAME" | tr -c 'A-Za-z0-9_-' '_')"

kwin_reload() {
    local q
    for q in qdbus6 qdbus; do
        command -v "$q" >/dev/null && { "$q" org.kde.KWin /KWin reconfigure >/dev/null 2>&1 || true; return; }
    done
    dbus-send --session --dest=org.kde.KWin /KWin org.kde.KWin.reconfigure >/dev/null 2>&1 || true
}

if [ "$UNINSTALL" = 1 ]; then
    say "removing sideroute"
    [ -x "$PREFIX/sideroute" ] && "$PREFIX/sideroute" off >/dev/null 2>&1 || true
    systemctl --user stop sideroute.service sideroute-holder.service 2>/dev/null || true
    rm -f "$UNIT_DIR/sideroute.service" "$UNIT_DIR/sideroute-holder.service" "$UNIT_DIR/app-sideroute.slice" \
          "$DBUS_DIR/$DBUS_NAME.service"
    systemctl --user daemon-reload
    if command -v kpackagetool6 >/dev/null; then
        kpackagetool6 --type=KWin/Script -r sideroute >/dev/null 2>&1 || true
        command -v kwriteconfig6 >/dev/null && kwriteconfig6 --file kwinrc --group Plugins --key siderouteEnabled --delete
        kwin_reload
    fi
    if [ "$PURGE" = 1 ] && [ -x "$PREFIX/sideroute-helper" ]; then sudo "$PREFIX/sideroute-helper" unpair || true; fi
    [ -x "$PREFIX/sideroute-helper" ] && sudo "$PREFIX/sideroute-helper" down >/dev/null 2>&1 || true
    sudo rm -f "$PREFIX/sideroute" "$PREFIX/sideroute-helper" "$SUDOERS"
    say "removed"
    [ "$PURGE" = 1 ] || echo "The pairing is kept in /etc/sideroute (remove it with --uninstall --purge)."
    exit 0
fi

# ---- packages ------------------------------------------------------------------------------------
missing=()
for t in wg nft ip ss; do command -v "$t" >/dev/null || missing+=("$t"); done
command -v notify-send >/dev/null || missing+=(notify-send)
if [ ${#missing[@]} -gt 0 ]; then
    say "installing: ${missing[*]}"
    if command -v pacman >/dev/null; then
        sudo pacman -S --needed --noconfirm wireguard-tools nftables iproute2 libnotify
    elif command -v apt-get >/dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y -qq wireguard-tools nftables iproute2 libnotify-bin
    elif command -v dnf >/dev/null; then
        sudo dnf install -y wireguard-tools nftables iproute libnotify
    elif command -v zypper >/dev/null; then
        sudo zypper --non-interactive install wireguard-tools nftables iproute2 libnotify-tools
    else
        die "please install wireguard-tools, nftables and iproute2 with your package manager, then run this again"
    fi
fi
for t in wg nft ip ss; do command -v "$t" >/dev/null || die "$t is still missing"; done

# ---- binaries and data files ---------------------------------------------------------------------
case "$(uname -m)" in
    x86_64|amd64)  ARCH=x86_64 ;;
    aarch64|arm64) ARCH=aarch64 ;;
    *) die "unsupported CPU architecture: $(uname -m)" ;;
esac
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
SRC_DIR=""   # a source checkout, when the script is run from one (not via curl | bash)
if [ -f "${BASH_SOURCE[0]:-}" ]; then SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; fi
[ -n "$SRC_DIR" ] && [ -f "$SRC_DIR/Cargo.toml" ] && [ -z "$FROM_SOURCE" ] && FROM_SOURCE=1

if [ "$FROM_SOURCE" = 1 ]; then
    if [ -z "$SRC_DIR" ] || [ ! -f "$SRC_DIR/Cargo.toml" ]; then
        command -v git >/dev/null || die "git is needed to build from source"
        SRC_DIR="$TMP/src"; git clone -q --depth 1 "https://github.com/$REPO.git" "$SRC_DIR"
    fi
    CARGO="$(command -v cargo || echo "$HOME/.cargo/bin/cargo")"
    [ -x "$CARGO" ] || die "cargo not found; install Rust from https://rustup.rs or use a release"
    say "building sideroute"
    (cd "$SRC_DIR" && "$CARGO" build --release --locked -p sideroute-client)
    BIN_DIR="$SRC_DIR/target/release"
    DATA="$SRC_DIR/client"
else
    asset="sideroute-linux-$ARCH.tar.gz"
    base="https://github.com/$REPO/releases/latest/download"
    say "downloading $asset"
    curl -fsSL -o "$TMP/$asset" "$base/$asset" || die "download failed ($base/$asset)"
    curl -fsSL -o "$TMP/SHA256SUMS" "$base/SHA256SUMS" || die "download failed (SHA256SUMS)"
    (cd "$TMP" && grep " $asset\$" SHA256SUMS | sha256sum -c --quiet -) || die "checksum mismatch for $asset"
    tar -xzf "$TMP/$asset" -C "$TMP"
    BIN_DIR="$TMP/sideroute-linux-$ARCH"
    DATA="$BIN_DIR/share"
fi
for f in "$BIN_DIR/sideroute" "$BIN_DIR/sideroute-helper" "$DATA/systemd/sideroute.service" "$DATA/kwin/metadata.json"; do
    [ -e "$f" ] || die "missing $f"
done

say "installing to $PREFIX (asks for your password)"
sudo install -m 755 -o root -g root "$BIN_DIR/sideroute" "$PREFIX/sideroute"
sudo install -m 755 -o root -g root "$BIN_DIR/sideroute-helper" "$PREFIX/sideroute-helper"
H="$PREFIX/sideroute-helper"
cat > "$TMP/sudoers" <<EOF
# sideroute: lets $USER_NAME run these network helper commands without a password.
# Pairing and unpairing still ask for it.
$USER_NAME ALL=(root) NOPASSWD: $H up, $H down, $H status, $H kill-sockets *
EOF
sudo visudo -cqf "$TMP/sudoers" || die "generated sudoers rule is invalid"
sudo install -m 440 -o root -g root "$TMP/sudoers" "$SUDOERS"

# ---- user session --------------------------------------------------------------------------------
mkdir -p "$UNIT_DIR" "$DBUS_DIR"
install -m 644 "$DATA/systemd/sideroute.service" "$DATA/systemd/sideroute-holder.service" \
    "$DATA/systemd/app-sideroute.slice" "$UNIT_DIR/"
install -m 644 "$DATA/dbus/$DBUS_NAME.service" "$DBUS_DIR/"
systemctl --user daemon-reload
systemctl --user try-restart sideroute.service 2>/dev/null || true

if command -v kpackagetool6 >/dev/null; then
    if kpackagetool6 --type=KWin/Script -s sideroute >/dev/null 2>&1; then
        kpackagetool6 --type=KWin/Script -u "$DATA/kwin" >/dev/null
    else
        kpackagetool6 --type=KWin/Script -i "$DATA/kwin" >/dev/null
    fi
    kwriteconfig6 --file kwinrc --group Plugins --key siderouteEnabled true
    kwin_reload
    KDE=1
else
    KDE=0
fi

# ---- pairing -------------------------------------------------------------------------------------
if [ "$PAIR" = 1 ]; then
    st="$(sudo -n "$H" status 2>/dev/null || true)"
    if grep -q '^paired: yes' <<<"$st"; then
        say "already paired ($(sed -n 's/^paired: yes (\(.*\))/\1/p' <<<"$st"))"
        echo "To pair with another server: sideroute pair"
    else
        if [ -z "$CODE" ]; then
            [ -r /dev/tty ] || die "no terminal to ask for the pairing code; use --code CODE or --warp"
            echo
            echo "Paste the pairing code shown by your server (sr1:...),"
            echo "or just press Enter to use Cloudflare WARP (free, no server needed):"
            read -r CODE < /dev/tty || true
            [ -n "$CODE" ] || CODE=warp
        fi
        printf '%s' "$CODE" | sudo "$H" pair || die "pairing failed; run 'sideroute pair' to try again"
    fi
fi

echo
say "sideroute is installed."
if [ "$KDE" = 1 ]; then
    echo "  Open the window menu (right-click the title bar, or Alt+F3) and pick \"Route through sideroute\","
    echo "  or press Meta+Alt+V for the active window. Do the same again to switch it back."
else
    echo "  sideroute toggle <program name or PID>   e.g.  sideroute toggle firefox"
fi
echo "  sideroute run <program>      start a program inside the tunnel"
echo "  sideroute status | off       see what is tunneled / switch everything back"
