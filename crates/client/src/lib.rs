//! Shared pieces of the Linux client: names and cgroup paths. Pairing lives in `sideroute-net`.

use sideroute_proto::{PairResponse, PairingCode};

/// Pairs with an own server (see `sideroute_net::request_pairing`).
pub fn request_pairing(code: &PairingCode, public_key: &str, name: &str) -> Result<PairResponse, String> {
    sideroute_net::request_pairing(code, public_key, name, "linux")
}

pub use sideroute_net::{warp_delete, warp_register};

/// WireGuard interface on the client.
pub const IFACE: &str = "sroute0";
/// systemd user slice holding tunneled apps. The dash makes it a child of `app.slice`.
pub const SLICE: &str = "app-sideroute.slice";
/// Keeps `SLICE` alive while no app is in it.
pub const HOLDER: &str = "sideroute-holder.service";
pub const HELPER: &str = "/usr/local/bin/sideroute-helper";
pub const BUS_NAME: &str = "io.github.attaberuku.Sideroute";
pub const OBJECT_PATH: &str = "/io/github/attaberuku/Sideroute";
/// fwmark and routing table for tunneled traffic (chosen to stay clear of Tailscale's 0xff0000 bits).
pub const MARK: u32 = 0x6174;
pub const TABLE: u32 = 7174;
pub const RULE_PRIORITY: u32 = 1074;

/// `user.slice/user-UID.slice/user@UID.service` (cgroup v2 path, no leading slash).
pub fn user_root(uid: u32) -> String {
    format!("user.slice/user-{uid}.slice/user@{uid}.service")
}

pub fn tunnel_cgroup(uid: u32) -> String {
    format!("{}/app.slice/{SLICE}", user_root(uid))
}

/// cgroup v2 path of a process, without the leading slash.
pub fn cgroup_of(pid: u32) -> Result<String, String> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(|e| format!("process {pid}: {e}"))?;
    s.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(|p| p.trim_start_matches('/').to_string())
        .ok_or_else(|| "no cgroup v2 entry (is this a cgroup v2 system?)".into())
}

