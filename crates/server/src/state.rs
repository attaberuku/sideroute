//! Configuration (`/etc/sideroute/server.json`) and mutable state (`/var/lib/sideroute/state.json`).

use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
}

impl Paths {
    /// `SIDEROUTE_CONFIG_DIR` / `SIDEROUTE_STATE_DIR` override the defaults (used by the tests).
    pub fn from_env() -> Paths {
        let dir = |var: &str, def: &str| PathBuf::from(std::env::var(var).unwrap_or_else(|_| def.into()));
        Paths {
            config_dir: dir("SIDEROUTE_CONFIG_DIR", "/etc/sideroute"),
            state_dir: dir("SIDEROUTE_STATE_DIR", "/var/lib/sideroute"),
        }
    }
    pub fn config(&self) -> PathBuf {
        self.config_dir.join("server.json")
    }
    pub fn server_key(&self) -> PathBuf {
        self.config_dir.join("server.key")
    }
    pub fn tls_cert(&self) -> PathBuf {
        self.config_dir.join("tls.crt.der")
    }
    pub fn tls_key(&self) -> PathBuf {
        self.config_dir.join("tls.key.der")
    }
    fn state(&self) -> PathBuf {
        self.state_dir.join("state.json")
    }
    fn lock(&self) -> PathBuf {
        self.state_dir.join("state.lock")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub interface: String,
    pub listen_port: u16,
    pub pair_port: u16,
    /// Public address clients use to reach this server (IP or DNS name).
    pub endpoint_host: String,
    pub subnet: String,
    pub dns: Vec<String>,
    pub mtu: u16,
    pub persistent_keepalive: u16,
    pub public_key: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            interface: "sroute0".into(),
            listen_port: sideroute_proto::DEFAULT_WG_PORT,
            pair_port: sideroute_proto::DEFAULT_PAIR_PORT,
            endpoint_host: String::new(),
            subnet: "10.77.0.0/24".into(),
            dns: vec!["1.1.1.1".into(), "1.0.0.1".into()],
            mtu: 1280,
            persistent_keepalive: 25,
            public_key: String::new(),
        }
    }
}

/// Parses `a.b.c.d/len` into (network address, prefix length).
pub fn parse_cidr(s: &str) -> Option<(u32, u8)> {
    let (a, l) = s.split_once('/').unwrap_or((s, "32"));
    let ip: Ipv4Addr = a.parse().ok()?;
    let len: u8 = l.parse().ok()?;
    if len > 32 {
        return None;
    }
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    Some((u32::from(ip) & mask, len))
}

impl Config {
    pub fn load(paths: &Paths) -> Result<Config, String> {
        let raw = fs::read(paths.config()).map_err(|e| {
            format!("{}: {e} (run: sideroute-server init)", paths.config().display())
        })?;
        serde_json::from_slice(&raw).map_err(|e| format!("{}: {e}", paths.config().display()))
    }

    pub fn save(&self, paths: &Paths) -> Result<(), String> {
        let mut j = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        j.push(b'\n');
        write_file(&paths.config(), &j, 0o644)
    }

    pub fn validate(&self) -> Result<(), String> {
        let i = &self.interface;
        if i.is_empty() || i.len() > 15 || !i.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(format!("invalid interface name '{i}'"));
        }
        let (_, len) = parse_cidr(&self.subnet).ok_or_else(|| format!("invalid subnet '{}'", self.subnet))?;
        if !(16..=29).contains(&len) {
            return Err("subnet prefix must be between /16 and /29".into());
        }
        if self.listen_port == 0 || self.pair_port == 0 {
            return Err("ports must not be 0".into());
        }
        let h = &self.endpoint_host;
        if h.is_empty() || !h.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':')) {
            return Err(format!("invalid endpoint '{h}'"));
        }
        for d in &self.dns {
            d.parse::<Ipv4Addr>().map_err(|_| format!("invalid DNS server '{d}' (IPv4 only)"))?;
        }
        if !(576..=1420).contains(&self.mtu) {
            return Err("mtu must be between 576 and 1420".into());
        }
        Ok(())
    }

    pub fn prefix(&self) -> Result<(u32, u8), String> {
        parse_cidr(&self.subnet).ok_or_else(|| format!("invalid subnet '{}'", self.subnet))
    }

    /// The server's own tunnel address: first host of the subnet.
    pub fn server_ip(&self) -> Result<Ipv4Addr, String> {
        Ok(Ipv4Addr::from(self.prefix()?.0 + 1))
    }

    /// Network in canonical form (`10.77.0.0/24`).
    pub fn network(&self) -> Result<String, String> {
        let (n, l) = self.prefix()?;
        Ok(format!("{}/{l}", Ipv4Addr::from(n)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub name: String,
    pub public_key: String,
    pub ip: String,
    pub platform: String,
    pub created: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Code {
    pub secret_sha256: String,
    pub expires: u64,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub peers: Vec<Peer>,
    pub codes: Vec<Code>,
}

impl State {
    /// Lowest free host address in the subnet (the first one belongs to the server).
    pub fn free_ip(&self, c: &Config) -> Result<Ipv4Addr, String> {
        let (net, len) = c.prefix()?;
        let size = 1u32 << (32 - len);
        (net + 2..net + size - 1)
            .map(Ipv4Addr::from)
            .find(|ip| !self.peers.iter().any(|p| p.ip == ip.to_string()))
            .ok_or_else(|| "the tunnel subnet is full; revoke unused devices".into())
    }
}

pub fn write_file(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    let err = |e: std::io::Error| format!("{}: {e}", path.display());
    if let Some(d) = path.parent() {
        fs::create_dir_all(d).map_err(err)?;
    }
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(&tmp).map_err(err)?;
    f.write_all(data).map_err(err)?;
    f.sync_all().map_err(err)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode)).map_err(err)?;
    fs::rename(&tmp, path).map_err(err)
}

pub fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(d) = path.parent() {
        fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        let _ = fs::set_permissions(d, fs::Permissions::from_mode(0o700));
    }
    write_file(path, data, 0o600)
}

/// Runs `f` on the state while holding an exclusive lock, and saves it afterwards.
/// The CLI and the pairing service both go through here.
pub fn with_state<T>(paths: &Paths, f: impl FnOnce(&mut State) -> Result<T, String>) -> Result<T, String> {
    fs::create_dir_all(&paths.state_dir).map_err(|e| format!("{}: {e}", paths.state_dir.display()))?;
    let _ = fs::set_permissions(&paths.state_dir, fs::Permissions::from_mode(0o700));
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(paths.lock())
        .map_err(|e| e.to_string())?;
    lock.lock().map_err(|e| format!("state lock: {e}"))?;
    let mut st: State = match fs::read(paths.state()) {
        Ok(raw) => serde_json::from_slice(&raw).map_err(|e| format!("{}: {e}", paths.state().display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
        Err(e) => return Err(format!("{}: {e}", paths.state().display())),
    };
    let before = serde_json::to_vec(&st).map_err(|e| e.to_string())?;
    let out = f(&mut st)?;
    let after = serde_json::to_vec_pretty(&st).map_err(|e| e.to_string())?;
    if serde_json::to_vec(&st).map_err(|e| e.to_string())? != before {
        write_file(&paths.state(), &after, 0o600)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_and_allocation() {
        assert_eq!(parse_cidr("10.77.0.9/24"), Some((u32::from(Ipv4Addr::new(10, 77, 0, 0)), 24)));
        assert_eq!(parse_cidr("bogus"), None);
        let c = Config { subnet: "10.77.0.0/29".into(), ..Config::default() };
        assert_eq!(c.server_ip().unwrap(), Ipv4Addr::new(10, 77, 0, 1));
        let mut st = State::default();
        for i in 2..=6 {
            let ip = st.free_ip(&c).unwrap();
            assert_eq!(ip, Ipv4Addr::new(10, 77, 0, i));
            st.peers.push(Peer { name: "x".into(), public_key: String::new(), ip: ip.to_string(), platform: "linux".into(), created: 0 });
        }
        assert!(st.free_ip(&c).is_err()); // .7 is broadcast
    }
}
