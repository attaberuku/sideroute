//! Files in `%ProgramData%\Sideroute` (the installer restricts the folder to SYSTEM and
//! Administrators): the tunnel configuration, the private key and the list of tunneled programs.

use std::fs;
use std::path::PathBuf;

use sideroute_proto::{PairResponse, warp};

/// Local SOCKS5 port ProxiFyre hands the tunneled programs' traffic to.
pub const SOCKS_PORT: u16 = 40871;

pub fn dir() -> PathBuf {
    let base = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("Sideroute")
}

fn path(name: &str) -> PathBuf {
    dir().join(name)
}

fn write(name: &str, data: &[u8]) -> Result<(), String> {
    fs::create_dir_all(dir()).map_err(|e| format!("{}: {e}", dir().display()))?;
    let tmp = path(&format!("{name}.tmp"));
    fs::write(&tmp, data).map_err(|e| format!("{}: {e}", tmp.display()))?;
    fs::rename(&tmp, path(name)).map_err(|e| format!("{}: {e}", path(name).display()))
}

pub fn load_config() -> Result<PairResponse, String> {
    let raw = fs::read(path("client.json")).map_err(|_| "not paired yet".to_string())?;
    serde_json::from_slice(&raw).map_err(|e| format!("client.json: {e}"))
}

pub fn save_config(c: &PairResponse) -> Result<(), String> {
    write("client.json", &serde_json::to_vec_pretty(c).map_err(|e| e.to_string())?)
}

/// The private key, created on first use. It never leaves this computer.
pub fn private_key() -> Result<String, String> {
    if let Ok(k) = fs::read_to_string(path("private.key")) {
        return Ok(k.trim().to_string());
    }
    let (private, _) = sideroute_net::generate_keypair()?;
    write("private.key", private.as_bytes())?;
    Ok(private)
}

pub fn load_warp() -> Option<warp::Account> {
    fs::read(path("warp.json")).ok().and_then(|r| serde_json::from_slice(&r).ok())
}

pub fn save_warp(a: Option<&warp::Account>) -> Result<(), String> {
    match a {
        Some(a) => write("warp.json", &serde_json::to_vec_pretty(a).map_err(|e| e.to_string())?),
        None => {
            let _ = fs::remove_file(path("warp.json"));
            Ok(())
        }
    }
}

/// Executable names (lower case, e.g. `firefox.exe`) routed through the tunnel.
pub fn apps() -> Vec<String> {
    fs::read(path("apps.json")).ok().and_then(|r| serde_json::from_slice(&r).ok()).unwrap_or_default()
}

pub fn save_apps(apps: &[String]) -> Result<(), String> {
    write("apps.json", &serde_json::to_vec_pretty(apps).map_err(|e| e.to_string())?)
}

/// Programs started by a tunneled program under another name (e.g. a helper or updater), keyed by
/// the program they belong to. They go through the tunnel together with it.
pub fn related() -> std::collections::BTreeMap<String, Vec<String>> {
    fs::read(path("related.json")).ok().and_then(|r| serde_json::from_slice(&r).ok()).unwrap_or_default()
}

pub fn save_related(r: &std::collections::BTreeMap<String, Vec<String>>) -> Result<(), String> {
    write("related.json", &serde_json::to_vec_pretty(r).map_err(|e| e.to_string())?)
}

/// Every executable name to redirect: the chosen programs and their related ones.
pub fn redirected_names() -> Vec<String> {
    let rel = related();
    let mut v = apps();
    for a in apps() {
        v.extend(rel.get(&a).cloned().unwrap_or_default());
    }
    v.sort();
    v.dedup();
    v
}
