//! `%ProgramData%\Sideroute\Sideroute.log`: what the tunnel and the SOCKS5 server did, for the
//! troubleshooting report. Kept small: truncated at start when it grows past 1 MB.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::state;

static LOCK: Mutex<()> = Mutex::new(());

pub fn path() -> std::path::PathBuf {
    state::dir().join("Sideroute.log")
}

pub fn init() {
    if fs::metadata(path()).is_ok_and(|m| m.len() > 1_000_000) {
        let _ = fs::remove_file(path());
    }
}

pub fn log(msg: &str) {
    let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path()) {
        let _ = writeln!(f, "{} {msg}", sideroute_proto::warp::timestamp(now));
    }
}

/// The last `n` lines of a text file.
pub fn tail(p: &std::path::Path, n: usize) -> String {
    let s = fs::read_to_string(p).unwrap_or_default();
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}
