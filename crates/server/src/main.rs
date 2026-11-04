//! sideroute-server: the VPS side of sideroute.
//!
//! ```text
//! sideroute-server init [--endpoint HOST] [--port N] [--pair-port N] [--subnet CIDR] [--interface NAME] [--dns A,B] [--mtu N]
//! sideroute-server up | down         bring the WireGuard interface and firewall rules up / down
//! sideroute-server serve             run the HTTPS pairing service
//! sideroute-server pair [--name LABEL] [--ttl MINUTES] [--no-qr]
//! sideroute-server list | status
//! sideroute-server revoke <name|ip|public-key>
//! sideroute-server cancel-codes      invalidate all unused pairing codes
//! ```

mod net;
mod serve;
mod state;

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use sideroute_proto::{PairingCode, cert_fingerprint, new_secret, secret_hash};

use state::{Code, Config, Paths};

/// GitHub `owner/repo` the client installer is downloaded from; set at build time.
pub const REPO: &str = match option_env!("SIDEROUTE_REPO") {
    Some(r) => r,
    None => "attaberuku/sideroute",
};

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn ago(t: u64) -> String {
    let d = now().saturating_sub(t);
    match d {
        0..=119 => format!("{d}s ago"),
        120..=7199 => format!("{}m ago", d / 60),
        7200..=172_799 => format!("{}h ago", d / 3600),
        _ => format!("{}d ago", d / 86400),
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: sideroute-server <command>\n\n\
         \x20 init [--endpoint HOST] [--port N] [--pair-port N] [--subnet CIDR] [--interface NAME] [--dns A,B] [--mtu N]\n\
         \x20 up | down          start / stop the WireGuard interface and firewall rules\n\
         \x20 serve              run the HTTPS pairing service (normally via systemd)\n\
         \x20 pair [--name LABEL] [--ttl MINUTES] [--no-qr]   print a one-time pairing code\n\
         \x20 list               paired devices\n\
         \x20 revoke <name|ip|key>  remove a device\n\
         \x20 cancel-codes       invalidate unused pairing codes\n\
         \x20 status             overview"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let paths = Paths::from_env();
    let res = match args.get(1).map(String::as_str) {
        Some("init") => init(&paths, &args[2..]),
        Some("up") => Config::load(&paths).and_then(|c| net::up(&paths, &c)),
        Some("down") => Config::load(&paths).and_then(|c| net::down(&c)),
        Some("serve") => Config::load(&paths).and_then(|c| serve::serve(&paths, c)),
        Some("pair") => pair(&paths, &args[2..]),
        Some("list") => list(&paths),
        Some("revoke") => match args.get(2) {
            Some(who) => revoke(&paths, who),
            None => return usage(),
        },
        Some("cancel-codes") => state::with_state(&paths, |st| {
            let n = st.codes.len();
            st.codes.clear();
            println!("cancelled {n} pairing code(s)");
            Ok(())
        }),
        Some("status") => status(&paths),
        Some("version" | "--version") => {
            println!("sideroute-server {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => return usage(),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn init(paths: &Paths, args: &[String]) -> Result<(), String> {
    let existing = Config::load(paths).ok();
    let had_peers = state::with_state(paths, |st| Ok(!st.peers.is_empty()))?;
    let mut c = existing.clone().unwrap_or_default();

    if let Some(v) = flag(args, "--interface") {
        c.interface = v;
    }
    if let Some(v) = flag(args, "--port") {
        c.listen_port = v.parse().map_err(|_| "--port: not a port number")?;
    }
    if let Some(v) = flag(args, "--pair-port") {
        c.pair_port = v.parse().map_err(|_| "--pair-port: not a port number")?;
    }
    if let Some(v) = flag(args, "--dns") {
        c.dns = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    }
    if let Some(v) = flag(args, "--mtu") {
        c.mtu = v.parse().map_err(|_| "--mtu: not a number")?;
    }
    if let Some(v) = flag(args, "--endpoint") {
        c.endpoint_host = v;
    }
    if c.endpoint_host.is_empty() {
        c.endpoint_host = net::default_source_ip().ok_or("could not detect this server's IP address; pass --endpoint")?;
    }
    match flag(args, "--subnet") {
        Some(v) => {
            if had_peers && existing.as_ref().is_some_and(|e| e.subnet != v) {
                return Err("devices are already paired in the current subnet; revoke them before changing --subnet".into());
            }
            c.subnet = v;
        }
        None if existing.is_none() => c.subnet = net::pick_free_subnet()?,
        None => {}
    }
    c.validate()?;

    // keys: the WireGuard private key and the TLS key never leave this machine
    if !paths.server_key().exists() {
        let key = net::run("wg", &["genkey"])?;
        state::write_private(&paths.server_key(), format!("{key}\n").as_bytes())?;
    }
    c.public_key = net::run_stdin("wg", &["pubkey"], &std::fs::read(paths.server_key()).map_err(|e| e.to_string())?)?;
    if !paths.tls_cert().exists() || !paths.tls_key().exists() {
        let ck = rcgen::generate_simple_self_signed(vec![sideroute_proto::TLS_SERVER_NAME.to_string()])
            .map_err(|e| format!("could not create TLS certificate: {e}"))?;
        state::write_private(&paths.tls_key(), &ck.signing_key.serialize_der())?;
        state::write_file(&paths.tls_cert(), ck.cert.der(), 0o644)?;
    }
    c.save(paths)?;
    let fp = cert_fingerprint(&std::fs::read(paths.tls_cert()).map_err(|e| e.to_string())?);
    println!(
        "configured: interface {} | WireGuard {}:{} | pairing port {} | subnet {}\nTLS fingerprint: {fp}",
        c.interface, c.endpoint_host, c.listen_port, c.pair_port, c.subnet
    );
    Ok(())
}

fn pair(paths: &Paths, args: &[String]) -> Result<(), String> {
    let c = Config::load(paths)?;
    let ttl_min: u64 = flag(args, "--ttl").map(|v| v.parse().map_err(|_| "--ttl: minutes")).transpose()?.unwrap_or(15);
    if !(1..=1440).contains(&ttl_min) {
        return Err("--ttl must be between 1 and 1440 minutes".into());
    }
    let label = flag(args, "--name").map(|n| sideroute_proto::clean_name(&n));
    let secret = new_secret().map_err(|e| e.to_string())?;
    let fingerprint = cert_fingerprint(&std::fs::read(paths.tls_cert()).map_err(|e| format!("TLS certificate: {e}"))?);
    state::with_state(paths, |st| {
        st.codes.retain(|k| k.expires > now());
        st.codes.push(Code { secret_sha256: secret_hash(&secret), expires: now() + ttl_min * 60, label: label.clone() });
        Ok(())
    })?;
    let code = PairingCode { secret, fingerprint, host: c.endpoint_host.clone(), port: c.pair_port }.to_string();

    if !has(args, "--no-qr") {
        if let Ok(qr) = net::run("qrencode", &["-t", "ansiutf8", "-m", "2", &code]) {
            println!("{qr}");
        }
    }
    println!("Pairing code (single use, valid for {ttl_min} minutes):\n\n    {code}\n");
    println!("On the Linux computer, run this and paste the code when asked:\n");
    println!("    curl -fsSL https://raw.githubusercontent.com/{REPO}/main/client/install.sh | bash\n");
    println!("Already installed?  sideroute pair '{code}'");
    Ok(())
}

fn list(paths: &Paths) -> Result<(), String> {
    let c = Config::load(paths)?;
    let st = state::with_state(paths, |st| Ok(st.clone()))?;
    if st.peers.is_empty() {
        println!("no paired devices (create a code with: sideroute-server pair)");
    } else {
        let hs = net::handshakes(&c.interface);
        println!("{:<20} {:<16} {:<9} {:<12} {:<14} public key", "NAME", "ADDRESS", "PLATFORM", "PAIRED", "LAST SEEN");
        for p in &st.peers {
            let seen = hs.get(&p.public_key).filter(|&&t| t > 0).map(|&t| ago(t)).unwrap_or_else(|| "never".into());
            println!("{:<20} {:<16} {:<9} {:<12} {:<14} {}", p.name, p.ip, p.platform, ago(p.created), seen, p.public_key);
        }
    }
    let pending = st.codes.iter().filter(|k| k.expires > now()).count();
    if pending > 0 {
        println!("\n{pending} unused pairing code(s) pending (cancel with: sideroute-server cancel-codes)");
    }
    Ok(())
}

fn revoke(paths: &Paths, who: &str) -> Result<(), String> {
    let c = Config::load(paths)?;
    let removed = state::with_state(paths, |st| {
        let hits: Vec<_> = st.peers.iter().filter(|p| p.name == who || p.ip == who || p.public_key == who).cloned().collect();
        match hits.len() {
            0 => Err(format!("no device matches '{who}' (see: sideroute-server list)")),
            1 => {
                st.peers.retain(|p| p.public_key != hits[0].public_key);
                Ok(hits[0].clone())
            }
            n => Err(format!("{n} devices are named '{who}'; revoke by address or public key instead")),
        }
    })?;
    if net::link_exists(&c.interface) {
        net::run("wg", &["set", &c.interface, "peer", &removed.public_key, "remove"])?;
    }
    println!("revoked {} ({}); it can no longer connect", removed.name, removed.ip);
    Ok(())
}

fn status(paths: &Paths) -> Result<(), String> {
    let c = Config::load(paths)?;
    let st = state::with_state(paths, |st| Ok(st.clone()))?;
    let up = net::link_exists(&c.interface);
    let hs = net::handshakes(&c.interface);
    let active = hs.values().filter(|&&t| t > 0 && now().saturating_sub(t) < 180).count();
    println!("interface:     {} ({})", c.interface, if up { "up" } else { "DOWN" });
    println!("endpoint:      {}:{} (UDP)", c.endpoint_host, c.listen_port);
    println!("pairing:       {}:{} (TCP/HTTPS)", c.endpoint_host, c.pair_port);
    println!("subnet:        {} (server {})", c.subnet, c.server_ip()?);
    println!("devices:       {} paired, {} connected now", st.peers.len(), active);
    println!("pending codes: {}", st.codes.iter().filter(|k| k.expires > now()).count());
    Ok(())
}
