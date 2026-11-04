//! sideroute-helper: the root part of the Linux client.
//!
//! Installed as `/usr/local/bin/sideroute-helper`. The installer lets the user run `up`, `down`,
//! `status` and `kill-sockets` through sudo without a password; `pair` and `unpair` still ask for one.
//!
//! ```text
//! up            bring up the tunnel, routing and nftables rules for every user's tunnel slice
//! down          remove rules, routes and the interface
//! status        tunnel state (handshake, traffic)
//! kill-sockets PID...   close the internet connections of these processes so they reconnect
//! pair [CODE]   pair with a server (code from stdin if omitted); the code `warp` registers a
//!               free Cloudflare WARP device instead, no server needed
//! unpair        forget the server
//! ```
//!
//! Tunneled apps live in `user.slice/user-UID.slice/user@UID.service/app.slice/app-sideroute.slice`.
//! nftables marks every socket of that cgroup (`socket cgroupv2`), the mark selects a routing table
//! whose default route is the WireGuard interface, and an `unreachable` fallback route makes the
//! traffic fail instead of leaking when the tunnel is gone.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::{env, fs};

use sideroute_client::{HELPER, IFACE, MARK, RULE_PRIORITY, TABLE, request_pairing, warp_delete, warp_register};
use sideroute_proto::{PairResponse, PairingCode, is_wg_key, warp};

const NFT_TABLE: &str = "sideroute";

fn command(prog: &str, args: &[&str]) -> Command {
    let mut c = Command::new(prog);
    // sudo already sanitizes the environment; be explicit anyway (and keep output parseable)
    c.args(args).env("LC_ALL", "C").env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    c
}

fn run(prog: &str, args: &[&str]) -> Result<String, String> {
    let out = command(prog, args).stdin(Stdio::null()).output().map_err(|e| format!("{prog}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(format!("{prog} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

fn run_stdin(prog: &str, args: &[&str], input: &[u8]) -> Result<String, String> {
    let mut ch = command(prog, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{prog}: {e}"))?;
    ch.stdin.take().ok_or("stdin")?.write_all(input).map_err(|e| e.to_string())?;
    let out = ch.wait_with_output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(format!("{prog}: {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}

/// Whether the tunnel interface exists (asked via netlink: sysfs may belong to another namespace).
fn link_exists() -> bool {
    run("ip", &["link", "show", "dev", IFACE]).is_ok()
}

fn sysctl(key: &str, value: &str) -> Result<(), String> {
    fs::write(format!("/proc/sys/{key}"), value).map_err(|e| format!("sysctl {key}: {e}"))
}

/// The calling user when run through sudo.
fn sudo_uid() -> Option<u32> {
    env::var("SUDO_UID").ok()?.parse().ok()
}

fn config_dir() -> PathBuf {
    // test override; ignored when invoked through sudo
    match (sudo_uid(), env::var("SIDEROUTE_CONFIG_DIR")) {
        (None, Ok(d)) => PathBuf::from(d),
        _ => PathBuf::from("/etc/sideroute"),
    }
}

fn config_path() -> PathBuf {
    config_dir().join("client.json")
}

fn key_path() -> PathBuf {
    config_dir().join("private.key")
}

/// Present when the tunnel goes to Cloudflare WARP instead of an own server.
fn warp_path() -> PathBuf {
    config_dir().join("warp.json")
}

/// Checks everything that came from the server before it reaches `wg`, `ip` or nftables.
fn validate(c: &PairResponse) -> Result<(), String> {
    let bad = |what: &str| Err(format!("server sent an invalid {what}"));
    if !is_wg_key(&c.server_public_key) {
        return bad("public key");
    }
    let (host, port) = c.endpoint.rsplit_once(':').ok_or("server sent an invalid endpoint")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() || !host.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | ':')) || port.parse::<u16>().is_err() {
        return bad("endpoint");
    }
    let (a, l) = c.client_address.split_once('/').ok_or("server sent an invalid address")?;
    if a.parse::<Ipv4Addr>().is_err() || !l.parse::<u8>().is_ok_and(|l| l <= 32) {
        return bad("address");
    }
    if c.dns.is_empty() || c.dns.iter().any(|d| d.parse::<Ipv4Addr>().is_err()) {
        return bad("DNS server list");
    }
    if !(576..=1420).contains(&c.mtu) || c.persistent_keepalive > 600 {
        return bad("MTU or keepalive");
    }
    Ok(())
}

fn load() -> Result<PairResponse, String> {
    let raw = fs::read(config_path()).map_err(|_| "not paired with a server yet (run: sideroute pair)".to_string())?;
    let c: PairResponse = serde_json::from_slice(&raw).map_err(|e| format!("{}: {e}", config_path().display()))?;
    validate(&c)?;
    Ok(c)
}

fn write_private(path: &PathBuf, data: &[u8]) -> Result<(), String> {
    let err = |e: std::io::Error| format!("{}: {e}", path.display());
    let dir = path.parent().ok_or("bad path")?;
    fs::create_dir_all(dir).map_err(err)?;
    fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).map_err(err)?;
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).map_err(err)?;
    f.write_all(data).map_err(err)?;
    f.sync_all().map_err(err)?;
    fs::rename(&tmp, path).map_err(err)
}

fn endpoint_v4(c: &PairResponse) -> Result<(Ipv4Addr, u16), String> {
    let (host, port) = c.endpoint.rsplit_once(':').ok_or("bad endpoint")?;
    let port: u16 = port.parse().map_err(|_| "bad endpoint port")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {host}: {e}"))?
        .find_map(|a| match a.ip() {
            IpAddr::V4(v) => Some((v, port)),
            IpAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("{host} has no IPv4 address"))
}

fn valid_cgroup(p: &str) -> bool {
    !p.is_empty()
        && !p.contains("..")
        && p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | ':' | '-' | '/'))
        && fs::metadata(format!("/sys/fs/cgroup/{p}")).is_ok_and(|m| m.is_dir())
}

/// Every user's tunnel slice that currently exists.
fn tunnel_cgroups() -> Vec<String> {
    let mut v = Vec::new();
    let Ok(users) = fs::read_dir("/sys/fs/cgroup/user.slice") else { return v };
    for u in users.flatten() {
        let name = u.file_name().to_string_lossy().to_string();
        let Some(uid) = name.strip_prefix("user-").and_then(|s| s.strip_suffix(".slice")) else { continue };
        let Ok(uid) = uid.parse::<u32>() else { continue };
        let p = sideroute_client::tunnel_cgroup(uid);
        if valid_cgroup(&p) {
            v.push(p);
        }
    }
    v
}

fn nft_ruleset(c: &PairResponse, endpoint: (Ipv4Addr, u16), cgroups: &[String]) -> String {
    let (ep_ip, ep_port) = endpoint;
    let dns = &c.dns[0];
    let mut mark = String::new();
    let mut dnat = String::new();
    let mut v6 = String::new();
    for p in cgroups {
        let lvl = p.split('/').count();
        let m = format!("socket cgroupv2 level {lvl} \"{p}\"");
        // DNS goes through the tunnel even when the system resolver is local or on the LAN
        mark.push_str(&format!("        {m} meta nfproto ipv4 meta l4proto {{ tcp, udp }} th dport 53 meta mark set {MARK:#x}\n"));
        mark.push_str(&format!("        {m} ip daddr != @local4 meta mark set {MARK:#x}\n"));
        dnat.push_str(&format!("        {m} meta nfproto ipv4 meta l4proto {{ tcp, udp }} th dport 53 dnat ip to {dns}\n"));
        v6.push_str(&format!("        {m} meta nfproto ipv6 ip6 daddr != {{ ::1, fe80::/10, fc00::/7 }} reject\n"));
    }
    format!(
        r#"table inet {NFT_TABLE} {{}}
delete table inet {NFT_TABLE}
table inet {NFT_TABLE} {{
    set local4 {{
        type ipv4_addr; flags interval
        elements = {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255 }}
    }}
    chain mark_output {{
        type route hook output priority mangle; policy accept;
        # WireGuard keeps the app's socket on the encrypted packet; never mark the tunnel's own
        # traffic to the server or it would be routed back into the tunnel (loop).
        ip daddr {ep_ip} udp dport {ep_port} return
{mark}    }}
    chain dns_redirect {{
        type nat hook output priority dstnat; policy accept;
{dnat}    }}
    chain block_ipv6 {{
        type filter hook output priority filter; policy accept;
        # the tunnel is IPv4 only; refuse IPv6 so apps fall back to IPv4 instead of leaking
{v6}    }}
    chain nat_tunnel {{
        type nat hook postrouting priority srcnat; policy accept;
        oifname "{IFACE}" masquerade
    }}
    chain clamp_mss {{
        type filter hook postrouting priority mangle; policy accept;
        oifname "{IFACE}" tcp flags & (syn | rst) == syn tcp option maxseg size set rt mtu
    }}
}}
"#
    )
}

fn setup_interface(c: &PairResponse, endpoint: (Ipv4Addr, u16)) -> Result<(), String> {
    if !link_exists() {
        run("ip", &["link", "add", IFACE, "type", "wireguard"]).map_err(|e| format!("{e}\nis the wireguard kernel module available?"))?;
    }
    let ep = format!("{}:{}", endpoint.0, endpoint.1);
    let key = key_path();
    for k in run("wg", &["show", IFACE, "peers"])?.lines().filter(|k| *k != c.server_public_key) {
        run("wg", &["set", IFACE, "peer", k, "remove"])?;
    }
    run(
        "wg",
        &[
            "set", IFACE, "private-key", &key.to_string_lossy(), "peer", &c.server_public_key, "endpoint", &ep,
            "allowed-ips", &c.allowed_ips.join(","), "persistent-keepalive", &c.persistent_keepalive.to_string(),
        ],
    )?;
    run("ip", &["address", "replace", &c.client_address, "dev", IFACE])?;
    run("ip", &["link", "set", IFACE, "mtu", &c.mtu.to_string(), "up"])?;
    let table = TABLE.to_string();
    run("ip", &["route", "replace", "default", "dev", IFACE, "table", &table])?;
    // kill switch: when the interface is gone, marked traffic fails instead of using the normal route
    run("ip", &["route", "replace", "unreachable", "default", "metric", "4000", "table", &table])?;
    let rule = format!("fwmark {MARK:#x} lookup {TABLE}");
    if !run("ip", &["-4", "rule", "show"])?.contains(&rule) {
        run("ip", &["-4", "rule", "add", "fwmark", &format!("{MARK:#x}"), "lookup", &table, "priority", &RULE_PRIORITY.to_string()])?;
    }
    sysctl("net/ipv4/conf/all/src_valid_mark", "1")?;
    sysctl(&format!("net/ipv4/conf/{IFACE}/rp_filter"), "2")?;
    // DNS to 127.0.0.53 is redirected into the tunnel; packets with a 127.0.0.1 source may only
    // leave through an interface that allows it (enabled on the tunnel interface only)
    sysctl(&format!("net/ipv4/conf/{IFACE}/route_localnet"), "1")?;
    if fs::read_to_string("/proc/sys/net/ipv4/conf/all/rp_filter").is_ok_and(|v| v.trim() == "1") {
        sysctl("net/ipv4/conf/all/rp_filter", "2")?;
    }
    Ok(())
}

fn up(extra_cgroup: Option<String>) -> Result<(), String> {
    let c = load()?;
    if !key_path().exists() {
        return Err("private key missing; pair again (sideroute pair)".into());
    }
    let endpoint = endpoint_v4(&c)?;
    setup_interface(&c, endpoint)?;
    let mut cgroups = tunnel_cgroups();
    if let Some(p) = extra_cgroup {
        let p = p.trim_start_matches('/').to_string();
        if !valid_cgroup(&p) {
            return Err(format!("invalid cgroup: {p}"));
        }
        cgroups.push(p);
    }
    run_stdin("nft", &["-f", "-"], nft_ruleset(&c, endpoint, &cgroups).as_bytes())?;
    println!("up: {IFACE} -> {}:{} ({} tunnel group(s))", endpoint.0, endpoint.1, cgroups.len());
    Ok(())
}

fn down_quiet() {
    let _ = run("nft", &["delete", "table", "inet", NFT_TABLE]);
    let rule = format!("fwmark {MARK:#x} lookup {TABLE}");
    while run("ip", &["-4", "rule", "show"]).is_ok_and(|r| r.contains(&rule)) {
        if run("ip", &["-4", "rule", "del", "fwmark", &format!("{MARK:#x}"), "lookup", &TABLE.to_string()]).is_err() {
            break;
        }
    }
    let _ = run("ip", &["route", "flush", "table", &TABLE.to_string()]);
    if link_exists() {
        let _ = run("ip", &["link", "del", IFACE]);
    }
}

fn down() -> Result<(), String> {
    let _ = run("nft", &["delete", "table", "inet", NFT_TABLE]);
    let rule = format!("fwmark {MARK:#x} lookup {TABLE}");
    while run("ip", &["-4", "rule", "show"]).is_ok_and(|r| r.contains(&rule)) {
        run("ip", &["-4", "rule", "del", "fwmark", &format!("{MARK:#x}"), "lookup", &TABLE.to_string()])?;
    }
    let _ = run("ip", &["route", "flush", "table", &TABLE.to_string()]);
    if link_exists() {
        run("ip", &["link", "del", IFACE])?;
    }
    println!("down");
    Ok(())
}

fn status() -> Result<(), String> {
    let Ok(c) = load() else {
        println!("paired: no");
        return Ok(());
    };
    let provider = if warp_path().exists() { "Cloudflare WARP" } else { "server" };
    println!("paired: yes ({provider} {}, address {})", c.endpoint, c.client_address);
    if !link_exists() {
        println!("tunnel: down");
        return Ok(());
    }
    let hs: u64 = run("wg", &["show", IFACE, "latest-handshakes"])?
        .split_whitespace()
        .nth(1)
        .and_then(|t| t.parse().ok())
        .unwrap_or(0);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    match hs {
        0 => println!("tunnel: up, no handshake yet (server unreachable?)"),
        t if now.saturating_sub(t) > 180 => println!("tunnel: up, last handshake {}s ago (server unreachable?)", now - t),
        t => println!("tunnel: connected (handshake {}s ago)", now.saturating_sub(t)),
    }
    let tr: Vec<u64> = run("wg", &["show", IFACE, "transfer"])?.split_whitespace().skip(1).filter_map(|x| x.parse().ok()).collect();
    if let [rx, tx] = tr[..] {
        println!("traffic: {:.1} MiB received, {:.1} MiB sent", rx as f64 / 1048576.0, tx as f64 / 1048576.0);
    }
    Ok(())
}

/// Closes the established, non-local TCP/UDP sockets of these processes so the apps reconnect
/// (and their new connections follow the new routing). Listening and LAN sockets are left alone.
fn kill_sockets(pids: &[String]) -> Result<(), String> {
    let caller = sudo_uid();
    let mut inodes = HashSet::new();
    for p in pids {
        let Ok(pid) = p.parse::<u32>() else { continue };
        let Ok(meta) = fs::metadata(format!("/proc/{pid}")) else { continue };
        if caller.is_some_and(|u| meta.uid() != u) {
            continue; // only the caller's own processes
        }
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
        for fd in fds.flatten() {
            if let Ok(t) = fs::read_link(fd.path()) {
                let t = t.to_string_lossy();
                if let Some(n) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                    inodes.insert(n.to_string());
                }
            }
        }
    }
    if inodes.is_empty() {
        println!("closed 0 connection(s)");
        return Ok(());
    }
    let out = run("ss", &["-Htunae"])?;
    let split = |s: &str| -> Option<(String, String)> {
        let (a, p) = s.rsplit_once(':')?;
        Some((a.trim_matches(['[', ']']).split('%').next()?.to_string(), p.to_string()))
    };
    let mut closed = 0;
    for line in out.lines() {
        let Some(ino) = line.split_whitespace().find_map(|t| t.strip_prefix("ino:")) else { continue };
        if !inodes.contains(ino) {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 || f[5].ends_with(":*") {
            continue; // listening / unconnected
        }
        let (Some((la, lp)), Some((ra, rp))) = (split(f[4]), split(f[5])) else { continue };
        let Ok(ip) = ra.parse::<IpAddr>() else { continue };
        let local = match ip {
            IpAddr::V4(v) => v.is_loopback() || v.is_private() || v.is_link_local() || (v.octets()[0] == 100 && v.octets()[1] & 0xc0 == 64),
            IpAddr::V6(v) => v.is_loopback() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80,
        };
        if local {
            continue;
        }
        let b = |s: &str| if s.contains(':') { format!("[{s}]") } else { s.to_string() };
        let (sp, dp) = (format!(":{lp}"), format!(":{rp}"));
        if run("ss", &["-K", "-tu", "src", &b(&la), "sport", "=", &sp, "dst", &b(&ra), "dport", "=", &dp]).is_ok() {
            closed += 1;
        }
    }
    println!("closed {closed} connection(s)");
    Ok(())
}

fn save_config(c: &PairResponse) -> Result<(), String> {
    let mut j = serde_json::to_vec_pretty(c).map_err(|e| e.to_string())?;
    j.push(b'\n');
    write_private(&config_path(), &j)
}

fn latest_handshake() -> u64 {
    run("wg", &["show", IFACE, "latest-handshakes"])
        .ok()
        .and_then(|o| o.split_whitespace().nth(1).and_then(|t| t.parse().ok()))
        .unwrap_or(0)
}

/// WARP answers on several UDP ports; some networks block 2408. Try them in turn until a
/// handshake succeeds and keep the one that works.
fn probe_warp_ports(c: &mut PairResponse, ports: &[u16]) -> Result<(), String> {
    let was_up = link_exists();
    let (host, _) = c.endpoint.rsplit_once(':').ok_or("bad endpoint")?;
    let host = host.to_string();
    let mut ok = false;
    for &p in ports {
        c.endpoint = format!("{host}:{p}");
        // a fresh interface per port: WireGuard keeps retrying the old endpoint otherwise
        if link_exists() {
            run("ip", &["link", "del", IFACE])?;
        }
        setup_interface(c, endpoint_v4(c)?)?;
        if (0..30).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(200));
            latest_handshake() > 0
        }) {
            println!("WARP reachable on UDP port {p}");
            ok = true;
            break;
        }
    }
    if !ok {
        c.endpoint = format!("{host}:{}", ports[0]);
        eprintln!("warning: no answer from Cloudflare WARP on UDP ports {ports:?}; this network may block it");
    }
    if !was_up {
        down_quiet();
    }
    Ok(())
}

fn pair(code: Option<&String>) -> Result<(), String> {
    let code = match code {
        Some(c) => c.clone(),
        None => {
            let mut s = String::new();
            std::io::stdin().take(4096).read_to_string(&mut s).map_err(|e| e.to_string())?;
            s
        }
    };
    let use_warp = code.trim().eq_ignore_ascii_case("warp");
    let parsed: Option<PairingCode> = if use_warp { None } else { Some(code.parse()?) };
    // keep an existing key: pairing again with the same server keeps the same address
    if !key_path().exists() {
        let k = run("wg", &["genkey"])?;
        write_private(&key_path(), format!("{k}\n").as_bytes())?;
    }
    let public = run_stdin("wg", &["pubkey"], &fs::read(key_path()).map_err(|e| e.to_string())?)?;

    // a previous WARP registration is replaced either way
    let old_warp: Option<warp::Account> = fs::read(warp_path()).ok().and_then(|r| serde_json::from_slice(&r).ok());
    let mut resp = match parsed {
        Some(code) => {
            let name = fs::read_to_string("/proc/sys/kernel/hostname").map(|h| h.trim().to_string()).unwrap_or_default();
            let r = request_pairing(&code, &public, &name)?;
            let _ = fs::remove_file(warp_path());
            r
        }
        None => {
            let (r, account) = warp_register(&public)?;
            let mut j = serde_json::to_vec_pretty(&account).map_err(|e| e.to_string())?;
            j.push(b'\n');
            write_private(&warp_path(), &j)?;
            r
        }
    };
    if let Some(old) = old_warp {
        let _ = warp_delete(&old);
    }
    validate(&resp)?;
    save_config(&resp)?;
    if use_warp && env::var_os("SIDEROUTE_NO_PROBE").is_none_or(|_| sudo_uid().is_some()) {
        let ports: Vec<u16> = fs::read(warp_path())
            .ok()
            .and_then(|r| serde_json::from_slice::<warp::Account>(&r).ok())
            .map(|a| a.ports)
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| vec![2408]);
        if let Err(e) = probe_warp_ports(&mut resp, &ports) {
            eprintln!("warning: could not test the WARP connection: {e}");
        }
        save_config(&resp)?;
    }
    if use_warp {
        println!("using Cloudflare WARP ({}, tunnel address {})", resp.endpoint, resp.client_address);
        println!("WARP is a free Cloudflare service; its terms apply: https://www.cloudflare.com/application/terms/");
    } else {
        println!("paired with {} (tunnel address {})", resp.endpoint, resp.client_address);
    }
    if link_exists() {
        up(None)?;
    }
    Ok(())
}

fn unpair() -> Result<(), String> {
    down()?;
    if let Some(a) = fs::read(warp_path()).ok().and_then(|r| serde_json::from_slice::<warp::Account>(&r).ok()) {
        if let Err(e) = warp_delete(&a) {
            eprintln!("warning: could not delete the WARP registration: {e}");
        }
    }
    for p in [config_path(), key_path(), warp_path()] {
        if p.exists() {
            fs::remove_file(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        }
    }
    println!("unpaired (if you used your own server, also run there: sideroute-server revoke <name>)");
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let euid = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("Uid:")).and_then(|l| l.split_whitespace().nth(1)?.parse::<u32>().ok()));
    if euid != Some(0) {
        eprintln!("sideroute-helper must run as root (sudo {HELPER} ...)");
        return ExitCode::from(1);
    }
    let res = match args.get(1).map(String::as_str) {
        Some("up") => {
            // --cgroup is for tests and manual use by root; never through the sudo rule
            let extra = args.iter().position(|a| a == "--cgroup").and_then(|i| args.get(i + 1)).cloned();
            if extra.is_some() && sudo_uid().is_some() {
                Err("--cgroup is not allowed through sudo".into())
            } else {
                up(extra)
            }
        }
        Some("down") => down(),
        Some("status") => status(),
        Some("kill-sockets") => kill_sockets(&args[2..]),
        Some("pair") => pair(args.get(2)),
        Some("unpair") => unpair(),
        _ => {
            eprintln!("usage: sideroute-helper up | down | status | kill-sockets PID... | pair [CODE|warp] | unpair");
            return ExitCode::from(2);
        }
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PairResponse {
        PairResponse {
            server_public_key: "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=".into(),
            endpoint: "203.0.113.5:51820".into(),
            client_address: "10.77.0.2/32".into(),
            server_address: "10.77.0.1".into(),
            dns: vec!["1.1.1.1".into()],
            allowed_ips: vec!["0.0.0.0/0".into()],
            mtu: 1280,
            persistent_keepalive: 25,
        }
    }

    #[test]
    fn rejects_hostile_server_values() {
        assert!(validate(&sample()).is_ok());
        assert!(validate(&PairResponse { dns: vec!["1.1.1.1; flush ruleset".into()], ..sample() }).is_err());
        assert!(validate(&PairResponse { endpoint: "a b:1".into(), ..sample() }).is_err());
        assert!(validate(&PairResponse { client_address: "10.0.0.2".into(), ..sample() }).is_err());
    }

    #[test]
    fn ruleset_excludes_endpoint_before_marking() {
        let r = nft_ruleset(&sample(), ("203.0.113.5".parse().unwrap(), 51820), &["user.slice/x/app.slice/app-sideroute.slice".into()]);
        let ep = r.find("ip daddr 203.0.113.5 udp dport 51820 return").unwrap();
        let mark = r.find("meta mark set").unwrap();
        assert!(ep < mark);
        assert!(r.contains("level 4 \"user.slice/x/app.slice/app-sideroute.slice\""));
        assert!(r.contains(sideroute_client::SLICE));
    }
}
