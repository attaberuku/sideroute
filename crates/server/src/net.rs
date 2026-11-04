//! WireGuard interface and firewall handling on the server.
//!
//! Firewall rules go through the `iptables` front-end (nft or legacy backend, whichever the system
//! uses) so they live next to Docker's and Tailscale's rules instead of in a separate nftables table
//! that their DROP policies would still override. Every rule carries the comment `sideroute` and is
//! inserted at the top of its chain.

use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};

use crate::state::{Config, Paths, parse_cidr};

const COMMENT: &str = "sideroute";
/// Destinations tunnel clients may not reach through the server: its private networks
/// (Docker bridges, tailnet, cloud metadata service, other tunnel clients).
const PRIVATE: &str = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16";

fn command(prog: &str, args: &[&str]) -> Command {
    let mut c = Command::new(prog);
    c.args(args).env("LC_ALL", "C").env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    c
}

pub fn run(prog: &str, args: &[&str]) -> Result<String, String> {
    let out = command(prog, args).stdin(Stdio::null()).output().map_err(|e| format!("{prog}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(format!("{prog} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

pub fn run_stdin(prog: &str, args: &[&str], input: &[u8]) -> Result<String, String> {
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

pub fn link_exists(iface: &str) -> bool {
    // not /sys/class/net: sysfs shows the network namespace it was mounted in, not ours
    run("ip", &["link", "show", "dev", iface]).is_ok()
}

/// public key -> unix time of the latest handshake (0 = never)
pub fn handshakes(iface: &str) -> HashMap<String, u64> {
    run("wg", &["show", iface, "latest-handshakes"])
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            Some((it.next()?.to_string(), it.next()?.parse().ok()?))
        })
        .collect()
}

pub fn default_source_ip() -> Option<String> {
    let out = run("ip", &["-4", "route", "get", "1.1.1.1"]).ok()?;
    let mut it = out.split_whitespace();
    it.find(|&w| w == "src")?;
    it.next().map(str::to_string)
}

/// First candidate subnet that overlaps nothing already routed or assigned on this host.
pub fn pick_free_subnet() -> Result<String, String> {
    let mut used = Vec::new();
    for out in [run("ip", &["-4", "-o", "addr", "show"]), run("ip", &["-4", "route", "show", "table", "all"])] {
        for w in out.unwrap_or_default().split_whitespace() {
            if w.contains('/') {
                if let Some(c) = parse_cidr(w) {
                    used.push(c);
                }
            }
        }
    }
    let overlaps = |(a, al): (u32, u8), (b, bl): (u32, u8)| {
        let l = al.min(bl);
        let m = if l == 0 { 0 } else { u32::MAX << (32 - l) };
        a & m == b & m
    };
    ["10.77.0.0/24", "10.78.0.0/24", "10.79.0.0/24", "10.177.77.0/24", "172.30.77.0/24", "192.168.177.0/24"]
        .into_iter()
        .find(|cand| {
            let c = parse_cidr(cand).unwrap();
            !used.iter().any(|&u| u.1 > 0 && overlaps(c, u))
        })
        .map(str::to_string)
        .ok_or_else(|| "no free private subnet found; pass --subnet".into())
}

/// (table, chain, rule) in the order they should appear at the top of each chain.
fn rules(c: &Config) -> Result<Vec<(&'static str, &'static str, Vec<String>)>, String> {
    let net = c.network()?;
    let i = c.interface.clone();
    let mss = (c.mtu - 40).to_string();
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    Ok(vec![
        ("filter", "INPUT", s(&["-p", "udp", "--dport", &c.listen_port.to_string(), "-j", "ACCEPT"])),
        ("filter", "INPUT", s(&["-p", "tcp", "--dport", &c.pair_port.to_string(), "-j", "ACCEPT"])),
        ("filter", "FORWARD", s(&["-i", &i, "-d", PRIVATE, "-j", "REJECT"])),
        ("filter", "FORWARD", s(&["-i", &i, "-j", "ACCEPT"])),
        ("filter", "FORWARD", s(&["-o", &i, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])),
        ("nat", "POSTROUTING", s(&["-s", &net, "!", "-o", &i, "-j", "MASQUERADE"])),
        ("mangle", "FORWARD", s(&["-i", &i, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", &mss])),
        ("mangle", "FORWARD", s(&["-o", &i, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", &mss])),
    ])
}

fn iptables(table: &str, op: &str, chain: &str, pos: Option<usize>, rule: &[String]) -> Result<String, String> {
    let mut a: Vec<String> = vec!["-w".into(), "-t".into(), table.into(), op.into(), chain.into()];
    if let Some(p) = pos {
        a.push(p.to_string());
    }
    a.extend(rule.iter().cloned());
    a.extend(["-m", "comment", "--comment", COMMENT].map(String::from));
    run("iptables", &a.iter().map(String::as_str).collect::<Vec<_>>())
}

fn remove_rules(c: &Config) -> Result<(), String> {
    for (t, ch, r) in rules(c)? {
        // a rule may have been added more than once (e.g. by an older run); remove all copies
        while iptables(t, "-C", ch, None, &r).is_ok() {
            iptables(t, "-D", ch, None, &r)?;
        }
    }
    Ok(())
}

fn add_rules(c: &Config) -> Result<(), String> {
    remove_rules(c)?;
    let mut pos: HashMap<(&str, &str), usize> = HashMap::new();
    for (t, ch, r) in rules(c)? {
        let p = pos.entry((t, ch)).or_insert(0);
        *p += 1;
        iptables(t, "-I", ch, Some(*p), &r)?;
    }
    Ok(())
}

pub fn up(paths: &Paths, c: &Config) -> Result<(), String> {
    c.validate()?;
    let i = c.interface.as_str();
    if !link_exists(i) {
        run("ip", &["link", "add", i, "type", "wireguard"]).map_err(|e| {
            format!("{e}\nthe kernel has no WireGuard support (OpenVZ/LXC containers usually do not); use a KVM VPS")
        })?;
    }
    let key = paths.server_key();
    run("wg", &["set", i, "listen-port", &c.listen_port.to_string(), "private-key", &key.to_string_lossy()])?;
    let (_, len) = c.prefix()?;
    run("ip", &["address", "replace", &format!("{}/{len}", c.server_ip()?), "dev", i])?;
    run("ip", &["link", "set", i, "mtu", &c.mtu.to_string(), "up"])?;

    // peers: exactly the paired devices
    let st = crate::state::with_state(paths, |st| Ok(st.clone()))?;
    let current = run("wg", &["show", i, "peers"])?;
    for k in current.lines().filter(|k| !st.peers.iter().any(|p| &p.public_key == k)) {
        run("wg", &["set", i, "peer", k, "remove"])?;
    }
    for p in &st.peers {
        run("wg", &["set", i, "peer", &p.public_key, "allowed-ips", &format!("{}/32", p.ip)])?;
    }

    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").map_err(|e| format!("enable IP forwarding: {e}"))?;
    add_rules(c)?;
    println!("{i} up: {} peer(s), listening on UDP {}", st.peers.len(), c.listen_port);
    Ok(())
}

pub fn down(c: &Config) -> Result<(), String> {
    remove_rules(c)?;
    if link_exists(&c.interface) {
        run("ip", &["link", "del", &c.interface])?;
    }
    println!("{} down", c.interface);
    Ok(())
}

/// Adds one peer to the running interface (no-op if the interface is down; `up` adds it later).
pub fn add_peer(c: &Config, key: &str, ip: &str) -> Result<(), String> {
    if link_exists(&c.interface) {
        run("wg", &["set", &c.interface, "peer", key, "allowed-ips", &format!("{ip}/32")])?;
    }
    Ok(())
}
