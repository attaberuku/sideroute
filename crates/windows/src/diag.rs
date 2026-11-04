//! Troubleshooting report: tunnel state, three test requests (directly through the tunnel,
//! through the SOCKS5 server, and without the tunnel), ProxiFyre state and the logs.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use socket2::{Domain, Protocol, Socket, Type};

use crate::wg::Tunnel;
use crate::{log, redirect, socks, state};

const TRACE_HOST: &str = "cloudflare.com";

fn trace_addr() -> Result<SocketAddr, String> {
    (TRACE_HOST, 80)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {TRACE_HOST}: {e}"))?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| format!("{TRACE_HOST} has no IPv4 address"))
}

/// Sends a plain HTTP request for Cloudflare's trace page and keeps the interesting lines.
fn trace(mut s: TcpStream, mask_ip: bool) -> String {
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    let req = format!("GET /cdn-cgi/trace HTTP/1.1\r\nHost: {TRACE_HOST}\r\nConnection: close\r\n\r\n");
    if let Err(e) = s.write_all(req.as_bytes()) {
        return format!("send failed: {e}");
    }
    let mut body = Vec::new();
    if let Err(e) = s.read_to_end(&mut body) {
        if body.is_empty() {
            return format!("no answer: {e}");
        }
    }
    let text = String::from_utf8_lossy(&body);
    let mut keep: Vec<String> = text
        .lines()
        .filter(|l| l.starts_with("ip=") || l.starts_with("colo=") || l.starts_with("warp="))
        .map(|l| match (mask_ip, l.strip_prefix("ip=")) {
            // the user's own address: keep the network, hide the host part
            (true, Some(ip)) => format!("ip={}", ip.split('.').take(2).collect::<Vec<_>>().join(".") + ".x.x"),
            _ => l.to_string(),
        })
        .collect();
    if keep.is_empty() {
        keep.push(format!("unexpected answer: {:?}", text.chars().take(120).collect::<String>()));
    }
    format!("OK  {}", keep.join("  "))
}

fn through_tunnel(address: Ipv4Addr, index: u32) -> String {
    let run = || -> Result<String, String> {
        let target = trace_addr()?;
        let egress: socks::Egress = Arc::new(RwLock::new(Some((address, index))));
        let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).map_err(|e| e.to_string())?;
        socks::pin(&sock, &egress).map_err(|e| format!("cannot bind to the tunnel: {e}"))?;
        sock.connect_timeout(&target.into(), Duration::from_secs(10)).map_err(|e| format!("connect {target}: {e}"))?;
        Ok(trace(sock.into(), false))
    };
    run().unwrap_or_else(|e| format!("FAILED  {e}"))
}

fn through_socks() -> String {
    let run = || -> Result<String, String> {
        let target = trace_addr()?;
        let SocketAddr::V4(t) = target else { return Err("no IPv4".into()) };
        let mut s = TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, state::SOCKS_PORT)), Duration::from_secs(5))
            .map_err(|e| format!("SOCKS5 server not reachable: {e}"))?;
        s.set_read_timeout(Some(Duration::from_secs(20))).map_err(|e| e.to_string())?;
        s.write_all(&[5, 1, 0]).map_err(|e| e.to_string())?;
        let mut r = [0u8; 2];
        s.read_exact(&mut r).map_err(|e| format!("greeting: {e}"))?;
        let mut req = vec![5, 1, 0, 1];
        req.extend_from_slice(&t.ip().octets());
        req.extend_from_slice(&t.port().to_be_bytes());
        s.write_all(&req).map_err(|e| e.to_string())?;
        let mut rep = [0u8; 10];
        s.read_exact(&mut rep).map_err(|e| format!("connect reply: {e}"))?;
        if rep[1] != 0 {
            return Err(format!("SOCKS5 server refused (code {}): {}", rep[1], socks::LAST_ERROR.lock().map(|e| e.clone()).unwrap_or_default()));
        }
        Ok(trace(s, false))
    };
    run().unwrap_or_else(|e| format!("FAILED  {e}"))
}

fn direct() -> String {
    let run = || -> Result<String, String> {
        let target = trace_addr()?;
        let s = TcpStream::connect_timeout(&target, Duration::from_secs(10)).map_err(|e| format!("connect {target}: {e}"))?;
        Ok(trace(s, true))
    };
    run().unwrap_or_else(|e| format!("FAILED  {e}"))
}

fn newest_file(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .max_by_key(|e| e.metadata().and_then(|m| m.modified()).unwrap_or(SystemTime::UNIX_EPOCH))
        .map(|e| e.path())
}

/// Lists the processes of every tunneled program and checks each of their open internet TCP
/// connections against the ones going through the SOCKS5 server.
fn bypass_check() -> String {
    let open = socks::OPEN.lock().map(|m| m.clone().unwrap_or_default()).unwrap_or_default();
    let mut out = String::new();
    for app in state::apps() {
        let main = crate::procs::pids_of(&app);
        let kids = crate::procs::descendants(&app);
        let mut pids: std::collections::HashSet<u32> = main.clone();
        pids.extend(kids.iter().map(|k| k.0));
        let mut names: Vec<String> = kids.iter().map(|k| k.1.clone()).collect();
        names.sort();
        names.dedup();
        let _ = writeln!(out, "{app}: {} process(es); started by it: {}", main.len(), if names.is_empty() { "-".into() } else { names.join(", ") });
        let conns = crate::procs::tcp_connections(&pids);
        let direct: Vec<_> = conns.iter().filter(|(_, a)| !open.contains_key(a)).collect();
        let _ = writeln!(out, "  {} internet TCP connection(s), {} through the tunnel, {} DIRECT", conns.len(), conns.len() - direct.len(), direct.len());
        for (pid, a) in direct.iter().take(15) {
            let name = crate::procs::all_processes().into_iter().find(|p| p.0 == *pid).map(|p| p.2).unwrap_or_default();
            let _ = writeln!(out, "    DIRECT  {a}  ({name}, pid {pid})");
        }
    }
    out
}

/// Builds the report. `in_tray`: counters of the running SOCKS5 server are only known there.
pub fn report(in_tray: bool) -> String {
    let mut r = String::new();
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let _ = writeln!(r, "Sideroute {} troubleshooting report, {}", env!("CARGO_PKG_VERSION"), sideroute_proto::warp::timestamp(now));
    let _ = writeln!(r, "Windows {} {}", std::env::var("PROCESSOR_ARCHITECTURE").unwrap_or_default(), std::env::var("OS").unwrap_or_default());
    let _ = writeln!(r);

    let cfg = state::load_config();
    match &cfg {
        Ok(c) => {
            let via = if state::load_warp().is_some() { "Cloudflare WARP" } else { "own server" };
            let _ = writeln!(r, "paired:       {via}, endpoint {}, address {}, mtu {}", c.endpoint, c.client_address, c.mtu);
        }
        Err(e) => {
            let _ = writeln!(r, "paired:       no ({e})");
        }
    }
    let _ = writeln!(r, "programs:     {}", state::apps().join(", "));
    let dpi = crate::procs::dpi_tools();
    if !dpi.is_empty() {
        let _ = writeln!(r, "WARNING:      {} is running; it rewrites TCP traffic and breaks the tunnel", dpi.join(", "));
    }
    if in_tray {
        let _ = writeln!(
            r,
            "socks5:       {} connections ok, {} failed; last error: {}",
            socks::CONNECTED.load(Ordering::Relaxed),
            socks::FAILED.load(Ordering::Relaxed),
            socks::LAST_ERROR.lock().map(|e| e.clone()).unwrap_or_default()
        );
        let mb = |n: u64| n as f64 / 1e6;
        let _ = writeln!(
            r,
            "traffic:      tcp {} open, {:.1} MB received, {:.1} MB sent; udp {} sessions, {} datagrams out, {} in",
            socks::TCP_OPEN.load(Ordering::Relaxed),
            mb(socks::TCP_DOWN.load(Ordering::Relaxed)),
            mb(socks::TCP_UP.load(Ordering::Relaxed)),
            socks::UDP_ASSOCIATIONS.load(Ordering::Relaxed),
            socks::UDP_OUT.load(Ordering::Relaxed),
            socks::UDP_IN.load(Ordering::Relaxed)
        );
    }

    if let Ok(c) = &cfg {
        match Tunnel::open_existing(c) {
            Ok(t) => {
                let st = t.stats();
                let hs = match st.last_handshake {
                    Some(h) => format!("{}s ago", SystemTime::now().duration_since(h).map(|d| d.as_secs()).unwrap_or(0)),
                    None => "NEVER (the server/WARP does not answer)".into(),
                };
                let _ = writeln!(r, "tunnel:       adapter index {}, handshake {hs}, received {} B, sent {} B", t.index, st.rx, st.tx);
                if let Some((mtu, metric)) = t.mtu_metric() {
                    let _ = writeln!(r, "adapter:      mtu {mtu}, metric {metric}");
                }
                let _ = writeln!(r, "test 1 (tunnel, no ProxiFyre):  {}", through_tunnel(t.address, t.index));
            }
            Err(e) => {
                let _ = writeln!(r, "tunnel:       {e}");
            }
        }
    }
    let _ = writeln!(r, "test 2 (via SOCKS5 server):     {}", through_socks());
    let _ = writeln!(r, "test 3 (direct, no tunnel):     {}", direct());
    let _ = writeln!(r);

    let pf = redirect::install_dir();
    let _ = writeln!(r, "ProxiFyre:    {} ({})", redirect::state_name(), pf.display());
    if let Ok(cfgtext) = std::fs::read_to_string(pf.join("app-config.json")) {
        let _ = writeln!(r, "app-config.json:\n{cfgtext}");
    }
    if let Some(f) = newest_file(&pf.join("logs")) {
        let _ = writeln!(r, "--- ProxiFyre log ({}) ---\n{}", f.display(), log::tail(&f, 30));
    }
    if in_tray {
        let _ = writeln!(r, "--- bypass check (programs in the tunnel) ---\n{}", bypass_check());
        let recent = socks::RECENT.lock().map(|r| r.iter().cloned().collect::<Vec<_>>().join("\n")).unwrap_or_default();
        let _ = writeln!(r, "--- last finished connections ---\n{recent}");
    }
    let _ = writeln!(r, "--- Sideroute log ---\n{}", log::tail(&log::path(), 40));
    r
}
