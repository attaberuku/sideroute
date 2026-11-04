//! HTTPS pairing service. TLS uses a self-signed certificate whose fingerprint is part of every
//! pairing code, so clients can pin it without any certificate authority.

use std::collections::VecDeque;
use std::io::{BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use sideroute_proto::{
    ErrorResponse, HEALTH_PATH, PAIR_PATH, PairRequest, PairResponse, cert_fingerprint, clean_name, is_wg_key, read_http,
    secret_hash, write_http,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use crate::state::{self, Config, Paths, Peer};
use crate::{net, now};

const MAX_CONNECTIONS: usize = 32;
/// Failed pairing attempts allowed per minute before the service answers 429 to everyone.
const MAX_FAILURES_PER_MINUTE: usize = 30;

struct Ctx {
    paths: Paths,
    tls: Arc<ServerConfig>,
    failures: Mutex<VecDeque<Instant>>,
}

pub fn serve(paths: &Paths, c: Config) -> Result<(), String> {
    let cert = std::fs::read(paths.tls_cert()).map_err(|e| format!("TLS certificate: {e} (run: sideroute-server init)"))?;
    let key = std::fs::read(paths.tls_key()).map_err(|e| format!("TLS key: {e}"))?;
    let fp = cert_fingerprint(&cert);
    let tls = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert)], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))
        .map_err(|e| format!("TLS: {e}"))?;
    let listener = TcpListener::bind(("::", c.pair_port))
        .or_else(|_| TcpListener::bind(("0.0.0.0", c.pair_port)))
        .map_err(|e| format!("listen on TCP {}: {e}", c.pair_port))?;
    eprintln!("pairing service on TCP {} (certificate fingerprint {fp})", c.pair_port);

    let ctx = Arc::new(Ctx { paths: paths.clone(), tls: Arc::new(tls), failures: Mutex::new(VecDeque::new()) });
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            continue; // dropped
        }
        active.fetch_add(1, Ordering::SeqCst);
        let (ctx, active) = (ctx.clone(), active.clone());
        thread::spawn(move || {
            let peer = stream.peer_addr().ok();
            if let Err(e) = handle(&ctx, stream, peer) {
                eprintln!("{}: {e}", peer.map(|p| p.to_string()).unwrap_or_default());
            }
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

fn json<T: serde::Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}

fn error(status: &str, msg: &str) -> (String, Vec<u8>) {
    (status.to_string(), json(&ErrorResponse { error: msg.to_string() }))
}

fn handle(ctx: &Ctx, stream: TcpStream, peer: Option<SocketAddr>) -> Result<(), String> {
    stream.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(Duration::from_secs(10))).map_err(|e| e.to_string())?;
    let conn = ServerConnection::new(ctx.tls.clone()).map_err(|e| e.to_string())?;
    let mut r = BufReader::new(StreamOwned::new(conn, stream));
    let req = read_http(&mut r, 16 * 1024).map_err(|e| e.to_string())?;
    let mut parts = req.start.split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let (status, body) = match (method, path) {
        ("GET", HEALTH_PATH) => ("200 OK".into(), br#"{"ok":true}"#.to_vec()),
        ("POST", PAIR_PATH) => pair(ctx, &req.body, peer),
        _ => error("404 Not Found", "not found"),
    };
    let tls = r.get_mut();
    write_http(tls, &format!("HTTP/1.1 {status}"), &[], &body).map_err(|e| e.to_string())?;
    tls.conn.send_close_notify();
    let _ = tls.flush();
    Ok(())
}

fn too_many_failures(ctx: &Ctx) -> bool {
    let mut f = ctx.failures.lock().unwrap_or_else(|p| p.into_inner());
    while f.front().is_some_and(|t| t.elapsed() > Duration::from_secs(60)) {
        f.pop_front();
    }
    f.len() >= MAX_FAILURES_PER_MINUTE
}

fn pair(ctx: &Ctx, body: &[u8], from: Option<SocketAddr>) -> (String, Vec<u8>) {
    let Ok(req) = serde_json::from_slice::<PairRequest>(body) else {
        return error("400 Bad Request", "malformed request");
    };
    if !is_wg_key(&req.public_key) {
        return error("400 Bad Request", "public_key is not a WireGuard key");
    }
    if too_many_failures(ctx) {
        return error("429 Too Many Requests", "too many failed attempts, try again in a minute");
    }
    let c = match Config::load(&ctx.paths) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return error("500 Internal Server Error", "server is not configured");
        }
    };
    let hash = secret_hash(req.secret.trim().to_uppercase().as_str());
    let res = state::with_state(&ctx.paths, |st| {
        st.codes.retain(|k| k.expires > now());
        let Some(i) = st.codes.iter().position(|k| k.secret_sha256 == hash) else {
            return Ok(None);
        };
        let code = st.codes.remove(i);
        // the same key pairing again (e.g. the installer was re-run) keeps its address
        if let Some(p) = st.peers.iter().find(|p| p.public_key == req.public_key) {
            return Ok(Some(p.clone()));
        }
        let base = code.label.unwrap_or_else(|| clean_name(&req.name));
        let mut name = base.clone();
        let mut n = 2;
        while st.peers.iter().any(|p| p.name == name) {
            name = format!("{base}-{n}");
            n += 1;
        }
        let peer = Peer {
            name,
            public_key: req.public_key.clone(),
            ip: st.free_ip(&c)?.to_string(),
            platform: clean_name(&req.platform),
            created: now(),
        };
        st.peers.push(peer.clone());
        Ok(Some(peer))
    });
    let peer = match res {
        Ok(Some(p)) => p,
        Ok(None) => {
            ctx.failures.lock().unwrap_or_else(|p| p.into_inner()).push_back(Instant::now());
            thread::sleep(Duration::from_secs(1));
            return error("403 Forbidden", "invalid, expired or already used pairing code");
        }
        Err(e) => {
            eprintln!("pairing failed: {e}");
            return error("500 Internal Server Error", &e);
        }
    };
    if let Err(e) = net::add_peer(&c, &peer.public_key, &peer.ip) {
        eprintln!("could not add peer to the interface (it is added on next start): {e}");
    }
    eprintln!(
        "paired {} ({}, {}) from {}",
        peer.name,
        peer.ip,
        peer.platform,
        from.map(|a| a.ip().to_string()).unwrap_or_default()
    );
    let host = if c.endpoint_host.contains(':') { format!("[{}]", c.endpoint_host) } else { c.endpoint_host.clone() };
    let resp = PairResponse {
        server_public_key: c.public_key.clone(),
        endpoint: format!("{host}:{}", c.listen_port),
        client_address: format!("{}/32", peer.ip),
        server_address: c.server_ip().map(|i| i.to_string()).unwrap_or_default(),
        dns: c.dns.clone(),
        allowed_ips: vec!["0.0.0.0/0".into()],
        mtu: c.mtu,
        persistent_keepalive: c.persistent_keepalive,
    };
    ("200 OK".into(), json(&resp))
}
