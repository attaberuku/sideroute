//! Pairing protocol shared by the sideroute server and its clients.
//!
//! A pairing code looks like `sr1:SECRET:FINGERPRINT@HOST:PORT`:
//!
//! * `SECRET`      one-time secret (base32, 100 bits) that authorizes exactly one device,
//! * `FINGERPRINT` first 130 bits (base32) of the SHA-256 of the server's self-signed TLS
//!   certificate; the client refuses to talk to any other certificate,
//! * `HOST:PORT`   where the pairing service listens (HTTPS).
//!
//! The client generates its WireGuard key pair locally and only sends the public key.
//! See `docs/PROTOCOL.md` for the full description.

use std::fmt;
use std::io::{self, BufRead, Read, Write};

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CODE_PREFIX: &str = "sr1";
pub const DEFAULT_WG_PORT: u16 = 51820;
pub const DEFAULT_PAIR_PORT: u16 = 51821;
/// TLS server name used by both sides; the certificate is pinned, so the name is not checked.
pub const TLS_SERVER_NAME: &str = "sideroute";
pub const PAIR_PATH: &str = "/v1/pair";
pub const HEALTH_PATH: &str = "/v1/health";

const SECRET_LEN: usize = 20; // 20 base32 chars = 100 bits
const FINGERPRINT_LEN: usize = 26; // 26 base32 chars = 130 bits
const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding.
pub fn base32(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Fingerprint of a DER certificate as it appears in pairing codes.
pub fn cert_fingerprint(der: &[u8]) -> String {
    base32(&Sha256::digest(der))[..FINGERPRINT_LEN].to_string()
}

/// Hex SHA-256 of a pairing secret; the server only stores this.
pub fn secret_hash(secret: &str) -> String {
    Sha256::digest(secret.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// A fresh random pairing secret (server side, Unix only).
pub fn new_secret() -> io::Result<String> {
    let mut raw = [0u8; 13];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut raw)?;
    Ok(base32(&raw)[..SECRET_LEN].to_string())
}

/// True if `s` is a base64 WireGuard key (32 bytes).
pub fn is_wg_key(s: &str) -> bool {
    s.len() == 44
        && base64::engine::general_purpose::STANDARD
            .decode(s)
            .map(|k| k.len() == 32)
            .unwrap_or(false)
}

/// Strips everything that is not part of a name: used for device labels coming from clients.
pub fn clean_name(s: &str) -> String {
    let n: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(32)
        .collect();
    if n.is_empty() { "device".into() } else { n }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingCode {
    pub secret: String,
    pub fingerprint: String,
    pub host: String,
    pub port: u16,
}

impl fmt::Display for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        write!(f, "{CODE_PREFIX}:{}:{}@{host}:{}", self.secret, self.fingerprint, self.port)
    }
}

impl std::str::FromStr for PairingCode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        let bad = || "this does not look like an sideroute pairing code (sr1:...@host:port)".to_string();
        let rest = s
            .strip_prefix(CODE_PREFIX)
            .or_else(|| s.strip_prefix(&CODE_PREFIX.to_uppercase()))
            .and_then(|r| r.strip_prefix(':'))
            .ok_or_else(bad)?;
        let (keys, addr) = rest.rsplit_once('@').ok_or_else(bad)?;
        let (secret, fp) = keys.split_once(':').ok_or_else(bad)?;
        let norm = |x: &str| x.chars().filter(|&c| c != '-').collect::<String>().to_uppercase();
        let (secret, fingerprint) = (norm(secret), norm(fp));
        let b32 = |x: &str| x.bytes().all(|c| B32.contains(&c));
        if secret.len() != SECRET_LEN || !b32(&secret) {
            return Err("the secret part of the pairing code is damaged (check for typos)".into());
        }
        if fingerprint.len() != FINGERPRINT_LEN || !b32(&fingerprint) {
            return Err("the fingerprint part of the pairing code is damaged (check for typos)".into());
        }
        let (host, port) = addr.rsplit_once(':').ok_or_else(bad)?;
        let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
        let port = port.parse().map_err(|_| bad())?;
        if host.is_empty() || !host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':')) {
            return Err(bad());
        }
        Ok(PairingCode { secret, fingerprint, host, port })
    }
}

/// `POST /v1/pair` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairRequest {
    pub secret: String,
    /// The client's WireGuard public key (base64). The private key never leaves the device.
    pub public_key: String,
    /// Human-readable device name, shown by `sideroute-server list`.
    pub name: String,
    /// `linux`, `windows`, ... (informational)
    pub platform: String,
}

/// `POST /v1/pair` success response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PairResponse {
    pub server_public_key: String,
    /// WireGuard endpoint as `host:port`.
    pub endpoint: String,
    /// Address for the client's tunnel interface, CIDR (`10.77.0.2/32`).
    pub client_address: String,
    /// Server address inside the tunnel.
    pub server_address: String,
    /// Resolvers the client should use for tunneled apps (reached through the tunnel).
    pub dns: Vec<String>,
    /// Networks routed through the tunnel (`0.0.0.0/0`).
    pub allowed_ips: Vec<String>,
    pub mtu: u16,
    pub persistent_keepalive: u16,
}

/// Error body for non-2xx responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// A minimal HTTP/1.1 message: enough for a JSON API with `Content-Length` bodies.
#[derive(Debug)]
pub struct HttpMessage {
    /// Request line or status line.
    pub start: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpMessage {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// Reads one HTTP message with a body of at most `max_body` bytes.
pub fn read_http<R: BufRead>(r: &mut R, max_body: usize) -> io::Result<HttpMessage> {
    let invalid = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
    let mut lines = Vec::new();
    let mut total = 0;
    loop {
        let mut line = String::new();
        let n = r.by_ref().take(8192).read_line(&mut line)?;
        if n == 0 {
            return Err(invalid("connection closed"));
        }
        total += n;
        if total > 16384 {
            return Err(invalid("headers too large"));
        }
        let line = line.trim_end_matches(['\r', '\n']).to_string();
        if line.is_empty() {
            break;
        }
        lines.push(line);
    }
    let mut it = lines.into_iter();
    let start = it.next().ok_or_else(|| invalid("empty message"))?;
    let headers: Vec<(String, String)> = it
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .collect();
    let mut msg = HttpMessage { start, headers, body: Vec::new() };
    if msg.header("transfer-encoding").is_some_and(|t| t.eq_ignore_ascii_case("chunked")) {
        loop {
            let mut size = String::new();
            r.by_ref().take(64).read_line(&mut size)?;
            let n = usize::from_str_radix(size.trim().split(';').next().unwrap_or(""), 16)
                .map_err(|_| invalid("bad chunk size"))?;
            if msg.body.len() + n > max_body {
                return Err(invalid("body too large"));
            }
            let start = msg.body.len();
            msg.body.resize(start + n, 0);
            r.read_exact(&mut msg.body[start..])?;
            let mut crlf = String::new();
            r.by_ref().take(2).read_line(&mut crlf)?;
            if n == 0 {
                break;
            }
        }
        return Ok(msg);
    }
    let len: usize = match msg.header("content-length") {
        Some(v) => v.parse().map_err(|_| invalid("bad content-length"))?,
        None => 0,
    };
    if len > max_body {
        return Err(invalid("body too large"));
    }
    msg.body.resize(len, 0);
    r.read_exact(&mut msg.body)?;
    Ok(msg)
}

/// Writes a complete HTTP message with a JSON body and `Connection: close`.
pub fn write_http<W: Write>(w: &mut W, start: &str, extra_headers: &[(&str, &str)], body: &[u8]) -> io::Result<()> {
    let mut head = format!("{start}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
    for (k, v) in extra_headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    w.write_all(head.as_bytes())?;
    w.write_all(body)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_matches_rfc4648() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
    }

    #[cfg(unix)]
    #[test]
    fn secrets_are_random() {
        let (a, b) = (new_secret().unwrap(), new_secret().unwrap());
        assert_eq!(a.len(), SECRET_LEN);
        assert_ne!(a, b);
    }

    #[test]
    fn code_roundtrip() {
        let c = PairingCode {
            secret: "K7Q2M3XD4TFAJ3PL6WRN".into(),
            fingerprint: cert_fingerprint(b"cert"),
            host: "203.0.113.5".into(),
            port: 51821,
        };
        let s = c.to_string();
        assert_eq!(s.parse::<PairingCode>().unwrap(), c);
        // tolerant to case, dashes and whitespace from copy/paste
        let messy = format!("  {}\n", s.to_lowercase().replacen("sr1:", "SR1:", 1));
        let p: PairingCode = messy.parse().unwrap();
        assert_eq!(p.secret, c.secret);
        let v6 = PairingCode { host: "2001:db8::1".into(), ..c };
        assert_eq!(v6.to_string().parse::<PairingCode>().unwrap(), v6);
    }

    #[test]
    fn code_rejects_garbage() {
        assert!("hello".parse::<PairingCode>().is_err());
        assert!("sr1:SHORT:AAAA@1.2.3.4:1".parse::<PairingCode>().is_err());
        let c = format!("sr1:{}:{}@bad host;rm:1", "A".repeat(20), "A".repeat(26));
        assert!(c.parse::<PairingCode>().is_err());
    }

    #[test]
    fn wg_key_check() {
        assert!(is_wg_key("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="));
        assert!(!is_wg_key("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBm="));
        assert!(!is_wg_key("x; rm -rf /"));
    }

    #[test]
    fn http_roundtrip() {
        let mut buf = Vec::new();
        write_http(&mut buf, "POST /v1/pair HTTP/1.1", &[("Host", "x")], b"{\"a\":1}").unwrap();
        let m = read_http(&mut io::Cursor::new(buf), 1024).unwrap();
        assert_eq!(m.start, "POST /v1/pair HTTP/1.1");
        assert_eq!(m.header("host"), Some("x"));
        assert_eq!(m.body, b"{\"a\":1}");
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        assert_eq!(read_http(&mut io::Cursor::new(&chunked[..]), 1024).unwrap().body, b"abcde");
    }
}

/// Cloudflare WARP as a tunnel provider (no own server needed).
///
/// This speaks the same device-registration API the official WARP apps use (as `wgcf` does):
/// the client sends its WireGuard public key, Cloudflare answers with its peer and an address.
/// Only the request/response handling lives here; each platform brings its own HTTPS transport.
pub mod warp {
    use serde::{Deserialize, Serialize};
    use serde_json::Value;

    use super::PairResponse;

    pub const API_HOST: &str = "api.cloudflareclient.com";
    pub const API_VERSION: &str = "v0a5641";
    pub const USER_AGENT: &str = "1.1.1.1/6.38.9-5641 (Android 16.0.0)";
    pub const CLIENT_VERSION: &str = "a-6.38.9-5641";
    const DEFAULT_PORT: u16 = 2408;

    pub fn register_path() -> String {
        format!("/{API_VERSION}/reg")
    }

    pub fn device_path(id: &str) -> String {
        format!("/{API_VERSION}/reg/{id}")
    }

    /// Extra headers every API request needs.
    pub fn headers() -> [(&'static str, &'static str); 2] {
        [("User-Agent", USER_AGENT), ("CF-Client-Version", CLIENT_VERSION)]
    }

    /// Body of `POST /reg`. `tos` is the current time, e.g. `2026-11-04T19:10:47.000Z`.
    pub fn register_body(public_key: &str, tos: &str) -> Vec<u8> {
        serde_json::json!({
            "key": public_key,
            "install_id": "",
            "fcm_token": "",
            "tos": tos,
            "model": "PC",
            "serial_number": "",
            "locale": "en_US",
            "os_version": "16.0.0",
            "key_type": "curve25519",
            "tunnel_type": "wireguard",
        })
        .to_string()
        .into_bytes()
    }

    /// What a client keeps to manage (delete) its WARP registration later.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Account {
        pub id: String,
        pub token: String,
        /// Other UDP ports Cloudflare accepts, tried when the first one is blocked.
        #[serde(default)]
        pub ports: Vec<u16>,
    }

    /// Turns the registration response into the same configuration a pairing returns.
    pub fn parse_registration(body: &[u8]) -> Result<(PairResponse, Account), String> {
        let v: Value = serde_json::from_slice(body).map_err(|e| format!("unexpected WARP response: {e}"))?;
        let s = |p: &str| v.pointer(p).and_then(Value::as_str).map(str::to_string);
        let missing = |what: &str| format!("WARP response has no {what}");
        let peer = v.pointer("/config/peers/0").ok_or_else(|| missing("peer"))?;
        let key = peer.pointer("/public_key").and_then(Value::as_str).ok_or_else(|| missing("server key"))?;
        let ports: Vec<u16> = peer
            .pointer("/endpoint/ports")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|p| p.as_u64().and_then(|p| u16::try_from(p).ok())).collect())
            .unwrap_or_default();
        let port = ports.first().copied().unwrap_or(DEFAULT_PORT);
        // prefer the literal IPv4 endpoint: it needs no DNS and the tunnel is IPv4 only
        let host = peer
            .pointer("/endpoint/v4")
            .and_then(Value::as_str)
            .and_then(|e| e.rsplit_once(':').map(|(h, _)| h.to_string()))
            .filter(|h| h.parse::<std::net::Ipv4Addr>().is_ok())
            .or_else(|| {
                peer.pointer("/endpoint/host").and_then(Value::as_str).and_then(|e| e.rsplit_once(':')).map(|(h, _)| h.to_string())
            })
            .ok_or_else(|| missing("endpoint"))?;
        let address = s("/config/interface/addresses/v4").ok_or_else(|| missing("address"))?;
        let account = Account {
            id: s("/id").ok_or_else(|| missing("device id"))?,
            token: s("/token").ok_or_else(|| missing("token"))?,
            ports: ports.clone(),
        };
        let resp = PairResponse {
            server_public_key: key.to_string(),
            endpoint: format!("{host}:{port}"),
            client_address: format!("{address}/32"),
            server_address: String::new(),
            dns: vec!["1.1.1.1".into(), "1.0.0.1".into()],
            allowed_ips: vec!["0.0.0.0/0".into()],
            mtu: 1280,
            persistent_keepalive: 25,
        };
        Ok((resp, account))
    }

    /// Current time in the format the API expects for `tos`.
    pub fn timestamp(unix_secs: u64) -> String {
        let (days, rem) = (unix_secs / 86400, unix_secs % 86400);
        // civil-from-days (Howard Hinnant)
        let z = days as i64 + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + i64::from(m <= 2);
        format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z", rem / 3600, rem % 3600 / 60, rem % 60)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_registration() {
            let body = br#"{"id":"dev","token":"tok","config":{"peers":[{"public_key":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                "endpoint":{"v4":"162.159.192.10:0","v6":"[2606:4700:d0::a29f:c00a]:0","host":"engage.cloudflareclient.com:2408","ports":[2408,500,1701,4500]}}],
                "interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700::1"}}}}"#;
            let (r, a) = parse_registration(body).unwrap();
            assert_eq!(r.endpoint, "162.159.192.10:2408");
            assert_eq!(r.client_address, "172.16.0.2/32");
            assert!(crate::is_wg_key(&r.server_public_key));
            assert_eq!((a.id.as_str(), a.token.as_str()), ("dev", "tok"));
            assert_eq!(a.ports, vec![2408, 500, 1701, 4500]);
            assert!(parse_registration(b"{}").is_err());
        }

        #[test]
        fn timestamps() {
            assert_eq!(timestamp(0), "1970-01-01T00:00:00.000Z");
            assert_eq!(timestamp(1_793_819_447), "2026-11-04T19:10:47.000Z");
        }
    }
}
