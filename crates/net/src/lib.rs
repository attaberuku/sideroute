//! Client-side network calls shared by the Linux and Windows clients: pairing with an own server
//! (pinned self-signed certificate) and registering with Cloudflare WARP (public CA).

use std::io::BufReader;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use sideroute_proto::{
    ErrorResponse, PAIR_PATH, PairRequest, PairResponse, PairingCode, cert_fingerprint, read_http, warp, write_http,
};
use base64::Engine;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

/// A new WireGuard key pair as base64 (private, public), for platforms without `wg genkey`.
pub fn generate_keypair() -> Result<(String, String), String> {
    let mut raw = [0u8; 32];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut raw)
        .map_err(|_| "no secure random source".to_string())?;
    let secret = x25519_dalek::StaticSecret::from(raw);
    let public = x25519_dalek::PublicKey::from(&secret);
    let b64 = base64::engine::general_purpose::STANDARD;
    Ok((b64.encode(secret.to_bytes()), b64.encode(public.as_bytes())))
}

/// Public key (base64) for a base64 private key.
pub fn public_key(private_b64: &str) -> Result<String, String> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let raw: [u8; 32] = b64
        .decode(private_b64.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("invalid private key")?;
    let secret = x25519_dalek::StaticSecret::from(raw);
    Ok(b64.encode(x25519_dalek::PublicKey::from(&secret).as_bytes()))
}

/// Pins the server certificate by fingerprint; signatures are still verified normally.
#[derive(Debug)]
struct Pinned {
    fingerprint: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if cert_fingerprint(end_entity) == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate does not match the pairing code (wrong server, or someone is intercepting)".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// One HTTPS request with a JSON body over HTTP/1.1; returns (status, body).
fn https(
    tls: ClientConfig,
    host: &str,
    port: u16,
    request_line: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(u16, Vec<u8>), String> {
    let addrs: Vec<_> = (host, port).to_socket_addrs().map_err(|e| format!("cannot resolve {host}: {e}"))?.collect();
    let mut last = format!("{host} has no address");
    let stream = addrs
        .iter()
        .find_map(|a| match TcpStream::connect_timeout(a, Duration::from_secs(10)) {
            Ok(s) => Some(s),
            Err(e) => {
                last = format!("cannot reach {a}: {e}");
                None
            }
        })
        .ok_or(last)?;
    stream.set_read_timeout(Some(Duration::from_secs(20))).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(Duration::from_secs(20))).map_err(|e| e.to_string())?;
    let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let conn = ClientConnection::new(Arc::new(tls), name).map_err(|e| e.to_string())?;
    let mut s = StreamOwned::new(conn, stream);
    let host_header = if port == 443 { host.to_string() } else { format!("{host}:{port}") };
    let mut all = vec![("Host", host_header.as_str())];
    all.extend_from_slice(headers);
    write_http(&mut s, request_line, &all, body).map_err(|e| e.to_string())?;
    let resp = read_http(&mut BufReader::new(s), 256 * 1024).map_err(|e| e.to_string())?;
    let status = resp.start.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    Ok((status, resp.body))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Sends the pairing request to the server named in `code`.
pub fn request_pairing(code: &PairingCode, public_key: &str, name: &str, platform: &str) -> Result<PairResponse, String> {
    let verifier = Pinned { fingerprint: code.fingerprint.clone(), provider: provider() };
    let tls = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let body = serde_json::to_vec(&PairRequest {
        secret: code.secret.clone(),
        public_key: public_key.to_string(),
        name: name.to_string(),
        platform: platform.into(),
    })
    .map_err(|e| e.to_string())?;
    // the certificate is pinned by fingerprint, so the name in it is not checked
    let (status, resp) = https(tls, &code.host, code.port, &format!("POST {PAIR_PATH} HTTP/1.1"), &[], &body)
        .map_err(|e| format!("pairing service at {}:{}: {e} (is TCP port {} open on the server firewall?)", code.host, code.port, code.port))?;
    if status == 200 {
        serde_json::from_slice(&resp).map_err(|e| format!("unexpected server response: {e}"))
    } else {
        let msg = serde_json::from_slice::<ErrorResponse>(&resp).map(|e| e.error).unwrap_or_default();
        Err(format!("server refused pairing ({status}): {msg}"))
    }
}

fn webpki_tls() -> Result<ClientConfig, String> {
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    Ok(ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Registers a new Cloudflare WARP device for `public_key`.
pub fn warp_register(public_key: &str) -> Result<(PairResponse, warp::Account), String> {
    let body = warp::register_body(public_key, &warp::timestamp(now_secs()));
    let mut h = warp::headers().to_vec();
    h.push(("Content-Type", "application/json; charset=UTF-8"));
    let (status, resp) = https(webpki_tls()?, warp::API_HOST, 443, &format!("POST {} HTTP/1.1", warp::register_path()), &h, &body)
        .map_err(|e| format!("Cloudflare WARP: {e}"))?;
    if status != 200 {
        return Err(format!("Cloudflare WARP refused the registration ({status}): {}", String::from_utf8_lossy(&resp).chars().take(200).collect::<String>()));
    }
    warp::parse_registration(&resp)
}

/// Deletes a WARP registration (best effort when unpairing).
pub fn warp_delete(account: &warp::Account) -> Result<(), String> {
    let auth = format!("Bearer {}", account.token);
    let mut h = warp::headers().to_vec();
    h.push(("Authorization", &auth));
    let (status, _) = https(webpki_tls()?, warp::API_HOST, 443, &format!("DELETE {} HTTP/1.1", warp::device_path(&account.id)), &h, b"")?;
    if (200..300).contains(&status) { Ok(()) } else { Err(format!("Cloudflare WARP answered {status}")) }
}

#[cfg(test)]
mod tests {
    #[test]
    fn keypair_matches_wireguard() {
        // RFC 7748 test vector (Alice), base64 as `wg pubkey` prints it
        let private = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";
        assert_eq!(super::public_key(private).unwrap(), "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=");
        let (k, p) = super::generate_keypair().unwrap();
        assert_eq!(super::public_key(&k).unwrap(), p);
        assert!(sideroute_proto::is_wg_key(&p));
    }
}
