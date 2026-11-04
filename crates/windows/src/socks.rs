//! SOCKS5 server on 127.0.0.1 (TCP CONNECT and UDP ASSOCIATE, IPv4) whose outgoing sockets are
//! pinned to the tunnel adapter. ProxiFyre sends the selected programs' traffic here.
//!
//! When the tunnel is not up, requests wait for it a few seconds (it may just be starting) and are
//! then refused, so tunneled programs go offline instead of leaking (kill switch).

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::windows::io::AsRawSocket;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};
use windows_sys::Win32::Networking::WinSock::{IP_UNICAST_IF, IPPROTO_IP, setsockopt};

/// Where outgoing connections must leave: the tunnel's address and interface index.
pub type Egress = Arc<RwLock<Option<(Ipv4Addr, u32)>>>;

/// Counters for the status menu and the troubleshooting report.
pub static CONNECTED: AtomicU64 = AtomicU64::new(0);
pub static FAILED: AtomicU64 = AtomicU64::new(0);
pub static LAST_ERROR: Mutex<String> = Mutex::new(String::new());
pub static TCP_UP: AtomicU64 = AtomicU64::new(0);
pub static TCP_DOWN: AtomicU64 = AtomicU64::new(0);
pub static TCP_OPEN: AtomicU64 = AtomicU64::new(0);
pub static UDP_ASSOCIATIONS: AtomicU64 = AtomicU64::new(0);
pub static UDP_OUT: AtomicU64 = AtomicU64::new(0);
pub static UDP_IN: AtomicU64 = AtomicU64::new(0);
/// The last finished connections, newest last: "tcp 1.2.3.4:443 sent 1.2 kB, got 30 kB in 4 s".
pub static RECENT: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

/// Destinations with an open connection through the tunnel (for the bypass check in the report).
pub static OPEN: Mutex<Option<HashMap<SocketAddrV4, u32>>> = Mutex::new(None);

fn open_target(t: SocketAddrV4, delta: i32) {
    let mut m = OPEN.lock().unwrap_or_else(|p| p.into_inner());
    let m = m.get_or_insert_with(HashMap::new);
    let c = m.entry(t).or_insert(0);
    *c = c.saturating_add_signed(delta);
    if *c == 0 {
        m.remove(&t);
    }
}

fn recent(line: String) {
    let mut r = RECENT.lock().unwrap_or_else(|p| p.into_inner());
    if r.len() >= 40 {
        r.pop_front();
    }
    r.push_back(line);
}

fn kb(n: u64) -> String {
    if n < 10_000 { format!("{n} B") } else { format!("{} kB", n / 1000) }
}

fn failed(what: String) {
    FAILED.fetch_add(1, Ordering::Relaxed);
    // log the first failures and then every 50th, not every one
    let n = FAILED.load(Ordering::Relaxed);
    if n <= 20 || n % 50 == 0 {
        crate::log::log(&format!("socks: {what} (failure #{n})"));
    }
    *LAST_ERROR.lock().unwrap_or_else(|p| p.into_inner()) = what;
}

pub fn start(port: u16, egress: Egress) -> io::Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let egress = egress.clone();
            thread::spawn(move || {
                let _ = handle(stream, &egress);
            });
        }
    });
    Ok(())
}

/// Pins a socket to the tunnel: bound to its address and forced out of its interface.
pub fn pin(sock: &Socket, egress: &Egress) -> io::Result<()> {
    // right after start (or a reconnect) the tunnel may need a moment; wait instead of failing
    let mut tunnel = *egress.read().unwrap_or_else(|p| p.into_inner());
    for _ in 0..100 {
        if tunnel.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
        tunnel = *egress.read().unwrap_or_else(|p| p.into_inner());
    }
    let (ip, index) = tunnel.ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "tunnel is down"))?;
    let idx = index.to_be(); // IP_UNICAST_IF takes the IPv4 interface index in network byte order
    let r = unsafe { setsockopt(sock.as_raw_socket() as usize, IPPROTO_IP, IP_UNICAST_IF, &idx as *const u32 as *const u8, 4) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    sock.bind(&SocketAddr::V4(SocketAddrV4::new(ip, 0)).into())
}

fn reply(s: &mut TcpStream, code: u8, bound: SocketAddrV4) -> io::Result<()> {
    let mut r = vec![5, code, 0, 1];
    r.extend_from_slice(&bound.ip().octets());
    r.extend_from_slice(&bound.port().to_be_bytes());
    s.write_all(&r)
}

/// Reads a SOCKS address (ATYP + address + port); IPv6 is refused (the tunnel is IPv4 only).
fn read_addr<R: Read>(r: &mut R, atyp: u8) -> io::Result<Option<SocketAddrV4>> {
    let ip = match atyp {
        1 => {
            let mut a = [0u8; 4];
            r.read_exact(&mut a)?;
            Some(Ipv4Addr::from(a))
        }
        3 => {
            let mut len = [0u8; 1];
            r.read_exact(&mut len)?;
            let mut name = vec![0u8; len[0] as usize];
            r.read_exact(&mut name)?;
            let name = String::from_utf8_lossy(&name).to_string();
            (name.as_str(), 0).to_socket_addrs().ok().and_then(|mut it| {
                it.find_map(|a| match a {
                    SocketAddr::V4(v) => Some(*v.ip()),
                    SocketAddr::V6(_) => None,
                })
            })
        }
        4 => {
            let mut a = [0u8; 16];
            r.read_exact(&mut a)?;
            None
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad address type")),
    };
    let mut port = [0u8; 2];
    r.read_exact(&mut port)?;
    Ok(ip.map(|ip| SocketAddrV4::new(ip, u16::from_be_bytes(port))))
}

fn handle(mut s: TcpStream, egress: &Egress) -> io::Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut head = [0u8; 2];
    s.read_exact(&mut head)?;
    if head[0] != 5 {
        return Ok(());
    }
    let mut methods = vec![0u8; head[1] as usize];
    s.read_exact(&mut methods)?;
    s.write_all(&[5, 0])?; // no authentication (localhost only)
    let mut req = [0u8; 4];
    s.read_exact(&mut req)?;
    let target = read_addr(&mut s, req[3])?;
    let none = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    match req[1] {
        1 => {
            let Some(target) = target else {
                failed("tcp: IPv6 or unresolvable destination refused".into());
                return reply(&mut s, 8, none);
            };
            let out = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            if let Err(e) = pin(&out, egress) {
                failed(format!("tcp {target}: cannot use the tunnel: {e}"));
                return reply(&mut s, 1, none); // tunnel down: refuse, never go direct
            }
            if let Err(e) = out.connect_timeout(&SocketAddr::V4(target).into(), Duration::from_secs(15)) {
                failed(format!("tcp {target}: {e}"));
                return reply(&mut s, 5, none);
            }
            CONNECTED.fetch_add(1, Ordering::Relaxed);
            let out: TcpStream = out.into();
            let bound = match out.local_addr()? {
                SocketAddr::V4(v) => v,
                SocketAddr::V6(_) => none,
            };
            reply(&mut s, 0, bound)?;
            s.set_read_timeout(None)?;
            let start = Instant::now();
            TCP_OPEN.fetch_add(1, Ordering::Relaxed);
            open_target(target, 1);
            let (up, down) = pipe(s, out);
            open_target(target, -1);
            TCP_OPEN.fetch_sub(1, Ordering::Relaxed);
            recent(format!("tcp {target}: sent {}, got {} in {} s", kb(up), kb(down), start.elapsed().as_secs()));
            Ok(())
        }
        3 => udp_associate(s, egress),
        _ => reply(&mut s, 7, none),
    }
}

/// Copies both ways until both sides are done; returns (bytes sent to the remote, bytes received).
fn pipe(a: TcpStream, b: TcpStream) -> (u64, u64) {
    let (Ok(mut a2), Ok(mut b2)) = (a.try_clone(), b.try_clone()) else { return (0, 0) };
    let t = thread::spawn(move || {
        let n = io::copy(&mut CountingReader(&mut a2, &TCP_UP), &mut b2).unwrap_or(0);
        let _ = b2.shutdown(Shutdown::Write);
        n
    });
    let (mut a, mut b) = (a, b);
    let down = io::copy(&mut CountingReader(&mut b, &TCP_DOWN), &mut a).unwrap_or(0);
    let _ = a.shutdown(Shutdown::Write);
    (t.join().unwrap_or(0), down)
}

/// Adds everything read to a global counter as it flows (long connections show up live).
struct CountingReader<'a, R>(&'a mut R, &'static AtomicU64);

impl<R: Read> Read for CountingReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.0.read(buf)?;
        self.1.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// UDP relay: datagrams from the program arrive on `local` with a SOCKS header and leave through
/// `out` (pinned to the tunnel); answers go back with the sender's address in the header.
fn udp_associate(mut ctrl: TcpStream, egress: &Egress) -> io::Result<()> {
    let none = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    let local = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let out = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    if let Err(e) = pin(&out, egress) {
        failed(format!("udp: cannot use the tunnel: {e}"));
        return reply(&mut ctrl, 1, none);
    }
    let out: UdpSocket = out.into();
    let bound = match local.local_addr()? {
        SocketAddr::V4(v) => v,
        SocketAddr::V6(_) => none,
    };
    reply(&mut ctrl, 0, bound)?;
    UDP_ASSOCIATIONS.fetch_add(1, Ordering::Relaxed);
    let start = Instant::now();
    let (sent, got) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let done = Arc::new(AtomicBool::new(false));
    let client: Arc<RwLock<Option<SocketAddr>>> = Arc::new(RwLock::new(None));
    local.set_read_timeout(Some(Duration::from_secs(1)))?;
    out.set_read_timeout(Some(Duration::from_secs(1)))?;

    // tunnel -> program
    let (l2, o2, d2, c2, got2) = (local.try_clone()?, out.try_clone()?, done.clone(), client.clone(), got.clone());
    let back = thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        while !d2.load(Ordering::Relaxed) {
            let Ok((n, SocketAddr::V4(from))) = o2.recv_from(&mut buf) else { continue };
            let Some(to) = *c2.read().unwrap_or_else(|p| p.into_inner()) else { continue };
            let mut pkt = vec![0, 0, 0, 1];
            pkt.extend_from_slice(&from.ip().octets());
            pkt.extend_from_slice(&from.port().to_be_bytes());
            pkt.extend_from_slice(&buf[..n]);
            let _ = l2.send_to(&pkt, to);
            UDP_IN.fetch_add(1, Ordering::Relaxed);
            got2.fetch_add(1, Ordering::Relaxed);
        }
    });
    // program -> tunnel
    let (d3, c3, sent3) = (done.clone(), client.clone(), sent.clone());
    let fwd = thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        while !d3.load(Ordering::Relaxed) {
            let Ok((n, from)) = local.recv_from(&mut buf) else { continue };
            if !from.ip().is_loopback() || n < 4 || buf[2] != 0 {
                continue; // fragments are not supported
            }
            *c3.write().unwrap_or_else(|p| p.into_inner()) = Some(from);
            let mut r = io::Cursor::new(&buf[4..n]);
            if let Ok(Some(target)) = read_addr(&mut r, buf[3]) {
                let at = 4 + r.position() as usize;
                let _ = out.send_to(&buf[at..n], target);
                UDP_OUT.fetch_add(1, Ordering::Relaxed);
                sent3.fetch_add(1, Ordering::Relaxed);
            }
        }
    });
    // the association lives as long as the control connection
    let mut sink = [0u8; 64];
    ctrl.set_read_timeout(None)?;
    while matches!(ctrl.read(&mut sink), Ok(n) if n > 0) {}
    done.store(true, Ordering::Relaxed);
    let _ = back.join();
    let _ = fwd.join();
    recent(format!(
        "udp: sent {} datagrams, got {} in {} s",
        sent.load(Ordering::Relaxed),
        got.load(Ordering::Relaxed),
        start.elapsed().as_secs()
    ));
    Ok(())
}
