//! WireGuard tunnel through wireguard-nt (`wireguard.dll` from download.wireguard.com, placed next
//! to the executable by the installer). Only the documented API of `wireguard.h` is used.
//!
//! The adapter gets the tunnel address and a default route with a very high metric: nothing uses
//! it unless a socket is explicitly bound to the adapter, which is what the SOCKS5 server does.
//! The adapter disappears when this process exits (the handle that created it is closed).

use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::os::windows::ffi::OsStrExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sideroute_proto::PairResponse;
use base64_decode::decode_key;
use windows_sys::Win32::Foundation::{ERROR_OBJECT_ALREADY_EXISTS, GetLastError, HMODULE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToIndex, CreateIpForwardEntry2, CreateUnicastIpAddressEntry, GetIpInterfaceEntry,
    InitializeIpForwardEntry, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2,
    MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, IN_ADDR, IN_ADDR_0, IpDadStatePreferred, MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_INET};
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetProcAddress, LoadLibraryW};

pub const ADAPTER_NAME: &str = "Sideroute";
/// Interface metric of the tunnel adapter: far above any real network, so the system never picks
/// its default route on its own.
const METRIC: u32 = 9000;

mod base64_decode {
    pub fn decode_key(s: &str) -> Result<[u8; 32], String> {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let s = s.trim().trim_end_matches('=');
        let mut out = Vec::with_capacity(32);
        let (mut buf, mut bits) = (0u32, 0);
        for c in s.bytes() {
            let v = A.iter().position(|&x| x == c).ok_or("invalid key")? as u32;
            buf = (buf << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
            }
        }
        out.try_into().map_err(|_| "invalid key length".to_string())
    }
}

// --- wireguard.h structures (all ALIGNED(8)) ------------------------------------------------------

const IF_HAS_PRIVATE_KEY: u32 = 1 << 1;
const IF_REPLACE_PEERS: u32 = 1 << 3;
const PEER_HAS_PUBLIC_KEY: u32 = 1 << 0;
const PEER_HAS_PERSISTENT_KEEPALIVE: u32 = 1 << 2;
const PEER_HAS_ENDPOINT: u32 = 1 << 3;
const PEER_REPLACE_ALLOWED_IPS: u32 = 1 << 5;
const ADAPTER_STATE_DOWN: i32 = 0;
const ADAPTER_STATE_UP: i32 = 1;

#[repr(C, align(8))]
struct WgInterface {
    flags: u32,
    listen_port: u16,
    private_key: [u8; 32],
    public_key: [u8; 32],
    peers_count: u32,
}

#[repr(C, align(8))]
struct WgPeer {
    flags: u32,
    reserved: u32,
    public_key: [u8; 32],
    preshared_key: [u8; 32],
    persistent_keepalive: u16,
    endpoint: SOCKADDR_INET,
    tx_bytes: u64,
    rx_bytes: u64,
    last_handshake: u64,
    allowed_ips_count: u32,
}

#[repr(C, align(8))]
struct WgAllowedIp {
    address: [u32; 4], // union { IN_ADDR V4; IN6_ADDR V6; }
    address_family: u16,
    cidr: u8,
    flags: u32,
}

const _: () = assert!(size_of::<SOCKADDR_INET>() == 28);
const _: () = assert!(size_of::<WgInterface>() == 80);
const _: () = assert!(size_of::<WgPeer>() == 136);
const _: () = assert!(size_of::<WgAllowedIp>() == 24);

type Handle = *mut c_void;
type CreateAdapterFn = unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> Handle;
type OpenAdapterFn = unsafe extern "system" fn(*const u16) -> Handle;
type CloseAdapterFn = unsafe extern "system" fn(Handle);
type GetLuidFn = unsafe extern "system" fn(Handle, *mut NET_LUID_LH);
type SetStateFn = unsafe extern "system" fn(Handle, i32) -> i32;
type SetConfigFn = unsafe extern "system" fn(Handle, *const u8, u32) -> i32;
type GetConfigFn = unsafe extern "system" fn(Handle, *mut u8, *mut u32) -> i32;

struct Api {
    create: CreateAdapterFn,
    open: OpenAdapterFn,
    close: CloseAdapterFn,
    luid: GetLuidFn,
    set_state: SetStateFn,
    set_config: SetConfigFn,
    get_config: GetConfigFn,
}

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn last_error(what: &str) -> String {
    format!("{what} failed (error {})", unsafe { GetLastError() })
}

impl Api {
    fn load() -> Result<Api, String> {
        let mut buf = [0u16; 1024];
        let n = unsafe { GetModuleFileNameW(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) } as usize;
        let exe = std::path::PathBuf::from(String::from_utf16_lossy(&buf[..n]));
        let dll = exe.with_file_name("wireguard.dll");
        let module: HMODULE = unsafe { LoadLibraryW(wide(&dll.to_string_lossy()).as_ptr()) };
        if module.is_null() {
            return Err(format!("cannot load {} (run the installer again)", dll.display()));
        }
        let sym = |name: &str| -> Result<unsafe extern "system" fn() -> isize, String> {
            let c = std::ffi::CString::new(name).map_err(|e| e.to_string())?;
            unsafe { GetProcAddress(module, c.as_ptr() as *const u8) }.ok_or_else(|| format!("wireguard.dll has no {name}"))
        };
        // SAFETY: the signatures match wireguard.h
        unsafe {
            Ok(Api {
                create: std::mem::transmute::<_, CreateAdapterFn>(sym("WireGuardCreateAdapter")?),
                open: std::mem::transmute::<_, OpenAdapterFn>(sym("WireGuardOpenAdapter")?),
                close: std::mem::transmute::<_, CloseAdapterFn>(sym("WireGuardCloseAdapter")?),
                luid: std::mem::transmute::<_, GetLuidFn>(sym("WireGuardGetAdapterLUID")?),
                set_state: std::mem::transmute::<_, SetStateFn>(sym("WireGuardSetAdapterState")?),
                set_config: std::mem::transmute::<_, SetConfigFn>(sym("WireGuardSetConfiguration")?),
                get_config: std::mem::transmute::<_, GetConfigFn>(sym("WireGuardGetConfiguration")?),
            })
        }
    }
}

fn sockaddr_v4(ip: Ipv4Addr, port: u16) -> SOCKADDR_INET {
    let mut a: SOCKADDR_INET = unsafe { zeroed() };
    a.Ipv4 = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: port.to_be(),
        sin_addr: IN_ADDR { S_un: IN_ADDR_0 { S_addr: u32::from_ne_bytes(ip.octets()) } },
        sin_zero: [0; 8],
    };
    a
}

fn resolve_v4(endpoint: &str) -> Result<(Ipv4Addr, u16), String> {
    endpoint
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {endpoint}: {e}"))?
        .find_map(|a| match a {
            SocketAddr::V4(v) => Some((*v.ip(), v.port())),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("{endpoint} has no IPv4 address"))
}

/// Builds the configuration blob: interface, one peer, one allowed IP (0.0.0.0/0).
fn config_blob(private: &[u8; 32], c: &PairResponse) -> Result<Vec<u8>, String> {
    let (ip, port) = resolve_v4(&c.endpoint)?;
    let iface = WgInterface { flags: IF_HAS_PRIVATE_KEY | IF_REPLACE_PEERS, listen_port: 0, private_key: *private, public_key: [0; 32], peers_count: 1 };
    let peer = WgPeer {
        flags: PEER_HAS_PUBLIC_KEY | PEER_HAS_PERSISTENT_KEEPALIVE | PEER_HAS_ENDPOINT | PEER_REPLACE_ALLOWED_IPS,
        reserved: 0,
        public_key: decode_key(&c.server_public_key)?,
        preshared_key: [0; 32],
        persistent_keepalive: c.persistent_keepalive,
        endpoint: sockaddr_v4(ip, port),
        tx_bytes: 0,
        rx_bytes: 0,
        last_handshake: 0,
        allowed_ips_count: 1,
    };
    let allowed = WgAllowedIp { address: [0; 4], address_family: AF_INET, cidr: 0, flags: 0 };
    let mut blob = Vec::with_capacity(size_of::<WgInterface>() + size_of::<WgPeer>() + size_of::<WgAllowedIp>());
    // SAFETY: plain-old-data structs laid out as in wireguard.h
    unsafe {
        blob.extend_from_slice(std::slice::from_raw_parts(&iface as *const _ as *const u8, size_of::<WgInterface>()));
        blob.extend_from_slice(std::slice::from_raw_parts(&peer as *const _ as *const u8, size_of::<WgPeer>()));
        blob.extend_from_slice(std::slice::from_raw_parts(&allowed as *const _ as *const u8, size_of::<WgAllowedIp>()));
    }
    Ok(blob)
}

pub struct Tunnel {
    api: Api,
    adapter: Handle,
    pub index: u32,
    pub address: Ipv4Addr,
    luid: NET_LUID_LH,
    /// false when only looking at the tray's adapter from another process (it must stay up)
    owned: bool,
}

// the adapter handle is only used behind the tray's mutex
unsafe impl Send for Tunnel {}

pub struct Stats {
    pub last_handshake: Option<SystemTime>,
    pub rx: u64,
    pub tx: u64,
}

impl Tunnel {
    /// Creates (or reuses) the adapter and brings it up with configuration `c`.
    pub fn up(c: &PairResponse, private_b64: &str) -> Result<Tunnel, String> {
        let api = Api::load()?;
        let name = wide(ADAPTER_NAME);
        let mut adapter = unsafe { (api.open)(name.as_ptr()) };
        if adapter.is_null() {
            adapter = unsafe { (api.create)(name.as_ptr(), name.as_ptr(), std::ptr::null()) };
        }
        if adapter.is_null() {
            return Err(last_error("creating the WireGuard adapter"));
        }
        let address: Ipv4Addr = c
            .client_address
            .split('/')
            .next()
            .and_then(|a| a.parse().ok())
            .ok_or("invalid tunnel address")?;
        let mut t = Tunnel { api, adapter, index: 0, address, luid: unsafe { zeroed() }, owned: true };
        t.configure(c, private_b64)?;

        let mut luid: NET_LUID_LH = unsafe { zeroed() };
        unsafe { (t.api.luid)(t.adapter, &mut luid) };
        t.luid = luid;
        if unsafe { ConvertInterfaceLuidToIndex(&luid, &mut t.index) } != NO_ERROR {
            return Err(last_error("looking up the adapter index"));
        }

        // address
        let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { zeroed() };
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };
        row.Address = sockaddr_v4(address, 0);
        row.InterfaceLuid = luid;
        row.OnLinkPrefixLength = 32;
        row.DadState = IpDadStatePreferred;
        let r = unsafe { CreateUnicastIpAddressEntry(&row) };
        if r != NO_ERROR && r != ERROR_OBJECT_ALREADY_EXISTS {
            return Err(format!("setting the tunnel address failed (error {r})"));
        }

        // interface: fixed high metric, tunnel MTU
        let mut ifrow: MIB_IPINTERFACE_ROW = unsafe { zeroed() };
        unsafe { InitializeIpInterfaceEntry(&mut ifrow) };
        ifrow.Family = AF_INET;
        ifrow.InterfaceLuid = luid;
        let r = unsafe { GetIpInterfaceEntry(&mut ifrow) };
        if r != NO_ERROR {
            return Err(format!("reading the adapter settings failed (error {r})"));
        }
        ifrow.UseAutomaticMetric = false;
        ifrow.Metric = METRIC;
        ifrow.NlMtu = c.mtu as u32;
        ifrow.SitePrefixLength = 0;
        let r = unsafe { SetIpInterfaceEntry(&mut ifrow) };
        if r != NO_ERROR {
            return Err(format!("configuring the adapter failed (error {r})"));
        }

        // default route on the adapter (used only by sockets bound to it)
        let mut route: MIB_IPFORWARD_ROW2 = unsafe { zeroed() };
        unsafe { InitializeIpForwardEntry(&mut route) };
        route.InterfaceLuid = luid;
        route.DestinationPrefix.Prefix = sockaddr_v4(Ipv4Addr::UNSPECIFIED, 0);
        route.DestinationPrefix.PrefixLength = 0;
        route.NextHop = sockaddr_v4(Ipv4Addr::UNSPECIFIED, 0);
        route.Metric = 0;
        route.Protocol = MIB_IPPROTO_NETMGMT;
        let r = unsafe { CreateIpForwardEntry2(&route) };
        if r != NO_ERROR && r != ERROR_OBJECT_ALREADY_EXISTS {
            return Err(format!("adding the tunnel route failed (error {r})"));
        }

        if unsafe { (t.api.set_state)(t.adapter, ADAPTER_STATE_UP) } == 0 {
            return Err(last_error("bringing the adapter up"));
        }
        Ok(t)
    }

    /// Opens the adapter the tray created, to read its state (for the troubleshooting report).
    pub fn open_existing(c: &PairResponse) -> Result<Tunnel, String> {
        let api = Api::load()?;
        let adapter = unsafe { (api.open)(wide(ADAPTER_NAME).as_ptr()) };
        if adapter.is_null() {
            return Err("the tunnel adapter does not exist (is Sideroute running?)".into());
        }
        let address = c.client_address.split('/').next().and_then(|a| a.parse().ok()).ok_or("invalid tunnel address")?;
        let mut t = Tunnel { api, adapter, index: 0, address, luid: unsafe { zeroed() }, owned: false };
        let mut luid: NET_LUID_LH = unsafe { zeroed() };
        unsafe { (t.api.luid)(t.adapter, &mut luid) };
        t.luid = luid;
        if unsafe { ConvertInterfaceLuidToIndex(&luid, &mut t.index) } != NO_ERROR {
            return Err(last_error("looking up the adapter index"));
        }
        Ok(t)
    }

    /// (Re)applies keys and the server endpoint.
    pub fn configure(&mut self, c: &PairResponse, private_b64: &str) -> Result<(), String> {
        let blob = config_blob(&decode_key(private_b64)?, c)?;
        if unsafe { (self.api.set_config)(self.adapter, blob.as_ptr(), blob.len() as u32) } == 0 {
            return Err(last_error("configuring WireGuard"));
        }
        Ok(())
    }

    /// The adapter's IPv4 MTU and interface metric as Windows reports them.
    pub fn mtu_metric(&self) -> Option<(u32, u32)> {
        let mut row: MIB_IPINTERFACE_ROW = unsafe { zeroed() };
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = AF_INET;
        row.InterfaceLuid = self.luid;
        (unsafe { GetIpInterfaceEntry(&mut row) } == NO_ERROR).then_some((row.NlMtu, row.Metric))
    }

    pub fn stats(&self) -> Stats {
        let mut size: u32 = 4096;
        let mut buf = vec![0u64; size as usize / 8]; // u64 storage keeps the 8-byte alignment
        loop {
            let ok = unsafe { (self.api.get_config)(self.adapter, buf.as_mut_ptr() as *mut u8, &mut size) };
            if ok != 0 {
                break;
            }
            if size as usize <= buf.len() * 8 {
                return Stats { last_handshake: None, rx: 0, tx: 0 };
            }
            buf = vec![0u64; (size as usize).div_ceil(8)];
        }
        // SAFETY: the driver wrote an interface struct followed by its peers
        let iface = unsafe { &*(buf.as_ptr() as *const WgInterface) };
        if iface.peers_count == 0 {
            return Stats { last_handshake: None, rx: 0, tx: 0 };
        }
        let peer = unsafe { &*((buf.as_ptr() as *const u8).add(size_of::<WgInterface>()) as *const WgPeer) };
        // 100 ns intervals since 1601-01-01
        let last_handshake = (peer.last_handshake > 0)
            .then(|| peer.last_handshake / 10_000_000)
            .and_then(|s| s.checked_sub(11_644_473_600))
            .map(|unix| UNIX_EPOCH + Duration::from_secs(unix));
        Stats { last_handshake, rx: peer.rx_bytes, tx: peer.tx_bytes }
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        unsafe {
            if self.owned {
                (self.api.set_state)(self.adapter, ADAPTER_STATE_DOWN);
            }
            (self.api.close)(self.adapter);
        }
    }
}
