//! Finding programs (foreground window, by executable name) and closing their open connections so
//! they reconnect through the new route.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use windows_sys::Win32::Foundation::{CloseHandle, HWND, INVALID_HANDLE_VALUE, LPARAM};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB, MIB_TCPROW_LH, MIB_TCPROW_LH_0,
    MIB_TCPROW_OWNER_PID, SetTcpEntry, TCP_TABLE_OWNER_PID_CONNECTIONS,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW};
use windows_sys::Win32::UI::WindowsAndMessaging::{EnumChildWindows, GetForegroundWindow, GetWindowThreadProcessId};

/// Programs that must never be redirected (the system, ourselves, the redirector).
const NEVER: &[&str] = &[
    "sideroute.exe", "proxifyre.exe", "explorer.exe", "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
    "dwm.exe", "system", "services.exe", "searchhost.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe",
];

pub fn allowed(exe: &str) -> bool {
    !NEVER.contains(&exe)
}

fn image_name(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        if ok == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        path.rsplit('\\').next().map(|n| n.to_lowercase())
    }
}

/// Executable name (lower case) of the program owning the foreground window. Store apps are hosted
/// by ApplicationFrameHost.exe; their real process owns one of its child windows.
pub fn foreground_app() -> Option<String> {
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.is_null() {
            return None;
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, &mut pid);
        let name = image_name(pid)?;
        if name != "applicationframehost.exe" {
            return Some(name);
        }
        unsafe extern "system" fn child(h: HWND, lp: LPARAM) -> i32 {
            let found = unsafe { &mut *(lp as *mut (u32, u32)) };
            let mut pid = 0u32;
            unsafe { GetWindowThreadProcessId(h, &mut pid) };
            if pid != found.0 {
                found.1 = pid;
                return 0;
            }
            1
        }
        let mut found = (pid, 0u32);
        EnumChildWindows(hwnd, Some(child), &mut found as *mut _ as LPARAM);
        if found.1 != 0 { image_name(found.1) } else { Some(name) }
    }
}

/// Process IDs of every running process with this executable name.
pub fn pids_of(exe: &str) -> HashSet<u32> {
    let mut out = HashSet::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut e);
        while ok != 0 {
            let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
            if String::from_utf16_lossy(&e.szExeFile[..len]).eq_ignore_ascii_case(exe) {
                out.insert(e.th32ProcessID);
            }
            ok = Process32NextW(snap, &mut e);
        }
        CloseHandle(snap);
    }
    out
}

fn is_local(ip: Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified() || (ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64)
}

/// Closes the established internet (non-LAN) TCP connections of these processes. Returns how many.
/// UDP has no connections to close; programs pick up the new route on their next packets.
pub fn close_connections(pids: &HashSet<u32>) -> usize {
    if pids.is_empty() {
        return 0;
    }
    let mut size = 0u32;
    unsafe { GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) };
    let mut buf = vec![0u32; (size as usize).div_ceil(4) + 64];
    size = (buf.len() * 4) as u32;
    if unsafe { GetExtendedTcpTable(buf.as_mut_ptr() as *mut _, &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) } != 0 {
        return 0;
    }
    let count = buf[0] as usize;
    let rows = unsafe { std::slice::from_raw_parts(buf.as_ptr().add(1) as *const MIB_TCPROW_OWNER_PID, count) };
    let mut closed = 0;
    for r in rows {
        if !pids.contains(&r.dwOwningPid) || r.dwState != MIB_TCP_STATE_ESTAB as u32 {
            continue;
        }
        if is_local(Ipv4Addr::from(u32::from_be(r.dwRemoteAddr))) {
            continue;
        }
        let row = MIB_TCPROW_LH {
            Anonymous: MIB_TCPROW_LH_0 { State: MIB_TCP_STATE_DELETE_TCB },
            dwLocalAddr: r.dwLocalAddr,
            dwLocalPort: r.dwLocalPort,
            dwRemoteAddr: r.dwRemoteAddr,
            dwRemotePort: r.dwRemotePort,
        };
        if unsafe { SetTcpEntry(&row) } == 0 {
            closed += 1;
        }
    }
    closed
}

/// Executable names of programs that currently have a visible, titled top-level window.
pub fn window_apps() -> Vec<String> {
    use windows_sys::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowTextLengthW, IsWindowVisible};
    unsafe extern "system" fn each(h: HWND, lp: LPARAM) -> i32 {
        let list = unsafe { &mut *(lp as *mut Vec<u32>) };
        if unsafe { IsWindowVisible(h) } != 0 && unsafe { GetWindowTextLengthW(h) } > 0 {
            let mut pid = 0u32;
            unsafe { GetWindowThreadProcessId(h, &mut pid) };
            list.push(pid);
        }
        1
    }
    let mut pids: Vec<u32> = Vec::new();
    unsafe { EnumWindows(Some(each), &mut pids as *mut _ as LPARAM) };
    let mut names: Vec<String> = pids.into_iter().filter_map(image_name).filter(|n| allowed(n) && n != "applicationframehost.exe").collect();
    names.sort();
    names.dedup();
    names
}

/// Running packet-manipulating anti-censorship tools (GoodbyeDPI, zapret). They rewrite TCP traffic
/// on every adapter, which breaks connections through the tunnel.
pub fn dpi_tools() -> Vec<&'static str> {
    ["goodbyedpi.exe", "winws.exe"].into_iter().filter(|n| !pids_of(n).is_empty()).collect()
}

/// (pid, parent pid, executable name in lower case) of every process.
pub fn all_processes() -> Vec<(u32, u32, String)> {
    let mut out = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut e);
        while ok != 0 {
            let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
            out.push((e.th32ProcessID, e.th32ParentProcessID, String::from_utf16_lossy(&e.szExeFile[..len]).to_lowercase()));
            ok = Process32NextW(snap, &mut e);
        }
        CloseHandle(snap);
    }
    out
}

/// Processes started by programs named `exe` (children, grandchildren...): (pid, name).
pub fn descendants(exe: &str) -> Vec<(u32, String)> {
    let all = all_processes();
    let mut set: HashSet<u32> = all.iter().filter(|p| p.2.eq_ignore_ascii_case(exe)).map(|p| p.0).collect();
    loop {
        let before = set.len();
        for p in &all {
            // pid 0/4 and reused parent ids would pull in the whole system
            if p.1 > 4 && set.contains(&p.1) {
                set.insert(p.0);
            }
        }
        if set.len() == before {
            break;
        }
    }
    all.into_iter().filter(|p| set.contains(&p.0) && !p.2.eq_ignore_ascii_case(exe)).map(|p| (p.0, p.2)).collect()
}

/// Helpers that belong to Windows rather than to the program that started them.
pub fn is_system_helper(exe: &str) -> bool {
    matches!(exe, "conhost.exe" | "werfault.exe" | "wermgr.exe" | "cmd.exe" | "powershell.exe" | "msedgewebview2.exe")
        || !allowed(exe)
}

/// Established internet TCP connections of these processes: (pid, remote address).
pub fn tcp_connections(pids: &HashSet<u32>) -> Vec<(u32, std::net::SocketAddrV4)> {
    let mut size = 0u32;
    unsafe { GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) };
    let mut buf = vec![0u32; (size as usize).div_ceil(4) + 64];
    size = (buf.len() * 4) as u32;
    if unsafe { GetExtendedTcpTable(buf.as_mut_ptr() as *mut _, &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) } != 0 {
        return Vec::new();
    }
    let rows = unsafe { std::slice::from_raw_parts(buf.as_ptr().add(1) as *const MIB_TCPROW_OWNER_PID, buf[0] as usize) };
    rows.iter()
        .filter(|r| pids.contains(&r.dwOwningPid) && r.dwState == MIB_TCP_STATE_ESTAB as u32)
        .map(|r| {
            let ip = Ipv4Addr::from(u32::from_be(r.dwRemoteAddr));
            (r.dwOwningPid, std::net::SocketAddrV4::new(ip, u16::from_be(r.dwRemotePort as u16)))
        })
        .filter(|(_, a)| !is_local(*a.ip()))
        .collect()
}
