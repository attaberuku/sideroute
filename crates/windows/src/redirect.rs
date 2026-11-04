//! Per-program redirection through ProxiFyre (installed by the installer; it runs as the
//! `ProxiFyreService` Windows service and reads `app-config.json` next to `ProxiFyre.exe`).

use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::Duration;

use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE,
    SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_STATUS,
    SERVICE_STOP, SERVICE_STOPPED, StartServiceW,
};

const SERVICE: &str = "ProxiFyreService";

pub fn install_dir() -> PathBuf {
    let pf = std::env::var_os("ProgramW6432")
        .or_else(|| std::env::var_os("ProgramFiles"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    pf.join("ProxiFyre")
}

/// An open handle to the ProxiFyre service, closed on drop.
struct Service(SC_HANDLE, SC_HANDLE);

impl Service {
    fn open() -> Option<Service> {
        let name: Vec<u16> = std::ffi::OsStr::new(SERVICE).encode_wide().chain(Some(0)).collect();
        unsafe {
            let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
            if scm.is_null() {
                return None;
            }
            let svc = OpenServiceW(scm, name.as_ptr(), SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP);
            if svc.is_null() {
                CloseServiceHandle(scm);
                return None;
            }
            Some(Service(scm, svc))
        }
    }

    fn state(&self) -> u32 {
        let mut st: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        unsafe { QueryServiceStatus(self.1, &mut st) };
        st.dwCurrentState
    }

    fn wait_for(&self, want: u32) -> bool {
        (0..60).any(|_| {
            if self.state() == want {
                return true;
            }
            std::thread::sleep(Duration::from_millis(250));
            false
        })
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.1);
            CloseServiceHandle(self.0);
        }
    }
}

/// Service state for the troubleshooting report.
pub fn state_name() -> &'static str {
    match Service::open().map(|s| s.state()) {
        None => "not installed",
        Some(SERVICE_RUNNING) => "running",
        Some(SERVICE_STOPPED) => "stopped",
        Some(_) => "starting/stopping",
    }
}

pub fn installed() -> bool {
    Service::open().is_some()
}

pub fn stop() -> Result<(), String> {
    let Some(svc) = Service::open() else { return Ok(()) };
    if svc.state() == SERVICE_STOPPED {
        return Ok(());
    }
    let mut st: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    unsafe { ControlService(svc.1, SERVICE_CONTROL_STOP, &mut st) };
    if svc.wait_for(SERVICE_STOPPED) { Ok(()) } else { Err("ProxiFyre did not stop".into()) }
}

/// Routes exactly `apps` through the SOCKS5 server on `port` (stops redirection when empty).
pub fn apply(apps: &[String], port: u16) -> Result<(), String> {
    if !installed() {
        return Err("ProxiFyre is not installed (run the installer again)".into());
    }
    stop()?;
    if apps.is_empty() {
        return Ok(());
    }
    let path = install_dir().join("app-config.json");
    // keep a configuration that was there before Sideroute took over
    let backup = install_dir().join("app-config.json.before-Sideroute");
    if path.exists() && !backup.exists() {
        let ours = std::fs::read_to_string(&path).is_ok_and(|s| s.contains(&format!("127.0.0.1:{port}")));
        if !ours {
            std::fs::copy(&path, &backup).map_err(|e| format!("backing up {}: {e}", path.display()))?;
        }
    }
    let config = serde_json::json!({
        "logLevel": "Error",
        "bypassLan": true,
        "proxies": [{
            "appNames": apps,
            "socks5ProxyEndpoint": format!("127.0.0.1:{port}"),
            "socks5Transport": "TCP",
            "supportedProtocols": ["TCP", "UDP"],
            // IPv6 of these programs is blocked instead of leaking past the IPv4-only tunnel
            "supportedAddressFamilies": ["IPv4"]
        }],
        "excludes": []
    });
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&config).map_err(|e| e.to_string())?)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
    let svc = Service::open().ok_or("ProxiFyre service not found")?;
    unsafe { StartServiceW(svc.1, 0, std::ptr::null()) };
    crate::log::log(&format!("ProxiFyre: redirecting {}", apps.join(", ")));
    if svc.wait_for(SERVICE_RUNNING) { Ok(()) } else { Err("ProxiFyre did not start (see the logs folder next to ProxiFyre.exe)".into()) }
}
