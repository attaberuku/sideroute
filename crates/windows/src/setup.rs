//! Installing, updating and removing Sideroute on Windows (used by the setup wizard and by
//! `Sideroute.exe setup --quiet` / `uninstall`).
//!
//! Installed layout:
//!   `%ProgramFiles%\Sideroute\`  Sideroute.exe, wireguard.dll, licenses
//!   `%ProgramData%\Sideroute\`   configuration and keys (SYSTEM and Administrators only)
//!   scheduled task `Sideroute`   starts the tray at logon with administrator rights (no UAC prompt)
//!   Start menu shortcut, and an entry in Settings > Apps for uninstalling.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_DWORD, RegCloseKey,
    RegCreateKeyExW, RegDeleteTreeW, RegGetValueW, RegSetValueExW,
};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

use crate::i18n::t;
use crate::{app, procs, redirect, state};

pub const TASK: &str = "Sideroute";
const UNINSTALL_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Sideroute";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(payload)]
mod payload {
    pub const WIREGUARD_DLL: &[u8] = include_bytes!(concat!(env!("SIDEROUTE_PAYLOAD_DIR"), "/wireguard.dll"));
    pub const WIREGUARD_LICENSE: &[u8] = include_bytes!(concat!(env!("SIDEROUTE_PAYLOAD_DIR"), "/wireguard-nt-LICENSE.txt"));
    pub const PROXIFYRE_SETUP: &[u8] = include_bytes!(concat!(env!("SIDEROUTE_PAYLOAD_DIR"), "/ProxiFyre-setup.exe"));
}
#[cfg(not(payload))]
mod payload {
    pub const WIREGUARD_DLL: &[u8] = &[];
    pub const WIREGUARD_LICENSE: &[u8] = &[];
    pub const PROXIFYRE_SETUP: &[u8] = &[];
}

const NOTICES: &str = include_str!("../../../windows/THIRD-PARTY-NOTICES.txt");

pub fn install_dir() -> PathBuf {
    let pf = std::env::var_os("ProgramW6432")
        .or_else(|| std::env::var_os("ProgramFiles"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    pf.join("Sideroute")
}

pub fn installed_exe() -> PathBuf {
    install_dir().join("Sideroute.exe")
}

/// True when this process is the installed copy (and not the downloaded setup file).
pub fn running_installed() -> bool {
    let me = std::env::current_exe().ok().and_then(|p| p.canonicalize().ok());
    let inst = installed_exe().canonicalize().ok();
    me.is_some() && me == inst
}

pub fn is_installed() -> bool {
    installed_exe().exists()
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn run_hidden(prog: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(prog)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("{prog}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(format!("{prog} {}: {}{}", args.join(" "), String::from_utf8_lossy(&out.stdout).trim(), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

fn system32(exe: &str) -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    format!(r"{root}\System32\{exe}")
}

/// .NET Framework 4.7.2+ is needed by ProxiFyre.
fn dotnet_ok() -> bool {
    let key = wide(r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full");
    let name = wide("Release");
    let mut v: u32 = 0;
    let mut size = 4u32;
    let r = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), name.as_ptr(), RRF_RT_REG_DWORD, std::ptr::null_mut(), &mut v as *mut u32 as *mut _, &mut size)
    };
    r == 0 && v >= 461_808
}

/// Ends the tray (and any other Sideroute process except this one).
fn stop_running() {
    let _ = run_hidden(&system32("schtasks.exe"), &["/End", "/TN", TASK]);
    let me = std::process::id();
    for pid in procs::pids_of("Sideroute.exe") {
        if pid == me {
            continue;
        }
        unsafe {
            let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if !h.is_null() {
                TerminateProcess(h, 0);
                CloseHandle(h);
            }
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(800)); // let the adapter go away
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// The logged-on user the tray should run as (the installer runs elevated as the same user).
fn user() -> String {
    let name = std::env::var("USERNAME").unwrap_or_default();
    match std::env::var("USERDOMAIN") {
        Ok(d) if !d.is_empty() => format!("{d}\\{name}"),
        _ => name,
    }
}

/// Scheduled task that runs the tray elevated without a UAC prompt; at logon when `autostart`.
fn register_task(autostart: bool) -> Result<(), String> {
    let exe = installed_exe().to_string_lossy().to_string();
    let user = xml_escape(&user());
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Sideroute: per-app VPN (notification area)</Description></RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>{autostart}</Enabled><UserId>{user}</UserId></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>{}</Command></Exec></Actions>
</Task>
"#,
        xml_escape(&exe)
    );
    let path = std::env::temp_dir().join("Sideroute-task.xml");
    // schtasks wants UTF-16 with a byte order mark
    let mut bytes = vec![0xff, 0xfe];
    for u in xml.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let r = run_hidden(&system32("schtasks.exe"), &["/Create", "/TN", TASK, "/XML", &path.to_string_lossy(), "/F"]);
    let _ = std::fs::remove_file(&path);
    r.map(|_| ())
}

/// Starts the tray through the scheduled task (elevated, as the logged-on user).
pub fn start_tray() -> Result<(), String> {
    run_hidden(&system32("schtasks.exe"), &["/Run", "/TN", TASK]).map(|_| ())
}

fn start_menu_shortcut() -> PathBuf {
    let base = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join(r"Microsoft\Windows\Start Menu\Programs\Sideroute.lnk")
}

fn create_shortcut() -> Result<(), String> {
    let q = |p: &Path| p.to_string_lossy().replace('\'', "''");
    let exe = installed_exe();
    let script = format!(
        "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{}');$s.TargetPath='{}';$s.IconLocation='{},0';$s.Description='Sideroute';$s.Save()",
        q(&start_menu_shortcut()),
        q(&exe),
        q(&exe)
    );
    run_hidden(&system32(r"WindowsPowerShell\v1.0\powershell.exe"), &["-NoProfile", "-NonInteractive", "-Command", &script]).map(|_| ())
}

fn reg_set_str(key: HKEY, name: &str, value: &str) {
    let n = wide(name);
    let v = wide(value);
    unsafe { RegSetValueExW(key, n.as_ptr(), 0, REG_SZ, v.as_ptr() as *const u8, (v.len() * 2) as u32) };
}

fn reg_set_dword(key: HKEY, name: &str, value: u32) {
    let n = wide(name);
    unsafe { RegSetValueExW(key, n.as_ptr(), 0, REG_DWORD, &value as *const u32 as *const u8, 4) };
}

/// Entry in Settings > Apps.
fn register_uninstall() -> Result<(), String> {
    let exe = installed_exe().to_string_lossy().to_string();
    let mut key: HKEY = std::ptr::null_mut();
    let path = wide(UNINSTALL_KEY);
    let r = unsafe {
        RegCreateKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, std::ptr::null(), REG_OPTION_NON_VOLATILE, KEY_WRITE, std::ptr::null(), &mut key, std::ptr::null_mut())
    };
    if r != 0 {
        return Err(format!("registry (error {r})"));
    }
    reg_set_str(key, "DisplayName", "Sideroute");
    reg_set_str(key, "DisplayVersion", env!("CARGO_PKG_VERSION"));
    reg_set_str(key, "Publisher", "Sideroute contributors");
    reg_set_str(key, "DisplayIcon", &format!("{exe},0"));
    reg_set_str(key, "InstallLocation", &install_dir().to_string_lossy());
    reg_set_str(key, "UninstallString", &format!("\"{exe}\" uninstall"));
    reg_set_str(key, "QuietUninstallString", &format!("\"{exe}\" uninstall --quiet"));
    reg_set_dword(key, "NoModify", 1);
    reg_set_dword(key, "NoRepair", 1);
    reg_set_dword(key, "EstimatedSize", 6 * 1024);
    unsafe { RegCloseKey(key) };
    Ok(())
}

/// Takes over an installation made under the project's former name "app-tunnel": its pairing,
/// key and program list move to the new folder, everything else of it is removed.
fn migrate_legacy() {
    let pd = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    let old_data = pd.join("app-tunnel");
    let old_dir = install_dir().with_file_name("app-tunnel");
    if !old_data.exists() && !old_dir.exists() {
        return;
    }
    let _ = run_hidden(&system32("schtasks.exe"), &["/Delete", "/TN", "app-tunnel", "/F"]);
    for pid in procs::pids_of("AppTunnel.exe") {
        unsafe {
            let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if !h.is_null() {
                TerminateProcess(h, 0);
                CloseHandle(h);
            }
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(800));
    let new_data = state::dir();
    if old_data.exists() && !new_data.join("client.json").exists() {
        let _ = std::fs::create_dir_all(&new_data);
        let mut copied = true;
        for f in ["client.json", "private.key", "warp.json", "apps.json", "related.json"] {
            if old_data.join(f).exists() && std::fs::copy(old_data.join(f), new_data.join(f)).is_err() {
                copied = false;
            }
        }
        if copied {
            let _ = std::fs::remove_dir_all(&old_data); // it holds a private key
        }
    }
    let _ = std::fs::remove_dir_all(&old_dir);
    let _ = std::fs::remove_file(start_menu_shortcut().with_file_name("app-tunnel.lnk"));
    let key = wide(r"Software\Microsoft\Windows\CurrentVersion\Uninstall\app-tunnel");
    unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, key.as_ptr()) };
    let pf = redirect::install_dir();
    let (old_backup, new_backup) = (pf.join("app-config.json.before-app-tunnel"), pf.join("app-config.json.before-Sideroute"));
    if old_backup.exists() && !new_backup.exists() {
        let _ = std::fs::rename(old_backup, new_backup);
    }
}

/// What the user picked for pairing.
#[derive(Clone)]
pub enum Pairing {
    /// keep an existing pairing (WARP when there is none)
    Keep,
    Warp,
    Code(String),
}

pub struct Options {
    pub pairing: Pairing,
    pub autostart: bool,
}

/// Runs the installation; `step(n, text)` reports progress (n of `STEPS`).
pub const STEPS: u32 = 6;

pub fn install(opts: &Options, step: &dyn Fn(u32, &str)) -> Result<String, String> {
    if !cfg!(payload) {
        return Err("this build does not contain the bundled components (build it with scripts/build-windows.sh)".into());
    }
    if !dotnet_ok() {
        return Err(t(
            "ProxiFyre needs .NET Framework 4.7.2 or later. Install it from Windows Update, then run this setup again.",
            "ProxiFyre için .NET Framework 4.7.2 veya üstü gerekiyor. Windows Update'ten kurup kurulumu tekrar çalıştır.",
        )
        .into());
    }
    step(1, t("Preparing...", "Hazırlanıyor..."));
    stop_running();
    migrate_legacy();
    let data = state::dir();
    std::fs::create_dir_all(&data).map_err(|e| format!("{}: {e}", data.display()))?;
    // only SYSTEM and Administrators may read the keys (SIDs, so it works in any language);
    // done before pairing creates the private key, so the key inherits it
    run_hidden(&system32("icacls.exe"), &[&data.to_string_lossy(), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/T"])?;

    // pairing next: a wrong code should not leave a half-done installation behind
    step(2, t("Connecting...", "Bağlanılıyor..."));
    let paired_msg = match (&opts.pairing, state::load_config().is_ok()) {
        (Pairing::Keep, true) => None,
        (Pairing::Keep, false) | (Pairing::Warp, _) => Some(app::pair("warp")?),
        (Pairing::Code(c), _) => Some(app::pair(c)?),
    };

    step(3, t("Copying files...", "Dosyalar kopyalanıyor..."));
    let dir = install_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    if !running_installed() {
        std::fs::copy(&me, installed_exe()).map_err(|e| format!("{}: {e}", installed_exe().display()))?;
    }
    for (name, data) in [
        ("wireguard.dll", payload::WIREGUARD_DLL),
        ("wireguard-nt-LICENSE.txt", payload::WIREGUARD_LICENSE),
        ("THIRD-PARTY-NOTICES.txt", NOTICES.as_bytes()),
    ] {
        std::fs::write(dir.join(name), data).map_err(|e| format!("{name}: {e}"))?;
    }

    step(4, t("Installing ProxiFyre and the packet filter driver (can take a minute)...",
              "ProxiFyre ve paket filtresi sürücüsü kuruluyor (bir dakika sürebilir)..."));
    if !redirect::installed() {
        let setup = std::env::temp_dir().join("ProxiFyre-setup.exe");
        std::fs::write(&setup, payload::PROXIFYRE_SETUP).map_err(|e| format!("{}: {e}", setup.display()))?;
        let status = Command::new(&setup).args(["/quiet", "/norestart"]).status().map_err(|e| format!("ProxiFyre setup: {e}"))?;
        let _ = std::fs::remove_file(&setup);
        // 3010: success, restart required (the driver works without one)
        if !(status.success() || status.code() == Some(3010)) {
            return Err(format!("ProxiFyre setup failed (exit code {:?})", status.code()));
        }
        if !redirect::installed() {
            return Err("ProxiFyre setup finished but its service is missing".into());
        }
    }

    step(5, t("Setting up the start at logon...", "Açılışta başlatma ayarlanıyor..."));
    register_task(opts.autostart)?;
    let _ = create_shortcut();
    register_uninstall()?;

    step(6, t("Done", "Tamamlandı"));
    Ok(paired_msg.unwrap_or_default())
}

/// Removes Sideroute. `purge` also deletes keys and pairing (and the WARP registration).
pub fn uninstall(purge: bool) -> Result<(), String> {
    let _ = app::off();
    stop_running();
    let _ = run_hidden(&system32("schtasks.exe"), &["/Delete", "/TN", TASK, "/F"]);
    let _ = std::fs::remove_file(start_menu_shortcut());
    let key = wide(UNINSTALL_KEY);
    unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, key.as_ptr()) };
    let pf = redirect::install_dir().join("app-config.json");
    let backup = redirect::install_dir().join("app-config.json.before-Sideroute");
    if backup.exists() {
        let _ = std::fs::rename(&backup, &pf);
    }
    if purge {
        if let Some(w) = state::load_warp() {
            let _ = sideroute_net::warp_delete(&w);
        }
        let _ = std::fs::remove_dir_all(state::dir());
    }
    // this program may be running from the folder: remove it once we have exited
    let dir = install_dir();
    let cmd = format!("ping -n 3 127.0.0.1 >nul & rmdir /s /q \"{}\"", dir.display());
    let _ = Command::new(system32("cmd.exe")).args(["/c", &cmd]).creation_flags(CREATE_NO_WINDOW).spawn();
    Ok(())
}
