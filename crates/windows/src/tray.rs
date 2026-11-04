//! Notification-area app: keeps the tunnel and the SOCKS5 server running, shows the state in the
//! icon and its tooltip, offers a menu and the Ctrl+Alt+V hotkey (routes the program of the
//! active window through the tunnel, or back).

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, SystemTime};

use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::System::DataExchange::{CloseClipboard, GetClipboardData, OpenClipboard};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{GlobalLock, GlobalUnlock};
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::Controls::{LIM_SMALL, LoadIconMetric};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{MOD_ALT, MOD_CONTROL, MOD_NOREPEAT, RegisterHotKey};
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_ERROR, NIIF_INFO, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
    ShellExecuteW, Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow, DispatchMessageW,
    GetCursorPos, GetMessageW, HICON, IDI_APPLICATION, LoadIconW, MF_CHECKED, MF_GRAYED, MF_POPUP,
    MF_SEPARATOR, MF_STRING, MSG, PostMessageW, PostQuitMessage, RegisterClassW, RegisterWindowMessageW, SW_SHOWNORMAL,
    SetForegroundWindow, TPM_BOTTOMALIGN, TPM_RIGHTBUTTON, TrackPopupMenu, TranslateMessage, WM_APP, WM_COMMAND,
    WM_CONTEXTMENU, WM_DESTROY, WM_HOTKEY, WM_LBUTTONUP, WM_NULL, WM_RBUTTONUP, WNDCLASSW, WS_OVERLAPPED,
};

use crate::i18n::{t, t1};
use crate::socks::{self, Egress};
use crate::wg::Tunnel;
use crate::{app, diag, log, procs, state};

pub const CLASS: &str = "SiderouteTray";
const WM_TRAY: u32 = WM_APP + 1;
/// Posted by the command line after pairing or changing the list.
pub const WM_RELOAD: u32 = WM_APP + 2;
const WM_BALLOON: u32 = WM_APP + 3;
const WM_REFRESH: u32 = WM_APP + 4;

const ID_PAIR_CLIPBOARD: usize = 10;
const ID_WARP: usize = 11;
const ID_OFF: usize = 12;
const ID_QUIT: usize = 13;
const ID_REPORT: usize = 14;
const ID_REMOVE: usize = 100; // + index into the tunneled list
const ID_ADD: usize = 500; // + index into the window list

#[derive(Clone, Copy, PartialEq)]
enum Health {
    Connecting,
    Connected,
    /// tunnel configured but no recent handshake
    NoAnswer,
    NotPaired,
    Error,
}

struct Shared {
    tunnel: Mutex<Option<Tunnel>>,
    egress: Egress,
    health: Mutex<(Health, String)>,
    hwnd: AtomicPtr<core::ffi::c_void>,
    menu_windows: Mutex<Vec<String>>,
    taskbar_created: u32,
}

static SHARED: OnceLock<Arc<Shared>> = OnceLock::new();

fn shared() -> &'static Arc<Shared> {
    SHARED.get().expect("tray not initialised")
}

pub fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn copy_wide(dst: &mut [u16], s: &str) {
    let w: Vec<u16> = OsStr::new(s).encode_wide().take(dst.len() - 1).collect();
    dst[..w.len()].copy_from_slice(&w);
    dst[w.len()] = 0;
}

fn icon_data(hwnd: HWND) -> NOTIFYICONDATAW {
    let mut d: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    d.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
    d.hWnd = hwnd;
    d.uID = 1;
    d
}

fn via() -> String {
    if state::load_warp().is_some() {
        "Cloudflare WARP".into()
    } else {
        state::load_config().map(|c| c.endpoint).unwrap_or_default()
    }
}

/// Icon and tooltip text for the current state.
fn look() -> (HICON, String) {
    let (health, detail) = shared().health.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let apps = state::apps();
    let line1 = match health {
        Health::Connecting => t("Sideroute: connecting...", "Sideroute: bağlanıyor...").to_string(),
        Health::Connected => t1("Sideroute: connected via {}", "Sideroute: {} üzerinden bağlı", &via()),
        Health::NoAnswer => t1("Sideroute: no answer from {}", "Sideroute: {} yanıt vermiyor", &via()),
        Health::NotPaired => t("Sideroute: not set up", "Sideroute: kurulmadı").to_string(),
        Health::Error => format!("Sideroute: {detail}"),
    };
    let line2 = if apps.is_empty() {
        t("No programs in the tunnel", "Tünelde program yok").to_string()
    } else {
        t1("In the tunnel: {}", "Tünelde: {}", &state::redirected_names().join(", "))
    };
    // icon resources (windows/app.rc): 2 idle, 3 programs tunneled, 4 problem
    let i = match health {
        Health::Connected if !apps.is_empty() => 1,
        Health::NoAnswer | Health::Error => 2,
        _ => 0,
    };
    (tray_icons()[i] as HICON, format!("{line1}\n{line2}"))
}

/// The three tray icons at the notification area's size, loaded once.
fn tray_icons() -> &'static [usize; 3] {
    static ICONS: OnceLock<[usize; 3]> = OnceLock::new();
    ICONS.get_or_init(|| {
        let hinst = unsafe { GetModuleHandleW(std::ptr::null()) };
        [2u16, 3, 4].map(|id| {
            let mut icon: HICON = std::ptr::null_mut();
            unsafe { LoadIconMetric(hinst, id as usize as *const u16, LIM_SMALL, &mut icon) };
            if icon.is_null() {
                icon = unsafe { LoadIconW(std::ptr::null_mut(), IDI_APPLICATION) };
            }
            icon as usize
        })
    })
}

fn update_icon(hwnd: HWND, add: bool) {
    let (icon, tip) = look();
    let mut d = icon_data(hwnd);
    d.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    d.uCallbackMessage = WM_TRAY;
    d.hIcon = icon;
    copy_wide(&mut d.szTip, &tip);
    unsafe { Shell_NotifyIconW(if add { NIM_ADD } else { NIM_MODIFY }, &d) };
}

/// Asks the UI thread to redraw the icon and tooltip.
fn refresh() {
    if let Some(s) = SHARED.get() {
        unsafe { PostMessageW(s.hwnd.load(Ordering::SeqCst), WM_REFRESH, 0, 0) };
    }
}

fn set_health(h: Health, detail: &str) {
    *shared().health.lock().unwrap_or_else(|p| p.into_inner()) = (h, detail.to_string());
    refresh();
}

/// Shows a notification (from any thread).
pub fn notify(title: &str, text: &str, error: bool) {
    let Some(s) = SHARED.get() else { return };
    let hwnd = s.hwnd.load(Ordering::SeqCst);
    let boxed = Box::new((title.to_string(), text.to_string(), error));
    unsafe { PostMessageW(hwnd, WM_BALLOON, 0, Box::into_raw(boxed) as LPARAM) };
}

fn balloon(hwnd: HWND, title: &str, text: &str, error: bool) {
    let mut d = icon_data(hwnd);
    d.uFlags = NIF_INFO;
    d.dwInfoFlags = if error { NIIF_ERROR } else { NIIF_INFO };
    copy_wide(&mut d.szInfoTitle, title);
    copy_wide(&mut d.szInfo, text);
    unsafe { Shell_NotifyIconW(NIM_MODIFY, &d) };
}

fn handshake_age(t: &Tunnel) -> Option<u64> {
    t.stats().last_handshake.map(|h| SystemTime::now().duration_since(h).map(|d| d.as_secs()).unwrap_or(0))
}

/// Brings the tunnel up from the saved configuration and re-applies the program list.
fn connect() {
    let s = shared();
    set_health(Health::Connecting, "");
    *s.egress.write().unwrap_or_else(|p| p.into_inner()) = None;
    *s.tunnel.lock().unwrap_or_else(|p| p.into_inner()) = None; // drops (removes) the old adapter
    let mut cfg = match state::load_config() {
        Ok(c) => c,
        Err(_) => {
            set_health(Health::NotPaired, "");
            notify(
                "Sideroute",
                t("Not set up yet: open this icon's menu and choose WARP or pair with your server.",
                  "Henüz kurulmadı: bu simgenin menüsünden WARP'ı seç ya da sunucunla eşleştir."),
                false,
            );
            return;
        }
    };
    log::log(&format!("tunnel: starting, endpoint {} address {}", cfg.endpoint, cfg.client_address));
    let result = state::private_key().and_then(|key| {
        let mut t = Tunnel::up(&cfg, &key)?;
        log::log(&format!("tunnel: adapter up (index {})", t.index));
        let wait = |t: &Tunnel| (0..30).any(|_| {
            std::thread::sleep(Duration::from_millis(200));
            t.stats().last_handshake.is_some()
        });
        let mut ok = wait(&t);
        // WARP answers on several ports; some networks block the first one
        if !ok {
            if let Some(w) = state::load_warp() {
                let host = cfg.endpoint.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_default();
                for p in w.ports.iter().skip(1) {
                    log::log(&format!("tunnel: no handshake, trying port {p}"));
                    cfg.endpoint = format!("{host}:{p}");
                    t.configure(&cfg, &key)?;
                    if wait(&t) {
                        ok = true;
                        let _ = state::save_config(&cfg);
                        break;
                    }
                }
            }
        }
        *s.egress.write().unwrap_or_else(|p| p.into_inner()) = Some((t.address, t.index));
        *s.tunnel.lock().unwrap_or_else(|p| p.into_inner()) = Some(t);
        Ok(ok)
    });
    match result {
        Ok(true) => {
            log::log(&format!("tunnel: handshake ok ({})", cfg.endpoint));
            set_health(Health::Connected, "");
        }
        Ok(false) => {
            log::log("tunnel: no handshake on any port");
            set_health(Health::NoAnswer, "");
            notify(
                "Sideroute",
                &t1("{} does not answer. Tunneled programs stay offline until it does.",
                    "{} yanıt vermiyor. Tüneldeki programlar o yanıt verene kadar çevrimdışı kalır.", &via()),
                true,
            );
        }
        Err(e) => {
            log::log(&format!("tunnel: error: {e}"));
            set_health(Health::Error, &e);
            notify(t("Sideroute: tunnel error", "Sideroute: tünel hatası"), &e, true);
        }
    }
    if let Err(e) = app::restore() {
        log::log(&format!("redirect: {e}"));
        notify("Sideroute", &e, true);
    }
    refresh();
}

/// Watches the handshake so the icon shows when the far end stops answering.
fn monitor() {
    loop {
        std::thread::sleep(Duration::from_secs(20));
        let s = shared();
        let age = s.tunnel.lock().unwrap_or_else(|p| p.into_inner()).as_ref().map(handshake_age);
        let current = s.health.lock().unwrap_or_else(|p| p.into_inner()).0;
        match (age, current) {
            // WireGuard renews the handshake every two minutes while traffic flows
            (Some(Some(a)), Health::Connected) if a > 200 => {
                log::log(&format!("tunnel: last handshake {a}s ago"));
                set_health(Health::NoAnswer, "");
            }
            (Some(Some(a)), Health::NoAnswer) if a <= 200 => set_health(Health::Connected, ""),
            _ => {}
        }
    }
}

fn spawn(f: impl FnOnce() + Send + 'static) {
    std::thread::spawn(f);
}

fn toggle(exe: String) {
    match app::toggle(&exe) {
        Ok(true) => {
            log::log(&format!("{exe}: into the tunnel"));
            let msg = match shared().health.lock().unwrap_or_else(|p| p.into_inner()).0 {
                Health::Connected => t1("{} now connects through the tunnel.", "{} artık tünelden bağlanıyor.", &exe),
                _ => t1("{} is routed to the tunnel, but the tunnel is not connected: it stays offline until it is.",
                        "{} tünele alındı ama tünel bağlı değil: bağlanana kadar çevrimdışı kalır.", &exe),
            };
            notify(t("Tunnel on", "Tünel açık"), &msg, false);
        }
        Ok(false) => {
            log::log(&format!("{exe}: direct"));
            notify(t("Tunnel off", "Tünel kapalı"), &t1("{} now connects directly.", "{} artık doğrudan bağlanıyor.", &exe), false);
        }
        Err(e) => {
            log::log(&format!("{exe}: {e}"));
            notify("Sideroute", &e, true);
        }
    }
    refresh();
}

fn clipboard_text(hwnd: HWND) -> Option<String> {
    const CF_UNICODETEXT: u32 = 13;
    unsafe {
        if OpenClipboard(hwnd) == 0 {
            return None;
        }
        let h = GetClipboardData(CF_UNICODETEXT);
        let mut out = None;
        if !h.is_null() {
            let p = GlobalLock(h as _) as *const u16;
            if !p.is_null() {
                let mut len = 0;
                while *p.add(len) != 0 && len < 4096 {
                    len += 1;
                }
                out = Some(String::from_utf16_lossy(std::slice::from_raw_parts(p, len)));
                GlobalUnlock(h as _);
            }
        }
        CloseClipboard();
        out
    }
}

fn pair(code: String) {
    match app::pair(&code) {
        Ok(msg) => {
            log::log(&msg);
            notify("Sideroute", &msg, false);
            connect();
        }
        Err(e) => {
            log::log(&format!("pairing failed: {e}"));
            notify(t("Sideroute: pairing failed", "Sideroute: eşleştirme başarısız"), &e, true);
        }
    }
}

/// Writes the troubleshooting report next to the log and opens it in Notepad.
fn open_report() {
    notify("Sideroute", t("Preparing the report (takes a few seconds)...", "Rapor hazırlanıyor (birkaç saniye sürer)..."), false);
    let text = diag::report(true);
    let path = state::dir().join("report.txt");
    if std::fs::write(&path, text.replace('\n', "\r\n")).is_ok() {
        unsafe {
            ShellExecuteW(std::ptr::null_mut(), wide("open").as_ptr(), wide("notepad.exe").as_ptr(), wide(&path.to_string_lossy()).as_ptr(), std::ptr::null(), SW_SHOWNORMAL)
        };
    }
}

fn show_menu(hwnd: HWND) {
    let s = shared();
    let tunneled = state::apps();
    let windows: Vec<String> = procs::window_apps().into_iter().filter(|a| !tunneled.contains(a)).collect();
    let (_, tip) = look();
    let mut status = tip.lines().next().unwrap_or("").to_string();
    if let Some(tn) = s.tunnel.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
        let st = tn.stats();
        status.push_str(&format!("  (\u{2193} {:.1} MB  \u{2191} {:.1} MB)", st.rx as f64 / 1e6, st.tx as f64 / 1e6));
    }
    unsafe {
        let menu = CreatePopupMenu();
        AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, wide(&status).as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        if tunneled.is_empty() {
            AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, wide(t("No programs in the tunnel", "Tünelde program yok")).as_ptr());
        } else {
            AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, wide(t("In the tunnel (click to remove):", "Tünelde (çıkarmak için tıkla):")).as_ptr());
        }
        for (i, a) in tunneled.iter().enumerate() {
            AppendMenuW(menu, MF_STRING | MF_CHECKED, ID_REMOVE + i, wide(a).as_ptr());
        }
        let add = CreatePopupMenu();
        for (i, a) in windows.iter().enumerate().take(300) {
            AppendMenuW(add, MF_STRING, ID_ADD + i, wide(a).as_ptr());
        }
        AppendMenuW(menu, MF_POPUP, add as usize, wide(t("Route a running program", "Çalışan bir programı tünele al")).as_ptr());
        AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, wide(t("Active window: Ctrl+Alt+V", "Etkin pencere: Ctrl+Alt+V")).as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        AppendMenuW(menu, MF_STRING, ID_PAIR_CLIPBOARD, wide(t("Pair with my server (code from clipboard)", "Sunucumla eşleştir (kod panoda)")).as_ptr());
        AppendMenuW(menu, MF_STRING, ID_WARP, wide(t("Use Cloudflare WARP (no server needed)", "Cloudflare WARP kullan (sunucu gerekmez)")).as_ptr());
        AppendMenuW(menu, MF_STRING, ID_OFF, wide(t("Route all programs directly", "Tüm programları doğrudan bağla")).as_ptr());
        AppendMenuW(menu, MF_STRING, ID_REPORT, wide(t("Troubleshooting report", "Sorun giderme raporu")).as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        AppendMenuW(menu, MF_STRING, ID_QUIT, wide(t("Quit (programs connect directly)", "Çık (programlar doğrudan bağlanır)")).as_ptr());
        *s.menu_windows.lock().unwrap_or_else(|p| p.into_inner()) = windows;

        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        SetForegroundWindow(hwnd); // otherwise the menu does not close when clicking elsewhere
        TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, 0, hwnd, std::ptr::null());
        PostMessageW(hwnd, WM_NULL, 0, 0);
        DestroyMenu(menu);
    }
}

fn command(hwnd: HWND, id: usize) {
    match id {
        ID_PAIR_CLIPBOARD => match clipboard_text(hwnd).filter(|c| c.trim().to_lowercase().starts_with("sr1:")) {
            Some(code) => spawn(move || pair(code)),
            None => notify(
                "Sideroute",
                t("Copy the pairing code (sr1:...) shown by your server first, then choose this again.",
                  "Önce sunucunun gösterdiği eşleştirme kodunu (sr1:...) kopyala, sonra bunu tekrar seç."),
                true,
            ),
        },
        ID_WARP => spawn(|| pair("warp".into())),
        ID_OFF => spawn(|| {
            match app::off() {
                Ok(()) => notify(t("Tunnel off", "Tünel kapalı"), t("All programs connect directly.", "Tüm programlar doğrudan bağlanıyor."), false),
                Err(e) => notify("Sideroute", &e, true),
            }
            refresh();
        }),
        ID_REPORT => spawn(open_report),
        ID_QUIT => {
            let _ = app::off_keep_list();
            unsafe { DestroyWindow(hwnd) };
        }
        i if (ID_REMOVE..ID_ADD).contains(&i) => {
            if let Some(a) = state::apps().get(i - ID_REMOVE).cloned() {
                spawn(move || toggle(a));
            }
        }
        i if i >= ID_ADD => {
            let list = shared().menu_windows.lock().unwrap_or_else(|p| p.into_inner()).clone();
            if let Some(a) = list.get(i - ID_ADD).cloned() {
                spawn(move || toggle(a));
            }
        }
        _ => {}
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_TRAY => {
            let ev = (lp & 0xffff) as u32;
            if ev == WM_RBUTTONUP || ev == WM_LBUTTONUP || ev == WM_CONTEXTMENU {
                show_menu(hwnd);
            }
            0
        }
        WM_HOTKEY => {
            match procs::foreground_app() {
                Some(exe) => spawn(move || toggle(exe)),
                None => notify("Sideroute", t("No program window is active.", "Etkin bir program penceresi yok."), true),
            }
            0
        }
        WM_RELOAD => {
            spawn(connect);
            0
        }
        WM_REFRESH => {
            update_icon(hwnd, false);
            0
        }
        WM_BALLOON => {
            let b = unsafe { Box::from_raw(lp as *mut (String, String, bool)) };
            balloon(hwnd, &b.0, &b.1, b.2);
            0
        }
        WM_COMMAND => {
            command(hwnd, wp & 0xffff);
            0
        }
        WM_DESTROY => {
            let d = icon_data(hwnd);
            unsafe { Shell_NotifyIconW(NIM_DELETE, &d) };
            unsafe { PostQuitMessage(0) };
            0
        }
        m if m == shared().taskbar_created => {
            update_icon(hwnd, true); // Explorer restarted
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wp, lp) },
    }
}

pub fn run() -> Result<(), String> {
    let mutex_name = wide("Local\\SiderouteTray");
    unsafe { CreateMutexW(std::ptr::null(), 1, mutex_name.as_ptr()) };
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        return Ok(()); // already running
    }
    log::init();
    log::log(&format!("Sideroute {} starting", env!("CARGO_PKG_VERSION")));
    let egress: Egress = Arc::new(RwLock::new(None));
    socks::start(state::SOCKS_PORT, egress.clone()).map_err(|e| format!("SOCKS5 port {}: {e}", state::SOCKS_PORT))?;
    let taskbar_created = unsafe { RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()) };
    let _ = SHARED.set(Arc::new(Shared {
        tunnel: Mutex::new(None),
        egress,
        health: Mutex::new((Health::Connecting, String::new())),
        hwnd: AtomicPtr::new(std::ptr::null_mut()),
        menu_windows: Mutex::new(Vec::new()),
        taskbar_created,
    }));

    let class = wide(CLASS);
    let hinst = unsafe { GetModuleHandleW(std::ptr::null()) };
    let mut wc: WNDCLASSW = unsafe { std::mem::zeroed() };
    wc.lpfnWndProc = Some(wndproc);
    wc.hInstance = hinst;
    wc.lpszClassName = class.as_ptr();
    unsafe { RegisterClassW(&wc) };
    let hwnd = unsafe {
        CreateWindowExW(0, class.as_ptr(), class.as_ptr(), WS_OVERLAPPED, 0, 0, 0, 0, std::ptr::null_mut(), std::ptr::null_mut(), hinst, std::ptr::null())
    };
    if hwnd.is_null() {
        return Err("cannot create the tray window".into());
    }
    shared().hwnd.store(hwnd, Ordering::SeqCst);
    update_icon(hwnd, true);
    if unsafe { RegisterHotKey(hwnd, 1, MOD_CONTROL | MOD_ALT | MOD_NOREPEAT, 'V' as u32) } == 0 {
        log::log("hotkey Ctrl+Alt+V is taken");
        notify("Sideroute", t("Ctrl+Alt+V is taken by another program; use the tray menu instead.",
                               "Ctrl+Alt+V başka bir program tarafından kullanılıyor; simgenin menüsünü kullan."), false);
    }
    spawn(connect);
    spawn(monitor);
    spawn(|| {
        let dpi = procs::dpi_tools();
        if !dpi.is_empty() {
            log::log(&format!("{} is running", dpi.join(", ")));
            notify(
                "Sideroute",
                &t1("{} is running. It alters network traffic and breaks connections through the tunnel; close it while you use Sideroute.",
                    "{} çalışıyor. Ağ trafiğini değiştirdiği için tünelden geçen bağlantıları bozar; Sideroute kullanırken kapat.",
                    &dpi.join(", ")),
                true,
            );
        }
    });

    let mut msg: MSG = unsafe { std::mem::zeroed() };
    while unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) } > 0 {
        unsafe {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    log::log("Sideroute quitting");
    *shared().egress.write().unwrap_or_else(|p| p.into_inner()) = None;
    *shared().tunnel.lock().unwrap_or_else(|p| p.into_inner()) = None;
    Ok(())
}
