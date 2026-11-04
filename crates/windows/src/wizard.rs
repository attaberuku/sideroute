//! Setup wizard: one window with three pages (options, progress, result). Native Win32 controls
//! with the themed common controls from the manifest, scaled for the screen's DPI.

use std::cell::RefCell;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, CLEARTYPE_QUALITY, CLIP_DEFAULT_PRECIS, CreateFontW, CreateSolidBrush, DEFAULT_CHARSET, DEFAULT_PITCH,
    DT_LEFT, DT_SINGLELINE, DrawTextW, EndPaint, FW_NORMAL, FW_SEMIBOLD, GRADIENT_FILL_RECT_H, GRADIENT_RECT,
    GetStockObject, GradientFill, HBRUSH, HDC, HFONT, InvalidateRect, OUT_DEFAULT_PRECIS, PAINTSTRUCT, SelectObject,
    SetBkColor, SetBkMode, SetTextColor, TRANSPARENT, TRIVERTEX, WHITE_BRUSH,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::{ICC_PROGRESS_CLASS, ICC_STANDARD_CLASSES, INITCOMMONCONTROLSEX, InitCommonControlsEx};
use windows_sys::Win32::UI::HiDpi::{AdjustWindowRectExForDpi, GetDpiForSystem};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, DrawIconEx, GetMessageW, GetSystemMetrics,
    GetWindowTextLengthW, GetWindowTextW, IMAGE_ICON, IsDialogMessageW, LR_DEFAULTCOLOR, LoadCursorW, LoadImageW,
    IDC_ARROW, MB_ICONWARNING, MB_OK, MSG, MessageBoxW, PostMessageW, PostQuitMessage, RegisterClassW, SM_CXSCREEN,
    SM_CYSCREEN, SW_HIDE, SW_SHOW, SendMessageW, SetWindowTextW, ShowWindow, TranslateMessage, WM_APP, WM_CLOSE,
    WM_COMMAND, WM_CTLCOLORSTATIC, WM_DESTROY, WM_PAINT, WM_SETFONT, WNDCLASSW, WS_CAPTION, WS_CHILD,
    WS_EX_CLIENTEDGE, WS_EX_CONTROLPARENT, WS_GROUP, WS_MINIMIZEBOX, WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
};

use crate::i18n::t;
use crate::setup::{self, Options, Pairing};
use crate::state;

const W: i32 = 560;
const H: i32 = 440;
const HEADER: i32 = 96;
const MARGIN: i32 = 28;

const WM_STEP: u32 = WM_APP + 10;
const WM_DONE: u32 = WM_APP + 11;

// control ids
const ID_KEEP: usize = 1;
const ID_WARP: usize = 2;
const ID_SERVER: usize = 3;
const ID_CODE: usize = 4;
const ID_AUTOSTART: usize = 5;
const ID_INSTALL: usize = 6;
const ID_CANCEL: usize = 7;
const ID_FINISH: usize = 8;
const ID_BACK: usize = 9;
const ID_LAUNCH: usize = 10;

const BM_GETCHECK: u32 = 0x00F0;
const BM_SETCHECK: u32 = 0x00F1;
const BST_CHECKED: usize = 1;
const BS_PUSHBUTTON: u32 = 0;
const BS_DEFPUSHBUTTON: u32 = 1;
const BS_AUTOCHECKBOX: u32 = 3;
const BS_AUTORADIOBUTTON: u32 = 9;
const BN_CLICKED: usize = 0;
const ES_AUTOHSCROLL: u32 = 0x0080;
const EM_SETCUEBANNER: u32 = 0x1501;
const PBM_SETPOS: u32 = 0x0402;
const PBM_SETRANGE32: u32 = 0x0406;

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn rgb(r: u8, g: u8, b: u8) -> COLORREF {
    r as u32 | (g as u32) << 8 | (b as u32) << 16
}

/// Window handles and state. Handlers work on a copy, so no borrow is held while Windows calls
/// back into the window procedure (message boxes, focus changes).
#[derive(Clone)]
struct Ui {
    dpi: i32,
    hwnd: HWND,
    font: HFONT,
    bold: HFONT,
    big: HFONT,
    title: HFONT,
    note_brush: HBRUSH,
    // options page
    options: Vec<HWND>,
    keep: HWND,
    warp: HWND,
    server: HWND,
    code: HWND,
    autostart: HWND,
    note: HWND,
    install: HWND,
    cancel: HWND,
    // progress page
    progress: Vec<HWND>,
    bar: HWND,
    status: HWND,
    // result page
    result: Vec<HWND>,
    result_title: HWND,
    result_text: HWND,
    launch: HWND,
    finish: HWND,
    back: HWND,
    busy: bool,
    ok: bool,
}

impl Default for Ui {
    fn default() -> Self {
        let n = std::ptr::null_mut();
        Ui {
            dpi: 96, hwnd: n, font: n, bold: n, big: n, title: n, note_brush: n,
            options: Vec::new(), keep: n, warp: n, server: n, code: n, autostart: n, note: n, install: n, cancel: n,
            progress: Vec::new(), bar: n, status: n,
            result: Vec::new(), result_title: n, result_text: n, launch: n, finish: n, back: n,
            busy: false, ok: false,
        }
    }
}

thread_local! {
    static UI: RefCell<Ui> = RefCell::new(Ui::default());
}

fn s(v: i32, dpi: i32) -> i32 {
    v * dpi / 96
}

fn font(pt: i32, weight: i32, dpi: i32) -> HFONT {
    let face = wide("Segoe UI");
    unsafe {
        CreateFontW(-(pt * dpi / 72), 0, 0, 0, weight, 0, 0, 0, DEFAULT_CHARSET as u32, OUT_DEFAULT_PRECIS as u32,
                    CLIP_DEFAULT_PRECIS as u32, CLEARTYPE_QUALITY as u32, DEFAULT_PITCH as u32, face.as_ptr())
    }
}

/// Creates a child control at logical coordinates.
fn control(ui: &Ui, class: &str, text: &str, style: u32, ex: u32, id: usize, x: i32, y: i32, w: i32, h: i32, f: HFONT) -> HWND {
    let d = ui.dpi;
    let hwnd = unsafe {
        CreateWindowExW(ex, wide(class).as_ptr(), wide(text).as_ptr(), WS_CHILD | style, s(x, d), s(y, d), s(w, d), s(h, d),
                        ui.hwnd, id as _, GetModuleHandleW(std::ptr::null()), std::ptr::null())
    };
    unsafe { SendMessageW(hwnd, WM_SETFONT, f as WPARAM, 1) };
    hwnd
}

fn checked(h: HWND) -> bool {
    unsafe { SendMessageW(h, BM_GETCHECK, 0, 0) == BST_CHECKED as isize }
}

fn set_checked(h: HWND, on: bool) {
    unsafe { SendMessageW(h, BM_SETCHECK, on as usize, 0) };
}

fn text_of(h: HWND) -> String {
    let n = unsafe { GetWindowTextLengthW(h) } as usize;
    let mut buf = vec![0u16; n + 1];
    let got = unsafe { GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32) } as usize;
    String::from_utf16_lossy(&buf[..got])
}

fn set_text(h: HWND, s: &str) {
    unsafe { SetWindowTextW(h, wide(s).as_ptr()) };
}

fn show(list: &[HWND], on: bool) {
    for &h in list {
        unsafe { ShowWindow(h, if on { SW_SHOW } else { SW_HIDE }) };
    }
}

fn build(ui: &mut Ui) {
    let paired = state::load_config().is_ok();
    let reinstall = setup::is_installed();
    let body = WS_VISIBLE;
    let mut y = HEADER + 20;
    let x = MARGIN;
    let cw = W - 2 * MARGIN;

    let head = control(ui, "STATIC", t("Where should the traffic of chosen programs exit?", "Seçilen programların trafiği nereden çıksın?"), body, 0, 0, x, y, cw, 22, ui.bold);
    ui.options.push(head);
    y += 32;
    if paired {
        let current = if state::load_warp().is_some() { "Cloudflare WARP".to_string() } else { state::load_config().map(|c| c.endpoint).unwrap_or_default() };
        let label = format!("{} ({current})", t("Keep the current setting", "Mevcut ayarı koru"));
        ui.keep = control(ui, "BUTTON", &label, body | BS_AUTORADIOBUTTON | WS_GROUP | WS_TABSTOP, 0, ID_KEEP, x, y, cw, 24, ui.font);
        ui.options.push(ui.keep);
        y += 28;
    }
    let first = if paired { 0 } else { WS_GROUP | WS_TABSTOP };
    ui.warp = control(ui, "BUTTON", t("Cloudflare WARP: free, no server needed", "Cloudflare WARP: ücretsiz, sunucu gerekmez"),
                      body | BS_AUTORADIOBUTTON | first, 0, ID_WARP, x, y, cw, 24, ui.font);
    y += 28;
    ui.server = control(ui, "BUTTON", t("My own server, with this pairing code:", "Kendi sunucum, şu eşleştirme koduyla:"),
                        body | BS_AUTORADIOBUTTON, 0, ID_SERVER, x, y, cw, 24, ui.font);
    y += 30;
    ui.code = control(ui, "EDIT", "", body | WS_TABSTOP | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, ID_CODE, x + 20, y, cw - 20, 26, ui.font);
    unsafe { SendMessageW(ui.code, EM_SETCUEBANNER, 1, wide("sr1:...@203.0.113.5:51821").as_ptr() as LPARAM) };
    y += 44;
    ui.autostart = control(ui, "BUTTON", t("Start Sideroute when I sign in to Windows", "Windows açılınca Sideroute'ı başlat"),
                           body | BS_AUTOCHECKBOX | WS_TABSTOP | WS_GROUP, 0, ID_AUTOSTART, x, y, cw, 24, ui.font);
    set_checked(ui.autostart, true);
    y += 36;
    let note = if reinstall {
        t("Sideroute is already installed; this updates it. Your programs list is kept.",
          "Sideroute zaten kurulu; bu kurulum onu günceller. Program listen korunur.")
    } else {
        t("Installs Sideroute, WireGuard (wireguard.dll), ProxiFyre and the Windows Packet Filter driver.",
          "Kurulacaklar: Sideroute, WireGuard (wireguard.dll), ProxiFyre ve Windows Packet Filter sürücüsü.")
    };
    ui.note = control(ui, "STATIC", note, body, 0, 0, x, y, cw, 40, ui.font);
    ui.options.extend([ui.warp, ui.server, ui.code, ui.autostart, ui.note]);
    set_checked(if paired { ui.keep } else { ui.warp }, true);
    unsafe { EnableWindow(ui.code, 0) };

    // footer buttons (shared positions)
    let by = H - 50;
    let label = if reinstall { t("Update", "Güncelle") } else { t("Install", "Kur") };
    ui.install = control(ui, "BUTTON", label, body | BS_DEFPUSHBUTTON | WS_TABSTOP | WS_GROUP, 0, ID_INSTALL, W - MARGIN - 230, by, 110, 32, ui.font);
    ui.cancel = control(ui, "BUTTON", t("Cancel", "İptal"), body | BS_PUSHBUTTON | WS_TABSTOP, 0, ID_CANCEL, W - MARGIN - 110, by, 110, 32, ui.font);
    ui.options.extend([ui.install, ui.cancel]);

    // progress page
    let mut y = HEADER + 28;
    let p_title = control(ui, "STATIC", t("Installing...", "Kuruluyor..."), 0, 0, 0, x, y, cw, 30, ui.big);
    y += 48;
    ui.bar = control(ui, "msctls_progress32", "", 0, 0, 0, x, y, cw, 14, ui.font);
    unsafe { SendMessageW(ui.bar, PBM_SETRANGE32, 0, setup::STEPS as LPARAM) };
    y += 28;
    ui.status = control(ui, "STATIC", "", 0, 0, 0, x, y, cw, 44, ui.font);
    ui.progress = vec![p_title, ui.bar, ui.status];

    // result page
    let mut y = HEADER + 28;
    ui.result_title = control(ui, "STATIC", "", 0, 0, 0, x, y, cw, 30, ui.big);
    y += 46;
    ui.result_text = control(ui, "STATIC", "", 0, 0, 0, x, y, cw, 150, ui.font);
    y += 160;
    ui.launch = control(ui, "BUTTON", t("Start Sideroute now", "Sideroute'ı şimdi başlat"), BS_AUTOCHECKBOX | WS_TABSTOP, 0, ID_LAUNCH, x, y, cw, 24, ui.font);
    set_checked(ui.launch, true);
    ui.back = control(ui, "BUTTON", t("Back", "Geri"), BS_PUSHBUTTON | WS_TABSTOP, 0, ID_BACK, W - MARGIN - 230, by, 110, 32, ui.font);
    ui.finish = control(ui, "BUTTON", t("Finish", "Bitir"), BS_DEFPUSHBUTTON | WS_TABSTOP, 0, ID_FINISH, W - MARGIN - 110, by, 110, 32, ui.font);
    ui.result = vec![ui.result_title, ui.result_text, ui.launch, ui.back, ui.finish];
}

fn paint_header(hwnd: HWND, dc: HDC, ui: &Ui) {
    let d = ui.dpi;
    let v = |x: i32, y: i32, (r, g, b): (u16, u16, u16)| TRIVERTEX { x, y, Red: r << 8, Green: g << 8, Blue: b << 8, Alpha: 0 };
    let verts = [v(0, 0, (0x25, 0x63, 0xeb)), v(s(W, d), s(HEADER, d), (0x7c, 0x3a, 0xed))];
    let rect = GRADIENT_RECT { UpperLeft: 0, LowerRight: 1 };
    unsafe { GradientFill(dc, verts.as_ptr(), 2, &rect as *const _ as *const _, 1, GRADIENT_FILL_RECT_H) };
    unsafe {
        let icon = LoadImageW(GetModuleHandleW(std::ptr::null()), 1 as _, IMAGE_ICON, s(52, d), s(52, d), LR_DEFAULTCOLOR);
        if !icon.is_null() {
            DrawIconEx(dc, s(MARGIN, d), s(22, d), icon as _, s(52, d), s(52, d), 0, std::ptr::null_mut(), 3);
        }
        SetBkMode(dc, TRANSPARENT as i32);
        SetTextColor(dc, rgb(255, 255, 255));
        let old = SelectObject(dc, ui.title as _);
        let mut r = RECT { left: s(MARGIN + 68, d), top: s(20, d), right: s(W - MARGIN, d), bottom: s(54, d) };
        DrawTextW(dc, wide("Sideroute").as_ptr(), -1, &mut r, DT_LEFT | DT_SINGLELINE);
        SelectObject(dc, ui.font as _);
        let mut r = RECT { left: s(MARGIN + 68, d), top: s(56, d), right: s(W - MARGIN, d), bottom: s(80, d) };
        let sub = t("Per-app VPN: the programs you choose go through the tunnel", "Uygulama bazlı VPN: seçtiğin programlar tünelden geçer");
        DrawTextW(dc, wide(sub).as_ptr(), -1, &mut r, DT_LEFT | DT_SINGLELINE);
        SelectObject(dc, old);
    }
    let _ = hwnd;
}

fn page(ui: &Ui, which: u8) {
    show(&ui.options, which == 0);
    show(&ui.progress, which == 1);
    show(&ui.result, which == 2);
    if which == 2 {
        show(&[ui.launch], ui.ok);
        show(&[ui.back], !ui.ok);
    }
}

fn start_install(ui: &Ui) {
    let pairing = if !ui.keep.is_null() && checked(ui.keep) {
        Pairing::Keep
    } else if checked(ui.server) {
        let code = text_of(ui.code);
        if let Err(e) = code.parse::<sideroute_proto::PairingCode>() {
            let msg = format!("{}\n\n{e}", t("The pairing code is not valid.", "Eşleştirme kodu geçerli değil."));
            unsafe { MessageBoxW(ui.hwnd, wide(&msg).as_ptr(), wide("Sideroute").as_ptr(), MB_OK | MB_ICONWARNING) };
            unsafe { SetFocus(ui.code) };
            return;
        }
        Pairing::Code(code)
    } else {
        Pairing::Warp
    };
    let opts = Options { pairing, autostart: checked(ui.autostart) };
    UI.with(|u| u.borrow_mut().busy = true);
    unsafe { SendMessageW(ui.bar, PBM_SETPOS, 0, 0) };
    page(ui, 1);
    let hwnd = ui.hwnd as usize;
    std::thread::spawn(move || {
        let post = |msg: u32, w: usize, text: String| unsafe {
            PostMessageW(hwnd as HWND, msg, w, Box::into_raw(Box::new(text)) as LPARAM);
        };
        let res = setup::install(&opts, &|n, text| post(WM_STEP, n as usize, text.to_string()));
        match res {
            Ok(m) => post(WM_DONE, 1, m),
            Err(e) => post(WM_DONE, 0, e),
        }
    });
}

fn finish_text(paired: &str) -> String {
    let mut s = String::new();
    if !paired.is_empty() {
        s.push_str(paired);
        s.push_str("\n\n");
    }
    s.push_str(t(
        "Press Ctrl+Alt+V in a program to send it through the tunnel, and again to switch it back.\n\nThe Sideroute icon in the notification area shows the state and lists the programs in the tunnel; its menu can also add programs.",
        "Bir programdayken Ctrl+Alt+V'ye bas: program tünele girer, tekrar basınca çıkar.\n\nBildirim alanındaki Sideroute simgesi durumu ve tüneldeki programları gösterir; menüsünden program da ekleyebilirsin.",
    ));
    s
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_PAINT => {
            let mut ps: PAINTSTRUCT = unsafe { std::mem::zeroed() };
            let dc = unsafe { BeginPaint(hwnd, &mut ps) };
            let u = UI.with(|u| u.borrow().clone());
            paint_header(hwnd, dc, &u);
            unsafe { EndPaint(hwnd, &ps) };
            0
        }
        WM_CTLCOLORSTATIC => {
            let dc = wp as HDC;
            let (note, brush) = UI.with(|u| {
                let u = u.borrow();
                (u.note, u.note_brush)
            });
            unsafe {
                SetBkColor(dc, rgb(255, 255, 255));
                if lp as HWND == note {
                    SetTextColor(dc, rgb(0x64, 0x74, 0x8b));
                }
            }
            brush as LRESULT
        }
        WM_COMMAND => {
            let id = wp & 0xffff;
            let code = (wp >> 16) & 0xffff;
            let u = UI.with(|u| u.borrow().clone());
            match (id, code) {
                (ID_KEEP | ID_WARP | ID_SERVER, BN_CLICKED) => unsafe {
                    EnableWindow(u.code, checked(u.server) as i32);
                    if checked(u.server) {
                        SetFocus(u.code);
                    }
                },
                (ID_INSTALL, BN_CLICKED) => start_install(&u),
                (ID_CANCEL, BN_CLICKED) => unsafe {
                    DestroyWindow(hwnd);
                },
                (ID_BACK, BN_CLICKED) => page(&u, 0),
                (ID_FINISH, BN_CLICKED) => {
                    if u.ok && checked(u.launch) {
                        let _ = setup::start_tray();
                    }
                    unsafe { DestroyWindow(hwnd) };
                }
                _ => {}
            }
            0
        }
        WM_STEP => {
            let text = unsafe { Box::from_raw(lp as *mut String) };
            let u = UI.with(|u| u.borrow().clone());
            unsafe { SendMessageW(u.bar, PBM_SETPOS, wp, 0) };
            set_text(u.status, &text);
            0
        }
        WM_DONE => {
            let text = unsafe { Box::from_raw(lp as *mut String) };
            let u = UI.with(|u| {
                let mut u = u.borrow_mut();
                u.busy = false;
                u.ok = wp == 1;
                u.clone()
            });
            if u.ok {
                set_text(u.result_title, t("Sideroute is ready", "Sideroute hazır"));
                set_text(u.result_text, &finish_text(&text));
                set_text(u.finish, t("Finish", "Bitir"));
            } else {
                set_text(u.result_title, t("Setup did not finish", "Kurulum tamamlanamadı"));
                set_text(u.result_text, &text);
                set_text(u.finish, t("Close", "Kapat"));
            }
            page(&u, 2);
            unsafe { InvalidateRect(hwnd, std::ptr::null(), 1) };
            0
        }
        WM_CLOSE => {
            // never leave a half-done installation by closing the window
            if !UI.with(|u| u.borrow().busy) {
                unsafe { DestroyWindow(hwnd) };
            }
            0
        }
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wp, lp) },
    }
}

pub fn run() -> Result<(), String> {
    let icc = INITCOMMONCONTROLSEX { dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32, dwICC: ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES };
    unsafe { InitCommonControlsEx(&icc) };
    let hinst = unsafe { GetModuleHandleW(std::ptr::null()) };
    let class = wide("SiderouteSetup");
    let mut wc: WNDCLASSW = unsafe { std::mem::zeroed() };
    wc.lpfnWndProc = Some(wndproc);
    wc.hInstance = hinst;
    wc.lpszClassName = class.as_ptr();
    wc.hbrBackground = unsafe { GetStockObject(WHITE_BRUSH) } as HBRUSH;
    wc.hCursor = unsafe { LoadCursorW(std::ptr::null_mut(), IDC_ARROW) };
    wc.hIcon = unsafe { LoadImageW(hinst, 1 as _, IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR) } as _;
    unsafe { RegisterClassW(&wc) };

    let dpi = unsafe { GetDpiForSystem() } as i32;
    let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    let mut r = RECT { left: 0, top: 0, right: s(W, dpi), bottom: s(H, dpi) };
    unsafe { AdjustWindowRectExForDpi(&mut r, style, 0, WS_EX_CONTROLPARENT, dpi as u32) };
    let (ww, wh) = (r.right - r.left, r.bottom - r.top);
    let (sx, sy) = unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };
    let title = wide(t("Sideroute setup", "Sideroute kurulumu"));
    let hwnd = unsafe {
        CreateWindowExW(WS_EX_CONTROLPARENT, class.as_ptr(), title.as_ptr(), style, (sx - ww) / 2, (sy - wh) / 2, ww, wh,
                        std::ptr::null_mut(), std::ptr::null_mut(), hinst, std::ptr::null())
    };
    if hwnd.is_null() {
        return Err("cannot create the setup window".into());
    }
    let mut ui = Ui {
        dpi,
        hwnd,
        font: font(10, FW_NORMAL as i32, dpi),
        bold: font(10, FW_SEMIBOLD as i32, dpi),
        big: font(15, FW_SEMIBOLD as i32, dpi),
        title: font(20, FW_SEMIBOLD as i32, dpi),
        note_brush: unsafe { CreateSolidBrush(rgb(255, 255, 255)) },
        ..Ui::default()
    };
    build(&mut ui);
    UI.with(|u| *u.borrow_mut() = ui.clone());
    page(&ui, 0);
    unsafe { ShowWindow(hwnd, SW_SHOW) };

    let mut msg: MSG = unsafe { std::mem::zeroed() };
    while unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) } > 0 {
        if unsafe { IsDialogMessageW(hwnd, &msg) } == 0 {
            unsafe {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
    Ok(())
}
