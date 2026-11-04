//! Sideroute for Windows: routes chosen programs through your own Sideroute server or through
//! Cloudflare WARP, without restarting them.
//!
//! ```text
//! Sideroute.exe                    setup wizard (downloaded copy) / notification-area app (installed copy)
//! Sideroute.exe setup [--quiet [--warp | --code CODE] [--no-autostart]]
//! Sideroute.exe uninstall [--quiet]
//! Sideroute.exe pair <CODE|warp>   pair with a server, or use Cloudflare WARP
//! Sideroute.exe toggle <program>   e.g. firefox.exe: into the tunnel, or back out
//! Sideroute.exe status | off | diag
//! ```
//!
//! Pieces: wireguard-nt runs the tunnel; a SOCKS5 server on 127.0.0.1 sends connections out
//! through it; ProxiFyre redirects the chosen programs to that SOCKS5 server.
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("Sideroute is the Windows client; build it for a Windows target.");
    std::process::exit(1);
}

#[cfg(windows)]
mod app;
#[cfg(windows)]
mod diag;
#[cfg(windows)]
mod i18n;
#[cfg(windows)]
mod log;
#[cfg(windows)]
mod procs;
#[cfg(windows)]
mod redirect;
#[cfg(windows)]
mod setup;
#[cfg(windows)]
mod socks;
#[cfg(windows)]
mod state;
#[cfg(windows)]
mod tray;
#[cfg(windows)]
mod wg;
#[cfg(windows)]
mod wizard;

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use std::process::ExitCode;
    use windows_sys::Win32::System::Console::{ATTACH_PARENT_PROCESS, AttachConsole};
    use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
    use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowW, PostMessageW, SW_SHOWNORMAL};

    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    if !cmd.is_empty() {
        // a GUI-subsystem program has no console; print into the one we were started from
        unsafe { AttachConsole(ATTACH_PARENT_PROCESS) };
    }
    let admin = unsafe { IsUserAnAdmin() } != 0;
    // runs this program again with administrator rights (UAC prompt)
    let elevate = |params: &str| {
        let exe = std::env::current_exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
        unsafe {
            ShellExecuteW(std::ptr::null_mut(), tray::wide("runas").as_ptr(), tray::wide(&exe).as_ptr(), tray::wide(params).as_ptr(), std::ptr::null(), SW_SHOWNORMAL)
        };
    };
    let rest = args[2.min(args.len())..].join(" ");
    match cmd {
        // the downloaded file is the installer; the installed copy is the tray app
        "" if !setup::running_installed() => {
            if !admin {
                elevate("setup");
                return ExitCode::SUCCESS;
            }
            return finish(wizard::run(), true);
        }
        "" if !admin => {
            // started from the Start menu: the scheduled task runs it elevated without a prompt
            if setup::start_tray().is_err() {
                elevate("");
            }
            return ExitCode::SUCCESS;
        }
        "setup" | "uninstall" if !admin => {
            elevate(&format!("{cmd} {rest}"));
            return ExitCode::SUCCESS;
        }
        "setup" if !args.iter().any(|a| a == "--quiet") => return finish(wizard::run(), true),
        "setup" => return finish(quiet_setup(&args), false),
        "uninstall" => return finish(uninstall(args.iter().any(|a| a == "--quiet")), args.iter().all(|a| a != "--quiet")),
        _ if !admin => {
            eprintln!("run this from an administrator terminal");
            return ExitCode::FAILURE;
        }
        _ => {}
    }
    // tell a running tray to pick up changes made here
    let reload = || unsafe {
        let hwnd = FindWindowW(tray::wide(tray::CLASS).as_ptr(), std::ptr::null());
        if !hwnd.is_null() {
            PostMessageW(hwnd, tray::WM_RELOAD, 0, 0);
        }
    };
    let res: Result<(), String> = match cmd {
        "" | "tray" => tray::run(),
        "setup" | "uninstall" => unreachable!(),
        "pair" => app::pair(args.get(2).map(String::as_str).unwrap_or("warp")).map(|m| {
            println!("{m}");
            reload();
        }),
        "toggle" => match args.get(2) {
            Some(p) => app::toggle(p).map(|on| {
                println!("{p}: {}", if on { "through the tunnel" } else { "direct" });
                reload();
            }),
            None => Err("usage: Sideroute.exe toggle <program.exe>".into()),
        },
        "off" => app::off(),
        "diag" | "report" => {
            println!("{}", diag::report(false));
            Ok(())
        }
        "status" => {
            match state::load_config() {
                Ok(c) => {
                    let via = if state::load_warp().is_some() { "Cloudflare WARP" } else { "own server" };
                    println!("paired: yes ({via} {}, address {})", c.endpoint, c.client_address);
                }
                Err(_) => println!("paired: no"),
            }
            let apps = state::apps();
            println!("programs in the tunnel: {}", if apps.is_empty() { "none".into() } else { apps.join(", ") });
            println!("ProxiFyre: {}", if redirect::installed() { "installed" } else { "missing" });
            Ok(())
        }
        "version" | "--version" => {
            println!("Sideroute {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => Err("usage: Sideroute.exe [pair <CODE|warp> | toggle <program.exe> | status | off | diag]".into()),
    };
    finish(res, false)
}

/// Exit code for a result; errors go to the console, or to a message box for GUI flows.
#[cfg(windows)]
fn finish(res: Result<(), String>, gui: bool) -> std::process::ExitCode {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
    match res {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            if gui {
                unsafe { MessageBoxW(std::ptr::null_mut(), tray::wide(&e).as_ptr(), tray::wide("Sideroute").as_ptr(), MB_OK | MB_ICONERROR) };
            }
            std::process::ExitCode::FAILURE
        }
    }
}

/// `setup --quiet [--warp | --code CODE] [--no-autostart]`: unattended install.
#[cfg(windows)]
fn quiet_setup(args: &[String]) -> Result<(), String> {
    let pairing = match args.iter().position(|a| a == "--code").and_then(|i| args.get(i + 1)) {
        Some(c) => setup::Pairing::Code(c.clone()),
        None if args.iter().any(|a| a == "--warp") => setup::Pairing::Warp,
        None => setup::Pairing::Keep,
    };
    let opts = setup::Options { pairing, autostart: !args.iter().any(|a| a == "--no-autostart") };
    let msg = setup::install(&opts, &|n, text| println!("[{n}/{}] {text}", setup::STEPS))?;
    if !msg.is_empty() {
        println!("{msg}");
    }
    setup::start_tray()
}

#[cfg(windows)]
fn uninstall(quiet: bool) -> Result<(), String> {
    use i18n::t;
    use windows_sys::Win32::UI::WindowsAndMessaging::{IDYES, MB_ICONINFORMATION, MB_ICONQUESTION, MB_OK, MB_YESNO, MessageBoxW};
    let ask = |text: &str, flags| unsafe { MessageBoxW(std::ptr::null_mut(), tray::wide(text).as_ptr(), tray::wide("Sideroute").as_ptr(), flags) };
    if !quiet && ask(t("Remove Sideroute from this computer?", "Sideroute bu bilgisayardan kaldırılsın mı?"), MB_YESNO | MB_ICONQUESTION) != IDYES {
        return Ok(());
    }
    let purge = !quiet
        && ask(
            t("Also delete the pairing and keys?\n\nChoose No to keep them, so a later installation works with the same settings.",
              "Eşleştirme ve anahtarlar da silinsin mi?\n\nHayır dersen saklanır; sonra tekrar kurarsan aynı ayarlarla çalışır."),
            MB_YESNO | MB_ICONQUESTION,
        ) == IDYES;
    setup::uninstall(purge)?;
    if !quiet {
        ask(
            t("Sideroute was removed.\n\nProxiFyre and Windows Packet Filter stay installed; remove them in Settings > Apps if nothing else uses them.",
              "Sideroute kaldırıldı.\n\nProxiFyre ve Windows Packet Filter kurulu kalır; başka bir şey kullanmıyorsa Ayarlar > Uygulamalar'dan kaldırabilirsin."),
            MB_OK | MB_ICONINFORMATION,
        );
    }
    Ok(())
}
