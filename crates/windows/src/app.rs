//! Actions shared by the tray and the command line.

use sideroute_proto::{PairResponse, PairingCode};

use crate::{procs, redirect, state};

/// Pairs with an own server (`code`) or registers with Cloudflare WARP (`code` = "warp" or empty).
pub fn pair(code: &str) -> Result<String, String> {
    let private = state::private_key()?;
    let public = sideroute_net::public_key(&private)?;
    let old_warp = state::load_warp();
    let code = code.trim();
    let (resp, msg): (PairResponse, String) = if code.is_empty() || code.eq_ignore_ascii_case("warp") {
        let (r, account) = sideroute_net::warp_register(&public)?;
        state::save_warp(Some(&account))?;
        let m = format!("Using Cloudflare WARP (tunnel address {}). Cloudflare's terms apply: https://www.cloudflare.com/application/terms/", r.client_address);
        (r, m)
    } else {
        let code: PairingCode = code.parse()?;
        let name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "windows".into());
        let r = sideroute_net::request_pairing(&code, &public, &name, "windows")?;
        state::save_warp(None)?;
        let m = format!("Paired with {} (tunnel address {})", r.endpoint, r.client_address);
        (r, m)
    };
    if let Some(old) = old_warp {
        let _ = sideroute_net::warp_delete(&old);
    }
    if !sideroute_proto::is_wg_key(&resp.server_public_key) {
        return Err("the server sent an invalid key".into());
    }
    state::save_config(&resp)?;
    Ok(msg)
}

/// Applies the program list: redirection, then closing the moved programs' connections.
fn apply(changed: &[String]) -> Result<usize, String> {
    redirect::apply(&state::redirected_names(), state::SOCKS_PORT)?;
    let mut pids = std::collections::HashSet::new();
    for exe in changed {
        pids.extend(procs::pids_of(exe));
    }
    Ok(procs::close_connections(&pids))
}

/// Adds the program to the tunnel, or removes it. Returns whether it is tunneled now.
pub fn toggle(exe: &str) -> Result<bool, String> {
    let exe = exe.trim().to_lowercase();
    let exe = if exe.ends_with(".exe") { exe } else { format!("{exe}.exe") };
    if !procs::allowed(&exe) {
        return Err(format!("{exe} is part of Windows or Sideroute and cannot be moved"));
    }
    let mut apps = state::apps();
    let mut related = state::related();
    let mut changed = vec![exe.clone()];
    let now = if let Some(i) = apps.iter().position(|a| *a == exe) {
        apps.remove(i);
        changed.extend(related.remove(&exe).unwrap_or_default());
        false
    } else {
        apps.push(exe.clone());
        // like on Linux, the whole program goes: also what it started under other names
        let mut kids: Vec<String> = procs::descendants(&exe).into_iter().map(|k| k.1).filter(|n| !procs::is_system_helper(n)).collect();
        kids.sort();
        kids.dedup();
        if !kids.is_empty() {
            crate::log::log(&format!("{exe}: also routing {}", kids.join(", ")));
            changed.extend(kids.clone());
            related.insert(exe.clone(), kids);
        }
        true
    };
    state::save_apps(&apps)?;
    state::save_related(&related)?;
    apply(&changed)?;
    Ok(now)
}

/// Every program back to a direct connection.
pub fn off() -> Result<(), String> {
    let apps = state::redirected_names();
    state::save_apps(&[])?;
    state::save_related(&Default::default())?;
    redirect::stop()?;
    for a in &apps {
        procs::close_connections(&procs::pids_of(a));
    }
    Ok(())
}

/// Re-applies the saved list (after the tunnel came up).
pub fn restore() -> Result<(), String> {
    let names = state::redirected_names();
    if names.is_empty() {
        return redirect::stop();
    }
    redirect::apply(&names, state::SOCKS_PORT)
}

/// Stops redirecting (when quitting) but keeps the list for the next start.
pub fn off_keep_list() -> Result<(), String> {
    redirect::stop()?;
    for a in state::redirected_names() {
        procs::close_connections(&procs::pids_of(&a));
    }
    Ok(())
}
