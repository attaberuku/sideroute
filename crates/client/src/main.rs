//! sideroute: move running apps into the WireGuard tunnel and back, without restarting them.
//!
//! ```text
//! sideroute toggle <PID|NAME>   move an app into the tunnel, or back out
//! sideroute run <COMMAND...>    start a program inside the tunnel
//! sideroute status              tunnel state and tunneled apps
//! sideroute off                 move every app back out and stop the tunnel
//! sideroute pair [CODE|warp]    pair with a server, or use Cloudflare WARP (asks for the sudo password)
//! sideroute daemon              session D-Bus service (started on demand by D-Bus/systemd)
//! ```
//!
//! An app's whole process tree is moved (via the systemd user manager, no root needed) into
//! `app.slice/app-sideroute.slice`; the root helper routes that cgroup through the tunnel. Existing
//! connections are closed so the app reconnects, now through the tunnel.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, fs, thread};

use sideroute_client::{BUS_NAME, HELPER, HOLDER, OBJECT_PATH, SLICE, cgroup_of, tunnel_cgroup, user_root};
use zbus::zvariant::Value;
use zbus::{Connection, interface};

fn uid() -> u32 {
    fs::metadata("/proc/self").map(|m| m.uid()).unwrap_or(0)
}

fn app_root() -> String {
    format!("{}/app.slice/", user_root(uid()))
}

fn in_tunnel(cgroup: &str) -> bool {
    cgroup.starts_with(&format!("{}/", tunnel_cgroup(uid())))
}

fn notify(title: &str, body: &str, icon: &str) {
    let _ = Command::new("notify-send")
        .args(["-a", "Sideroute", "-i", icon, title, body])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

/// Runs the root helper through the passwordless sudo rule.
fn helper(args: &[&str]) -> Result<String, String> {
    let out = Command::new("sudo")
        .env("LC_ALL", "C")
        .args(["-n", HELPER])
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("sudo: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn procs(cgroup: &str) -> Vec<u32> {
    fs::read_to_string(format!("/sys/fs/cgroup/{cgroup}/cgroup.procs"))
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|x| x.parse().ok())
        .collect()
}

fn parent(pid: u32) -> Option<u32> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // "pid (comm) state ppid ...": comm may contain spaces and parentheses, so split after the last ')'
    s.rsplit_once(')')?.1.split_whitespace().nth(1)?.parse().ok()
}

fn comm(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm")).map(|s| s.trim().to_string()).unwrap_or_else(|_| pid.to_string())
}

fn all_pids() -> Vec<u32> {
    fs::read_dir("/proc")
        .map(|d| d.flatten().filter_map(|e| e.file_name().to_str()?.parse().ok()).collect())
        .unwrap_or_default()
}

/// All processes of the app that owns `pid`: walk up to the topmost process of the app (stopping
/// at the user's systemd), take all its descendants, then every other process in the app cgroups
/// those live in. Browsers (Chromium, Brave, ...) run helpers such as the network service in
/// cgroups of their own.
fn app_processes(pid: u32) -> Vec<u32> {
    let root = app_root();
    let in_apps = |p: u32| cgroup_of(p).map(|c| c.starts_with(&root)).unwrap_or(false);
    let parents: HashMap<u32, u32> = all_pids().into_iter().filter_map(|p| Some((p, parent(p)?))).collect();

    let mut top = pid;
    while let Some(&pp) = parents.get(&top) {
        if pp <= 1 || !in_apps(pp) || comm(pp) == "systemd" {
            break;
        }
        top = pp;
    }
    let mut set: HashSet<u32> = HashSet::from([top]);
    loop {
        let before = set.len();
        for (&p, pp) in &parents {
            if set.contains(pp) {
                set.insert(p);
            }
        }
        if set.len() == before {
            break;
        }
    }
    let cgroups: HashSet<String> = set
        .iter()
        .filter_map(|&p| cgroup_of(p).ok())
        .filter(|c| c.starts_with(&root) && !c.ends_with(HOLDER))
        .collect();
    for c in &cgroups {
        set.extend(procs(c));
    }
    let mut v: Vec<u32> = set.into_iter().filter(|&p| in_apps(p)).collect();
    v.sort_unstable();
    v
}

/// Processes currently in the tunnel slice (excluding the holder).
fn tunneled() -> Vec<u32> {
    fn walk(dir: &Path, out: &mut Vec<u32>) {
        if dir.ends_with(HOLDER) {
            return;
        }
        if let Ok(s) = fs::read_to_string(dir.join("cgroup.procs")) {
            out.extend(s.split_whitespace().filter_map(|x| x.parse::<u32>().ok()));
        }
        if let Ok(d) = fs::read_dir(dir) {
            for e in d.flatten() {
                if e.file_type().is_ok_and(|t| t.is_dir()) {
                    walk(&e.path(), out);
                }
            }
        }
    }
    let mut v = Vec::new();
    walk(&Path::new("/sys/fs/cgroup").join(tunnel_cgroup(uid())), &mut v);
    v
}

struct Service {
    bus: Connection,
}

impl Service {
    async fn systemd<B>(&self, method: &str, body: &B) -> zbus::Result<()>
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        self.bus
            .call_method(
                Some("org.freedesktop.systemd1"),
                "/org/freedesktop/systemd1",
                Some("org.freedesktop.systemd1.Manager"),
                method,
                body,
            )
            .await
            .map(|_| ())
    }

    /// Makes sure the slice exists (holder unit) and the root side is up. Called on every move into
    /// the tunnel because the slice (and with it the cgroup the rules point at) may have been recreated.
    async fn ensure_up(&self) -> Result<(), String> {
        self.systemd("StartUnit", &(HOLDER, "replace")).await.map_err(|e| e.to_string())?;
        let path = Path::new("/sys/fs/cgroup").join(tunnel_cgroup(uid()));
        for _ in 0..50 {
            if path.is_dir() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        helper(&["up"]).map(|_| ())
    }

    async fn move_to(&self, pids: &[u32], slice: &str, name: &str) -> zbus::Result<()> {
        let ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        let clean: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).collect();
        let tunnel = slice == SLICE;
        let unit = format!("{}-{clean}-{ms}.scope", if tunnel { "tunnel" } else { "direct" });
        let description = format!("{name} ({})", if tunnel { "Sideroute" } else { "direct" });
        let props: Vec<(&str, Value)> = vec![
            ("PIDs", Value::from(pids.to_vec())),
            ("Slice", Value::from(slice)),
            ("Description", Value::from(description.as_str())),
        ];
        let aux: Vec<(&str, Vec<(&str, Value)>)> = vec![];
        self.systemd("StartTransientUnit", &(unit.as_str(), "fail", props, aux)).await
    }

    fn kill_sockets(pids: &[u32]) {
        let ids: Vec<String> = pids.iter().map(u32::to_string).collect();
        let mut args = vec!["kill-sockets"];
        args.extend(ids.iter().map(String::as_str));
        if let Err(e) = helper(&args) {
            eprintln!("kill-sockets: {e}");
        }
    }

    async fn toggle_pid(&self, pid: u32) -> Result<&'static str, String> {
        let cg = cgroup_of(pid)?;
        let name = comm(pid);
        if !cg.starts_with(&app_root()) {
            notify("Sideroute", &format!("{name} is not an app (system or session process); not moved."), "dialog-warning");
            return Ok("rejected");
        }
        let pids = app_processes(pid);
        if in_tunnel(&cg) {
            self.move_to(&pids, "app.slice", &name).await.map_err(|e| e.to_string())?;
            Self::kill_sockets(&pids);
            notify("Tunnel off", &format!("{name} now connects directly."), "network-wired");
            return Ok("direct");
        }
        self.ensure_up().await?;
        self.move_to(&pids, SLICE, &name).await.map_err(|e| e.to_string())?;
        Self::kill_sockets(&pids);
        notify("Tunnel on", &format!("{name} ({} processes) now connects through the tunnel.", pids.len()), "network-vpn");
        Ok("tunnel")
    }
}

#[interface(name = "io.github.attaberuku.Sideroute")]
impl Service {
    /// Moves the app owning `pid` into the tunnel or back. Returns `tunnel`, `direct`, `rejected`
    /// or `error: ...`. (`i32` because KWin's callDBus sends numbers as int32.)
    async fn toggle(&self, pid: i32) -> String {
        match self.toggle_pid(pid as u32).await {
            Ok(s) => s.to_string(),
            Err(e) => {
                notify("Sideroute: error", &e, "dialog-error");
                format!("error: {e}")
            }
        }
    }

    /// `tunnel` or `direct` for the app owning `pid`.
    async fn state(&self, pid: i32) -> String {
        match cgroup_of(pid as u32) {
            Ok(c) if in_tunnel(&c) => "tunnel".into(),
            Ok(_) => "direct".into(),
            Err(e) => format!("error: {e}"),
        }
    }

    /// Prepares the slice and the tunnel so a program can be started inside it.
    async fn prepare(&self) -> String {
        match self.ensure_up().await {
            Ok(()) => "ok".into(),
            Err(e) => format!("error: {e}"),
        }
    }

    /// Moves every app back out and stops the tunnel.
    async fn disable_all(&self) -> String {
        let pids = tunneled();
        if !pids.is_empty() {
            if let Err(e) = self.move_to(&pids, "app.slice", "restored").await {
                return format!("error: {e}");
            }
            Self::kill_sockets(&pids);
        }
        let _ = self.systemd("StopUnit", &(HOLDER, "replace")).await;
        match helper(&["down"]) {
            Ok(_) => {
                notify("Tunnel off", "All apps connect directly again.", "network-wired");
                "ok".into()
            }
            Err(e) => format!("error: {e}"),
        }
    }
}

fn call(method: &str, arg: Option<i32>) -> Result<String, String> {
    zbus::block_on(async {
        let c = Connection::session().await?;
        let m = match arg {
            Some(a) => c.call_method(Some(BUS_NAME), OBJECT_PATH, Some(BUS_NAME), method, &(a,)).await?,
            None => c.call_method(Some(BUS_NAME), OBJECT_PATH, Some(BUS_NAME), method, &()).await?,
        };
        m.body().deserialize::<String>()
    })
    .map_err(|e| e.to_string())
}

fn find_pid(arg: &str) -> Result<u32, String> {
    if let Ok(p) = arg.parse() {
        return Ok(p);
    }
    let root = app_root();
    let me = uid();
    all_pids()
        .into_iter()
        .filter(|&p| fs::metadata(format!("/proc/{p}")).is_ok_and(|m| m.uid() == me))
        .filter(|&p| comm(p) == arg && cgroup_of(p).is_ok_and(|c| c.starts_with(&root)))
        .min()
        .ok_or_else(|| format!("no running app named '{arg}' (process names: see `ps -u $USER -o comm=`)"))
}

fn status() -> Result<(), String> {
    match helper(&["status"]) {
        Ok(s) => println!("{s}"),
        Err(e) => println!("tunnel: unknown ({e})"),
    }
    let mut apps: BTreeMap<String, usize> = BTreeMap::new();
    for p in tunneled() {
        *apps.entry(comm(p)).or_default() += 1;
    }
    if apps.is_empty() {
        println!("apps in tunnel: none");
    } else {
        println!("apps in tunnel:");
        for (n, c) in apps {
            println!("  {n} ({c} process{})", if c == 1 { "" } else { "es" });
        }
    }
    Ok(())
}

fn pair(code: Option<&String>) -> Result<(), String> {
    let code = match code {
        Some(c) => c.clone(),
        None => {
            println!("Paste the pairing code from your server, or just press Enter to use");
            print!("Cloudflare WARP (free, no server needed): ");
            std::io::stdout().flush().ok();
            let mut s = String::new();
            std::io::stdin().read_line(&mut s).map_err(|e| e.to_string())?;
            s
        }
    };
    let code = if code.trim().is_empty() || code.trim() == "--warp" { "warp".to_string() } else { code };
    // the code goes through stdin so it does not show up in the process list
    let mut ch = Command::new("sudo").args([HELPER, "pair"]).stdin(Stdio::piped()).spawn().map_err(|e| e.to_string())?;
    ch.stdin.take().ok_or("stdin")?.write_all(code.trim().as_bytes()).map_err(|e| e.to_string())?;
    if ch.wait().map_err(|e| e.to_string())?.success() { Ok(()) } else { Err("pairing failed".into()) }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: sideroute <command>\n\n\
         \x20 toggle <PID|NAME>   move a running app into the tunnel, or back out\n\
         \x20 run <COMMAND...>    start a program inside the tunnel\n\
         \x20 status              tunnel state and tunneled apps\n\
         \x20 off                 move every app back out and stop the tunnel\n\
         \x20 pair [CODE|warp]    pair with your server, or use Cloudflare WARP (no server)\n\
         \x20 daemon              D-Bus service (started automatically)"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let res: Result<(), String> = match args.get(1).map(String::as_str) {
        Some("daemon") => zbus::block_on(async {
            let bus = Connection::session().await.map_err(|e| format!("session D-Bus: {e}"))?;
            let _conn = zbus::connection::Builder::session()
                .and_then(|b| b.name(BUS_NAME))
                .and_then(|b| b.serve_at(OBJECT_PATH, Service { bus }))
                .map_err(|e| e.to_string())?
                .build()
                .await
                .map_err(|e| format!("cannot own {BUS_NAME}: {e}"))?;
            std::future::pending::<()>().await;
            Ok(())
        }),
        Some("toggle") => match args.get(2) {
            Some(a) => find_pid(a).and_then(|p| call("Toggle", Some(p as i32))).and_then(|r| {
                println!("{r}");
                if r.starts_with("error") { Err("toggle failed".into()) } else { Ok(()) }
            }),
            None => return usage(),
        },
        Some("run") if args.len() > 2 => match call("Prepare", None) {
            Ok(r) if r == "ok" => {
                let err = Command::new("systemd-run")
                    .args(["--user", "--scope", "--quiet", "--collect", &format!("--slice={SLICE}"), "--"])
                    .args(&args[2..])
                    .exec();
                Err(format!("systemd-run: {err}"))
            }
            Ok(r) => Err(r),
            Err(e) => Err(e),
        },
        Some("status") => status(),
        Some("off") => call("DisableAll", None).and_then(|r| if r == "ok" { Ok(()) } else { Err(r) }),
        Some("pair") => pair(args.get(2)),
        Some("version" | "--version") => {
            println!("sideroute {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => return usage(),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
