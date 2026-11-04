//! Embeds the icons, manifest and version information (`windows/app.rc`), and the bundled
//! third-party components when `SIDEROUTE_PAYLOAD_DIR` points at them (see
//! `scripts/fetch-windows-payload.sh`): `wireguard.dll`, its license and the ProxiFyre setup.

use std::path::Path;

const PAYLOAD: &[&str] = &["wireguard.dll", "wireguard-nt-LICENSE.txt", "ProxiFyre-setup.exe"];

fn main() {
    println!("cargo::rustc-check-cfg=cfg(payload)");
    println!("cargo::rerun-if-env-changed=SIDEROUTE_PAYLOAD_DIR");
    println!("cargo::rerun-if-changed=../../windows/app.rc");
    println!("cargo::rerun-if-changed=../../windows/app.manifest");
    println!("cargo::rerun-if-changed=../../windows/assets");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    embed_resource::compile("../../windows/app.rc", embed_resource::NONE)
        .manifest_required()
        .expect("compiling windows/app.rc");

    if let Ok(dir) = std::env::var("SIDEROUTE_PAYLOAD_DIR") {
        let dir = Path::new(&dir);
        for f in PAYLOAD {
            assert!(dir.join(f).is_file(), "SIDEROUTE_PAYLOAD_DIR is missing {f}");
            println!("cargo::rerun-if-changed={}", dir.join(f).display());
        }
        println!("cargo::rustc-cfg=payload");
        println!("cargo::rustc-env=SIDEROUTE_PAYLOAD_DIR={}", dir.display());
    }
}
