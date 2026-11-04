# Security policy

Sideroute moves network traffic and runs parts of itself with administrator rights, so security
reports are very welcome.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead:
[Report a vulnerability](https://github.com/attaberuku/sideroute/security/advisories/new).

Include what you found, how to reproduce it and what an attacker could do with it. You will get an
answer within a week. Once a fix is released, the report is published with credit to you (unless
you prefer otherwise).

## Scope

- the pairing service and protocol (`crates/server`, `crates/proto`, `docs/PROTOCOL.md`)
- the Linux root helper and its sudoers rule (`crates/client/src/helper.rs`, `client/install.sh`)
- the Windows tray app, its local SOCKS5 proxy and the installer (`crates/windows`)
- leaks: traffic of a tunneled app leaving outside the tunnel

Weaknesses of bundled third-party components (wireguard-nt, ProxiFyre, Windows Packet Filter)
should go to their projects; tell us too if Sideroute should react.
