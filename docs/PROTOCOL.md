# Pairing protocol (v1)

This is everything a client needs to pair with an Sideroute server. The Linux client implements it
in `crates/client/src/lib.rs`; a Windows (or any other) client can implement it with a standard
HTTPS library that allows a custom certificate check.

## Pairing code

```
sr1:SECRET:FINGERPRINT@HOST:PORT
```

| part          | format                                   | meaning |
|---------------|------------------------------------------|---------|
| `sr1`         | literal                                  | code format version |
| `SECRET`      | 20 chars, base32 (`A-Z2-7`), 100 bits    | one-time secret; authorizes exactly one device |
| `FINGERPRINT` | 26 chars, base32, 130 bits               | first 26 base32 characters of SHA-256 over the server's TLS certificate (DER) |
| `HOST`        | IPv4, DNS name, or `[IPv6]`              | pairing service address (normally the VPS public IP) |
| `PORT`        | decimal                                  | pairing service TCP port (default 51821) |

Parsers should ignore whitespace and `-`, and accept lower case. Base32 is RFC 4648 without padding.

A code expires after 15 minutes by default (`sideroute-server pair --ttl`) and works once.
The server stores only the SHA-256 of the secret.

## Transport

HTTPS (TLS 1.2 or 1.3) to `HOST:PORT`. The server uses a long-lived self-signed certificate
(ECDSA P-256, SNI name `sideroute`). The client must **not** use the system CA store; it accepts the
connection only if the fingerprint of the presented end-entity certificate equals `FINGERPRINT`
(handshake signatures are verified normally). This pins the server, so a network attacker cannot
substitute its own WireGuard key.

## `POST /v1/pair`

Request (`Content-Type: application/json`):

```json
{
  "secret": "K7Q2M3XD4TFAJ3PL6WRN",
  "public_key": "<client WireGuard public key, base64>",
  "name": "laptop",
  "platform": "linux"
}
```

The client generates its WireGuard key pair locally; the private key never leaves the device.
`name` is a label shown in `sideroute-server list` (the server keeps `[A-Za-z0-9._-]`, max 32,
and makes it unique). `platform` is informational (`linux`, `windows`, ...).

Response `200 OK`:

```json
{
  "server_public_key": "<base64>",
  "endpoint": "203.0.113.5:51820",
  "client_address": "10.77.0.2/32",
  "server_address": "10.77.0.1",
  "dns": ["1.1.1.1", "1.0.0.1"],
  "allowed_ips": ["0.0.0.0/0"],
  "mtu": 1280,
  "persistent_keepalive": 25
}
```

This maps directly onto a WireGuard configuration:

```ini
[Interface]
PrivateKey = <client private key>
Address = 10.77.0.2/32
MTU = 1280

[Peer]
PublicKey = <server_public_key>
Endpoint = 203.0.113.5:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

A client that routes only selected apps must not install `AllowedIPs` as the system default route
(on Linux: a separate routing table selected by fwmark; on Windows: WireGuard with
`Table = off`-like behaviour plus per-process redirection). The tunnel carries IPv4 only; tunneled
apps should have IPv6 blocked to avoid leaks. DNS for tunneled apps should be sent to `dns`
through the tunnel.

Pairing again with the same public key (and a new code) returns the same address.

Errors return a JSON body `{"error": "..."}`:

| status | meaning |
|--------|---------|
| 400    | malformed request or invalid public key |
| 403    | invalid, expired or already used code (answered after a 1 s delay) |
| 429    | more than 30 failed attempts in the last minute (server-wide) |
| 500    | server-side problem (see `journalctl -u sideroute`) |

## `GET /v1/health`

`200 OK` with `{"ok":true}`. Useful for checking reachability and the pinned certificate.

## Server-side network

* WireGuard interface `sroute0`, UDP 51820, subnet picked from 10.77.0.0/24, 10.78.0.0/24, ...
  so it does not collide with existing networks.
* Traffic from the tunnel is masqueraded out of the default interface.
* Tunnel clients may not reach the server's private networks (10/8, 172.16/12, 192.168/16,
  100.64/10, 169.254/16: Docker networks, tailnet, cloud metadata) nor each other.

## Cloudflare WARP mode

Instead of pairing with an own server, a client can register with Cloudflare WARP
(`crates/proto/src/lib.rs`, module `warp`; transport in `crates/net`):

* `POST https://api.cloudflareclient.com/v0a5641/reg` with the headers
  `User-Agent: 1.1.1.1/6.38.9-5641 (Android 16.0.0)` and `CF-Client-Version: a-6.38.9-5641` and a
  JSON body containing the client's WireGuard public key (`key`) and the current time (`tos`).
  The certificate is checked against the public web PKI (no pinning).
* The response's `config.peers[0]` gives the server key and endpoint (`endpoint.v4`, with the port
  replaced by `endpoint.ports[0]`, normally 2408); `config.interface.addresses.v4` the client
  address. It is turned into the same `PairResponse` structure as above (DNS `1.1.1.1`,
  `0.0.0.0/0`, MTU 1280).
* `id` and `token` are stored (`warp.json`) to delete the registration later with
  `DELETE /v0a5641/reg/{id}` and `Authorization: Bearer {token}`.
* If no handshake happens on port 2408, clients try the other ports from `endpoint.ports`
  (500, 1701, 4500).
