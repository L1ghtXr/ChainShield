# ChainShield

**Layered Network Protection** for Linux and Android Termux.

Author: **L1ghtXr** · Contribution: **DevBrezz**

Repository: https://github.com/L1ghtXr/ChainShield

## What it does

ChainShield is a Python 3 terminal application that:

- Manages SOCKS4/5 and HTTP CONNECT proxy hops (including sequential multi-hop chains)
- Runs selected commands under a configured protection policy (fail-closed when required)
- Verifies public egress IP through real HTTPS IP-echo endpoints
- Emits structured traffic/diagnostic events with explicit provenance
- Reports protection state honestly (application-level vs device-wide)

It is **not** a silent system-wide VPN. A connected proxy does **not** produce a global `PROTECTED` state by itself.

## Compatibility matrix

| Feature                         | Linux (user) | Linux (root) | Termux      |
|---------------------------------|--------------|--------------|-------------|
| SOCKS5 / SOCKS4 / HTTP CONNECT  | Yes          | Yes          | Yes         |
| Multi-hop TCP chain             | Yes          | Yes          | Yes         |
| Local full-chain forwarder (`run`) | Yes       | Yes          | Yes*        |
| SOCKS5 UDP ASSOCIATE (1 hop)   | Partial      | Partial      | Partial     |
| Multi-hop UDP                  | No           | No           | No          |
| App proxy env (`run`)           | Yes          | Yes          | Yes         |
| Public IP verify (HTTPS)        | Yes          | Yes          | Yes         |
| DNS diagnostic (resolv.conf)    | Yes          | Yes          | Partial     |
| LD_PRELOAD interception         | Unverified*  | Unverified*  | No          |
| Device-wide VPN                 | External     | External     | Companion app required |
| Firewall management             | Disabled     | Optional**   | No          |

\* No bundled `libproxychains`; capability reported as integration boundary.  
\*\* Not performed automatically; requires explicit authorization design.

## Requirements

- Python **3.10+** (3.11+ recommended). On Python 3.10, `tomli` is required and installed automatically via packaging metadata.

## Install

### Linux

```bash
git clone https://github.com/L1ghtXr/ChainShield.git
cd ChainShield
chmod +x install.sh
./install.sh
# ensure ~/.local/bin is on PATH
chainshield --version
```

### Termux

```bash
pkg install python git
git clone https://github.com/L1ghtXr/ChainShield.git
cd ChainShield
./install.sh
chainshield --version
```

Uninstall: `./uninstall.sh`

## Configuration

Example file: `config.example.toml`  
Default path: `~/.config/chainshield/config.toml`

```toml
[[proxy.chain]]
type = "socks5"
host = "127.0.0.1"
port = 9050
```

Policies:

- `strict` / `fail_closed` — hop failure rejects the route; no direct fallback
- `manual` — use only the configured route

## Commands

```text
chainshield                 Interactive menu
chainshield --version
chainshield status
chainshield start
chainshield stop
chainshield proxy list
chainshield proxy test
chainshield run -- curl https://example.com
chainshield monitor
chainshield verify-ip
chainshield diagnostics
chainshield config
```

### `run` behavior

1. Inspect command and required transport
2. Select route from proxies / tunnel capability
3. Health-check hops when configured
4. Start a localhost SOCKS5 forwarder that applies all configured hops
5. Point the child process at the forwarder (no remote credentials in child env)
6. Refuse execution when protection is required and route is invalid
7. Stop the forwarder and report actual coverage after exit

**Important:** `run` points proxy-aware tools at a **localhost SOCKS5 forwarder** that walks the full configured chain. Only applications that honor `ALL_PROXY` / `SOCKS_PROXY` (or equivalent) are covered. Arbitrary processes are not intercepted on Termux or Linux without additional integration.

## Protection states

| State                 | Meaning |
|-----------------------|---------|
| INACTIVE              | No working proxy/tunnel path |
| INITIALIZING          | Start in progress |
| PARTIALLY PROTECTED   | Application/process route active (and optionally verified) |
| NOT VERIFIED          | Path present but egress verification not confirmed |
| PROTECTED             | Device-level coverage **and** verified egress (requires real tunnel) |
| ERROR                 | Required component failed |

## Architecture (modules)

- `platform` — Linux / Termux detection
- `capabilities` — validated feature registry
- `proxy` — SOCKS/HTTP handshakes and chaining
- `routing` — engine selection and `run`
- `verification` — real IP-echo checks
- `tunnel` — external VPN integration boundary
- `events` / `monitor` — provenance-tagged events
- `diagnostics` — DNS and capability reports
- `ui` / `cli` — purple terminal interface

## Tests

```bash
cd ChainShield
python3 -m pytest -q
```

Local mock proxy servers are used for handshake tests. Live IP verification is not required for the unit suite.

## Traffic paths (honest)

| Path | How |
|------|-----|
| TCP via `chainshield run` | App → localhost SOCKS5 forwarder → hop1 → hop2 → … → destination |
| TCP/HTTPS via `verify-ip` with proxies | ChainShield native CONNECT through full hop list |
| UDP | Single-hop SOCKS5 UDP ASSOCIATE API only; not exposed to child processes via forwarder |
| DNS | System resolver unless the application tunnels DNS; not claimed protected |
| Device-wide | Requires external tunnel / Android VpnService — not this CLI alone |

## Protection levels

- **Level A (implemented):** Cooperative apps via localhost SOCKS5 forwarder + full hop chain. `NO_PROXY` and stale proxy env vars are cleared for the child.
- **Level B (not implemented):** Host transparent redirect / netns / firewall — requires explicit privileged design.
- **Level C (not implemented):** Android VpnService device-wide routing.

## Limitations (explicit)

- No fabricated packet logs or IP addresses
- UDP and raw sockets are not covered by the TCP proxy chain
- `chainshield run` starts a localhost SOCKS5 forwarder that applies the **full** configured hop chain; child processes never receive remote proxy passwords in their environment
- Applications that ignore SOCKS/HTTP proxy settings can still bypass application-level routing
- Parent `NO_PROXY=*` would bypass many clients; ChainShield clears it for protected children
- Android device-wide routing needs a separate `VpnService` application
- Reference project [proxychains](https://github.com/haad/proxychains) is GPL-2.0; ChainShield is original MIT-licensed code and does not copy its sources

## License

MIT — see `LICENSE`.

## Security

See `SECURITY.md`.
