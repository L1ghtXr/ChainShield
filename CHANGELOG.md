# Changelog

## 0.1.0 — 2026-10-29

Initial release candidate.

### Core
- Interactive purple-themed CLI (responsive columns / Termux-friendly stack)
- Pure-Python SOCKS4, SOCKS5, HTTP CONNECT client with ordered multi-hop TCP chaining
- Strict / fail_closed / manual chain policies (no silent direct fallback)
- Application-level `run` with proxy environment and proxy-aware tool hints
- Public egress IP verification via configurable HTTPS IP-echo endpoints (TLS verified)
- Optional remote client-IP endpoint diagnostic
- DNS diagnostic with truthful NOT VERIFIED classification (no fabricated leaks)
- Capability registry with Linux / Termux detection
- Structured event bus with provenance and secret redaction
- Protection state machine that never maps “proxy TCP connected” to global PROTECTED
- Tunnel adapter as integration boundary only (no fake VpnService)

### Hardening
- Neutralize `NO_PROXY` / stale proxy env in protected children (Level A)
- `verify-ip` reports hop count, chain_enforced, protection level
- Adversarial leak tests (fail-closed, credentials, unsupported tools)
- SOCKS5 **UDP ASSOCIATE** client (single-hop only; multi-hop UDP explicitly unsupported)
- Application capability profiles (`apps.py`) for strict reject of raw/UDP tools
- HTTP multi-hop integration test via local forwarder
- `chainshield run` uses a localhost SOCKS5 **local chain forwarder** so multi-hop applies to child traffic and remote proxy credentials stay out of child environment
- Real dual-proxy bidirectional multi-hop relay integration tests
- Process-group cleanup on Ctrl+C for managed subprocesses
- URL and query-parameter credential redaction in event details
- Python 3.10 support via conditional `tomli` dependency
- Installer creates mode-700 config dir and mode-600 config; launcher works if pip fails
- Explicit messaging that non-proxy-aware binaries are not guaranteed protected

### Tests
- Unit and local integration coverage for handshakes, multi-hop relay, fail-closed,
  redaction, config, routing, capabilities, and CLI smoke paths
