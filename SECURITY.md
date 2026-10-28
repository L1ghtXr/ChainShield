# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository or contact the maintainers.

Do not include live credentials or private proxy endpoints in public issues.

## Security principles of ChainShield

- TLS certificate verification is never disabled.
- Proxy credentials are redacted from logs when `redact_secrets` is true.
- Configuration files should use restrictive permissions (installer sets `0600` when possible).
- Subprocess execution does not use shell string interpolation.
- Fail-closed policies refuse unprotected fallbacks.
- Firewall changes are not performed automatically.
- Device-wide Android protection is not claimed by this CLI alone.
