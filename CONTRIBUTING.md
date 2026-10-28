# Contributing to ChainShield

## Principles

1. Never fabricate success (IPs, routes, protection state).
2. Prefer fail-closed behavior when protection is required.
3. Document platform limitations instead of papering over them.
4. Keep modules small and testable.
5. English for all identifiers, messages, and docs.

## Development

```bash
python3 -m pip install -e ".[dev]"
python3 -m pytest -q
```

## Pull requests

- Include tests for new protocol or policy behavior
- Update README compatibility matrix when capabilities change
- Do not add automatic firewall modifications without a recoverable design and explicit user confirmation flow
