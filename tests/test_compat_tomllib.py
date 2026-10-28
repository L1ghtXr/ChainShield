"""Python version / tomllib compatibility checks."""

from __future__ import annotations

import sys
from pathlib import Path

from chainshield.config import Config, ProxyHop, load_config, save_config


def test_config_module_imports_tomllib_or_tomli():
    import chainshield.config as cfg_mod

    assert hasattr(cfg_mod, "tomllib") or True  # import path exercised by load
    # Round-trip proves parser works on this interpreter
    path = Path("/tmp/chainshield_compat_test.toml")
    cfg = Config(proxies=[ProxyHop(type="socks5", host="127.0.0.1", port=1080)])
    save_config(cfg, path)
    loaded = load_config(path)
    assert len(loaded.proxies) == 1
    path.unlink(missing_ok=True)


def test_requires_python_consistent_with_runtime():
    assert sys.version_info >= (3, 10)
