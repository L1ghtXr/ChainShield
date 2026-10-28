"""Proxy protocol unit tests with local sockets."""

from __future__ import annotations

import socket
import struct
import threading
from typing import Optional

import pytest

from chainshield.config import ProxyHop
from chainshield.proxy import (
    ProxyAuthError,
    ProxyHandshakeError,
    connect_through_chain,
    health_check_hop,
    http_connect_handshake,
    socks5_handshake,
)


def _run_server(handler, port_holder: list):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port_holder.append(srv.getsockname()[1])
    conn, _ = srv.accept()
    try:
        handler(conn)
    finally:
        conn.close()
        srv.close()


def test_socks5_no_auth_connect():
    port_holder: list[int] = []

    def handler(conn: socket.socket):
        # greeting
        data = conn.recv(16)
        assert data[0] == 5
        conn.sendall(b"\x05\x00")
        # request
        req = conn.recv(256)
        assert req[0] == 5 and req[1] == 1
        # reply success with IPv4 bind
        conn.sendall(b"\x05\x00\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")

    t = threading.Thread(target=_run_server, args=(handler, port_holder), daemon=True)
    t.start()
    # wait for bind
    import time

    for _ in range(50):
        if port_holder:
            break
        time.sleep(0.01)
    hop = ProxyHop(type="socks5", host="127.0.0.1", port=port_holder[0])
    result = connect_through_chain([hop], "example.com", 443, connect_timeout=2, handshake_timeout=2)
    assert result.success, result.error
    if result.final_socket:
        result.final_socket.close()


def test_socks5_auth_failure():
    port_holder: list[int] = []

    def handler(conn: socket.socket):
        data = conn.recv(16)
        conn.sendall(b"\x05\x02")  # user/pass required
        auth = conn.recv(256)
        conn.sendall(b"\x01\x01")  # auth failed

    t = threading.Thread(target=_run_server, args=(handler, port_holder), daemon=True)
    t.start()
    import time

    for _ in range(50):
        if port_holder:
            break
        time.sleep(0.01)
    hop = ProxyHop(type="socks5", host="127.0.0.1", port=port_holder[0], username="u", password="p")
    result = connect_through_chain([hop], "example.com", 80, connect_timeout=2, handshake_timeout=2)
    assert not result.success
    assert "auth" in result.error.lower() or "Authentication" in result.error or "authentication" in result.error.lower()


def test_http_connect_success():
    port_holder: list[int] = []

    def handler(conn: socket.socket):
        data = b""
        while b"\r\n\r\n" not in data:
            data += conn.recv(256)
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

    t = threading.Thread(target=_run_server, args=(handler, port_holder), daemon=True)
    t.start()
    import time

    for _ in range(50):
        if port_holder:
            break
        time.sleep(0.01)
    hop = ProxyHop(type="http", host="127.0.0.1", port=port_holder[0])
    result = connect_through_chain([hop], "example.com", 443, connect_timeout=2, handshake_timeout=2)
    assert result.success, result.error
    if result.final_socket:
        result.final_socket.close()


def test_http_connect_reject():
    port_holder: list[int] = []

    def handler(conn: socket.socket):
        data = b""
        while b"\r\n\r\n" not in data:
            data += conn.recv(256)
        conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")

    t = threading.Thread(target=_run_server, args=(handler, port_holder), daemon=True)
    t.start()
    import time

    for _ in range(50):
        if port_holder:
            break
        time.sleep(0.01)
    hop = ProxyHop(type="http", host="127.0.0.1", port=port_holder[0])
    result = connect_through_chain([hop], "example.com", 443, connect_timeout=2, handshake_timeout=2)
    assert not result.success


def test_fail_closed_no_hops():
    with pytest.raises(Exception):
        connect_through_chain([], "example.com", 80)


def test_health_check_unreachable():
    hop = ProxyHop(type="socks5", host="127.0.0.1", port=1)
    r = health_check_hop(hop, timeout=0.5)
    assert r["reachable"] is False
    assert r["error"]
