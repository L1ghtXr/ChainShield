"""Extended proxy protocol tests: SOCKS4, multi-hop, intermediate failure."""

from __future__ import annotations

import socket
import threading
import time

import pytest

from chainshield.config import ProxyHop
from chainshield.proxy import connect_through_chain


def _serve_once(handler) -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run() -> None:
        try:
            conn, _ = srv.accept()
            try:
                handler(conn)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
        finally:
            try:
                srv.close()
            except OSError:
                pass

    threading.Thread(target=run, daemon=True).start()
    time.sleep(0.03)
    return port


def test_socks4_success():
    def handler(conn: socket.socket) -> None:
        data = conn.recv(256)
        assert data[0] == 4 and data[1] == 1
        conn.sendall(b"\x00\x5a\x00\x00\x00\x00\x00\x00")

    port = _serve_once(handler)
    hop = ProxyHop(type="socks4", host="127.0.0.1", port=port)
    result = connect_through_chain(
        [hop], "example.com", 80, connect_timeout=2, handshake_timeout=2
    )
    assert result.success, result.error
    if result.final_socket:
        result.final_socket.close()


def test_socks4_rejected():
    def handler(conn: socket.socket) -> None:
        conn.recv(256)
        conn.sendall(b"\x00\x5b\x00\x00\x00\x00\x00\x00")

    port = _serve_once(handler)
    hop = ProxyHop(type="socks4", host="127.0.0.1", port=port)
    result = connect_through_chain(
        [hop], "example.com", 80, connect_timeout=2, handshake_timeout=2
    )
    assert result.success is False
    assert "SOCKS4" in result.error


def test_multi_hop_sequential_socks5_then_http():
    """Sequential handshakes on one socket (mock acts as tunnel endpoint)."""

    def handler(conn: socket.socket) -> None:
        # SOCKS5 greeting + CONNECT ack
        conn.recv(16)
        conn.sendall(b"\x05\x00")
        conn.recv(512)
        conn.sendall(b"\x05\x00\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
        # Then HTTP CONNECT from client for final destination
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 8192:
            chunk = conn.recv(256)
            if not chunk:
                return
            buf += chunk
        assert b"CONNECT" in buf
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

    port = _serve_once(handler)
    # Second hop host is only used as CONNECT target string to first hop;
    # mock does not open a separate TCP to hop2.
    hops = [
        ProxyHop(type="socks5", host="127.0.0.1", port=port),
        ProxyHop(type="http", host="127.0.0.1", port=9),
    ]
    result = connect_through_chain(
        hops, "example.com", 443, connect_timeout=2, handshake_timeout=2
    )
    assert result.success, result.error
    assert len(result.route) >= 2
    if result.final_socket:
        result.final_socket.close()


def test_intermediate_hop_handshake_failure_fail_closed():
    def handler(conn: socket.socket) -> None:
        conn.recv(16)
        conn.sendall(b"\x05\x00")
        conn.recv(512)
        # Reject CONNECT to intermediate
        conn.sendall(b"\x05\x05\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")

    port = _serve_once(handler)
    hops = [
        ProxyHop(type="socks5", host="127.0.0.1", port=port),
        ProxyHop(type="socks5", host="10.255.255.1", port=9999),
    ]
    result = connect_through_chain(
        hops,
        "example.com",
        443,
        connect_timeout=2,
        handshake_timeout=2,
        policy="strict",
    )
    assert result.success is False
    assert result.error


def test_http_connect_with_basic_auth():
    def handler(conn: socket.socket) -> None:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(256)
            if not chunk:
                return
            buf += chunk
        assert b"Proxy-Authorization" in buf
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

    port = _serve_once(handler)
    hop = ProxyHop(
        type="http", host="127.0.0.1", port=port, username="u", password="pw"
    )
    result = connect_through_chain(
        [hop], "example.com", 443, connect_timeout=2, handshake_timeout=2
    )
    assert result.success, result.error
    if result.final_socket:
        result.final_socket.close()


def test_socks5_ipv4_literal_destination():
    def handler(conn: socket.socket) -> None:
        conn.recv(16)
        conn.sendall(b"\x05\x00")
        req = conn.recv(64)
        # ATYP should be 0x01 for IPv4
        assert req[0] == 5 and req[3] == 0x01
        conn.sendall(b"\x05\x00\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")

    port = _serve_once(handler)
    hop = ProxyHop(type="socks5", host="127.0.0.1", port=port)
    result = connect_through_chain(
        [hop], "203.0.113.10", 443, connect_timeout=2, handshake_timeout=2
    )
    assert result.success, result.error
    if result.final_socket:
        result.final_socket.close()
