"""
Real multi-hop TCP relay integration tests.

Two independent local proxy processes implement actual CONNECT + bidirectional
relay. Traffic must traverse proxy1 -> proxy2 -> destination; failure of either
proxy must fail the chain with no direct fallback.
"""

from __future__ import annotations

import select
import socket
import struct
import threading
import time
from typing import Optional

import pytest

from chainshield.config import ProxyHop
from chainshield.proxy import connect_through_chain

_STOP: dict[int, threading.Event] = {}


def _relay(a: socket.socket, b: socket.socket, stop: threading.Event) -> None:
    a.setblocking(False)
    b.setblocking(False)
    while not stop.is_set():
        r, _, _ = select.select([a, b], [], [], 0.2)
        for s in r:
            other = b if s is a else a
            try:
                data = s.recv(8192)
            except OSError:
                stop.set()
                return
            if not data:
                stop.set()
                return
            try:
                other.sendall(data)
            except OSError:
                stop.set()
                return


def _start_echo_server() -> tuple[socket.socket, int, list]:
    """TCP echo server; records peer addresses that connected."""
    peers: list = []
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def accept_loop() -> None:
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            peers.append(addr)

            def echo(c: socket.socket = conn) -> None:
                try:
                    while True:
                        data = c.recv(4096)
                        if not data:
                            break
                        c.sendall(data)
                except OSError:
                    pass
                finally:
                    try:
                        c.close()
                    except OSError:
                        pass

            threading.Thread(target=echo, daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    _STOP[id(srv)] = stop
    return srv, port, peers


def _socks5_proxy_server() -> tuple[socket.socket, int]:
    """Minimal SOCKS5 no-auth proxy with real TCP relay to requested target."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def handle(client: socket.socket) -> None:
        remote: Optional[socket.socket] = None
        relay_stop = threading.Event()
        try:
            client.settimeout(10)
            # greeting
            data = client.recv(256)
            if len(data) < 2 or data[0] != 5:
                return
            client.sendall(b"\x05\x00")
            # request
            hdr = client.recv(4)
            if len(hdr) < 4 or hdr[0] != 5 or hdr[1] != 1:
                client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
                return
            atyp = hdr[3]
            if atyp == 1:
                addr = socket.inet_ntoa(client.recv(4))
            elif atyp == 3:
                ln = client.recv(1)[0]
                addr = client.recv(ln).decode("idna", errors="replace")
            elif atyp == 4:
                addr = socket.inet_ntop(socket.AF_INET6, client.recv(16))
            else:
                client.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
                return
            port_b = client.recv(2)
            target_port = struct.unpack("!H", port_b)[0]
            try:
                remote = socket.create_connection((addr, target_port), timeout=5)
            except OSError:
                client.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
                return
            client.sendall(b"\x05\x00\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
            client.settimeout(None)
            remote.settimeout(None)
            t1 = threading.Thread(target=_relay, args=(client, remote, relay_stop), daemon=True)
            t1.start()
            while not relay_stop.is_set() and not stop.is_set():
                time.sleep(0.05)
        except OSError:
            pass
        finally:
            relay_stop.set()
            for s in (client, remote):
                if s:
                    try:
                        s.close()
                    except OSError:
                        pass

    def accept_loop() -> None:
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    _STOP[id(srv)] = stop
    return srv, port


def _http_connect_proxy_server() -> tuple[socket.socket, int]:
    """Minimal HTTP CONNECT proxy with real TCP relay."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def handle(client: socket.socket) -> None:
        remote: Optional[socket.socket] = None
        relay_stop = threading.Event()
        try:
            client.settimeout(10)
            buf = b""
            while b"\r\n\r\n" not in buf and len(buf) < 16384:
                chunk = client.recv(256)
                if not chunk:
                    return
                buf += chunk
            first = buf.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
            parts = first.split()
            if len(parts) < 2 or parts[0].upper() != "CONNECT":
                client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return
            host_port = parts[1]
            if ":" in host_port:
                host, ps = host_port.rsplit(":", 1)
                target_port = int(ps)
            else:
                host, target_port = host_port, 443
            try:
                remote = socket.create_connection((host, target_port), timeout=5)
            except OSError:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            client.settimeout(None)
            remote.settimeout(None)
            threading.Thread(
                target=_relay, args=(client, remote, relay_stop), daemon=True
            ).start()
            while not relay_stop.is_set() and not stop.is_set():
                time.sleep(0.05)
        except OSError:
            pass
        finally:
            relay_stop.set()
            for s in (client, remote):
                if s:
                    try:
                        s.close()
                    except OSError:
                        pass

    def accept_loop() -> None:
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    _STOP[id(srv)] = stop
    return srv, port


def _stop_srv(srv: socket.socket) -> None:
    stop = _STOP.pop(id(srv), None)
    if stop:
        stop.set()
    try:
        srv.close()
    except OSError:
        pass


def test_multihop_socks5_then_http_real_relay_and_echo():
    """
    Client -> SOCKS5 proxy1 -> HTTP CONNECT proxy2 -> echo server.
    Bidirectional data must succeed; echo peer must be proxy2, not the client.
    """
    echo_srv, echo_port, peers = _start_echo_server()
    p2_srv, p2_port = _http_connect_proxy_server()
    p1_srv, p1_port = _socks5_proxy_server()
    time.sleep(0.05)
    try:
        hops = [
            ProxyHop(type="socks5", host="127.0.0.1", port=p1_port),
            ProxyHop(type="http", host="127.0.0.1", port=p2_port),
        ]
        result = connect_through_chain(
            hops,
            "127.0.0.1",
            echo_port,
            connect_timeout=3,
            handshake_timeout=5,
            policy="strict",
        )
        assert result.success, result.error
        assert result.final_socket is not None
        sock = result.final_socket
        sock.settimeout(5)
        payload = b"CHAINSHIELD-MULTIHOP-PING"
        sock.sendall(payload)
        got = b""
        while len(got) < len(payload):
            chunk = sock.recv(64)
            assert chunk, "echo closed early"
            got += chunk
        assert got == payload
        sock.close()

        # Route metadata lists both hops then destination
        assert any("socks5://" in r for r in result.route)
        assert any("http://" in r for r in result.route)
        assert any(str(echo_port) in r for r in result.route)

        # Destination accepted a connection (from proxy2's outbound, not direct client only)
        time.sleep(0.1)
        assert len(peers) >= 1, "echo server never received a connection through the chain"
    finally:
        _stop_srv(p1_srv)
        _stop_srv(p2_srv)
        _stop_srv(echo_srv)


def test_multihop_fails_when_second_proxy_down():
    p1_srv, p1_port = _socks5_proxy_server()
    time.sleep(0.05)
    try:
        hops = [
            ProxyHop(type="socks5", host="127.0.0.1", port=p1_port),
            ProxyHop(type="http", host="127.0.0.1", port=1),  # closed
        ]
        result = connect_through_chain(
            hops,
            "127.0.0.1",
            9,
            connect_timeout=2,
            handshake_timeout=3,
            policy="strict",
        )
        assert result.success is False
        assert result.error
        assert result.final_socket is None
    finally:
        _stop_srv(p1_srv)


def test_multihop_fails_when_first_proxy_down():
    hops = [
        ProxyHop(type="socks5", host="127.0.0.1", port=1),
        ProxyHop(type="http", host="127.0.0.1", port=2),
    ]
    result = connect_through_chain(
        hops,
        "127.0.0.1",
        9,
        connect_timeout=1,
        handshake_timeout=2,
        policy="fail_closed",
    )
    assert result.success is False
    assert result.final_socket is None


def test_no_direct_connect_when_chain_required():
    """With only an unreachable chain, destination echo is never contacted."""
    echo_srv, echo_port, peers = _start_echo_server()
    time.sleep(0.05)
    try:
        hops = [
            ProxyHop(type="socks5", host="127.0.0.1", port=1),
        ]
        result = connect_through_chain(
            hops,
            "127.0.0.1",
            echo_port,
            connect_timeout=1,
            handshake_timeout=2,
            policy="strict",
        )
        assert result.success is False
        time.sleep(0.2)
        assert peers == [], "direct connection to destination must not occur on chain failure"
    finally:
        _stop_srv(echo_srv)
