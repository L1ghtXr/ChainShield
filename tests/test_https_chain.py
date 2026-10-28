"""HTTP traffic through local multi-hop chain + forwarder."""

from __future__ import annotations

import socket
import struct
import threading
import time

from chainshield.config import Config, ProxyHop
from chainshield.forwarder import LocalChainForwarder
from chainshield.proxy import connect_through_chain


def _relay(a: socket.socket, b: socket.socket, stop: threading.Event) -> None:
    a.setblocking(False)
    b.setblocking(False)
    while not stop.is_set():
        r, _, _ = __import__("select").select([a, b], [], [], 0.2)
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


def _socks5_relay() -> tuple[socket.socket, int, threading.Event]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def handle(client: socket.socket) -> None:
        remote = None
        rs = threading.Event()
        try:
            client.settimeout(5)
            client.recv(256)
            client.sendall(b"\x05\x00")
            hdr = client.recv(4)
            atyp = hdr[3]
            if atyp == 1:
                addr = socket.inet_ntoa(client.recv(4))
            elif atyp == 3:
                ln = client.recv(1)[0]
                addr = client.recv(ln).decode()
            else:
                return
            dport = struct.unpack("!H", client.recv(2))[0]
            remote = socket.create_connection((addr, dport), timeout=5)
            client.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            client.settimeout(None)
            remote.settimeout(None)
            threading.Thread(target=_relay, args=(client, remote, rs), daemon=True).start()
            while not rs.is_set() and not stop.is_set():
                time.sleep(0.05)
        except OSError:
            pass
        finally:
            rs.set()
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
    return srv, port, stop


def _http_origin() -> tuple[socket.socket, int, list, threading.Event]:
    """HTTP server that records peer addresses and returns fixed body."""
    peers: list = []
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def loop() -> None:
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                c, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            peers.append(addr)

            def serve(conn: socket.socket = c) -> None:
                try:
                    conn.recv(4096)
                    body = b"CHAIN-OK"
                    resp = (
                        b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n"
                        b"Connection: close\r\n\r\n" + body
                    )
                    conn.sendall(resp)
                except OSError:
                    pass
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass

            threading.Thread(target=serve, daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv, port, peers, stop


def test_http_get_through_two_hop_forwarder():
    p1_srv, p1_port, p1_stop = _socks5_relay()
    p2_srv, p2_port, p2_stop = _socks5_relay()
    origin_srv, origin_port, peers, origin_stop = _http_origin()
    time.sleep(0.05)
    hops = [
        ProxyHop(type="socks5", host="127.0.0.1", port=p1_port),
        ProxyHop(type="socks5", host="127.0.0.1", port=p2_port),
    ]
    cfg = Config(proxies=hops, connect_timeout=3, handshake_timeout=5)
    fwd = LocalChainForwarder(hops, cfg)
    host, port = fwd.start()
    try:
        # CONNECT to origin via local forwarder (full chain)
        result = connect_through_chain(
            [ProxyHop(type="socks5", host=host, port=port)],
            "127.0.0.1",
            origin_port,
            connect_timeout=3,
            handshake_timeout=8,
            policy="strict",
        )
        assert result.success, result.error
        sock = result.final_socket
        assert sock is not None
        sock.settimeout(5)
        req = f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n"
        sock.sendall(req.encode())
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        assert b"200" in data
        assert b"CHAIN-OK" in data
        time.sleep(0.05)
        assert len(peers) >= 1, "origin never saw a connection through the chain"
    finally:
        fwd.stop()
        for st in (p1_stop, p2_stop, origin_stop):
            st.set()
        for s in (p1_srv, p2_srv, origin_srv):
            try:
                s.close()
            except OSError:
                pass
