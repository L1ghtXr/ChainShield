"""Local chain forwarder: full multi-hop via localhost SOCKS5."""

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


def _socks5_relay_proxy() -> tuple[socket.socket, int, threading.Event]:
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


def _echo_server() -> tuple[socket.socket, int, threading.Event]:
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
                c, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            def echo(conn: socket.socket = c) -> None:
                try:
                    while True:
                        d = conn.recv(4096)
                        if not d:
                            break
                        conn.sendall(d)
                except OSError:
                    pass
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass

            threading.Thread(target=echo, daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv, port, stop


def test_forwarder_env_has_no_remote_credentials():
    hops = [
        ProxyHop(type="socks5", host="10.0.0.1", port=1080, username="u", password="secret"),
        ProxyHop(type="http", host="10.0.0.2", port=8080, username="a", password="b"),
    ]
    cfg = Config(proxies=hops)
    # Don't start network; just construct and inspect env helper after bind
    fwd = LocalChainForwarder(hops, cfg)
    host, port = fwd.start()
    try:
        env = fwd.proxy_env()
        blob = " ".join(env.values())
        assert "secret" not in blob
        assert "10.0.0.1" not in blob
        assert env["ALL_PROXY"] == f"socks5://{host}:{port}"
        assert env["CHAINSHIELD_CHAIN_HOPS"] == "2"
    finally:
        fwd.stop()


def test_forwarder_full_chain_bidirectional_echo():
    p1_srv, p1_port, p1_stop = _socks5_relay_proxy()
    p2_srv, p2_port, p2_stop = _socks5_relay_proxy()
    echo_srv, echo_port, echo_stop = _echo_server()
    time.sleep(0.05)
    hops = [
        ProxyHop(type="socks5", host="127.0.0.1", port=p1_port),
        ProxyHop(type="socks5", host="127.0.0.1", port=p2_port),
    ]
    cfg = Config(proxies=hops, connect_timeout=3, handshake_timeout=5)
    fwd = LocalChainForwarder(hops, cfg)
    host, port = fwd.start()
    try:
        # Client uses local forwarder as SOCKS5 → full chain → echo
        result = connect_through_chain(
            [ProxyHop(type="socks5", host=host, port=port)],
            "127.0.0.1",
            echo_port,
            connect_timeout=3,
            handshake_timeout=8,
            policy="strict",
        )
        assert result.success, result.error
        sock = result.final_socket
        assert sock is not None
        sock.settimeout(5)
        msg = b"FORWARDER-CHAIN-OK"
        sock.sendall(msg)
        got = b""
        while len(got) < len(msg):
            chunk = sock.recv(64)
            assert chunk
            got += chunk
        assert got == msg
        sock.close()
    finally:
        fwd.stop()
        p1_stop.set()
        p2_stop.set()
        echo_stop.set()
        for s in (p1_srv, p2_srv, echo_srv):
            try:
                s.close()
            except OSError:
                pass


def test_forwarder_stops_cleanly():
    hops = [ProxyHop(type="socks5", host="127.0.0.1", port=1)]
    cfg = Config(proxies=hops)
    fwd = LocalChainForwarder(hops, cfg)
    fwd.start()
    fwd.stop()
    # Second stop is safe
    fwd.stop()
