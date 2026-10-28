"""SOCKS5 UDP ASSOCIATE (single-hop) tests with a local mock proxy."""

from __future__ import annotations

import socket
import struct
import threading
import time

from chainshield.config import ProxyHop
from chainshield.proxy import (
    ProxyHandshakeError,
    socks5_udp_associate,
    socks5_udp_recv,
    socks5_udp_send,
)


def _udp_echo() -> tuple[socket.socket, int, threading.Event]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    stop = threading.Event()

    def loop() -> None:
        s.settimeout(0.5)
        while not stop.is_set():
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                s.sendto(data, addr)
            except OSError:
                break

    threading.Thread(target=loop, daemon=True).start()
    return s, port, stop


def _socks5_with_udp_associate() -> tuple[socket.socket, int, threading.Event]:
    """Minimal SOCKS5: CONNECT not needed; UDP ASSOCIATE returns this host's UDP port."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    tcp_port = srv.getsockname()[1]
    stop = threading.Event()

    # UDP relay socket
    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    relay.bind(("127.0.0.1", 0))
    relay_port = relay.getsockname()[1]

    def udp_relay_loop() -> None:
        relay.settimeout(0.5)
        # map client addr -> last dest for replies is simplified: one client
        client_addr = None
        while not stop.is_set():
            try:
                data, addr = relay.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) < 10:
                continue
            # SOCKS UDP header from client
            atyp = data[3]
            idx = 4
            if atyp == 1:
                dest = socket.inet_ntoa(data[idx : idx + 4])
                idx += 4
            elif atyp == 3:
                ln = data[idx]
                idx += 1
                dest = data[idx : idx + ln].decode()
                idx += ln
            else:
                continue
            dport = struct.unpack("!H", data[idx : idx + 2])[0]
            idx += 2
            payload = data[idx:]
            client_addr = addr
            try:
                # forward to destination
                tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                tmp.settimeout(2)
                tmp.sendto(payload, (dest, dport))
                resp, _ = tmp.recvfrom(65535)
                tmp.close()
            except OSError:
                continue
            # wrap response for client
            hdr = b"\x00\x00\x00\x01" + socket.inet_aton(dest) + struct.pack("!H", dport)
            try:
                relay.sendto(hdr + resp, client_addr)
            except OSError:
                pass

    threading.Thread(target=udp_relay_loop, daemon=True).start()

    def handle(client: socket.socket) -> None:
        try:
            client.settimeout(5)
            client.recv(256)
            client.sendall(b"\x05\x00")
            hdr = client.recv(4)
            if len(hdr) < 4:
                return
            cmd = hdr[1]
            if cmd == 0x03:  # UDP ASSOCIATE
                # consume address
                atyp = hdr[3]
                if atyp == 1:
                    client.recv(4)
                elif atyp == 3:
                    ln = client.recv(1)[0]
                    client.recv(ln)
                client.recv(2)
                # reply with relay IPv4
                reply = (
                    b"\x05\x00\x00\x01"
                    + socket.inet_aton("127.0.0.1")
                    + struct.pack("!H", relay_port)
                )
                client.sendall(reply)
                # keep control channel open until client closes
                while not stop.is_set():
                    try:
                        if not client.recv(1):
                            break
                    except socket.timeout:
                        continue
                    except OSError:
                        break
            else:
                client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
        except OSError:
            pass
        finally:
            try:
                client.close()
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
    return srv, tcp_port, stop


def test_socks5_udp_associate_echo():
    echo_sock, echo_port, echo_stop = _udp_echo()
    srv, proxy_port, stop = _socks5_with_udp_associate()
    time.sleep(0.05)
    hop = ProxyHop(type="socks5", host="127.0.0.1", port=proxy_port)
    try:
        ctrl, relay_host, relay_port = socks5_udp_associate(hop, connect_timeout=2, handshake_timeout=3)
        assert relay_port > 0
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            msg = b"UDP-CHAIN-TEST"
            socks5_udp_send(udp, relay_host, relay_port, "127.0.0.1", echo_port, msg)
            _src, _sport, payload = socks5_udp_recv(udp, timeout=3)
            assert payload == msg
        finally:
            udp.close()
            ctrl.close()
    finally:
        stop.set()
        echo_stop.set()
        for s in (srv, echo_sock):
            try:
                s.close()
            except OSError:
                pass


def test_udp_associate_rejects_http_hop():
    hop = ProxyHop(type="http", host="127.0.0.1", port=1)
    try:
        socks5_udp_associate(hop)
        assert False, "should raise"
    except Exception as e:
        assert "SOCKS5" in str(e)
