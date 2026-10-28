"""
Local SOCKS5 forwarder that applies the full configured proxy chain.

Bound to 127.0.0.1 only. Child processes point ALL_PROXY at this listener so
multi-hop routing and credential isolation are handled in-process by ChainShield.
"""

from __future__ import annotations

import select
import socket
import struct
import threading
from typing import Optional

from chainshield.config import Config, ProxyHop
from chainshield.events import EventBus, EventProvenance, EventSource
from chainshield.proxy import connect_through_chain


def _relay_pair(a: socket.socket, b: socket.socket, stop: threading.Event) -> None:
    sockets = [a, b]
    for s in sockets:
        try:
            s.setblocking(False)
        except OSError:
            stop.set()
            return
    while not stop.is_set():
        try:
            readable, _, errored = select.select(sockets, [], sockets, 0.5)
        except (OSError, ValueError):
            break
        if errored:
            break
        for s in readable:
            other = b if s is a else a
            try:
                data = s.recv(65536)
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


class LocalChainForwarder:
    """
    Minimal localhost SOCKS5 server (no auth) that tunnels each CONNECT
    through Config.proxies via connect_through_chain.
    """

    def __init__(
        self,
        hops: list[ProxyHop],
        cfg: Config,
        events: Optional[EventBus] = None,
    ):
        if not hops:
            raise ValueError("LocalChainForwarder requires at least one hop")
        self.hops = hops
        self.cfg = cfg
        self.events = events
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._clients: list[threading.Thread] = []
        self.host = "127.0.0.1"
        self.port = 0

    def start(self) -> tuple[str, int]:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, 0))
        srv.listen(64)
        srv.settimeout(0.5)
        self.port = srv.getsockname()[1]
        self._sock = srv
        self._stop.clear()
        self._thread = threading.Thread(target=self._accept_loop, name="cs-forwarder", daemon=True)
        self._thread.start()
        if self.events:
            self.events.emit(
                "FORWARDER",
                protocol="SOCKS5",
                destination=f"{self.host}:{self.port}",
                engine="local_chain_forwarder",
                route=[h.redacted() for h in self.hops],
                source=EventSource.PROXY_ADAPTER.value,
                result="listening",
                verification=EventProvenance.OBSERVED.value,
            )
        return self.host, self.port

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None
        if self.events:
            self.events.emit(
                "FORWARDER",
                engine="local_chain_forwarder",
                source=EventSource.PROXY_ADAPTER.value,
                result="stopped",
                verification=EventProvenance.OBSERVED.value,
            )

    def proxy_env(self) -> dict[str, str]:
        """
        Environment for children: local SOCKS5 only — no remote credentials.

        Explicitly neutralizes common bypass variables (NO_PROXY, stale HTTP_PROXY,
        etc.). Empty string is not always enough for every client; callers should
        also delete these keys from the parent environment copy when possible.
        """
        url = f"socks5://{self.host}:{self.port}"
        return {
            "ALL_PROXY": url,
            "all_proxy": url,
            "SOCKS_PROXY": url,
            "socks_proxy": url,
            # Point HTTP(S) proxy vars at the same local SOCKS endpoint where
            # clients honor them; otherwise clear.
            "HTTP_PROXY": url,
            "HTTPS_PROXY": url,
            "http_proxy": url,
            "https_proxy": url,
            # Critical: NO_PROXY causes curl/wget/git to bypass the proxy.
            "NO_PROXY": "",
            "no_proxy": "",
            "FTP_PROXY": url,
            "ftp_proxy": url,
            "CHAINSHIELD_FORWARDER": url,
            "CHAINSHIELD_CHAIN_HOPS": str(len(self.hops)),
            "CHAINSHIELD_PROTECTION_LEVEL": "A",  # application-level only
        }

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                client, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle_client, args=(client,), daemon=True)
            t.start()
            self._clients.append(t)

    def _handle_client(self, client: socket.socket) -> None:
        remote: Optional[socket.socket] = None
        relay_stop = threading.Event()
        try:
            client.settimeout(self.cfg.handshake_timeout)
            # SOCKS5 greeting
            data = client.recv(256)
            if len(data) < 2 or data[0] != 5:
                return
            client.sendall(b"\x05\x00")  # no-auth (localhost only)

            hdr = client.recv(4)
            if len(hdr) < 4 or hdr[0] != 5:
                return
            cmd = hdr[1]
            atyp = hdr[3]
            if cmd != 1:  # CONNECT only
                client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
                return

            if atyp == 1:
                raw = client.recv(4)
                if len(raw) < 4:
                    return
                dest_host = socket.inet_ntoa(raw)
            elif atyp == 3:
                ln_b = client.recv(1)
                if not ln_b:
                    return
                ln = ln_b[0]
                name = client.recv(ln)
                if len(name) < ln:
                    return
                dest_host = name.decode("idna", errors="replace")
            elif atyp == 4:
                raw = client.recv(16)
                if len(raw) < 16:
                    return
                dest_host = socket.inet_ntop(socket.AF_INET6, raw)
            else:
                client.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
                return

            port_b = client.recv(2)
            if len(port_b) < 2:
                return
            dest_port = struct.unpack("!H", port_b)[0]

            chain = connect_through_chain(
                self.hops,
                dest_host,
                dest_port,
                connect_timeout=self.cfg.connect_timeout,
                handshake_timeout=self.cfg.handshake_timeout,
                policy=self.cfg.chain_policy,
                events=self.events,
            )
            if not chain.success or not chain.final_socket:
                client.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
                if self.events:
                    self.events.emit(
                        "FORWARDER",
                        protocol="TCP",
                        destination=f"{dest_host}:{dest_port}",
                        engine="local_chain_forwarder",
                        route=chain.route,
                        source=EventSource.PROXY_ADAPTER.value,
                        result="chain_failed",
                        verification=EventProvenance.OBSERVED.value,
                        error=chain.error,
                    )
                return

            remote = chain.final_socket
            client.sendall(b"\x05\x00\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
            client.settimeout(None)
            remote.settimeout(None)
            if self.events:
                self.events.emit(
                    "FORWARDER",
                    protocol="TCP",
                    destination=f"{dest_host}:{dest_port}",
                    engine="local_chain_forwarder",
                    route=chain.route,
                    source=EventSource.PROXY_ADAPTER.value,
                    result="relay_start",
                    verification=EventProvenance.OBSERVED.value,
                )
            _relay_pair(client, remote, relay_stop)
        except OSError:
            pass
        finally:
            relay_stop.set()
            for s in (client, remote):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass
