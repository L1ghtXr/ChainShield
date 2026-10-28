"""Proxy engine: SOCKS4/5, HTTP CONNECT, chaining, health checks."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Optional

from chainshield.config import Config, ProxyHop
from chainshield.events import EventBus, EventProvenance, EventSource


class ProxyError(Exception):
    pass


class ProxyTimeout(ProxyError):
    pass


class ProxyAuthError(ProxyError):
    pass


class ProxyHandshakeError(ProxyError):
    pass


@dataclass
class ChainResult:
    success: bool
    hop_results: list[dict]
    final_socket: Optional[socket.socket] = None
    error: str = ""
    route: list[str] = field(default_factory=list)


def _set_timeout(sock: socket.socket, timeout: float) -> None:
    sock.settimeout(timeout)


def _connect_tcp(host: str, port: int, timeout: float) -> socket.socket:
    # Prefer IPv4 for simplicity; try getaddrinfo
    last_err: Optional[Exception] = None
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ProxyError(f"DNS resolution failed for {host}: {e}") from e

    for family, type_, proto, _, sockaddr in infos:
        sock = socket.socket(family, type_, proto)
        try:
            _set_timeout(sock, timeout)
            sock.connect(sockaddr)
            return sock
        except OSError as e:
            last_err = e
            try:
                sock.close()
            except OSError:
                pass
    raise ProxyError(f"Connect to {host}:{port} failed: {last_err}")


def socks5_handshake(
    sock: socket.socket,
    hop: ProxyHop,
    dest_host: str,
    dest_port: int,
    timeout: float,
) -> None:
    _set_timeout(sock, timeout)
    # Greeting: offer user/pass only when credentials are configured; otherwise no-auth.
    if hop.username:
        methods = [0x02]
    else:
        methods = [0x00]
    sock.sendall(bytes([0x05, len(methods)] + methods))
    resp = _recv_exact(sock, 2)
    if resp[0] != 0x05:
        raise ProxyHandshakeError(f"SOCKS5 version mismatch: {resp[0]}")
    method = resp[1]
    if method == 0xFF:
        raise ProxyAuthError("SOCKS5: no acceptable auth method")
    if method == 0x02:
        user = hop.username.encode("utf-8")
        pw = hop.password.encode("utf-8")
        if len(user) > 255 or len(pw) > 255:
            raise ProxyAuthError("SOCKS5 credentials too long")
        sock.sendall(bytes([0x01, len(user)]) + user + bytes([len(pw)]) + pw)
        auth_resp = _recv_exact(sock, 2)
        if auth_resp[1] != 0x00:
            raise ProxyAuthError("SOCKS5 authentication failed")
    elif method != 0x00:
        raise ProxyHandshakeError(f"SOCKS5 unsupported method: {method}")

    # CONNECT request — prefer address literals, else domain (ATYP 0x03)
    req = bytearray([0x05, 0x01, 0x00])
    try:
        ip4 = socket.inet_pton(socket.AF_INET, dest_host)
        req.append(0x01)
        req.extend(ip4)
    except OSError:
        try:
            ip6 = socket.inet_pton(socket.AF_INET6, dest_host)
            req.append(0x04)
            req.extend(ip6)
        except OSError:
            try:
                host_b = dest_host.encode("idna")
            except Exception as e:
                raise ProxyError(f"Invalid destination host: {dest_host}") from e
            if len(host_b) > 255:
                raise ProxyError("hostname too long for SOCKS5")
            req.append(0x03)
            req.append(len(host_b))
            req.extend(host_b)
    req.extend(struct.pack("!H", dest_port))
    sock.sendall(req)

    # Reply: VER REP RSV ATYP
    hdr = _recv_exact(sock, 4)
    if hdr[0] != 0x05:
        raise ProxyHandshakeError("SOCKS5 reply version error")
    if hdr[1] != 0x00:
        codes = {
            0x01: "general failure",
            0x02: "connection not allowed",
            0x03: "network unreachable",
            0x04: "host unreachable",
            0x05: "connection refused",
            0x06: "TTL expired",
            0x07: "command not supported",
            0x08: "address type not supported",
        }
        raise ProxyHandshakeError(f"SOCKS5 CONNECT failed: {codes.get(hdr[1], hex(hdr[1]))}")
    atyp = hdr[3]
    if atyp == 0x01:
        _recv_exact(sock, 4 + 2)
    elif atyp == 0x03:
        ln = _recv_exact(sock, 1)[0]
        _recv_exact(sock, ln + 2)
    elif atyp == 0x04:
        _recv_exact(sock, 16 + 2)
    else:
        raise ProxyHandshakeError(f"SOCKS5 unknown ATYP {atyp}")


def socks4_handshake(
    sock: socket.socket,
    hop: ProxyHop,
    dest_host: str,
    dest_port: int,
    timeout: float,
) -> None:
    _set_timeout(sock, timeout)
    # SOCKS4a with domain
    user = (hop.username or "").encode("utf-8") + b"\x00"
    try:
        ip = socket.inet_aton(dest_host)
        host_part = b""
    except OSError:
        ip = b"\x00\x00\x00\x01"  # SOCKS4a marker
        host_part = dest_host.encode("idna") + b"\x00"
    req = b"\x04\x01" + struct.pack("!H", dest_port) + ip + user + host_part
    sock.sendall(req)
    resp = _recv_exact(sock, 8)
    if resp[0] != 0x00 or resp[1] != 0x5A:
        raise ProxyHandshakeError(f"SOCKS4 CONNECT failed code={resp[1]}")


def http_connect_handshake(
    sock: socket.socket,
    hop: ProxyHop,
    dest_host: str,
    dest_port: int,
    timeout: float,
) -> None:
    _set_timeout(sock, timeout)
    target = f"{dest_host}:{dest_port}"
    lines = [
        f"CONNECT {target} HTTP/1.1",
        f"Host: {target}",
        "Proxy-Connection: Keep-Alive",
    ]
    if hop.username:
        import base64

        token = base64.b64encode(f"{hop.username}:{hop.password}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {token}")
    lines.append("")
    lines.append("")
    sock.sendall("\r\n".join(lines).encode("utf-8"))

    # Read response headers
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 8192:
        chunk = sock.recv(256)
        if not chunk:
            raise ProxyHandshakeError("HTTP CONNECT: connection closed during handshake")
        buf += chunk
    header = buf.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", errors="replace")
    status_line = header.split("\r\n", 1)[0]
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[1].startswith("2"):
        raise ProxyHandshakeError(f"HTTP CONNECT failed: {status_line}")


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ProxyHandshakeError("Connection closed during handshake")
        data += chunk
    return data


def connect_through_chain(
    hops: list[ProxyHop],
    dest_host: str,
    dest_port: int,
    *,
    connect_timeout: float = 10.0,
    handshake_timeout: float = 15.0,
    policy: str = "strict",
    events: Optional[EventBus] = None,
) -> ChainResult:
    """
    Establish a TCP connection to dest through ordered proxy hops.
    Policy strict/fail_closed: any hop failure aborts (no unprotected fallback).
    """
    if not hops:
        raise ProxyError("No proxy hops configured")

    hop_results: list[dict] = []
    route: list[str] = []
    sock: Optional[socket.socket] = None

    try:
        # Connect to first hop
        first = hops[0]
        route.append(first.redacted())
        if events:
            events.emit(
                "CONNECT",
                protocol="TCP",
                destination=f"{first.host}:{first.port}",
                engine="proxy_chain",
                route=route[:],
                source=EventSource.PROXY_ADAPTER.value,
                result="attempt",
                verification=EventProvenance.OBSERVED.value,
            )
        sock = _connect_tcp(first.host, first.port, connect_timeout)
        hop_results.append({"hop": first.redacted(), "status": "connected"})

        # For each hop i, request CONNECT to next hop or final dest
        for i, hop in enumerate(hops):
            if i + 1 < len(hops):
                next_hop = hops[i + 1]
                target_host, target_port = next_hop.host, next_hop.port
            else:
                target_host, target_port = dest_host, dest_port

            try:
                if hop.type == "socks5":
                    socks5_handshake(sock, hop, target_host, target_port, handshake_timeout)
                elif hop.type == "socks4":
                    socks4_handshake(sock, hop, target_host, target_port, handshake_timeout)
                elif hop.type == "http":
                    http_connect_handshake(sock, hop, target_host, target_port, handshake_timeout)
                else:
                    raise ProxyError(f"Unsupported hop type: {hop.type}")

                if i + 1 < len(hops):
                    route.append(hops[i + 1].redacted())
                else:
                    route.append(f"{dest_host}:{dest_port}")

                hop_results[-1]["handshake"] = "ok"
                hop_results[-1]["target"] = f"{target_host}:{target_port}"
                if events:
                    events.emit(
                        "HANDSHAKE",
                        protocol=hop.type.upper(),
                        destination=f"{target_host}:{target_port}",
                        engine="proxy_chain",
                        route=route[:],
                        source=EventSource.PROXY_ADAPTER.value,
                        result="ok",
                        verification=EventProvenance.OBSERVED.value,
                    )
                if i + 1 < len(hops):
                    hop_results.append({"hop": hops[i + 1].redacted(), "status": "via_previous"})
            except ProxyError as e:
                hop_results[-1]["handshake"] = "failed"
                hop_results[-1]["error"] = str(e)
                if events:
                    events.emit(
                        "HANDSHAKE",
                        protocol=hop.type.upper(),
                        destination=f"{target_host}:{target_port}",
                        engine="proxy_chain",
                        route=route[:],
                        source=EventSource.PROXY_ADAPTER.value,
                        result="failed",
                        verification=EventProvenance.OBSERVED.value,
                        error=str(e),
                    )
                if policy in ("strict", "fail_closed"):
                    if sock:
                        try:
                            sock.close()
                        except OSError:
                            pass
                    return ChainResult(
                        success=False,
                        hop_results=hop_results,
                        error=str(e),
                        route=route,
                    )
                raise

        return ChainResult(success=True, hop_results=hop_results, final_socket=sock, route=route)
    except ProxyError as e:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
        return ChainResult(success=False, hop_results=hop_results, error=str(e), route=route)
    except OSError as e:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
        return ChainResult(
            success=False,
            hop_results=hop_results,
            error=f"OS error: {e}",
            route=route,
        )




def socks5_udp_associate(
    hop: ProxyHop,
    *,
    connect_timeout: float = 10.0,
    handshake_timeout: float = 15.0,
) -> tuple[socket.socket, str, int]:
    """
    Establish a SOCKS5 UDP ASSOCIATE control channel (single hop only).

    Returns (control_socket, relay_host, relay_port).
    Multi-hop UDP is not supported by sequential CONNECT chaining.
    The control TCP connection must remain open for the association lifetime.
    """
    if hop.type != "socks5":
        raise ProxyError("UDP ASSOCIATE requires a SOCKS5 hop")
    sock = _connect_tcp(hop.host, hop.port, connect_timeout)
    try:
        _set_timeout(sock, handshake_timeout)
        # greeting
        if hop.username:
            methods = [0x02]
        else:
            methods = [0x00]
        sock.sendall(bytes([0x05, len(methods)] + methods))
        resp = _recv_exact(sock, 2)
        if resp[0] != 0x05:
            raise ProxyHandshakeError("SOCKS5 version mismatch")
        if resp[1] == 0xFF:
            raise ProxyAuthError("SOCKS5: no acceptable auth method")
        if resp[1] == 0x02:
            user = hop.username.encode("utf-8")
            pw = hop.password.encode("utf-8")
            sock.sendall(bytes([0x01, len(user)]) + user + bytes([len(pw)]) + pw)
            auth_resp = _recv_exact(sock, 2)
            if auth_resp[1] != 0x00:
                raise ProxyAuthError("SOCKS5 authentication failed")
        elif resp[1] != 0x00:
            raise ProxyHandshakeError(f"SOCKS5 unsupported method: {resp[1]}")

        # UDP ASSOCIATE to 0.0.0.0:0
        req = bytearray([0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        sock.sendall(req)
        hdr = _recv_exact(sock, 4)
        if hdr[0] != 0x05 or hdr[1] != 0x00:
            raise ProxyHandshakeError(f"SOCKS5 UDP ASSOCIATE failed code={hdr[1]}")
        atyp = hdr[3]
        if atyp == 0x01:
            addr = socket.inet_ntoa(_recv_exact(sock, 4))
        elif atyp == 0x03:
            ln = _recv_exact(sock, 1)[0]
            addr = _recv_exact(sock, ln).decode("idna", errors="replace")
        elif atyp == 0x04:
            addr = socket.inet_ntop(socket.AF_INET6, _recv_exact(sock, 16))
        else:
            raise ProxyHandshakeError(f"SOCKS5 unknown ATYP {atyp}")
        port = struct.unpack("!H", _recv_exact(sock, 2))[0]
        # If relay reports 0.0.0.0, use the proxy host
        if addr in ("0.0.0.0", "::"):
            addr = hop.host
        return sock, addr, port
    except Exception:
        try:
            sock.close()
        except OSError:
            pass
        raise


def socks5_udp_send(
    udp_sock: socket.socket,
    relay_host: str,
    relay_port: int,
    dest_host: str,
    dest_port: int,
    payload: bytes,
) -> None:
    """Send one SOCKS5 UDP datagram header + payload to the relay."""
    header = bytearray([0x00, 0x00, 0x00])  # RSV RSV FRAG
    try:
        ip4 = socket.inet_pton(socket.AF_INET, dest_host)
        header.append(0x01)
        header.extend(ip4)
    except OSError:
        try:
            ip6 = socket.inet_pton(socket.AF_INET6, dest_host)
            header.append(0x04)
            header.extend(ip6)
        except OSError:
            host_b = dest_host.encode("idna")
            header.append(0x03)
            header.append(len(host_b))
            header.extend(host_b)
    header.extend(struct.pack("!H", dest_port))
    udp_sock.sendto(bytes(header) + payload, (relay_host, relay_port))


def socks5_udp_recv(
    udp_sock: socket.socket,
    *,
    timeout: float = 5.0,
) -> tuple[str, int, bytes]:
    """Receive and parse one SOCKS5 UDP datagram. Returns (src_host, src_port, payload)."""
    udp_sock.settimeout(timeout)
    data, _addr = udp_sock.recvfrom(65535)
    if len(data) < 7:
        raise ProxyError("SOCKS5 UDP packet too short")
    # RSV(2) FRAG(1) ATYP
    atyp = data[3]
    idx = 4
    if atyp == 0x01:
        host = socket.inet_ntoa(data[idx : idx + 4])
        idx += 4
    elif atyp == 0x03:
        ln = data[idx]
        idx += 1
        host = data[idx : idx + ln].decode("idna", errors="replace")
        idx += ln
    elif atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, data[idx : idx + 16])
        idx += 16
    else:
        raise ProxyError(f"SOCKS5 UDP unknown ATYP {atyp}")
    port = struct.unpack("!H", data[idx : idx + 2])[0]
    idx += 2
    return host, port, data[idx:]



def health_check_hop(
    hop: ProxyHop,
    *,
    timeout: float = 8.0,
    events: Optional[EventBus] = None,
) -> dict:
    """
    Basic health: TCP connect + optional minimal handshake toward a known port.
    Does not claim full proxy functionality beyond reachability of the hop itself.
    """
    result = {"hop": hop.redacted(), "reachable": False, "error": ""}
    try:
        sock = _connect_tcp(hop.host, hop.port, timeout)
        sock.close()
        result["reachable"] = True
        if events:
            events.emit(
                "HEALTH",
                protocol=hop.type.upper(),
                destination=f"{hop.host}:{hop.port}",
                engine="proxy",
                source=EventSource.PROXY_ADAPTER.value,
                result="reachable",
                verification=EventProvenance.OBSERVED.value,
            )
    except Exception as e:
        result["error"] = str(e)
        if events:
            events.emit(
                "HEALTH",
                protocol=hop.type.upper(),
                destination=f"{hop.host}:{hop.port}",
                engine="proxy",
                source=EventSource.PROXY_ADAPTER.value,
                result="unreachable",
                verification=EventProvenance.OBSERVED.value,
                error=str(e),
            )
    return result


def health_check_chain(cfg: Config, events: Optional[EventBus] = None) -> list[dict]:
    return [
        health_check_hop(h, timeout=cfg.health_check_timeout, events=events)
        for h in cfg.proxies
    ]


def build_proxy_env(hops: list[ProxyHop]) -> dict[str, str]:
    """
    Environment variables pointing at the first hop (legacy helper).

    Preferred path for `chainshield run` is LocalChainForwarder.proxy_env(),
    which exposes only a localhost SOCKS5 URL and applies the full hop list
    inside the parent process.
    """
    env: dict[str, str] = {}
    if not hops:
        return env
    first = hops[0]
    auth = ""
    if first.username:
        auth = f"{first.username}:{first.password}@"
    if first.type in ("socks5", "socks4"):
        url = f"{first.type}://{auth}{first.host}:{first.port}"
        env["ALL_PROXY"] = url
        env["all_proxy"] = url
        env["SOCKS_PROXY"] = url
        env["socks_proxy"] = url
    elif first.type == "http":
        url = f"http://{auth}{first.host}:{first.port}"
        env["HTTP_PROXY"] = url
        env["HTTPS_PROXY"] = url
        env["http_proxy"] = url
        env["https_proxy"] = url
        env["ALL_PROXY"] = url
        env["all_proxy"] = url
    if len(hops) > 1:
        env["CHAINSHIELD_NOTE"] = (
            "Multi-hop: only first hop exported via env; full chain requires "
            "chainshield run with supported adapter or local forwarder"
        )
    return env
