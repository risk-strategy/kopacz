"""
CONNECT proxy — relay-side blind TCP forwarder.

The relay opens a raw TCP connection to the target (optionally via
Tor SOCKS5) and forwards bytes blindly.  The client does its own
TLS handshake with the target through the DNS tunnel.  The relay
never sees plaintext.

Wire format (after 0x01 stripped by AppDispatcher):

    CONNECT (0x01): type(1) + port(2 BE) + host (remaining, UTF-8)
    OK      (0x00): type(1)
    ERROR   (0x01): type(1) + message (UTF-8)
    DATA    (0x02): type(1) + raw_bytes
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
from typing import Dict, Optional

from ..relay.switch import Switch

log = logging.getLogger(__name__)

CONNECT = 0x01
OK = 0x00
ERROR = 0x01
DATA = 0x02


def _is_safe_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True only if *ip* (and any IPv4-mapped address) is globally routable."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if (
        not ip.is_global
        or ip.is_private
        or ip.is_loopback
        or ip.is_reserved
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return False
    return True


def validate_target(host: str, port: int, resolve_dns: bool = False) -> bool:
    """Reject private/internal targets (SSRF protection)."""
    if port < 1 or port > 65535:
        return False

    if not host or any(c.isspace() or ord(c) < 0x21 for c in host):
        return False

    cleaned = host.strip().rstrip(".").lower()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]
    if not cleaned:
        return False

    blocked_hosts = ("localhost", "127.0.0.1", "::1", "0.0.0.0", "broadcasthost")
    if cleaned in blocked_hosts or cleaned.endswith(
        (".localhost", ".local", ".internal", ".home.arpa")
    ):
        return False

    # Reject numeric/hex/octal IP encodings (e.g. 2130706433, 0x7f000001, 0177.0.0.1)
    # that socket.connect() accepts on POSIX but ipaddress.ip_address() treats as hostnames
    labels = cleaned.split(".")
    if all(
        lbl.isdigit() or lbl.startswith("0x")
        for lbl in labels
    ):
        try:
            ip_obj = ipaddress.ip_address(cleaned)
        except ValueError:
            return False
        return _is_safe_ip(ip_obj)

    try:
        ip = ipaddress.ip_address(cleaned)
        return _is_safe_ip(ip)
    except ValueError:
        pass  # hostname, not IP

    if resolve_dns:
        try:
            infos = socket.getaddrinfo(cleaned, port, type=socket.SOCK_STREAM)
            if not infos:
                return False
            for family, _, _, _, sockaddr in infos:
                addr_str = sockaddr[0]
                ip_resolved = ipaddress.ip_address(addr_str)
                if not _is_safe_ip(ip_resolved):
                    return False
        except Exception:
            return False

    return True


class ConnectProxy:
    """
    Relay-side CONNECT proxy.  Blind TCP forwarder.

    Each tunnel session gets one TCP connection.  The relay never
    sees plaintext — it forwards encrypted TLS bytes.
    """

    def __init__(
        self,
        switch: Switch,
        tor_host: str = "127.0.0.1",
        tor_port: int = 9050,
        timeout: float = 30.0,
        use_tor: bool = True,
    ):
        self.switch = switch
        self._tor_host = tor_host
        self._tor_port = tor_port
        self._timeout = timeout
        self._use_tor = use_tor
        self._connections: Dict[str, socket.socket] = {}
        self._read_threads: Dict[str, threading.Thread] = {}
        self._lock = threading.Lock()
        self.switch.on_unregister(self._on_session_unregister)

    def _on_session_unregister(self, tag: str) -> None:
        """Close and remove any proxied TCP socket when its tunnel session is unregistered."""
        with self._lock:
            sock = self._connections.pop(tag, None)
            self._read_threads.pop(tag, None)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def on_data(self, tag: str, payload: bytes) -> Optional[bytes]:
        """Dispatcher callback.  Payload has 0x01 prefix stripped."""
        if not payload:
            return None

        msg_type = payload[0]
        if msg_type == CONNECT:
            return self._handle_connect(tag, payload)
        elif msg_type == DATA:
            return self._handle_data(tag, payload[1:])

        return None

    def _handle_connect(self, tag: str, payload: bytes) -> Optional[bytes]:
        """Process CONNECT request, establish TCP connection.

        Runs the actual TCP connect in a background thread so the DNS
        handler returns immediately.  Result (OK/ERROR) is delivered
        via the switch downstream queue and picked up on the next poll.
        """
        if len(payload) < 4:  # type(1) + port(2) + host(1+)
            return bytes([ERROR]) + b"Malformed CONNECT"

        port = int.from_bytes(payload[1:3], "big")
        host = payload[3:].decode("utf-8", errors="replace")

        if not validate_target(host, port):
            return bytes([ERROR]) + b"Target not allowed"

        # Run connection in background to avoid blocking the DNS handler
        t = threading.Thread(
            target=self._connect_bg, args=(tag, host, port), daemon=True
        )
        t.start()
        return None

    def _connect_bg(self, tag: str, host: str, port: int) -> None:
        """Background thread: establish TCP connection and report result."""
        try:
            sock = self._make_socket()
            sock.settimeout(self._timeout)
            sock.connect((host, port))
        except Exception as e:
            log.debug("CONNECT failed for %s:%d: %s", host, port, e)
            self.switch.enqueue_downstream(
                tag, bytes([ERROR]) + str(e).encode("utf-8", errors="replace")
            )
            return

        with self._lock:
            old_sock = self._connections.get(tag)
            self._connections[tag] = sock
        if old_sock is not None:
            try:
                old_sock.close()
            except OSError:
                pass
        self.switch.enqueue_downstream(tag, bytes([OK]))

        # Start background read: TCP → switch downstream
        rt = threading.Thread(
            target=self._tcp_read_loop, args=(tag, sock), daemon=True
        )
        with self._lock:
            self._read_threads[tag] = rt
        rt.start()

    def _make_socket(self) -> socket.socket:
        """Create a socket — Tor SOCKS5 or plain TCP."""
        if self._use_tor:
            try:
                import socks
            except ImportError:
                raise RuntimeError(
                    "PySocks required for Tor: pip install 'kopacz[proxy]'"
                )
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, self._tor_host, self._tor_port, rdns=True)
            return sock
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def _handle_data(self, tag: str, data: bytes) -> Optional[bytes]:
        """Forward client data to TCP target."""
        with self._lock:
            sock = self._connections.get(tag)
        if sock is None:
            return None
        try:
            sock.sendall(data)
        except OSError as e:
            log.debug("TCP send failed for %s: %s", tag, e)
        return None

    def _tcp_read_loop(self, tag: str, sock: socket.socket) -> None:
        """Read from TCP target, enqueue to switch downstream."""
        try:
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                self.switch.enqueue_downstream(tag, bytes([DATA]) + data)
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass
            with self._lock:
                if self._connections.get(tag) is sock:
                    self._connections.pop(tag, None)

    def close_all(self) -> None:
        """Close all active connections."""
        with self._lock:
            socks = list(self._connections.values())
            self._connections.clear()
        for sock in socks:
            try:
                sock.close()
            except OSError:
                pass
