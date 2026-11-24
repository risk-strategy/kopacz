"""
CONNECT proxy client — programmatic API and local SOCKS5 server.

ConnectClient: direct API for establishing CONNECT tunnels.
TunnelSocket:  socket-like wrapper for ssl.wrap_socket compatibility.
LocalProxy:    local SOCKS5 server bridging browser → tunnel → relay.
"""

from __future__ import annotations

import io
import logging
import socket
import struct
import threading
from typing import Callable, List, Optional

from ...client.tunnel import TunnelClient

log = logging.getLogger(__name__)

APP_ID = 0x01
CONNECT = 0x01
OK = 0x00
ERROR = 0x01
DATA = 0x02


class ConnectClient:
    """Programmatic CONNECT client (no SOCKS5, direct API)."""

    APP_ID = APP_ID

    def __init__(self, tunnel: TunnelClient):
        self.tunnel = tunnel
        self._connected = False
        self._inbox: List[bytes] = []

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self, host: str, port: int, poll_attempts: int = 30,
                poll_delay: float = 1.0) -> None:
        """Send CONNECT request through tunnel.

        The relay establishes the TCP connection asynchronously, so the
        result arrives via downstream polling rather than inline.
        """
        import time

        payload = (
            bytes([self.APP_ID, CONNECT])
            + port.to_bytes(2, "big")
            + host.encode("utf-8")
        )
        downstream = self.tunnel.send(payload)

        # Check for inline response (fast / direct connections)
        response = None
        if downstream:
            response = downstream[0]
            if len(downstream) > 1:
                self._inbox.extend(downstream[1:])

        # Poll for async response (Tor connections are slow)
        if response is None:
            for _ in range(poll_attempts):
                polled = self.tunnel.poll_all()
                if polled:
                    response = polled[0]
                    if len(polled) > 1:
                        self._inbox.extend(polled[1:])
                    break
                time.sleep(poll_delay)

        if response is None:
            raise ConnectionError("No CONNECT response from relay")

        if response[0] == OK:
            self._connected = True
        elif response[0] == ERROR:
            raise ConnectionError(
                f"CONNECT failed: {response[1:].decode('utf-8', errors='replace')}"
            )
        else:
            raise ConnectionError(f"Unknown CONNECT response: {response[0]:#x}")

    def send(self, data: bytes) -> List[bytes]:
        """Send DATA through the CONNECT tunnel. Returns any downstream."""
        payload = bytes([self.APP_ID, DATA]) + data
        downstream = self.tunnel.send(payload)
        return self._strip_data_prefix(downstream)

    def poll_all(self) -> List[bytes]:
        """Poll for data from the remote target."""
        downstream = list(self._inbox)
        self._inbox.clear()
        downstream.extend(self.tunnel.poll_all())
        return self._strip_data_prefix(downstream)

    @staticmethod
    def _strip_data_prefix(msgs: List[bytes]) -> List[bytes]:
        """Strip DATA(0x02) prefix from downstream messages."""
        result = []
        for msg in msgs:
            if msg and msg[0] == DATA:
                result.append(msg[1:])
            else:
                result.append(msg)
        return result

    def make_socket(self) -> "TunnelSocket":
        """Returns a socket-like object wrapping this tunnel connection.

        Can be passed to ssl.SSLContext.wrap_socket() for TLS.
        """
        return TunnelSocket(self)


class TunnelSocket:
    """
    Socket-like wrapper around ConnectClient.

    Implements enough of the socket API (recv, send, makefile)
    for Python's ssl module to wrap it.
    """

    def __init__(self, client: ConnectClient):
        self._client = client
        self._recv_buf = bytearray()
        self._closed = False

    def send(self, data: bytes, flags: int = 0) -> int:
        """Send data through tunnel."""
        for chunk in self._client.send(data):
            self._recv_buf.extend(chunk)
        return len(data)

    def sendall(self, data: bytes, flags: int = 0) -> None:
        """Send all data through tunnel."""
        self.send(data)

    def recv(self, bufsize: int, flags: int = 0) -> bytes:
        """Receive data from tunnel."""
        while len(self._recv_buf) < bufsize:
            chunks = self._client.poll_all()
            if not chunks:
                break
            for chunk in chunks:
                self._recv_buf.extend(chunk)

        result = bytes(self._recv_buf[:bufsize])
        self._recv_buf = self._recv_buf[bufsize:]
        return result

    def recv_into(self, buffer, nbytes=0, flags=0):
        data = self.recv(nbytes or len(buffer))
        n = len(data)
        buffer[:n] = data
        return n

    def makefile(self, mode: str = "rb", buffering: int = -1, **kwargs) -> io.BufferedIOBase:
        """Create a file-like object wrapping this socket."""
        if "b" in mode:
            raw = _SocketRawIO(self)
            if "w" in mode:
                return io.BufferedWriter(raw, buffer_size=buffering if buffering > 0 else 8192)
            return io.BufferedReader(raw, buffer_size=buffering if buffering > 0 else 8192)
        raise ValueError(f"Unsupported mode: {mode}")

    def settimeout(self, timeout) -> None:
        pass  # timeout handled by tunnel

    def gettimeout(self) -> float:
        return 0.0

    def setblocking(self, flag: bool) -> None:
        pass

    def getpeername(self):
        return ("tunnel", 0)

    def fileno(self) -> int:
        raise OSError("TunnelSocket has no file descriptor")

    def close(self) -> None:
        self._closed = True

    @property
    def _closed_flag(self) -> bool:
        return self._closed


class _SocketRawIO(io.RawIOBase):
    """Raw IO adapter for TunnelSocket."""

    def __init__(self, sock: TunnelSocket):
        self._sock = sock

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            n = 65536
        return self._sock.recv(n)

    def readinto(self, b):
        data = self.read(len(b))
        n = len(data)
        b[:n] = data
        return n

    def write(self, b: bytes) -> int:
        return self._sock.send(b)

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return True


# ── Local SOCKS5 server ──────────────────────────────────────

class LocalProxy:
    """
    Local SOCKS5 proxy that tunnels connections over DNS.

    User configures browser: SOCKS5 proxy = 127.0.0.1:1080
    Each browser connection becomes a separate tunnel session
    with its own CONNECT request through the DNS tunnel.
    """

    APP_ID = APP_ID

    def __init__(
        self,
        tunnel_factory: Callable[[], TunnelClient],
        bind: str = "127.0.0.1",
        port: int = 1080,
    ):
        self._tunnel_factory = tunnel_factory
        self.bind = bind
        self.port = port
        self._running = False
        self._server_sock: Optional[socket.socket] = None

    def run(self) -> None:
        """Blocking SOCKS5 server loop."""
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.bind, self.port))
        self._server_sock.listen(128)
        self._running = True
        log.info("SOCKS5 proxy on %s:%d", self.bind, self.port)

        try:
            while self._running:
                try:
                    conn, addr = self._server_sock.accept()
                    t = threading.Thread(
                        target=self._handle_client, args=(conn,), daemon=True
                    )
                    t.start()
                except OSError:
                    break
        finally:
            if self._server_sock:
                self._server_sock.close()

    def stop(self) -> None:
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass

    def _handle_client(self, client: socket.socket) -> None:
        """Handle one SOCKS5 client connection."""
        tunnel = None
        try:
            # SOCKS5 greeting: VER(1) + NMETHODS(1) + METHODS(1..255)
            data = client.recv(258)
            if len(data) < 2 or data[0] != 0x05:
                return
            nmethods = data[1]
            if len(data) < 2 + nmethods:
                return
            # No auth
            client.sendall(b"\x05\x00")

            # CONNECT request
            data = client.recv(262)
            if len(data) < 7 or data[0] != 0x05 or data[1] != 0x01:
                client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
                return

            atyp = data[3]
            if atyp == 0x01:  # IPv4
                if len(data) < 10:
                    return
                host = socket.inet_ntoa(data[4:8])
                port = struct.unpack("!H", data[8:10])[0]
            elif atyp == 0x03:  # Domain
                domain_len = data[4]
                if domain_len == 0 or len(data) < 5 + domain_len + 2:
                    return
                host = data[5:5 + domain_len].decode("utf-8")
                port = struct.unpack("!H", data[5 + domain_len:7 + domain_len])[0]
            elif atyp == 0x04:  # IPv6
                if len(data) < 22:
                    return
                host = socket.inet_ntop(socket.AF_INET6, data[4:20])
                port = struct.unpack("!H", data[20:22])[0]
            else:
                client.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
                return

            # Establish tunnel
            tunnel = self._tunnel_factory()
            tunnel.connect()
            conn_client = ConnectClient(tunnel)
            conn_client.connect(host, port)

            # Success response
            client.sendall(
                b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
            )

            # Bidirectional forwarding
            self._forward(client, conn_client)

        except Exception as e:
            log.debug("SOCKS5 error: %s", e)
            try:
                client.sendall(b"\x05\x01\x00\x01" + b"\x00" * 6)
            except OSError:
                pass
        finally:
            if tunnel is not None:
                try:
                    tunnel.close()
                except Exception:
                    pass
            try:
                client.close()
            except OSError:
                pass

    @staticmethod
    def _forward(client_sock: socket.socket, conn_client: ConnectClient) -> None:
        """Bidirectional forwarding between browser and tunnel."""
        import time
        done = threading.Event()

        def browser_to_tunnel():
            try:
                while not done.is_set():
                    data = client_sock.recv(4096)
                    if not data:
                        break
                    for chunk in conn_client.send(data):
                        client_sock.sendall(chunk)
            except OSError:
                pass
            finally:
                done.set()

        def tunnel_to_browser():
            idle_sleep = 0.02
            try:
                while not done.is_set():
                    chunks = conn_client.poll_all()
                    for chunk in chunks:
                        client_sock.sendall(chunk)
                    if chunks:
                        idle_sleep = 0.02
                    else:
                        time.sleep(idle_sleep)
                        idle_sleep = min(0.25, idle_sleep * 1.5)
            except OSError:
                pass
            finally:
                done.set()

        t1 = threading.Thread(target=browser_to_tunnel, daemon=True)
        t2 = threading.Thread(target=tunnel_to_browser, daemon=True)
        t1.start()
        t2.start()
        done.wait()
