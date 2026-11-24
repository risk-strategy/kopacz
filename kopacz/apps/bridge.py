"""
TCP bridge — bridges a TCP socket to a tunnel session.

Use case: reverse SSH. An external operator connects via TCP
to the relay. A restricted server connects via DNS tunnel.
The bridge forwards between them.

          TCP                    DNS tunnel
Operator ←→ Bridge ←→ Switch ←→ Restricted Server

The bridge is a relay-side application. It plugs into the
Switch's downstream queue and the on_data callback.
"""

from __future__ import annotations

import socket
import logging
import threading
from typing import Optional

from ..relay.switch import Switch

log = logging.getLogger(__name__)


class TCPBridge:
    """
    Bridges one TCP connection to one tunnel session via the Switch.

    TCP → tunnel: reads TCP socket, enqueues to switch downstream.
    Tunnel → TCP: called by relay's on_data callback, writes to TCP socket.

    Thread-safe. The TCP read loop runs in a background thread.
    """

    def __init__(
        self,
        switch: Switch,
        tunnel_tag: str,
        bind: str = "0.0.0.0",
        port: int = 8022,
    ):
        self.switch = switch
        self.tunnel_tag = tunnel_tag
        self.bind = bind
        self.port = port
        self._conn: Optional[socket.socket] = None
        self._srv: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._running = False

    @property
    def connected(self) -> bool:
        return self._conn is not None

    def on_tunnel_data(self, tag: str, data: bytes) -> Optional[bytes]:
        """
        Relay on_data callback. Forward tunnel data to TCP.

        Wire this into RelayHandler's on_data:
            handler = RelayHandler(..., on_data=bridge.on_tunnel_data)

        Returns None (bridge handles forwarding, not echo).
        """
        if tag != self.tunnel_tag:
            return None
        with self._lock:
            if self._conn:
                try:
                    self._conn.sendall(data)
                except OSError:
                    log.debug("TCP send failed for %s", tag)
        return None

    def _tcp_read_loop(self) -> None:
        """Read from TCP, enqueue to switch downstream."""
        while self._running and self._conn:
            try:
                data = self._conn.recv(4096)
                if not data:
                    log.info("TCP client disconnected")
                    break
                self.switch.enqueue_downstream(self.tunnel_tag, data)
            except OSError:
                break
        self._running = False

    def run_once(self) -> None:
        """Accept one TCP connection, bridge it, block until done."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.bind, self.port))
        srv.listen(1)
        with self._lock:
            self._srv = srv
        log.info("TCP bridge listening on %s:%d for tunnel tag '%s'",
                 self.bind, self.port, self.tunnel_tag)

        try:
            conn, addr = srv.accept()
            log.info("TCP connection from %s", addr)
            with self._lock:
                self._conn = conn
            self._running = True
            self._tcp_read_loop()
        finally:
            with self._lock:
                if self._conn:
                    try:
                        self._conn.close()
                    except OSError:
                        pass
                    self._conn = None
                self._srv = None
            try:
                srv.close()
            except OSError:
                pass

    def run(self) -> None:
        """Accept sequential TCP connections and bridge them until stop() is called."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.bind, self.port))
        srv.listen(4)
        with self._lock:
            self._srv = srv
            self._running = True
        log.info("TCP bridge listening on %s:%d for tunnel tag '%s'",
                 self.bind, self.port, self.tunnel_tag)

        try:
            while self._running:
                try:
                    conn, addr = srv.accept()
                except OSError:
                    break
                log.info("TCP connection from %s", addr)
                with self._lock:
                    if not self._running:
                        conn.close()
                        break
                    self._conn = conn
                try:
                    self._tcp_read_loop()
                finally:
                    with self._lock:
                        if self._conn:
                            try:
                                self._conn.close()
                            except OSError:
                                pass
                            self._conn = None
                    # Re-arm _running if loop exited due to client disconnect rather than stop()
                    if self._srv is not None:
                        self._running = True
        finally:
            with self._lock:
                self._srv = None
            try:
                srv.close()
            except OSError:
                pass

    def start_background(self) -> threading.Thread:
        """Run in a background thread. Returns the thread."""
        t = threading.Thread(target=self.run, daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        """Stop the bridge."""
        self._running = False
        with self._lock:
            if self._srv:
                try:
                    self._srv.close()
                except OSError:
                    pass
                self._srv = None
            if self._conn:
                try:
                    self._conn.close()
                except OSError:
                    pass
                self._conn = None
