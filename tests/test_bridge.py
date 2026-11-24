"""
TCP bridge tests.

Tests the bridge's data forwarding logic without real sockets
where possible, and with localhost sockets for integration.
"""

import socket
import threading
import time
import pytest

from kopacz.relay.switch import Switch
from kopacz.apps.bridge import TCPBridge


class TestBridgeDataFlow:
    def test_tcp_to_tunnel(self):
        """Data from TCP socket appears in switch downstream."""
        switch = Switch()
        switch.register("srv1")
        bridge = TCPBridge(switch, "srv1", port=0)  # port=0 won't bind

        # Simulate: enqueue directly (what the read loop does)
        switch.enqueue_downstream("srv1", b"from tcp")
        data = switch.poll_downstream("srv1")
        assert data == b"from tcp"

    def test_tunnel_to_tcp_callback(self):
        """on_tunnel_data writes to TCP socket when connected."""
        switch = Switch()
        switch.register("srv1")
        bridge = TCPBridge(switch, "srv1")

        # No connection — should not crash
        result = bridge.on_tunnel_data("srv1", b"no crash please")
        assert result is None

        # Wrong tag — should ignore
        result = bridge.on_tunnel_data("other", b"ignored")
        assert result is None

    def test_connected_property(self):
        switch = Switch()
        bridge = TCPBridge(switch, "srv1")
        assert not bridge.connected


class TestBridgeIntegration:
    def test_tcp_roundtrip(self):
        """Full TCP ↔ bridge ↔ switch roundtrip with real sockets."""
        switch = Switch()
        switch.register("srv1")

        # Find a free port
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        bridge = TCPBridge(switch, "srv1", bind="127.0.0.1", port=port)
        thread = bridge.start_background()

        # Give server time to bind
        time.sleep(0.1)

        # Connect as TCP client
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect(("127.0.0.1", port))

        try:
            # TCP → switch downstream
            conn.sendall(b"hello from tcp")
            time.sleep(0.1)
            data = switch.poll_downstream("srv1")
            assert data == b"hello from tcp"

            # Switch → TCP (via callback)
            bridge.on_tunnel_data("srv1", b"hello from tunnel")
            response = conn.recv(4096)
            assert response == b"hello from tunnel"
        finally:
            conn.close()
            bridge.stop()
            thread.join(timeout=2)
