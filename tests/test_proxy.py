"""Tests for CONNECT proxy: validation, data flow, TunnelSocket."""

import os
import socket
import threading
import time

import pytest

from kopacz.apps.proxy import ConnectProxy, validate_target, OK, ERROR, DATA, CONNECT
from kopacz.apps.dispatch import AppDispatcher
from kopacz.apps.clients.proxy import ConnectClient, TunnelSocket
from kopacz.client.tunnel import TunnelClient
from kopacz.protocol.crypto import derive_pubkey
from kopacz.relay.server import RelayHandler
from kopacz.relay.switch import Switch

SERVER_PRIV = b"\x42" * 32
PSK = derive_pubkey(SERVER_PRIV)
DOMAIN = "proxy.example.com"


class MockResolver:
    def __init__(self, handler: RelayHandler):
        self.handler = handler

    def query(self, qname: str) -> str | None:
        txt = self.handler.build_response(qname)
        return txt if txt else None


class MockTCPTarget:
    """Localhost TCP echo server for testing."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.host = "127.0.0.1"
        self._thread = None
        self._running = False
        self.received: list[bytes] = []

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def _serve(self):
        while self._running:
            try:
                self.sock.settimeout(0.5)
                conn, _ = self.sock.accept()
                threading.Thread(
                    target=self._handle, args=(conn,), daemon=True
                ).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle(self, conn):
        try:
            while self._running:
                data = conn.recv(4096)
                if not data:
                    break
                self.received.append(data)
                conn.sendall(data)  # echo
        except OSError:
            pass
        finally:
            conn.close()

    def stop(self):
        self._running = False
        self.sock.close()


# ── SSRF validation ───────────────────────────────────────────

class TestValidateTarget:
    def test_public_host_allowed(self):
        assert validate_target("bbc.co.uk", 443) is True

    def test_public_ip_allowed(self):
        assert validate_target("93.184.216.34", 80) is True

    def test_localhost_rejected(self):
        assert validate_target("localhost", 80) is False

    def test_loopback_rejected(self):
        assert validate_target("127.0.0.1", 80) is False

    def test_ipv6_loopback_rejected(self):
        assert validate_target("::1", 80) is False

    def test_private_ip_rejected(self):
        assert validate_target("192.168.1.1", 80) is False
        assert validate_target("10.0.0.1", 80) is False
        assert validate_target("172.16.0.1", 80) is False

    def test_zero_address_rejected(self):
        assert validate_target("0.0.0.0", 80) is False

    def test_port_zero_rejected(self):
        assert validate_target("example.com", 0) is False

    def test_port_too_high_rejected(self):
        assert validate_target("example.com", 70000) is False

    def test_port_max_allowed(self):
        assert validate_target("example.com", 65535) is True

    def test_hostname_not_ip_allowed(self):
        assert validate_target("some-internal.example.com", 443) is True

    def test_reserved_ip_rejected(self):
        assert validate_target("240.0.0.1", 80) is False


# ── ConnectProxy relay side ───────────────────────────────────

class TestConnectProxyRelay:
    @staticmethod
    def _allow_localhost(target):
        """Patch validate_target to allow localhost for testing."""
        import kopacz.apps.proxy as proxy_mod
        original = proxy_mod.validate_target

        def patched(host, port):
            if host == "127.0.0.1" and port == target.port:
                return True
            return original(host, port)

        proxy_mod.validate_target = patched
        return original

    @staticmethod
    def _restore_validate(original):
        import kopacz.apps.proxy as proxy_mod
        proxy_mod.validate_target = original

    def test_connect_to_mock_target(self):
        """CONNECT request creates TCP connection to mock target."""
        target = MockTCPTarget().start()
        orig = self._allow_localhost(target)
        try:
            switch = Switch()
            switch.register("client1")
            proxy = ConnectProxy(switch, use_tor=False, timeout=5.0)

            payload = (
                bytes([CONNECT])
                + target.port.to_bytes(2, "big")
                + target.host.encode()
            )
            proxy.on_data("client1", payload)

            # Connection happens in background thread
            time.sleep(0.5)
            ok = switch.poll_downstream("client1")
            assert ok == bytes([OK])
            assert "client1" in proxy._connections
        finally:
            proxy.close_all()
            target.stop()
            self._restore_validate(orig)

    def test_connect_ssrf_rejected(self):
        """CONNECT to private IP is rejected."""
        switch = Switch()
        proxy = ConnectProxy(switch, use_tor=False)

        payload = (
            bytes([CONNECT])
            + (80).to_bytes(2, "big")
            + b"127.0.0.1"
        )
        result = proxy.on_data("x", payload)
        assert result[0] == ERROR
        assert b"not allowed" in result[1:]

    def test_connect_malformed_rejected(self):
        switch = Switch()
        proxy = ConnectProxy(switch, use_tor=False)

        result = proxy.on_data("x", bytes([CONNECT]) + b"\x00")
        assert result[0] == ERROR

    def test_data_forwarded_to_target(self):
        """DATA messages forwarded to TCP target."""
        target = MockTCPTarget().start()
        orig = self._allow_localhost(target)
        try:
            switch = Switch()
            switch.register("c1")
            proxy = ConnectProxy(switch, use_tor=False, timeout=5.0)

            # Connect
            connect_payload = (
                bytes([CONNECT])
                + target.port.to_bytes(2, "big")
                + target.host.encode()
            )
            proxy.on_data("c1", connect_payload)
            time.sleep(0.5)
            switch.poll_downstream("c1")  # drain OK

            # Send data
            proxy.on_data("c1", bytes([DATA]) + b"hello target")
            time.sleep(0.3)

            assert any(b"hello target" in d for d in target.received)
        finally:
            proxy.close_all()
            target.stop()
            self._restore_validate(orig)

    def test_target_echo_enqueued_downstream(self):
        """TCP target response enqueued to switch downstream."""
        target = MockTCPTarget().start()
        orig = self._allow_localhost(target)
        try:
            switch = Switch()
            switch.register("c1")
            proxy = ConnectProxy(switch, use_tor=False, timeout=5.0)

            connect_payload = (
                bytes([CONNECT])
                + target.port.to_bytes(2, "big")
                + target.host.encode()
            )
            proxy.on_data("c1", connect_payload)
            time.sleep(0.5)

            # Drain the OK response from connect
            ok = switch.poll_downstream("c1")
            assert ok == bytes([OK])

            proxy.on_data("c1", bytes([DATA]) + b"ping")
            time.sleep(0.3)

            # Downstream should have the echo
            msg = switch.poll_downstream("c1")
            assert msg is not None
            assert msg[0] == DATA
            assert msg[1:] == b"ping"
        finally:
            proxy.close_all()
            target.stop()
            self._restore_validate(orig)

    def test_connect_failure_returns_error(self):
        """Connection to unreachable host returns ERROR."""
        switch = Switch()
        switch.register("c1")
        proxy = ConnectProxy(switch, use_tor=False, timeout=1.0)

        # 192.0.2.1 is TEST-NET (reserved) — rejected synchronously
        payload = (
            bytes([CONNECT])
            + (1).to_bytes(2, "big")  # port 1 — almost certainly closed
            + b"192.0.2.1"  # TEST-NET, unreachable
        )
        result = proxy.on_data("c1", payload)
        assert result is not None
        assert result[0] == ERROR

    def test_empty_payload_safe(self):
        switch = Switch()
        proxy = ConnectProxy(switch, use_tor=False)
        assert proxy.on_data("x", b"") is None

    def test_data_to_unknown_tag(self):
        """DATA for non-connected tag does nothing."""
        switch = Switch()
        proxy = ConnectProxy(switch, use_tor=False)
        result = proxy.on_data("nonexistent", bytes([DATA]) + b"data")
        assert result is None


# ── ConnectClient + TunnelSocket ──────────────────────────────

class TestConnectClient:
    def test_connect_through_tunnel(self):
        """Full path: ConnectClient → tunnel → relay → mock TCP target."""
        target = MockTCPTarget().start()
        try:
            dispatcher = AppDispatcher()
            handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=dispatcher.on_data)
            # Allow localhost for testing
            proxy = ConnectProxy(handler.switch, use_tor=False, timeout=5.0)
            dispatcher.register(0x01, proxy.on_data)

            # Patch validate_target to allow localhost in tests
            import kopacz.apps.proxy as proxy_mod
            original_validate = proxy_mod.validate_target

            def test_validate(host, port):
                if host == "127.0.0.1" and port == target.port:
                    return True
                return original_validate(host, port)

            proxy_mod.validate_target = test_validate

            try:
                resolver = MockResolver(handler)
                tunnel = TunnelClient(DOMAIN, PSK, resolver, tag="proxy-client")
                tunnel.connect()

                client = ConnectClient(tunnel)
                client.connect("127.0.0.1", target.port)
                assert client.connected
            finally:
                proxy_mod.validate_target = original_validate
                proxy.close_all()
        finally:
            target.stop()

    def test_data_roundtrip(self):
        """Data flows client → relay → target → relay → client."""
        target = MockTCPTarget().start()
        try:
            dispatcher = AppDispatcher()
            handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=dispatcher.on_data)
            proxy = ConnectProxy(handler.switch, use_tor=False, timeout=5.0)
            dispatcher.register(0x01, proxy.on_data)

            import kopacz.apps.proxy as proxy_mod
            original_validate = proxy_mod.validate_target

            def test_validate(host, port):
                if host == "127.0.0.1" and port == target.port:
                    return True
                return original_validate(host, port)

            proxy_mod.validate_target = test_validate

            try:
                resolver = MockResolver(handler)
                tunnel = TunnelClient(DOMAIN, PSK, resolver, tag="rt-client")
                tunnel.connect()

                client = ConnectClient(tunnel)
                client.connect("127.0.0.1", target.port)

                # Send data through tunnel
                client.send(b"roundtrip-test")

                # Poll for echo (retry — echo traverses background threads)
                results = []
                for _ in range(10):
                    time.sleep(0.2)
                    results = client.poll_all()
                    if results:
                        break
                assert any(b"roundtrip-test" in r for r in results)
            finally:
                proxy_mod.validate_target = original_validate
                proxy.close_all()
        finally:
            target.stop()


class TestTunnelSocket:
    def test_send_recv(self):
        """TunnelSocket send/recv basic operation."""
        target = MockTCPTarget().start()
        try:
            dispatcher = AppDispatcher()
            handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=dispatcher.on_data)
            proxy = ConnectProxy(handler.switch, use_tor=False, timeout=5.0)
            dispatcher.register(0x01, proxy.on_data)

            import kopacz.apps.proxy as proxy_mod
            original_validate = proxy_mod.validate_target

            def test_validate(host, port):
                if host == "127.0.0.1" and port == target.port:
                    return True
                return original_validate(host, port)

            proxy_mod.validate_target = test_validate

            try:
                resolver = MockResolver(handler)
                tunnel = TunnelClient(DOMAIN, PSK, resolver, tag="sock-test")
                tunnel.connect()

                client = ConnectClient(tunnel)
                client.connect("127.0.0.1", target.port)

                ts = client.make_socket()

                ts.send(b"via socket")
                time.sleep(0.3)
                data = ts.recv(1024)
                assert b"via socket" in data
            finally:
                proxy_mod.validate_target = original_validate
                proxy.close_all()
        finally:
            target.stop()

    def test_sendall(self):
        """TunnelSocket sendall works."""
        target = MockTCPTarget().start()
        try:
            dispatcher = AppDispatcher()
            handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=dispatcher.on_data)
            proxy = ConnectProxy(handler.switch, use_tor=False, timeout=5.0)
            dispatcher.register(0x01, proxy.on_data)

            import kopacz.apps.proxy as proxy_mod
            original_validate = proxy_mod.validate_target

            def test_validate(host, port):
                if host == "127.0.0.1" and port == target.port:
                    return True
                return original_validate(host, port)

            proxy_mod.validate_target = test_validate

            try:
                resolver = MockResolver(handler)
                tunnel = TunnelClient(DOMAIN, PSK, resolver, tag="sendall-test")
                tunnel.connect()

                client = ConnectClient(tunnel)
                client.connect("127.0.0.1", target.port)

                ts = client.make_socket()
                ts.sendall(b"bulk data")
                time.sleep(0.3)
                data = ts.recv(1024)
                assert b"bulk data" in data
            finally:
                proxy_mod.validate_target = original_validate
                proxy.close_all()
        finally:
            target.stop()

    def test_socket_methods_exist(self):
        """TunnelSocket has required socket API methods."""
        # Create a minimal mock without real connection
        class FakeClient:
            connected = True
            def send(self, data): return []
            def poll_all(self): return []

        ts = TunnelSocket(FakeClient())
        assert callable(ts.send)
        assert callable(ts.recv)
        assert callable(ts.sendall)
        assert callable(ts.makefile)
        assert callable(ts.settimeout)
        assert callable(ts.close)
        assert callable(ts.getpeername)

    def test_close(self):
        class FakeClient:
            connected = True
            def send(self, data): return []
            def poll_all(self): return []

        ts = TunnelSocket(FakeClient())
        ts.close()
        assert ts._closed is True


# ── Full E2E with dispatcher ─────────────────────────────────

class TestProxyE2E:
    def test_full_e2e_echo(self):
        """Full stack: client → CONNECT → tunnel → relay → echo target → relay → tunnel → client."""
        target = MockTCPTarget().start()
        try:
            dispatcher = AppDispatcher()
            handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=dispatcher.on_data)
            proxy = ConnectProxy(handler.switch, use_tor=False, timeout=5.0)
            dispatcher.register(0x01, proxy.on_data)

            import kopacz.apps.proxy as proxy_mod
            original_validate = proxy_mod.validate_target

            def test_validate(host, port):
                if host == "127.0.0.1" and port == target.port:
                    return True
                return original_validate(host, port)

            proxy_mod.validate_target = test_validate

            try:
                resolver = MockResolver(handler)
                tunnel = TunnelClient(DOMAIN, PSK, resolver, tag="e2e-proxy")
                tunnel.connect()

                client = ConnectClient(tunnel)
                client.connect("127.0.0.1", target.port)

                # Send and receive
                client.send(b"e2e-test-data")
                time.sleep(0.3)
                results = client.poll_all()

                assert any(b"e2e-test-data" in r for r in results)

                # Verify target received it
                assert any(b"e2e-test-data" in d for d in target.received)
            finally:
                proxy_mod.validate_target = original_validate
                proxy.close_all()
        finally:
            target.stop()

    def test_coexists_with_ssh_and_messaging(self):
        """All three apps work simultaneously through one dispatcher."""
        target = MockTCPTarget().start()
        try:
            dispatcher = AppDispatcher()
            handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=dispatcher.on_data)

            # Register all three apps
            proxy = ConnectProxy(handler.switch, use_tor=False, timeout=5.0)
            dispatcher.register(0x01, proxy.on_data)

            ssh_data = []
            dispatcher.register(0x02, lambda t, d: ssh_data.append(d))

            msg_data = []
            dispatcher.register(0x03, lambda t, d: msg_data.append(d))

            import kopacz.apps.proxy as proxy_mod
            original_validate = proxy_mod.validate_target

            def test_validate(host, port):
                if host == "127.0.0.1" and port == target.port:
                    return True
                return original_validate(host, port)

            proxy_mod.validate_target = test_validate

            try:
                resolver = MockResolver(handler)

                # Proxy client
                t1 = TunnelClient(DOMAIN, PSK, resolver, tag="proxy1")
                t1.connect()
                pc = ConnectClient(t1)
                pc.connect("127.0.0.1", target.port)

                # SSH client
                t2 = TunnelClient(DOMAIN, PSK, resolver, tag="ssh1")
                t2.connect()
                t2.send(b"\x02ssh-command")

                # Messaging client
                t3 = TunnelClient(DOMAIN, PSK, resolver, tag="msg1")
                t3.connect()
                t3.send(b"\x03register-msg")

                assert len(ssh_data) == 1
                assert ssh_data[0] == b"ssh-command"
                assert len(msg_data) == 1
                assert msg_data[0] == b"register-msg"
            finally:
                proxy_mod.validate_target = original_validate
                proxy.close_all()
        finally:
            target.stop()
