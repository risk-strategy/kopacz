"""Tests for SSH bridge wiring through AppDispatcher."""

from kopacz.apps.dispatch import AppDispatcher
from kopacz.apps.bridge import TCPBridge
from kopacz.apps.clients.ssh import SSHClient
from kopacz.client.tunnel import TunnelClient
from kopacz.protocol.crypto import derive_pubkey
from kopacz.relay.server import RelayHandler
from kopacz.relay.switch import Switch

SERVER_PRIV = b"\x42" * 32
PSK = derive_pubkey(SERVER_PRIV)
DOMAIN = "ssh.example.com"


class MockResolver:
    """Direct in-process relay resolver."""

    def __init__(self, handler: RelayHandler):
        self.handler = handler

    def query(self, qname: str) -> str | None:
        txt = self.handler.build_response(qname)
        return txt if txt else None


class TestSSHDispatchRouting:
    def test_dispatcher_routes_0x02_to_bridge(self):
        """Dispatcher strips 0x02 and calls bridge.on_tunnel_data."""
        switch = Switch()
        bridge = TCPBridge(switch, "ssh-srv1")
        dispatcher = AppDispatcher()
        dispatcher.register(0x02, bridge.on_tunnel_data)

        # No TCP connection → data goes nowhere but no error
        result = dispatcher.on_data("ssh-srv1", b"\x02hello-ssh")
        assert result is None

    def test_bridge_receives_stripped_payload(self):
        """Bridge sees data without 0x02 prefix."""
        received = []

        def fake_bridge(tag, data):
            received.append((tag, data))
            return None

        dispatcher = AppDispatcher()
        dispatcher.register(0x02, fake_bridge)
        dispatcher.on_data("ssh-srv1", b"\x02raw-ssh-bytes")

        assert received == [("ssh-srv1", b"raw-ssh-bytes")]

    def test_coexistence_with_other_apps(self):
        """0x01 and 0x02 routed to different handlers."""
        ssh_data = []
        proxy_data = []

        dispatcher = AppDispatcher()
        dispatcher.register(0x01, lambda t, d: proxy_data.append(d))
        dispatcher.register(0x02, lambda t, d: ssh_data.append(d))

        dispatcher.on_data("x", b"\x01http-data")
        dispatcher.on_data("y", b"\x02ssh-data")

        assert proxy_data == [b"http-data"]
        assert ssh_data == [b"ssh-data"]


class TestSSHClientHelper:
    def test_send_prepends_app_id(self):
        """SSHClient.send prepends 0x02 to tunnel payload."""
        handler = RelayHandler(DOMAIN, SERVER_PRIV)
        resolver = MockResolver(handler)
        tunnel = TunnelClient(DOMAIN, PSK, resolver, tag="ssh1")
        tunnel.connect()

        # Capture what the handler receives
        received = []
        handler._on_data = lambda tag, data: received.append((tag, data))

        ssh = SSHClient(tunnel)
        ssh.send(b"SSH-2.0-OpenSSH")

        # The handler's on_data should get the full 0x02-prefixed data
        # because SSHClient prepends 0x02 and handler sees raw app data
        assert len(received) == 1
        tag, data = received[0]
        assert data == b"\x02SSH-2.0-OpenSSH"
        assert tag == "ssh1"


class TestSSHFullRoundtrip:
    def test_roundtrip_through_dispatcher(self):
        """Full path: SSHClient → tunnel → relay → dispatcher → bridge handler."""
        collected = []

        dispatcher = AppDispatcher()
        dispatcher.register(0x02, lambda tag, data: collected.append((tag, data)))

        handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=dispatcher.on_data)
        resolver = MockResolver(handler)

        client = TunnelClient(DOMAIN, PSK, resolver, tag="ssh-roundtrip")
        client.connect()

        ssh = SSHClient(client)
        ssh.send(b"SSH-2.0-test")

        assert len(collected) == 1
        tag, data = collected[0]
        assert tag == "ssh-roundtrip"
        assert data == b"SSH-2.0-test"  # 0x02 stripped by dispatcher

    def test_downstream_response_from_bridge(self):
        """Bridge enqueues downstream; client receives it."""
        dispatcher = AppDispatcher()
        handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=dispatcher.on_data)

        # Bridge callback that echoes back via switch
        def ssh_handler(tag, data):
            handler.switch.enqueue_downstream(tag, b"SSH-REPLY:" + data)
            return None

        dispatcher.register(0x02, ssh_handler)

        resolver = MockResolver(handler)
        client = TunnelClient(DOMAIN, PSK, resolver, tag="ssh-down")
        client.connect()

        ssh = SSHClient(client)
        downstream = ssh.send(b"hello")

        # Response is piggybacked on the send's DNS reply
        if not downstream:
            downstream = ssh.poll_all()
        assert b"SSH-REPLY:hello" in downstream

    def test_multiple_messages(self):
        """Multiple SSH messages through dispatcher."""
        collected = []

        dispatcher = AppDispatcher()
        dispatcher.register(0x02, lambda t, d: collected.append(d))

        handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=dispatcher.on_data)
        resolver = MockResolver(handler)
        client = TunnelClient(DOMAIN, PSK, resolver, tag="ssh-multi")
        client.connect()

        ssh = SSHClient(client)
        for i in range(5):
            ssh.send(f"cmd-{i}".encode())

        assert len(collected) == 5
        for i in range(5):
            assert f"cmd-{i}".encode() in collected
