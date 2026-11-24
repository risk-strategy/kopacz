"""
Client tunnel tests.

Uses MockResolver to route queries through RelayHandler
without any network I/O. Full end-to-end: client → DNS → relay → app → DNS → client.
"""

import os
import pytest
from hypothesis import given, strategies as st, settings

from kopacz.client.tunnel import TunnelClient, _random_tag
from kopacz.protocol.crypto import derive_pubkey
from kopacz.relay.server import RelayHandler

SERVER_PRIV = b"\x42" * 32
PSK = derive_pubkey(SERVER_PRIV)
DOMAIN = "test.example.com"


class MockResolver:
    """Routes DNS queries directly to a RelayHandler."""

    def __init__(self, handler: RelayHandler):
        self.handler = handler
        self.query_count = 0

    def query(self, qname: str) -> str | None:
        self.query_count += 1
        txt = self.handler.build_response(qname)
        return txt if txt else None


def _echo_handler() -> RelayHandler:
    return RelayHandler(DOMAIN, SERVER_PRIV, on_data=lambda t, d: d)


class TestClientConnect:
    def test_handshake(self):
        handler = _echo_handler()
        resolver = MockResolver(handler)
        client = TunnelClient(DOMAIN, PSK, resolver, tag="test1")
        client.connect()
        assert client.connected

    def test_wrong_psk_fails(self):
        handler = _echo_handler()
        resolver = MockResolver(handler)
        client = TunnelClient(DOMAIN, b"\xff" * 32, resolver, tag="bad")
        with pytest.raises(ConnectionError):
            client.connect()

    def test_random_tag_generation(self):
        tag = _random_tag()
        assert len(tag) == 8
        assert all(c in "0123456789abcdefghijklmnopqrstuvwxyz" for c in tag)


class TestClientData:
    def test_echo_small(self):
        handler = _echo_handler()
        resolver = MockResolver(handler)
        client = TunnelClient(DOMAIN, PSK, resolver, tag="s1")
        client.connect()

        downstream = client.send(b"hello")
        # Echo may come in send response or need a poll
        if not downstream:
            downstream = client.poll_all()
        assert b"hello" in downstream

    def test_echo_multiple(self):
        handler = _echo_handler()
        resolver = MockResolver(handler)
        client = TunnelClient(DOMAIN, PSK, resolver, tag="s1")
        client.connect()

        for i in range(5):
            msg = f"msg-{i}".encode()
            downstream = client.send(msg)
            if not downstream:
                downstream = client.poll_all()
            assert msg in downstream

    @settings(max_examples=50)
    @given(st.binary(min_size=1, max_size=2000))
    def test_prop_echo_roundtrip(self, data):
        handler = _echo_handler()
        resolver = MockResolver(handler)
        client = TunnelClient(DOMAIN, PSK, resolver, tag="prop", max_frag_payload=80)
        client.connect()

        downstream = client.send(data)
        if not downstream:
            downstream = client.poll_all()
        assert data in downstream

    def test_large_fragmented(self):
        handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=lambda t, d: d, max_frag_payload=50)
        resolver = MockResolver(handler)
        client = TunnelClient(DOMAIN, PSK, resolver, tag="frag", max_frag_payload=50)
        client.connect()

        data = os.urandom(500)
        downstream = client.send(data)
        if not downstream:
            downstream = client.poll_all()
        assert data in downstream


class TestClientPoll:
    def test_poll_empty(self):
        handler = _echo_handler()
        resolver = MockResolver(handler)
        client = TunnelClient(DOMAIN, PSK, resolver, tag="s1")
        client.connect()
        assert client.poll() is None

    def test_poll_after_enqueue(self):
        handler = _echo_handler()
        resolver = MockResolver(handler)
        client = TunnelClient(DOMAIN, PSK, resolver, tag="s1")
        client.connect()

        handler.switch.enqueue_downstream("s1", b"pushed")
        result = client.poll()
        assert result == b"pushed"


class TestClientClose:
    def test_close(self):
        handler = _echo_handler()
        resolver = MockResolver(handler)
        client = TunnelClient(DOMAIN, PSK, resolver, tag="s1")
        client.connect()
        assert client.connected
        client.close()
        assert not client.connected

    def test_close_idempotent(self):
        handler = _echo_handler()
        resolver = MockResolver(handler)
        client = TunnelClient(DOMAIN, PSK, resolver, tag="s1")
        client.connect()
        client.close()
        client.close()  # should not raise


class TestTwoClients:
    def test_independent_sessions(self):
        handler = _echo_handler()
        r1 = MockResolver(handler)
        r2 = MockResolver(handler)
        c1 = TunnelClient(DOMAIN, PSK, r1, tag="alice")
        c2 = TunnelClient(DOMAIN, PSK, r2, tag="bob")
        c1.connect()
        c2.connect()
        assert handler.session_count == 2

        d1 = c1.send(b"from alice")
        if not d1:
            d1 = c1.poll_all()
        d2 = c2.send(b"from bob")
        if not d2:
            d2 = c2.poll_all()

        assert b"from alice" in d1
        assert b"from bob" in d2
