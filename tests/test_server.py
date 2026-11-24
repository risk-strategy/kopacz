"""
Relay server integration tests.

Tests RelayHandler (pure logic, no UDP) through a full
client↔server interaction using Carrier for DNS encoding.

Key: in DNS tunnelling, every query gets a response. The response
to a DATA query may contain downstream data — not just POLLs.
"""

import os
import pytest
from hypothesis import given, strategies as st, settings

from kopacz.protocol.crypto import derive_pubkey
from kopacz.protocol.header import Header, Flags, HEADER_SIZE
from kopacz.session.state import Session, State
from kopacz.transport.carrier import Carrier
from kopacz.relay.server import RelayHandler

PSK = b"\x42" * 32
SERVER_PUB = derive_pubkey(PSK)
DOMAIN = "test.example.com"


class MockClient:
    """Client-side of the tunnel for testing."""

    def __init__(self, psk: bytes, domain: str, tag: str = "s1"):
        pub = SERVER_PUB if psk == PSK else psk
        self.session = Session(pub, is_client=True)
        self.carrier = Carrier(domain)
        self.tag = tag

    def handshake_syn(self) -> str:
        pkts = self.session.initiate()
        return self.carrier.pack_query(pkts[0], self.tag)

    def process_response(self, txt: str) -> bytes | None:
        raw = self.carrier.unpack_response(txt)
        return self.session.handle_packet(raw)

    def send_data(self, data: bytes) -> list[str]:
        pkts = self.session.send(data)
        return [self.carrier.pack_query(p, self.tag) for p in pkts]

    def make_poll(self) -> str:
        return self.carrier.pack_query(self.session.make_poll(), self.tag)


def _do_handshake(handler: RelayHandler, client: MockClient) -> None:
    """Complete handshake between client and handler."""
    syn_qname = client.handshake_syn()
    txt = handler.build_response(syn_qname)
    assert txt, "Server should respond with SYN-ACK"
    client.process_response(txt)
    assert client.session.state == State.ESTABLISHED


def _send_and_receive(handler: RelayHandler, client: MockClient, data: bytes) -> bytes | None:
    """Send data, process all responses (from DATA queries and POLLs).

    Returns application data once reassembled, or None.
    """
    qnames = client.send_data(data)
    result = None
    for qn in qnames:
        txt = handler.build_response(qn)
        if txt:
            r = client.process_response(txt)
            if r is not None:
                result = r

    # Poll for remaining downstream fragments if needed
    if result is None:
        for _ in range(30):
            txt = handler.build_response(client.make_poll())
            if not txt:
                break
            r = client.process_response(txt)
            if r is not None:
                result = r
                break

    return result


class TestRelayHandshake:
    def test_handshake_establishes(self):
        handler = RelayHandler(DOMAIN, PSK)
        client = MockClient(PSK, DOMAIN)
        _do_handshake(handler, client)
        assert handler.session_count == 1

    def test_handshake_wrong_psk_fails(self):
        handler = RelayHandler(DOMAIN, PSK)
        client = MockClient(b"\xff" * 32, DOMAIN)
        syn_qname = client.handshake_syn()
        txt = handler.build_response(syn_qname)
        assert txt == ""
        assert handler.session_count == 0

    def test_unauthenticated_non_syn_does_not_allocate_session(self):
        """Spoofed POLL or DATA queries for unknown tags must not allocate sessions."""
        handler = RelayHandler(DOMAIN, PSK)
        carrier = Carrier(DOMAIN)
        fake_poll = Header(Flags.POLL, 0, 0, 0, 1).pack()
        for i in range(20):
            qname = carrier.pack_query(fake_poll, f"spoof{i}")
            assert handler.build_response(qname) == ""
        assert handler.session_count == 0

    def test_syn_nonce_replay_across_tags_rejected(self):
        """Replaying a captured SYN packet under a different session tag is rejected."""
        handler = RelayHandler(DOMAIN, PSK)
        client = MockClient(PSK, DOMAIN, tag="legit")
        syn_pkts = client.session.initiate()
        qname1 = client.carrier.pack_query(syn_pkts[0], "legit")
        assert handler.build_response(qname1) != ""
        assert handler.session_count == 1

        # Attacker replays exact same SYN packet under a new tag
        qname_replay = client.carrier.pack_query(syn_pkts[0], "replayed")
        assert handler.build_response(qname_replay) == ""
        assert handler.session_count == 1

    def test_idempotent_synack_retransmission_on_dropped_response(self):
        """If initial SYN-ACK is lost in transit, retrying the same SYN returns SYN-ACK."""
        handler = RelayHandler(DOMAIN, PSK)
        client = MockClient(PSK, DOMAIN, tag="retrytag")
        syn_qname = client.handshake_syn()

        # First SYN processed by server, imagine response was dropped on UDP
        txt1 = handler.build_response(syn_qname)
        assert txt1 != ""

        # Client retries the exact same SYN query
        txt2 = handler.build_response(syn_qname)
        assert txt2 == txt1
        client.process_response(txt2)
        assert client.session.state == State.ESTABLISHED

    def test_session_cleanup_evicts_expired_and_closed(self):
        handler = RelayHandler(DOMAIN, PSK, session_ttl=10.0)
        c1 = MockClient(PSK, DOMAIN, tag="c1")
        _do_handshake(handler, c1)
        assert handler.session_count == 1
        # Advance monotonic clock by 15s
        now = handler._last_seen["c1"] + 15.0
        removed = handler.cleanup_sessions(now=now)
        assert removed == 1
        assert handler.session_count == 0



class TestRelayData:
    def test_echo(self):
        """Send data, echo callback returns it in response."""
        handler = RelayHandler(DOMAIN, PSK, on_data=lambda tag, data: data)
        client = MockClient(PSK, DOMAIN)
        _do_handshake(handler, client)

        result = _send_and_receive(handler, client, b"hello relay")
        assert result == b"hello relay"

    def test_no_callback_no_downstream(self):
        """Without an on_data callback, no downstream data is generated."""
        handler = RelayHandler(DOMAIN, PSK)
        client = MockClient(PSK, DOMAIN)
        _do_handshake(handler, client)

        qnames = client.send_data(b"into the void")
        for qn in qnames:
            txt = handler.build_response(qn)
            if txt:
                raw = client.carrier.unpack_response(txt)
                hdr = Header.unpack(raw)
                # Should be ACK, not DATA
                assert not (hdr.flags & Flags.DATA) or (hdr.flags & Flags.ACK)

    def test_multiple_messages(self):
        """Multiple messages echoed correctly."""
        handler = RelayHandler(DOMAIN, PSK, on_data=lambda t, d: d)
        client = MockClient(PSK, DOMAIN)
        _do_handshake(handler, client)

        for i in range(5):
            msg = f"msg-{i}".encode()
            result = _send_and_receive(handler, client, msg)
            assert result == msg

    def test_large_fragmented_message(self):
        """Large message fragments and reassembles through relay."""
        handler = RelayHandler(DOMAIN, PSK, on_data=lambda t, d: d, max_frag_payload=50)
        client = MockClient(PSK, DOMAIN, tag="s1")
        client.session.max_frag_payload = 50
        _do_handshake(handler, client)

        data = os.urandom(500)
        result = _send_and_receive(handler, client, data)
        assert result == data


class TestRelayPoll:
    def test_poll_empty(self):
        """POLL with nothing downstream returns empty."""
        handler = RelayHandler(DOMAIN, PSK)
        client = MockClient(PSK, DOMAIN)
        _do_handshake(handler, client)

        txt = handler.build_response(client.make_poll())
        assert txt == ""

    def test_poll_after_enqueue(self):
        """Manually enqueued downstream data is returned on POLL."""
        handler = RelayHandler(DOMAIN, PSK)
        client = MockClient(PSK, DOMAIN)
        _do_handshake(handler, client)

        handler.switch.enqueue_downstream("s1", b"pushed data")

        txt = handler.build_response(client.make_poll())
        assert txt
        result = client.process_response(txt)
        assert result == b"pushed data"


class TestRelayMultiSession:
    def test_two_sessions(self):
        """Two clients with different tags don't interfere."""
        handler = RelayHandler(DOMAIN, PSK, on_data=lambda t, d: d)
        c1 = MockClient(PSK, DOMAIN, tag="alice")
        c2 = MockClient(PSK, DOMAIN, tag="bob")
        _do_handshake(handler, c1)
        _do_handshake(handler, c2)
        assert handler.session_count == 2

        r1 = _send_and_receive(handler, c1, b"from alice")
        r2 = _send_and_receive(handler, c2, b"from bob")
        assert r1 == b"from alice"
        assert r2 == b"from bob"

    def test_cross_session_routing(self):
        """Data routed between sessions via switch."""
        received = {}

        def on_data(tag, data):
            received[tag] = data
            return None

        handler = RelayHandler(DOMAIN, PSK, on_data=on_data)
        c1 = MockClient(PSK, DOMAIN, tag="src")
        c2 = MockClient(PSK, DOMAIN, tag="dst")
        _do_handshake(handler, c1)
        _do_handshake(handler, c2)

        for qn in c1.send_data(b"routed msg"):
            handler.build_response(qn)

        assert received.get("src") == b"routed msg"

        handler.switch.enqueue_downstream("dst", b"routed msg")

        txt = handler.build_response(c2.make_poll())
        assert txt
        assert c2.process_response(txt) == b"routed msg"
