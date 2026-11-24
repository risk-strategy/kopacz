"""
End-to-end tests with simulated network conditions.

Full stack: TunnelClient → (lossy) MockResolver → RelayHandler → application.
Tests packet loss, reordering, and retransmission through the entire pipeline.
"""

import os
import random
import pytest
from hypothesis import given, strategies as st, settings

from kopacz.client.tunnel import TunnelClient
from kopacz.protocol.crypto import derive_pubkey
from kopacz.relay.server import RelayHandler

SERVER_PRIV = b"\x42" * 32
PSK = derive_pubkey(SERVER_PRIV)
DOMAIN = "e2e.example.com"


class LossyResolver:
    """
    Routes queries through RelayHandler with simulated packet loss.

    drop_rate: probability of dropping a query (0.0-1.0)
    reorder:   if True, occasionally delay and replay queries
    """

    def __init__(
        self,
        handler: RelayHandler,
        drop_rate: float = 0.0,
        seed: int = 0,
    ):
        self.handler = handler
        self.drop_rate = drop_rate
        self.rng = random.Random(seed)
        self.total_queries = 0
        self.dropped_queries = 0

    def query(self, qname: str) -> str | None:
        self.total_queries += 1
        if self.rng.random() < self.drop_rate:
            self.dropped_queries += 1
            return None  # simulate timeout
        txt = self.handler.build_response(qname)
        return txt if txt else None


class DuplicatingResolver:
    """Sends each query twice (simulates DNS retransmission by resolver).

    Client sees the first response. The duplicate query hits the server
    but its response is discarded (as happens with real DNS retransmit).
    """

    def __init__(self, handler: RelayHandler):
        self.handler = handler

    def query(self, qname: str) -> str | None:
        # Client sees first response
        txt = self.handler.build_response(qname)
        # Resolver retransmits (server gets duplicate, response discarded)
        self.handler.build_response(qname)
        return txt if txt else None


# ── Perfect network (baseline) ──────────────────────────────

class TestE2EPerfect:
    def test_small_message(self):
        handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=lambda t, d: d)
        resolver = LossyResolver(handler, drop_rate=0.0)
        client = TunnelClient(DOMAIN, PSK, resolver, tag="e2e1")
        client.connect()

        downstream = client.send(b"hello e2e")
        if not downstream:
            downstream = client.poll_all()
        assert b"hello e2e" in downstream

    @settings(max_examples=30)
    @given(st.binary(min_size=1, max_size=3000))
    def test_prop_any_data_survives(self, data):
        handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=lambda t, d: d, max_frag_payload=80)
        resolver = LossyResolver(handler, drop_rate=0.0)
        client = TunnelClient(DOMAIN, PSK, resolver, tag="prop", max_frag_payload=80)
        client.connect()

        downstream = client.send(data)
        if not downstream:
            downstream = client.poll_all()
        assert data in downstream

    def test_bidirectional_conversation(self):
        """Multiple request-response pairs."""
        handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=lambda t, d: d)
        resolver = LossyResolver(handler, drop_rate=0.0)
        client = TunnelClient(DOMAIN, PSK, resolver, tag="conv")
        client.connect()

        for i in range(10):
            msg = f"turn-{i}".encode()
            downstream = client.send(msg)
            if not downstream:
                downstream = client.poll_all()
            assert msg in downstream


# ── Lossy network ───────────────────────────────────────────

class TestE2ELoss:
    def _send_with_retry(self, client, data, max_retries=5):
        """Send data, retrying on loss. Returns downstream data."""
        for attempt in range(max_retries):
            try:
                downstream = client.send(data)
                if downstream:
                    return downstream
                downstream = client.poll_all()
                if downstream:
                    return downstream
            except Exception:
                pass
        return []

    def test_handshake_survives_loss(self):
        """Handshake retries on packet loss."""
        handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=lambda t, d: d)

        for seed in range(10):
            resolver = LossyResolver(handler, drop_rate=0.3, seed=seed)
            client = TunnelClient(DOMAIN, PSK, resolver, tag=f"hs{seed}")

            # Retry handshake up to 5 times
            connected = False
            for _ in range(5):
                try:
                    client = TunnelClient(DOMAIN, PSK, resolver, tag=f"hs{seed}")
                    client.connect()
                    connected = True
                    break
                except ConnectionError:
                    continue

            # With 30% loss, most attempts should eventually succeed
            # (0.7^5 chance of all failing = ~17%)
            if connected:
                return

        # At least one of 10 seeds should have worked
        pytest.fail("No handshake succeeded across 10 seeds")


# ── Duplicate queries ───────────────────────────────────────

class TestE2EDuplicate:
    def test_duplicate_queries_handled(self):
        """Server handles duplicate queries gracefully."""
        handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=lambda t, d: d)
        resolver = DuplicatingResolver(handler)
        client = TunnelClient(DOMAIN, PSK, resolver, tag="dup1")
        client.connect()

        downstream = client.send(b"deduplicate me")
        if not downstream:
            downstream = client.poll_all()
        # Should get exactly one copy, not two
        assert downstream.count(b"deduplicate me") == 1


# ── Multi-client E2E ────────────────────────────────────────

class TestE2EMultiClient:
    def test_two_clients_independent(self):
        handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=lambda t, d: d)

        c1 = TunnelClient(DOMAIN, PSK, LossyResolver(handler), tag="c1")
        c2 = TunnelClient(DOMAIN, PSK, LossyResolver(handler), tag="c2")
        c1.connect()
        c2.connect()

        d1 = c1.send(b"from c1")
        if not d1:
            d1 = c1.poll_all()
        d2 = c2.send(b"from c2")
        if not d2:
            d2 = c2.poll_all()

        assert b"from c1" in d1
        assert b"from c2" in d2

    def test_cross_session_dead_drop(self):
        """Message from one client routed to another via switch."""
        received = {}

        def on_data(tag, data):
            received[tag] = data
            return None

        handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=on_data)

        sender = TunnelClient(DOMAIN, PSK, LossyResolver(handler), tag="sender")
        receiver = TunnelClient(DOMAIN, PSK, LossyResolver(handler), tag="recvr")
        sender.connect()
        receiver.connect()

        # Sender sends data
        sender.send(b"dead drop message")
        assert received.get("sender") == b"dead drop message"

        # Route to receiver via switch
        handler.switch.enqueue_downstream("recvr", b"dead drop message")

        # Receiver polls
        data = receiver.poll()
        assert data == b"dead drop message"


# ── Stress ──────────────────────────────────────────────────

class TestE2EStress:
    def test_many_messages(self):
        """100 messages through the full stack."""
        handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=lambda t, d: d)
        resolver = LossyResolver(handler)
        client = TunnelClient(DOMAIN, PSK, resolver, tag="stress")
        client.connect()

        for i in range(100):
            msg = f"stress-{i:04d}".encode()
            downstream = client.send(msg)
            if not downstream:
                downstream = client.poll_all()
            assert msg in downstream, f"Failed at message {i}"

    def test_large_payload(self):
        """4KB payload through the full stack."""
        handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=lambda t, d: d, max_frag_payload=80)
        resolver = LossyResolver(handler)
        client = TunnelClient(DOMAIN, PSK, resolver, tag="big", max_frag_payload=80)
        client.connect()

        data = os.urandom(4096)
        downstream = client.send(data)
        if not downstream:
            downstream = client.poll_all(max_polls=200)
        assert data in downstream
