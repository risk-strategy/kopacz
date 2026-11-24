"""
End-to-end pipeline tests.

Verifies the full data path:
  compress → encrypt → fragment → carrier → carrier → reassemble → decrypt → decompress
"""

import os
import random
import pytest
from hypothesis import given, strategies as st, settings

from kopacz.protocol.header import Header, Flags, HEADER_SIZE
from kopacz.protocol.crypto import CryptoState, OVERHEAD, derive_pubkey
from kopacz.protocol.fragment import fragment, ReassemblyBuffer
from kopacz.protocol.compress import compress, decompress
from kopacz.transport.carrier import Carrier
from kopacz.transport.encoding import Base32Encoder
from kopacz.session.state import Session, State

PSK = b"\x42" * 32


def _handshake_crypto(psk=PSK):
    c = CryptoState(derive_pubkey(psk), True)
    s = CryptoState(psk, False)
    syn = c.client_hello()
    synack = s.server_hello(syn)
    c.client_finish(synack)
    return c, s


# ── Raw pipeline (no Session, manual steps) ─────────────────────

@settings(max_examples=100)
@given(st.binary(min_size=1, max_size=2000))
def test_prop_full_pipeline_raw(data):
    """
    data → compress → encrypt → fragment
         → carrier encode → carrier decode
         → reassemble → decrypt → decompress → data
    """
    c_crypto, s_crypto = _handshake_crypto()
    carrier = Carrier("test.example.com", Base32Encoder())
    max_frag = 100

    # === SEND ===
    compressed = compress(data)
    encrypted = c_crypto.encrypt(compressed)
    packets = fragment(encrypted, stream_id=1, sequence=0, max_payload=max_frag)

    # Encode each packet into DNS query, then decode back
    decoded_packets = []
    for pkt in packets:
        qname = carrier.pack_query(pkt, "s1")
        _, raw = carrier.unpack_query(qname)
        decoded_packets.append(raw)

    # === RECEIVE ===
    buf = ReassemblyBuffer()
    reassembled = None
    for pkt in decoded_packets:
        hdr = Header.unpack(pkt)
        r = buf.add(hdr, pkt[HEADER_SIZE:])
        if r is not None:
            reassembled = r

    assert reassembled is not None
    decrypted = s_crypto.decrypt(reassembled)
    result = decompress(decrypted)
    assert result == data


@settings(max_examples=50)
@given(
    data=st.binary(min_size=1, max_size=2000),
    seed=st.integers(0, 2**32),
)
def test_prop_pipeline_survives_reorder(data, seed):
    """Full pipeline works even when DNS queries arrive out of order."""
    c_crypto, s_crypto = _handshake_crypto()
    carrier = Carrier("test.example.com")
    max_frag = 80

    compressed = compress(data)
    encrypted = c_crypto.encrypt(compressed)
    packets = fragment(encrypted, 1, 0, max_frag)

    # Encode, shuffle, decode
    qnames = [carrier.pack_query(pkt, "s1") for pkt in packets]
    rng = random.Random(seed)
    rng.shuffle(qnames)

    buf = ReassemblyBuffer()
    reassembled = None
    for qn in qnames:
        _, raw = carrier.unpack_query(qn)
        hdr = Header.unpack(raw)
        r = buf.add(hdr, raw[HEADER_SIZE:])
        if r is not None:
            reassembled = r

    assert reassembled is not None
    assert decompress(s_crypto.decrypt(reassembled)) == data


# ── Session-level pipeline ──────────────────────────────────────

def _session_pair(psk=PSK, max_frag=100):
    """Create a client+server Session pair with completed handshake."""
    client = Session(derive_pubkey(psk), is_client=True, max_frag_payload=max_frag)
    server = Session(psk, is_client=False, max_frag_payload=max_frag)

    # Client sends SYN
    syn_pkts = client.initiate()
    assert client.state == State.HANDSHAKE_SENT

    # Server receives SYN
    for pkt in syn_pkts:
        server.handle_packet(pkt)
    assert server.state == State.ESTABLISHED
    synack = server.pop_synack()
    assert synack is not None

    # Client receives SYN-ACK
    client.handle_packet(synack)
    assert client.state == State.ESTABLISHED

    return client, server


class TestSessionPipeline:
    def test_handshake(self):
        c, s = _session_pair()
        assert c.state == State.ESTABLISHED
        assert s.state == State.ESTABLISHED

    def test_send_receive(self):
        c, s = _session_pair()
        packets = c.send(b"hello from client")
        result = None
        for pkt in packets:
            r = s.handle_packet(pkt)
            if r is not None:
                result = r
        assert result == b"hello from client"

    def test_bidirectional(self):
        c, s = _session_pair()

        # client → server
        for pkt in c.send(b"ping"):
            r = s.handle_packet(pkt)
        assert r == b"ping"

        # server → client
        for pkt in s.send(b"pong"):
            r = c.handle_packet(pkt)
        assert r == b"pong"

    @settings(max_examples=100)
    @given(st.binary(min_size=1, max_size=3000))
    def test_prop_session_roundtrip(self, data):
        c, s = _session_pair()
        packets = c.send(data)
        result = None
        for pkt in packets:
            r = s.handle_packet(pkt)
            if r is not None:
                result = r
        assert result == data

    def test_multiple_messages(self):
        c, s = _session_pair()
        for i in range(10):
            msg = f"message-{i}".encode()
            pkts = c.send(msg)
            result = None
            for pkt in pkts:
                r = s.handle_packet(pkt)
                if r is not None:
                    result = r
            assert result == msg

    def test_large_fragmented_message(self):
        c, s = _session_pair(max_frag=50)
        data = os.urandom(2000)
        pkts = c.send(data)
        assert len(pkts) > 1  # must fragment

        result = None
        for pkt in pkts:
            r = s.handle_packet(pkt)
            if r is not None:
                result = r
        assert result == data

    def test_fin(self):
        c, s = _session_pair()
        fin = c.make_fin()
        s.handle_packet(fin)
        assert c.state == State.CLOSED

    def test_poll_packet(self):
        c, _ = _session_pair()
        poll = c.make_poll()
        hdr = Header.unpack(poll)
        assert hdr.flags & Flags.POLL

    def test_interleaved_polls_do_not_break_data_sequence(self):
        """POLL packets use a separate counter and do not create gaps in DATA sequence space."""
        c, s = _session_pair()
        for i in range(5):
            # Interleave multiple polls between data messages
            s.handle_packet(c.make_poll())
            s.handle_packet(c.make_poll())
            pkts = c.send(f"data-{i}".encode())
            res = None
            for p in pkts:
                r = s.handle_packet(p)
                if r is not None:
                    res = r
            assert res == f"data-{i}".encode()
            # Server's cumulative ack_number must advance contiguously with each DATA message
            assert s._recv_window.ack_number == i

    def test_duplicate_data_suppressed(self):
        """Retransmitted or duplicate DATA packets are acknowledged but not re-delivered."""
        c, s = _session_pair()
        pkts = c.send(b"idempotent payload")
        assert len(pkts) == 1
        assert s.handle_packet(pkts[0]) == b"idempotent payload"
        # Second delivery of the exact same packet must return None
        assert s.handle_packet(pkts[0]) is None
        assert s.make_ack() is not None

    def test_out_of_order_data_delivered_in_order(self):
        """If seq=1 arrives before seq=0, seq=1 is buffered until seq=0 arrives."""
        c, s = _session_pair()
        pkts0 = c.send(b"first")
        pkts1 = c.send(b"second")
        pkts2 = c.send(b"third")

        # Deliver seq=1 and seq=2 before seq=0
        assert s.handle_packet(pkts1[0]) is None
        assert s.handle_packet(pkts2[0]) is None
        assert s.drain_received() == []

        # Now deliver seq=0 -> returns seq=0 and unlocks seq=1, seq=2 in drain_received()
        assert s.handle_packet(pkts0[0]) == b"first"
        assert s.drain_received() == [b"second", b"third"]

    def test_piggybacked_ack_on_poll_and_data(self):
        """Downstream DATA is acknowledged via piggybacked ACK on client's next POLL or DATA."""
        c, s = _session_pair()
        # Server sends downstream message (tracked in s._send_window)
        s_pkts = s.send(b"downstream-1")
        assert len(s._send_window) == 1
        assert c.handle_packet(s_pkts[0]) == b"downstream-1"
        assert c.make_ack() is not None

        # Client sends POLL -> piggybacks Flags.ACK with sequence=0
        poll_pkt = c.make_poll()
        poll_hdr = Header.unpack(poll_pkt)
        assert poll_hdr.flags & Flags.ACK
        assert poll_hdr.sequence == 0

        # Server processes POLL|ACK -> retires seq=0 from s._send_window
        s.handle_packet(poll_pkt)
        assert len(s._send_window) == 0

        # Server sends second downstream message (seq=1)
        s_pkts2 = s.send(b"downstream-2")
        assert len(s._send_window) == 1
        assert c.handle_packet(s_pkts2[0]) == b"downstream-2"

        # Client sends upstream DATA -> piggybacks low 8 bits of ACK in reserved byte
        c_pkts = c.send(b"upstream-reply")
        c_hdr = Header.unpack(c_pkts[0])
        assert c_hdr.flags & Flags.ACK
        assert c_hdr.reserved == 1
        assert s.handle_packet(c_pkts[0]) == b"upstream-reply"
        assert len(s._send_window) == 0

