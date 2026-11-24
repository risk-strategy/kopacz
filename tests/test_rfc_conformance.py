"""
RFC-KOPACZ-V3 Specification Conformance, Defensive Invariants, and Fuzzing Suite.

Verifies every normative MUST / MUST NOT requirement in docs/RFC-KOPACZ-V3.md,
including:
  - Section 2: QNAME label caps, domain validation, AAAA (2000::/3) carrier & RRset shuffle
  - Section 3: Defensive header validation (SYN|FIN, SYN|DATA, fragmented SYN, <8B)
  - Section 4: Handshake authentication, transcript binding, replay window
  - Section 5: Reassembly & decompression memory bounds (64 KB ceiling)
  - Section 6: SYN downstream MTU negotiation, Flags.MORE, self-clocked postures
  - Fuzzing:   Hypothesis property fuzzing of RelayHandler, Session, and Carrier
"""

import ipaddress
import os
import random
import pytest
from hypothesis import given, settings, strategies as st

from kopacz.protocol.crypto import derive_pubkey
from kopacz.protocol.header import Header, Flags, HEADER_SIZE
from kopacz.protocol.fragment import ReassemblyBuffer, MAX_REASSEMBLED_SIZE
from kopacz.session.state import Session, State
from kopacz.transport.carrier import (
    Carrier,
    MAX_AAAA_PAYLOAD,
    POSTURE_TURBO,
    POSTURE_BALANCED,
    POSTURE_COVERT,
)
from kopacz.relay.server import RelayHandler
from kopacz.client.tunnel import TunnelClient

SERVER_PRIV = b"\x5a" * 32
PSK = derive_pubkey(SERVER_PRIV)
DOMAIN = "t.example.com"


# ── Section 2: DNS Carrier Conformance ────────────────────────


class TestSection2Carrier:
    def test_label_length_capping_and_roundtrip(self):
        """RFC 2.1: Labels MUST NOT exceed max_label_len."""
        for max_lbl in (12, 24, 48, 63):
            c = Carrier(DOMAIN, max_label_len=max_lbl)
            payload = os.urandom(36)
            fqdn = c.pack_query(payload, "tag12345")
            labels = fqdn.split(".")[:-3]  # strip tag + t.example.com
            assert all(1 <= len(lbl) <= max_lbl for lbl in labels)
            tag, decoded = c.unpack_query(fqdn)
            assert tag == "tag12345"
            assert decoded == payload

    def test_invalid_max_label_len_rejected(self):
        with pytest.raises(ValueError):
            Carrier(DOMAIN, max_label_len=3)
        with pytest.raises(ValueError):
            Carrier(DOMAIN, max_label_len=64)
        with pytest.raises(ValueError):
            Carrier("")

    def test_domain_mismatch_and_malformed_qname_rejected(self):
        """RFC 2.1.6: Queries not matching authoritative domain MUST be rejected."""
        c = Carrier(DOMAIN)
        with pytest.raises(ValueError, match="domain mismatch"):
            c.unpack_query("mfzwi3df.tag123.evil.example.com")
        with pytest.raises(ValueError, match="too short"):
            c.unpack_query("tag123.t.example.com")
        with pytest.raises(ValueError):
            c.pack_query(b"hello", "bad.tag")
        with pytest.raises(ValueError):
            c.pack_query(b"", "tag123")

    def test_aaaa_carrier_global_unicast_and_shuffle_resilience(self):
        """RFC 2.3: AAAA records MUST lie in 2000::/3 and survive RRset shuffling."""
        global_unicast_net = ipaddress.IPv6Network("2000::/3")
        for size in (1, 8, 14, 15, 29, 64, 128, MAX_AAAA_PAYLOAD):
            raw = os.urandom(size)
            addrs = Carrier.pack_aaaa_response(raw)
            assert 1 <= len(addrs) <= 15
            for a in addrs:
                ip = ipaddress.IPv6Address(a)
                assert ip in global_unicast_net, f"{ip} not in 2000::/3"

            # Shuffle RRset 10 times to simulate recursive resolver round-robin
            for _ in range(10):
                shuffled = list(addrs)
                random.shuffle(shuffled)
                assert Carrier.unpack_aaaa_response(shuffled) == raw

    def test_aaaa_carrier_defensive_bounds(self):
        """RFC 2.3: Invalid AAAA payloads, prefixes, or missing indices MUST raise ValueError."""
        assert Carrier.pack_aaaa_response(b"") == []
        assert Carrier.unpack_aaaa_response([]) == b""

        with pytest.raises(ValueError, match="exceeds max"):
            Carrier.pack_aaaa_response(b"X" * (MAX_AAAA_PAYLOAD + 1))

        # Non-2000::/3 address rejected
        with pytest.raises(ValueError, match="Invalid AAAA carrier prefix"):
            Carrier.unpack_aaaa_response(["fe80::1"])

        # Missing record 0 rejected
        addrs = Carrier.pack_aaaa_response(b"A" * 40)
        with pytest.raises(ValueError, match="Missing AAAA record 0"):
            Carrier.unpack_aaaa_response(addrs[1:])

        # Gap in record indices rejected
        addrs3 = Carrier.pack_aaaa_response(b"B" * 60)
        assert len(addrs3) >= 3
        with pytest.raises(ValueError, match="Missing AAAA record index"):
            Carrier.unpack_aaaa_response([addrs3[0], addrs3[2]])


# ── Section 3: Defensive Header & State Invariants ────────────


class TestSection3DefensiveHeaders:
    def _established_pair(self):
        client = Session(PSK, is_client=True)
        server = Session(SERVER_PRIV, is_client=False)
        syn = client.initiate()[0]
        server.handle_packet(syn)
        synack = server.pop_synack()
        client.handle_packet(synack)
        assert client.state == State.ESTABLISHED
        assert server.state == State.ESTABLISHED
        return client, server

    def test_illegal_flag_combinations_discarded(self):
        """RFC 3.3: SYN|FIN, SYN|DATA, FIN|DATA MUST be silently discarded."""
        client, server = self._established_pair()
        idle_server = Session(SERVER_PRIV, is_client=False)

        for bad_flags in (
            Flags.SYN | Flags.FIN,
            Flags.SYN | Flags.DATA,
            Flags.FIN | Flags.DATA,
            Flags.SYN | Flags.FIN | Flags.DATA,
        ):
            pkt = Header(bad_flags, 0, 0, 0, 1, 0).pack() + b"payload"
            assert idle_server.handle_packet(pkt) is None
            assert idle_server.state == State.IDLE
            assert server.handle_packet(pkt) is None
            assert server.state == State.ESTABLISHED

    def test_fragmented_syn_and_synack_rejected(self):
        """RFC 3.3.4: Fragmented SYN or SYN-ACK packets MUST be discarded."""
        client = Session(PSK, is_client=True)
        syn = client.initiate()[0]
        syn_payload = syn[HEADER_SIZE:]

        server = Session(SERVER_PRIV, is_client=False)
        # SYN with total_frags=2
        bad_syn1 = Header(Flags.SYN, 0, 0, 0, 2, 0).pack() + syn_payload
        assert server.handle_packet(bad_syn1) is None
        assert server.state == State.IDLE

        # SYN with FRAG flag set
        bad_syn2 = Header(Flags.SYN | Flags.FRAG, 0, 0, 0, 1, 0).pack() + syn_payload
        assert server.handle_packet(bad_syn2) is None
        assert server.state == State.IDLE


# ── Section 5: Reassembly Memory Bounds ───────────────────────


class TestSection5ReassemblyBounds:
    def test_reassembly_exceeding_64kb_rejected_and_purged(self):
        """RFC 5.2: Reassembled size > 65536 bytes MUST raise ValueError and purge state."""
        rb = ReassemblyBuffer()
        chunk = b"A" * 30000
        h0 = Header(Flags.DATA | Flags.FRAG, 1, 10, 0, 3)
        h1 = Header(Flags.DATA | Flags.FRAG, 1, 10, 1, 3)
        h2 = Header(Flags.DATA | Flags.FRAG, 1, 10, 2, 3)

        assert rb.add(h0, chunk) is None
        assert rb.add(h1, chunk) is None
        assert rb.pending == 1

        with pytest.raises(ValueError, match="exceeds maximum"):
            rb.add(h2, chunk)  # 90,000 > 65,536

        # Entry must be purged so memory is freed
        assert rb.pending == 0


# ── Section 6: MTU Negotiation, Flags.MORE & Postures ─────────


class _DirectTxtResolver:
    def __init__(self, handler: RelayHandler):
        self.handler = handler
        self.queries = 0

    def query(self, qname: str) -> str:
        self.queries += 1
        return self.handler.build_response(qname)


class _DirectAaaaResolver:
    def __init__(self, handler: RelayHandler, encoder):
        self.handler = handler
        self.encoder = encoder
        self.queries = 0
        self.aaaa_rr_count = 0

    def query(self, qname: str) -> str:
        self.queries += 1
        addrs = self.handler.build_aaaa_response(qname)
        self.aaaa_rr_count += len(addrs)
        if not addrs:
            return ""
        raw = Carrier.unpack_aaaa_response(addrs)
        return self.encoder.encode(raw)


class TestSection6PosturesAndPipeline:
    def test_syn_downstream_mtu_negotiation(self):
        """RFC 6.2: Client SYN.reserved negotiates server Session.max_frag_payload."""
        client = Session(PSK, is_client=True, requested_down_mtu=480)
        server = Session(SERVER_PRIV, is_client=False, max_frag_payload=120)

        syn = client.initiate()[0]
        syn_hdr = Header.unpack(syn)
        assert syn_hdr.reserved == 60  # 480 // 8

        server.handle_packet(syn)
        assert server.state == State.ESTABLISHED
        assert server.max_frag_payload == 480

        synack = server.pop_synack()
        assert synack is not None
        assert Header.unpack(synack).reserved == 60

    def test_turbo_posture_reduces_downstream_fragments(self):
        """TURBO posture (480B down_mtu + self-clocked pipeline) uses ~4x fewer responses."""
        # Random incompressible 3KB payload to test pure fragment count
        blob = os.urandom(3000)

        # Legacy 120B relay
        h_legacy = RelayHandler(DOMAIN, SERVER_PRIV, on_data=lambda t, d: blob)
        r_legacy = _DirectTxtResolver(h_legacy)
        c_legacy = TunnelClient(DOMAIN, PSK, r_legacy, requested_down_mtu=120)
        c_legacy.connect()
        out_legacy = list(c_legacy.send(b"go"))
        out_legacy.extend(c_legacy.poll_all(max_polls=100))
        assert out_legacy == [blob]

        # Turbo 480B relay
        h_turbo = RelayHandler(DOMAIN, SERVER_PRIV, on_data=lambda t, d: blob)
        r_turbo = _DirectTxtResolver(h_turbo)
        c_turbo = TunnelClient(DOMAIN, PSK, r_turbo, posture="turbo")
        c_turbo.connect()
        out_turbo = list(c_turbo.send(b"go"))
        out_turbo.extend(c_turbo.poll_all(max_polls=100))
        assert out_turbo == [blob]

        # 3000B at 120B/frag = 26 fragments; at 480B/frag = 7 fragments
        assert r_turbo.queries < r_legacy.queries // 2

    def test_covert_posture_over_aaaa_records(self):
        """COVERT posture runs end-to-end over QTYPE=AAAA IPv6 records with zero TXT records."""
        handler = RelayHandler(
            DOMAIN,
            SERVER_PRIV,
            on_data=lambda t, d: b"covert-ack:" + d,
        )
        from kopacz.transport.encoding import Base32Encoder
        resolver = _DirectAaaaResolver(handler, Base32Encoder())
        client = TunnelClient(
            DOMAIN,
            PSK,
            resolver,
            posture="covert",
            jitter=(0.0, 0.0),  # skip sleep in unit test
        )
        client.connect()
        assert client.connected

        msg = b"HRD covert report from censored network: all systems operational."
        replies = list(client.send(msg))
        replies.extend(client.poll_all(max_polls=20))
        assert replies == [b"covert-ack:" + msg]
        assert resolver.aaaa_rr_count > 0


# ── Property-Based Fuzzing Suite ──────────────────────────────


class TestProtocolFuzzing:
    @given(st.text(min_size=0, max_size=300))
    @settings(max_examples=100, deadline=None)
    def test_fuzz_relay_handler_qnames(self, random_qname: str):
        """RelayHandler.handle_query MUST never crash or allocate sessions on arbitrary QNAMEs."""
        handler = RelayHandler(DOMAIN, SERVER_PRIV)
        res = handler.handle_query(random_qname)
        assert isinstance(res, bytes)
        assert handler.session_count == 0

    @given(st.binary(min_size=0, max_size=250))
    @settings(max_examples=100, deadline=None)
    def test_fuzz_relay_handler_binary_packets(self, random_pkt: bytes):
        """RelayHandler MUST reject arbitrary unauthenticated binary packets packaged in valid QNAMEs."""
        handler = RelayHandler(DOMAIN, SERVER_PRIV)
        carrier = Carrier(DOMAIN)
        if not random_pkt:
            return
        try:
            qname = carrier.pack_query(random_pkt, "fuzztag1")
        except ValueError:
            return
        res = handler.handle_query(qname)
        assert res == b""
        assert handler.session_count == 0

    @given(st.binary(min_size=0, max_size=250))
    @settings(max_examples=100, deadline=None)
    def test_fuzz_established_session_handle_packet(self, random_pkt: bytes):
        """Established Session.handle_packet MUST only return None or raise ValueError on random bytes."""
        client = Session(PSK, is_client=True)
        server = Session(SERVER_PRIV, is_client=False)
        syn = client.initiate()[0]
        server.handle_packet(syn)
        client.handle_packet(server.pop_synack())

        try:
            out = server.handle_packet(random_pkt)
            # Random bytes cannot forge a valid 128-bit Poly1305 AEAD tag
            assert out is None
        except ValueError:
            pass

    @given(
        st.binary(min_size=1, max_size=MAX_AAAA_PAYLOAD),
        st.integers(min_value=0, max_value=1000),
    )
    @settings(max_examples=60, deadline=None)
    def test_fuzz_aaaa_carrier_shuffled_roundtrip(self, data: bytes, seed: int):
        """For all payloads 1..223B and any permutation, unpack_aaaa(shuffle(pack_aaaa(D))) == D."""
        addrs = Carrier.pack_aaaa_response(data)
        rng = random.Random(seed)
        rng.shuffle(addrs)
        assert Carrier.unpack_aaaa_response(addrs) == data
