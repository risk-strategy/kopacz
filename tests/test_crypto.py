import pytest
from hypothesis import given, settings, strategies as st

from kopacz.protocol.crypto import (
    KEY_SIZE,
    NONCE_SIZE,
    OVERHEAD,
    SYN_SIZE,
    SYNACK_SIZE,
    TAG_SIZE,
    CryptoState,
    derive_pubkey,
    generate_keypair,
)

SERVER_PRIV = b"\x42" * 32
SERVER_PUB = derive_pubkey(SERVER_PRIV)


# ── Static Keypair & Asymmetry ──────────────────────────────────

class TestStaticKeypair:
    def test_derive_pubkey_deterministic(self):
        assert derive_pubkey(SERVER_PRIV) == SERVER_PUB
        assert len(SERVER_PUB) == KEY_SIZE
        assert SERVER_PUB != SERVER_PRIV

    def test_generate_keypair_unique(self):
        priv1, pub1 = generate_keypair()
        priv2, pub2 = generate_keypair()
        assert priv1 != priv2
        assert pub1 != pub2
        assert derive_pubkey(priv1) == pub1


# ── Handshake (Noise_NK pattern: es + ee) ───────────────────────

def _handshake(server_priv=SERVER_PRIV, server_pub=SERVER_PUB):
    c = CryptoState(server_pub, is_client=True)
    s = CryptoState(server_priv, is_client=False)
    syn = c.client_hello()
    assert len(syn) == SYN_SIZE  # 56 bytes
    synack = s.server_hello(syn)
    assert len(synack) == SYNACK_SIZE  # 48 bytes
    c.client_finish(synack)
    return c, s


class TestHandshake:
    def test_both_established(self):
        c, s = _handshake()
        assert c.established
        assert s.established

    def test_keys_match(self):
        c, s = _handshake()
        assert c.keys.client_to_server == s.keys.client_to_server
        assert c.keys.server_to_client == s.keys.server_to_client

    def test_pfs(self):
        """Each handshake produces different session keys even with same static server key."""
        k1 = _handshake()[0].keys
        k2 = _handshake()[0].keys
        assert k1.client_to_server != k2.client_to_server

    def test_wrong_server_pubkey_fails(self):
        _, wrong_pub = generate_keypair()
        c = CryptoState(wrong_pub, is_client=True)
        s = CryptoState(SERVER_PRIV, is_client=False)
        syn = c.client_hello()
        with pytest.raises(ValueError):
            s.server_hello(syn)

    def test_captured_client_pubkey_cannot_impersonate_server(self):
        """
        If an attacker captures a client and extracts SERVER_PUB, they cannot
        use SERVER_PUB as a server private key to MitM another client.
        """
        victim_client = CryptoState(SERVER_PUB, is_client=True)
        syn = victim_client.client_hello()

        fake_server = CryptoState(SERVER_PUB, is_client=False)
        with pytest.raises(ValueError):
            fake_server.server_hello(syn)

    def test_ephemeral_cleared(self):
        c, _ = _handshake()
        assert c._eph_priv is None
        assert c._local_pub is None
        assert c._es is None

    def test_reflection_attack_rejected(self):
        """Reflecting a client's SYN back as SYN-ACK is rejected."""
        c = CryptoState(SERVER_PUB, is_client=True)
        syn = c.client_hello()
        with pytest.raises(ValueError):
            c.client_finish(syn)
        with pytest.raises(ValueError):
            c.client_finish(syn[:SYNACK_SIZE])

    def test_cross_session_synack_replay_rejected(self):
        """A SYN-ACK generated for client 1 is rejected by client 2 due to (es, ee, c_pub) binding."""
        c1 = CryptoState(SERVER_PUB, is_client=True)
        c2 = CryptoState(SERVER_PUB, is_client=True)
        s = CryptoState(SERVER_PRIV, is_client=False)
        syn1 = c1.client_hello()
        _syn2 = c2.client_hello()
        synack1 = s.server_hello(syn1)
        with pytest.raises(ValueError):
            c2.client_finish(synack1)


# ── Data encryption ─────────────────────────────────────────────

class TestData:
    def test_client_to_server(self):
        c, s = _handshake()
        assert s.decrypt(c.encrypt(b"hello")) == b"hello"

    def test_server_to_client(self):
        c, s = _handshake()
        assert c.decrypt(s.encrypt(b"world")) == b"world"

    @settings(max_examples=300)
    @given(st.binary(min_size=0, max_size=2000))
    def test_prop_c2s_roundtrip(self, data):
        c, s = _handshake()
        assert s.decrypt(c.encrypt(data)) == data

    @settings(max_examples=300)
    @given(st.binary(min_size=0, max_size=2000))
    def test_prop_s2c_roundtrip(self, data):
        c, s = _handshake()
        assert c.decrypt(s.encrypt(data)) == data

    @settings(max_examples=100)
    @given(st.binary(min_size=1, max_size=500), st.integers(min_value=0))
    def test_prop_tamper_detected(self, data, pos):
        c, s = _handshake()
        ct = c.encrypt(data)
        idx = NONCE_SIZE + (pos % (len(ct) - NONCE_SIZE))
        bad = bytearray(ct)
        bad[idx] ^= 0x01
        with pytest.raises(ValueError):
            s.decrypt(bytes(bad))

    def test_overhead_is_28(self):
        c, s = _handshake()
        ct = c.encrypt(b"x" * 100)
        assert len(ct) == 100 + OVERHEAD

    def test_nonces_increment(self):
        c, s = _handshake()
        ct1 = c.encrypt(b"a")
        ct2 = c.encrypt(b"b")
        assert ct1[:NONCE_SIZE] != ct2[:NONCE_SIZE]

    def test_aad_binding_rejects_mismatch(self):
        c, s = _handshake()
        ct = c.encrypt(b"bound payload", aad=b"hdr-1")
        with pytest.raises(ValueError):
            s.decrypt(ct, aad=b"hdr-2")
        assert s.decrypt(ct, aad=b"hdr-1") == b"bound payload"

    def test_replay_window_rejects_duplicate_nonce(self):
        c, s = _handshake()
        ct = c.encrypt(b"once only")
        assert s.decrypt(ct) == b"once only"
        with pytest.raises(ValueError, match="Replayed"):
            s.decrypt(ct)

    def test_replay_window_allows_out_of_order_within_64(self):
        c, s = _handshake()
        ciphertexts = [c.encrypt(f"msg-{i}".encode()) for i in range(10)]
        for i in reversed(range(10)):
            assert s.decrypt(ciphertexts[i]) == f"msg-{i}".encode()
        for i in range(10):
            with pytest.raises(ValueError, match="Replayed"):
                s.decrypt(ciphertexts[i])

    def test_replay_window_rejects_expired_beyond_64(self):
        c, s = _handshake()
        ct_old = c.encrypt(b"very old")
        for _ in range(64):
            ct = c.encrypt(b"newer")
        assert s.decrypt(ct) == b"newer"
        with pytest.raises(ValueError, match="expired"):
            s.decrypt(ct_old)
