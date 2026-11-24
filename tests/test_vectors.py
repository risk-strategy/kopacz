"""
Cross-language test vector generator.

Generates JSON with hex-encoded byte strings for validating the
JavaScript protocol implementation against the Python reference.

Run directly to print vectors:
    python tests/test_vectors.py

Or import as a test:
    pytest tests/test_vectors.py
"""

import json
import os

from Cryptodome.Cipher import ChaCha20_Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from kopacz.protocol.crypto import (
    derive_pubkey,
    derive_keys,
    CryptoState,
    _seal,
    _open,
    NONCE_SIZE,
    KEY_SIZE,
)
from kopacz.protocol.header import Header, Flags, HEADER_SIZE
from kopacz.protocol.compress import compress, decompress
from kopacz.transport.encoding import Base32Encoder


def generate_vectors() -> dict:
    """Generate all cross-language test vectors."""
    vectors = {}

    # ── Base32 ────────────────────────────────────────────────
    b32 = Base32Encoder()
    base32_vectors = []
    for raw in [b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar",
                b"\x00" * 16, b"\xff" * 16, os.urandom(32)]:
        encoded = b32.encode(raw)
        base32_vectors.append({
            "raw_hex": raw.hex(),
            "encoded": encoded,
        })
    vectors["base32"] = base32_vectors

    # ── ChaCha20-Poly1305 RFC 7539 Section 2.8.2 ─────────────
    rfc_key = bytes.fromhex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    )
    rfc_nonce = bytes.fromhex("070000004041424344454647")
    rfc_aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    rfc_plaintext = (
        b"Ladies and Gentlemen of the class of '99: "
        b"If I could offer you only one tip for the future, "
        b"sunscreen would be it."
    )

    # With AAD (RFC test)
    c = ChaCha20_Poly1305.new(key=rfc_key, nonce=rfc_nonce)
    c.update(rfc_aad)
    rfc_ct, rfc_tag = c.encrypt_and_digest(rfc_plaintext)

    vectors["chacha20_poly1305_rfc7539"] = {
        "key_hex": rfc_key.hex(),
        "nonce_hex": rfc_nonce.hex(),
        "aad_hex": rfc_aad.hex(),
        "plaintext_hex": rfc_plaintext.hex(),
        "ciphertext_hex": rfc_ct.hex(),
        "tag_hex": rfc_tag.hex(),
    }

    # Without AAD (how kopacz uses it)
    no_aad_ct_tag = _seal(rfc_key, rfc_plaintext, rfc_nonce)
    vectors["chacha20_poly1305_no_aad"] = {
        "key_hex": rfc_key.hex(),
        "nonce_hex": rfc_nonce.hex(),
        "plaintext_hex": rfc_plaintext.hex(),
        "sealed_hex": no_aad_ct_tag.hex(),
        "note": "ct||tag(16), no AAD — this is how kopacz encrypts",
    }

    # ── Static server keypair derivation ──────────────────────
    server_priv = bytes(range(32))
    server_pub = derive_pubkey(server_priv)
    vectors["static_keypair"] = {
        "server_priv_hex": server_priv.hex(),
        "server_pub_hex": server_pub.hex(),
        "note": "Server holds server_priv; clients hold server_pub.",
    }

    # ── HKDF-SHA256 ───────────────────────────────────────────
    hkdf_ikm = bytes(range(32))
    hkdf_salt = bytes(range(0x30, 0x30 + 32))
    hkdf_info = b"kopacz-v3"
    hkdf_output = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=hkdf_salt,
        info=hkdf_info,
    ).derive(hkdf_ikm)
    vectors["hkdf_sha256"] = {
        "ikm_hex": hkdf_ikm.hex(),
        "salt_hex": hkdf_salt.hex(),
        "info": "kopacz-v3",
        "length": 64,
        "output_hex": hkdf_output.hex(),
    }

    # ── Header pack/unpack ────────────────────────────────────
    header_vectors = []
    for flags, sid, seq, fidx, ftot in [
        (0, 0, 0, 0, 1),
        (Flags.SYN, 0, 0, 0, 1),
        (Flags.SYN | Flags.ACK, 42, 1000, 0, 1),
        (Flags.DATA | Flags.FRAG, 0xFFFF, 0xFFFF, 254, 255),
        (Flags.DATA | Flags.ACK, 100, 200, 3, 10),
    ]:
        hdr = Header(flags, sid, seq, fidx, ftot)
        packed = hdr.pack()
        header_vectors.append({
            "flags": flags,
            "stream_id": sid,
            "sequence": seq,
            "frag_index": fidx,
            "total_frags": ftot,
            "packed_hex": packed.hex(),
        })
    vectors["headers"] = header_vectors

    # ── LZ4 compress/decompress ───────────────────────────────
    lz4_vectors = []
    for raw in [b"Hello, world!", b"A" * 1000, bytes(range(256))]:
        compressed = compress(raw)
        lz4_vectors.append({
            "raw_hex": raw.hex(),
            "compressed_hex": compressed.hex(),
        })
    vectors["lz4"] = lz4_vectors

    # ── Full handshake (Noise_NK: es + ee) ────────────────────
    priv_hs = b"\x42" * 32
    pub_hs = derive_pubkey(priv_hs)

    client_crypto = CryptoState(pub_hs, is_client=True)
    syn_payload = client_crypto.client_hello()

    server_crypto = CryptoState(priv_hs, is_client=False)
    synack_payload = server_crypto.server_hello(syn_payload)

    client_crypto.client_finish(synack_payload)

    # Both should now have the same session keys
    assert client_crypto.keys is not None
    assert server_crypto.keys is not None
    assert client_crypto.keys.client_to_server == server_crypto.keys.client_to_server
    assert client_crypto.keys.server_to_client == server_crypto.keys.server_to_client

    # Test encrypt/decrypt with data-plane AAD
    test_plaintext = b"Handshake verified!"
    data_aad = bytes([Flags.DATA, 0x00, 0x01, 0x00, 0x00])
    client_encrypted = client_crypto.encrypt(test_plaintext, aad=data_aad)
    server_decrypted = server_crypto.decrypt(client_encrypted, aad=data_aad)
    assert server_decrypted == test_plaintext

    vectors["handshake"] = {
        "server_priv_hex": priv_hs.hex(),
        "server_pub_hex": pub_hs.hex(),
        "syn_payload_hex": syn_payload.hex(),
        "synack_payload_hex": synack_payload.hex(),
        "client_to_server_key_hex": client_crypto.keys.client_to_server.hex(),
        "server_to_client_key_hex": client_crypto.keys.server_to_client.hex(),
        "test_plaintext_hex": test_plaintext.hex(),
        "test_aad_hex": data_aad.hex(),
        "test_encrypted_hex": client_encrypted.hex(),
        "note": "Client encrypts with client_to_server key, counter nonce 0 (big-endian 12 bytes), and header AAD.",
    }

    # ── Counter nonce encrypt/decrypt ─────────────────────────
    key = bytes(range(32))
    counter_vectors = []
    for ctr in [0, 1, 2, 255, 65535]:
        nonce = ctr.to_bytes(NONCE_SIZE, "big")
        pt = f"counter={ctr}".encode()
        sealed = nonce + _seal(key, pt, nonce)
        counter_vectors.append({
            "counter": ctr,
            "nonce_hex": nonce.hex(),
            "plaintext_hex": pt.hex(),
            "sealed_hex": sealed.hex(),
        })
    vectors["counter_nonce"] = {
        "key_hex": key.hex(),
        "vectors": counter_vectors,
    }

    return vectors


def test_vectors_consistency():
    """Verify that generated vectors are self-consistent."""
    vectors = generate_vectors()

    # Base32 round-trip
    b32 = Base32Encoder()
    for v in vectors["base32"]:
        raw = bytes.fromhex(v["raw_hex"])
        assert b32.encode(raw) == v["encoded"]
        assert b32.decode(v["encoded"]) == raw

    # ChaCha20-Poly1305 no-AAD decrypt
    key = bytes.fromhex(vectors["chacha20_poly1305_no_aad"]["key_hex"])
    nonce = bytes.fromhex(vectors["chacha20_poly1305_no_aad"]["nonce_hex"])
    sealed = bytes.fromhex(vectors["chacha20_poly1305_no_aad"]["sealed_hex"])
    pt = bytes.fromhex(vectors["chacha20_poly1305_no_aad"]["plaintext_hex"])
    assert _open(key, sealed, nonce) == pt

    # Static keypair derivation
    priv = bytes.fromhex(vectors["static_keypair"]["server_priv_hex"])
    pub = bytes.fromhex(vectors["static_keypair"]["server_pub_hex"])
    assert derive_pubkey(priv) == pub

    # Header round-trip
    for v in vectors["headers"]:
        packed = bytes.fromhex(v["packed_hex"])
        hdr = Header.unpack(packed)
        assert hdr.flags == v["flags"]
        assert hdr.stream_id == v["stream_id"]
        assert hdr.sequence == v["sequence"]
        assert hdr.frag_index == v["frag_index"]
        assert hdr.total_frags == v["total_frags"]

    # LZ4 round-trip
    for v in vectors["lz4"]:
        raw = bytes.fromhex(v["raw_hex"])
        compressed = bytes.fromhex(v["compressed_hex"])
        assert decompress(compressed) == raw

    # Counter nonce decrypt
    key = bytes.fromhex(vectors["counter_nonce"]["key_hex"])
    for v in vectors["counter_nonce"]["vectors"]:
        sealed = bytes.fromhex(v["sealed_hex"])
        nonce = sealed[:NONCE_SIZE]
        pt = _open(key, sealed[NONCE_SIZE:], nonce)
        assert pt == bytes.fromhex(v["plaintext_hex"])


if __name__ == "__main__":
    vectors = generate_vectors()
    print(json.dumps(vectors, indent=2))
