"""
Cryptographic engine for Kopacz.

Handshake : 1-RTT Noise_NK-style asymmetric X25519 (`es` + `ee`)
            - Relay holds static private key `server_priv` (32 B)
            - Clients hold static public key `server_pub` (32 B)
            - SYN     (56 B): c_eph_pub(32) ‖ AEAD(key=HKDF(es), pt=timestamp(8), tag(16))
            - SYN-ACK (48 B): s_eph_pub(32) ‖ AEAD_Tag(key=HKDF(es‖ee), pt=b"", tag(16))
Data      : ChaCha20-Poly1305 counter nonce (in-blob) + 64-bit anti-replay window + AAD
KDF       : HKDF-SHA256
"""

import hmac
import os
import struct
import time
from dataclasses import dataclass
from typing import Optional

from Cryptodome.Cipher import ChaCha20_Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
CTRL_TAG_SIZE = 8
OVERHEAD = NONCE_SIZE + TAG_SIZE  # 28 bytes per encrypted blob

SYN_SIZE = KEY_SIZE + 8 + TAG_SIZE      # 56 bytes: c_eph_pub(32) + enc_ts(8) + tag(16)
SYNACK_SIZE = KEY_SIZE + TAG_SIZE       # 48 bytes: s_eph_pub(32) + tag(16)
ZERO_NONCE = b"\x00" * NONCE_SIZE

SYN_AAD = b"kopacz-v3-syn"
SYNACK_AAD_PREFIX = b"kopacz-v3-synack:"
REPLAY_WINDOW_SIZE = 64
SYN_MAX_SKEW_SECONDS = 300


# ── Static keypair helpers ──────────────────────────────────────

def derive_pubkey(priv_bytes: bytes) -> bytes:
    """Derive 32-byte raw X25519 public key from 32-byte private key."""
    if len(priv_bytes) != KEY_SIZE:
        raise ValueError(f"Private key must be {KEY_SIZE} bytes")
    return X25519PrivateKey.from_private_bytes(priv_bytes).public_key().public_bytes_raw()


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a new (server_priv, server_pub) 32-byte raw X25519 keypair."""
    priv = os.urandom(KEY_SIZE)
    return priv, derive_pubkey(priv)


# ── low-level AEAD ──────────────────────────────────────────────

def _seal(key: bytes, plaintext: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
    """Encrypt + MAC.  Returns ciphertext‖tag."""
    c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    if aad:
        c.update(aad)
    ct, tag = c.encrypt_and_digest(plaintext)
    return ct + tag


def _open(key: bytes, blob: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
    """Decrypt + verify.  Input: ciphertext‖tag(16)."""
    if len(blob) < TAG_SIZE:
        raise ValueError("Ciphertext too short")
    ct, tag = blob[:-TAG_SIZE], blob[-TAG_SIZE:]
    c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    if aad:
        c.update(aad)
    return c.decrypt_and_verify(ct, tag)


def _x25519(priv: X25519PrivateKey, peer_pub_bytes: bytes) -> bytes:
    """Compute X25519 shared secret and reject low-order all-zero output."""
    if len(peer_pub_bytes) != KEY_SIZE:
        raise ValueError("Invalid X25519 public key length")
    shared = priv.exchange(X25519PublicKey.from_public_bytes(peer_pub_bytes))
    if shared == b"\x00" * KEY_SIZE:
        raise ValueError("Low-order X25519 public key rejected")
    return shared


# ── Key derivation ──────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class SessionKeys:
    client_to_server: bytes   # 32 B
    server_to_client: bytes   # 32 B


def derive_syn_key(
    es_secret: bytes,
    client_pub: bytes,
    server_static_pub: bytes,
) -> bytes:
    """HKDF-SHA256 key for encrypting the SYN timestamp under `es = ECDH(c_eph, s_static)`."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=client_pub + server_static_pub,
        info=b"kopacz-v3-syn",
    ).derive(es_secret)


def derive_handshake_keys(
    es_secret: bytes,
    ee_secret: bytes,
    client_pub: bytes,
    server_eph_pub: bytes,
) -> tuple[SessionKeys, bytes]:
    """
    HKDF-SHA256 from `es ‖ ee` bound to `(client_pub, server_eph_pub)`.
    Returns `(SessionKeys(c2s, s2c), synack_key)`.
    """
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE * 3,
        salt=client_pub + server_eph_pub,
        info=b"kopacz-v3",
    ).derive(es_secret + ee_secret)
    keys = SessionKeys(material[:KEY_SIZE], material[KEY_SIZE : KEY_SIZE * 2])
    synack_key = material[KEY_SIZE * 2 :]
    return keys, synack_key


def derive_keys(
    shared_secret: bytes,
    client_pub: bytes,
    server_pub: bytes,
) -> SessionKeys:
    """HKDF-SHA256 helper bound to both public keys."""
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=client_pub + server_pub,
        info=b"kopacz-v3",
    ).derive(shared_secret)
    return SessionKeys(material[:KEY_SIZE], material[KEY_SIZE:])


# ── Per-session state ───────────────────────────────────────────

class CryptoState:
    """
    Manages one session's cryptographic lifecycle (Noise_NK pattern: `es` + `ee`).

    Arguments:
        key:
            - When `is_client=True`:  32-byte `server_pub` (relay's static X25519 public key)
            - When `is_client=False`: 32-byte `server_priv` (relay's static X25519 private key)
        is_client: True for client, False for server/relay.

    Handshake (1-RTT):
        Client:  client_hello()  →  send 56 B SYN payload
                 client_finish(synack_payload)
        Server:  server_hello(syn_payload)  →  send 48 B SYN-ACK payload

    Data:
        encrypt(plaintext, aad=b"") → nonce‖ciphertext‖tag   (28 B overhead)
        decrypt(blob, aad=b"")      → plaintext (with 64-bit anti-replay window)
    """

    def __init__(self, key: bytes, is_client: bool):
        if len(key) != KEY_SIZE:
            raise ValueError(f"Key must be {KEY_SIZE} bytes")
        self.is_client = is_client
        if is_client:
            self._server_priv: Optional[X25519PrivateKey] = None
            self._server_pub: bytes = key
        else:
            self._server_priv = X25519PrivateKey.from_private_bytes(key)
            self._server_pub = self._server_priv.public_key().public_bytes_raw()

        self.keys: Optional[SessionKeys] = None
        self._send_ctr: int = 0
        # Anti-replay sliding window (RFC 6479 style)
        self._max_recv_ctr: int = -1
        self._recv_bitmap: int = 0
        # ephemeral (cleared after handshake)
        self._eph_priv: Optional[X25519PrivateKey] = None
        self._local_pub: Optional[bytes] = None
        self._es: Optional[bytes] = None

    @property
    def established(self) -> bool:
        return self.keys is not None

    @property
    def server_public_key(self) -> bytes:
        return self._server_pub

    # ── handshake ───────────────────────────────────────────────

    def client_hello(self) -> bytes:
        """Generate 56-byte SYN payload: c_eph_pub(32) ‖ AEAD(key=HKDF(es), pt=timestamp(8))."""
        self._eph_priv = X25519PrivateKey.generate()
        self._local_pub = self._eph_priv.public_key().public_bytes_raw()
        self._es = _x25519(self._eph_priv, self._server_pub)
        syn_key = derive_syn_key(self._es, self._local_pub, self._server_pub)
        ts_bytes = struct.pack(">Q", int(time.time()))
        sealed_ts = _seal(syn_key, ts_bytes, ZERO_NONCE, aad=SYN_AAD + self._local_pub)
        return self._local_pub + sealed_ts

    def client_finish(self, synack_payload: bytes) -> None:
        """Process 48-byte SYN-ACK, verify transcript tag over (es, ee), derive session keys."""
        if self._eph_priv is None or self._local_pub is None or self._es is None:
            raise ValueError("Handshake not initiated")
        if len(synack_payload) != SYNACK_SIZE:
            raise ValueError("Bad SYN-ACK length")
        s_eph_pub = synack_payload[:KEY_SIZE]
        tag = synack_payload[KEY_SIZE:]
        if s_eph_pub == self._local_pub or s_eph_pub == self._server_pub:
            raise ValueError("Reflected public key rejected")
        ee = _x25519(self._eph_priv, s_eph_pub)
        keys, synack_key = derive_handshake_keys(self._es, ee, self._local_pub, s_eph_pub)
        _open(
            synack_key,
            tag,
            ZERO_NONCE,
            aad=SYNACK_AAD_PREFIX + self._local_pub + s_eph_pub,
        )
        self.keys = keys
        self._eph_priv = None
        self._local_pub = None
        self._es = None

    def server_hello(self, syn_payload: bytes) -> bytes:
        """Process 56-byte SYN, verify `es` & timestamp freshness, derive keys, return 48-byte SYN-ACK."""
        if self._server_priv is None:
            raise ValueError("CryptoState not initialized as server")
        if len(syn_payload) != SYN_SIZE:
            raise ValueError("Bad SYN length")
        c_pub = syn_payload[:KEY_SIZE]
        sealed_ts = syn_payload[KEY_SIZE:]
        if c_pub == self._server_pub:
            raise ValueError("Invalid client public key")
        es = _x25519(self._server_priv, c_pub)
        syn_key = derive_syn_key(es, c_pub, self._server_pub)
        ts_bytes = _open(syn_key, sealed_ts, ZERO_NONCE, aad=SYN_AAD + c_pub)
        ts = struct.unpack(">Q", ts_bytes)[0]
        if abs(int(time.time()) - ts) > SYN_MAX_SKEW_SECONDS:
            raise ValueError("Expired or future SYN timestamp")

        s_priv = X25519PrivateKey.generate()
        s_pub = s_priv.public_key().public_bytes_raw()
        if s_pub == c_pub:
            raise ValueError("Invalid client public key")
        ee = _x25519(s_priv, c_pub)
        self.keys, synack_key = derive_handshake_keys(es, ee, c_pub, s_pub)
        tag = _seal(
            synack_key,
            b"",
            ZERO_NONCE,
            aad=SYNACK_AAD_PREFIX + c_pub + s_pub,
        )
        return s_pub + tag

    def sign_control(self, header_bytes: bytes) -> bytes:
        """Compute 8-byte AEAD control tag over an 8-byte header."""
        if len(header_bytes) != 8:
            raise ValueError("Header must be 8 bytes")
        nonce = b"ctrl" + header_bytes
        return _seal(self._send_key(), b"", nonce, aad=header_bytes)[:CTRL_TAG_SIZE]

    def verify_control(self, header_bytes: bytes, tag: bytes) -> bool:
        """Verify 8-byte AEAD control tag over an 8-byte header."""
        if len(header_bytes) != 8 or len(tag) != CTRL_TAG_SIZE or self.keys is None:
            return False
        nonce = b"ctrl" + header_bytes
        expected = _seal(self._recv_key(), b"", nonce, aad=header_bytes)[:CTRL_TAG_SIZE]
        return hmac.compare_digest(expected, tag)

    # ── data encryption ─────────────────────────────────────────

    def _send_key(self) -> bytes:
        if self.keys is None:
            raise ValueError("Session keys not established")
        return self.keys.client_to_server if self.is_client else self.keys.server_to_client

    def _recv_key(self) -> bytes:
        if self.keys is None:
            raise ValueError("Session keys not established")
        return self.keys.server_to_client if self.is_client else self.keys.client_to_server

    def _check_replay(self, ctr: int) -> bool:
        """Return True if *ctr* is fresh and within the 64-packet sliding window."""
        if self._max_recv_ctr < 0:
            return True
        if ctr > self._max_recv_ctr:
            return True
        diff = self._max_recv_ctr - ctr
        if diff >= REPLAY_WINDOW_SIZE:
            return False
        return not bool(self._recv_bitmap & (1 << diff))

    def _record_replay(self, ctr: int) -> None:
        """Advance sliding anti-replay window after successful AEAD verification."""
        if self._max_recv_ctr < 0:
            self._max_recv_ctr = ctr
            self._recv_bitmap = 1
        elif ctr > self._max_recv_ctr:
            shift = ctr - self._max_recv_ctr
            if shift >= REPLAY_WINDOW_SIZE:
                self._recv_bitmap = 1
            else:
                self._recv_bitmap = ((self._recv_bitmap << shift) | 1) & (
                    (1 << REPLAY_WINDOW_SIZE) - 1
                )
            self._max_recv_ctr = ctr
        else:
            diff = self._max_recv_ctr - ctr
            self._recv_bitmap |= 1 << diff

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Returns nonce(12)‖ciphertext‖tag(16)."""
        nonce = self._send_ctr.to_bytes(NONCE_SIZE, "big")
        self._send_ctr += 1
        return nonce + _seal(self._send_key(), plaintext, nonce, aad=aad)

    def decrypt(self, blob: bytes, aad: bytes = b"") -> bytes:
        """Input: nonce(12)‖ciphertext‖tag(16). Verifies anti-replay and AEAD tag."""
        if len(blob) < OVERHEAD:
            raise ValueError("Blob too short")
        nonce = blob[:NONCE_SIZE]
        ctr = int.from_bytes(nonce, "big")
        if not self._check_replay(ctr):
            raise ValueError("Replayed or expired packet nonce")
        pt = _open(self._recv_key(), blob[NONCE_SIZE:], nonce, aad=aad)
        self._record_replay(ctr)
        return pt
