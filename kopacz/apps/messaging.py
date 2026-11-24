"""
Messaging — dead-drop pattern with E2E encryption.

Wire format (after 0x03 stripped by AppDispatcher):

    REGISTER (0x01): type(1) + handle(16, zero-padded UTF-8)
    SEND     (0x02): type(1) + recipient_handle(16) + sender_pubkey(32) + encrypted_payload

Delivered downstream to recipient:
    type(0x02) + sender_handle(16) + sender_pubkey(32) + encrypted_payload

E2E encryption means the relay never sees plaintext — it is a
blind forwarder of opaque blobs.
"""

from __future__ import annotations

import os
import logging
import random
import threading
import time
from collections import deque
from typing import Deque, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from Cryptodome.Cipher import ChaCha20_Poly1305

from ..relay.switch import Switch

log = logging.getLogger(__name__)

HANDLE_SIZE = 16
PUBKEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16

MSG_REGISTER = 0x01
MSG_SEND = 0x02


# ── E2E Crypto ────────────────────────────────────────────────

class E2ECrypto:
    """
    End-to-end encryption for messaging.

    X25519 ECDH between sender and recipient (long-lived keypairs).
    HKDF-SHA256 to derive message key.
    ChaCha20-Poly1305 with counter nonces.

    Key format: nonce(12) || ciphertext || tag(16)
    """

    def __init__(self, private_key: X25519PrivateKey | None = None):
        self.private_key = private_key or X25519PrivateKey.generate()
        self._send_ctr: int = 0

    @property
    def public_key_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes_raw()

    @property
    def private_key_bytes(self) -> bytes:
        return self.private_key.private_bytes_raw()

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "E2ECrypto":
        return cls(private_key=X25519PrivateKey.from_private_bytes(raw))

    @staticmethod
    def _derive_key(
        shared_secret: bytes,
        sender_pub: bytes,
        recipient_pub: bytes,
    ) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=sender_pub + recipient_pub,
            info=b"kopacz-e2e-messaging",
        ).derive(shared_secret)

    def encrypt(self, plaintext: bytes, recipient_pubkey: bytes) -> bytes:
        """Encrypt for a recipient. Returns nonce(12) || ciphertext || tag(16)."""
        peer_pub = X25519PublicKey.from_public_bytes(recipient_pubkey)
        shared = self.private_key.exchange(peer_pub)
        sender_pub = self.public_key_bytes
        key = self._derive_key(shared, sender_pub, recipient_pubkey)

        # 8-byte CSPRNG prefix + 4-byte monotonic counter prevents nonce reuse across restarts
        nonce = os.urandom(8) + (self._send_ctr & 0xFFFFFFFF).to_bytes(4, "big")
        self._send_ctr += 1

        c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        c.update(sender_pub + recipient_pubkey)
        ct, tag = c.encrypt_and_digest(plaintext)
        return nonce + ct + tag

    def decrypt(self, blob: bytes, sender_pubkey: bytes) -> bytes:
        """Decrypt from a sender. Input: nonce(12) || ciphertext || tag(16)."""
        if len(blob) < NONCE_SIZE + TAG_SIZE:
            raise ValueError("E2E blob too short")

        peer_pub = X25519PublicKey.from_public_bytes(sender_pubkey)
        shared = self.private_key.exchange(peer_pub)
        recipient_pub = self.public_key_bytes
        key = self._derive_key(shared, sender_pubkey, recipient_pub)

        nonce = blob[:NONCE_SIZE]
        ct_and_tag = blob[NONCE_SIZE:]
        ct, tag = ct_and_tag[:-TAG_SIZE], ct_and_tag[-TAG_SIZE:]

        c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        c.update(sender_pubkey + recipient_pub)
        return c.decrypt_and_verify(ct, tag)


# ── Relay side ────────────────────────────────────────────────

def _pad_handle(handle: str) -> bytes:
    """Encode handle to exactly HANDLE_SIZE bytes, zero-padded."""
    raw = handle.encode("utf-8")[:HANDLE_SIZE]
    return raw.ljust(HANDLE_SIZE, b"\x00")


def _unpad_handle(raw: bytes) -> str:
    """Decode zero-padded handle bytes."""
    return raw.rstrip(b"\x00").decode("utf-8")


class MessageRelay:
    """
    Relay-side message router.

    Registered as dispatcher handler for app ID 0x03.
    Routes messages between registered handles via the Switch,
    with dead-drop for offline recipients.
    """

    MAX_MSG_SIZE = 32768

    def __init__(self, switch: Switch, dead_drop_max: int = 1000, max_handles: int = 1024):
        self.switch = switch
        self._handle_to_tag: Dict[bytes, str] = {}
        self._tag_to_handle: Dict[str, bytes] = {}
        self._handle_to_key: Dict[bytes, bytes] = {}
        self._dead_drop: Dict[bytes, Deque[bytes]] = {}
        self._dd_max = dead_drop_max
        self._max_handles = max_handles
        self._lock = threading.Lock()
        self.switch.on_unregister(self._on_session_unregister)

    def _on_session_unregister(self, tag: str) -> None:
        """Clean up tag → handle mapping when a session is removed from the Switch."""
        with self._lock:
            handle = self._tag_to_handle.pop(tag, None)
            if handle is not None and self._handle_to_tag.get(handle) == tag:
                del self._handle_to_tag[handle]

    def on_data(self, tag: str, payload: bytes) -> Optional[bytes]:
        """
        Dispatcher callback. Payload has 0x03 prefix already stripped.

        Returns None (all routing is done via Switch enqueue).
        """
        if not payload or len(payload) > self.MAX_MSG_SIZE:
            return None

        msg_type = payload[0]
        if msg_type == MSG_REGISTER:
            return self._handle_register(tag, payload)
        elif msg_type == MSG_SEND:
            return self._handle_send(tag, payload)

        return None

    def _handle_register(self, tag: str, payload: bytes) -> Optional[bytes]:
        """Register handle → tag mapping (with optional owner pubkey binding). Flush dead-drop."""
        if len(payload) < 1 + HANDLE_SIZE:
            return None

        handle = payload[1:1 + HANDLE_SIZE]
        pubkey: Optional[bytes] = None
        if len(payload) >= 1 + HANDLE_SIZE + PUBKEY_SIZE:
            pubkey = payload[1 + HANDLE_SIZE:1 + HANDLE_SIZE + PUBKEY_SIZE]

        with self._lock:
            # If handle is already bound to a different owner key, refuse takeover
            owner_key = self._handle_to_key.get(handle)
            if owner_key is not None and pubkey is not None and owner_key != pubkey:
                return None

            # If handle is currently owned by another live session in the Switch, refuse takeover
            current_tag = self._handle_to_tag.get(handle)
            if current_tag is not None and current_tag != tag and self.switch.get(current_tag) is not None:
                return None

            # Clean up previous handle registered by this tag (if any)
            prev_handle = self._tag_to_handle.get(tag)
            if prev_handle is not None and prev_handle != handle:
                if self._handle_to_tag.get(prev_handle) == tag:
                    del self._handle_to_tag[prev_handle]

            if pubkey is not None:
                self._handle_to_key[handle] = pubkey
            self._handle_to_tag[handle] = tag
            self._tag_to_handle[tag] = handle

            # Flush dead-drop to switch downstream
            pending: List[bytes] = []
            if handle in self._dead_drop:
                while self._dead_drop[handle]:
                    pending.append(self._dead_drop[handle].popleft())
                del self._dead_drop[handle]

        for msg in pending:
            self.switch.enqueue_downstream(tag, msg)

        return None

    def _handle_send(self, tag: str, payload: bytes) -> Optional[bytes]:
        """Route message to recipient (online via switch, or dead-drop)."""
        min_size = 1 + HANDLE_SIZE + PUBKEY_SIZE
        if len(payload) < min_size:
            return None

        recipient_handle = payload[1:1 + HANDLE_SIZE]
        sender_pubkey = payload[1 + HANDLE_SIZE:1 + HANDLE_SIZE + PUBKEY_SIZE]
        encrypted_payload = payload[1 + HANDLE_SIZE + PUBKEY_SIZE:]

        with self._lock:
            # Build delivery envelope
            sender_handle = self._tag_to_handle.get(tag, _pad_handle("unknown"))
            bound_key = self._handle_to_key.get(sender_handle)
            if bound_key is not None and bound_key != sender_pubkey:
                return None
            if sender_handle != _pad_handle("unknown") and bound_key is None:
                self._handle_to_key[sender_handle] = sender_pubkey
            envelope = (
                bytes([MSG_SEND])
                + sender_handle
                + sender_pubkey
                + encrypted_payload
            )

            recipient_tag = self._handle_to_tag.get(recipient_handle)
            if recipient_tag is None:
                # Dead-drop with bounded handle count
                if recipient_handle not in self._dead_drop:
                    if len(self._dead_drop) >= self._max_handles:
                        oldest = next(iter(self._dead_drop))
                        del self._dead_drop[oldest]
                    self._dead_drop[recipient_handle] = deque(maxlen=self._dd_max)
                self._dead_drop[recipient_handle].append(envelope)

        if recipient_tag is not None:
            self.switch.enqueue_downstream(recipient_tag, envelope)

        return None


# ── Stealth poller ────────────────────────────────────────────

class StealthPoller:
    """
    Jittered polling loop for message receive.

    base ± jitter_factor * base interval between polls.
    """

    def __init__(self, base: float = 30.0, jitter_factor: float = 0.3):
        self.base = base
        self.jitter_factor = jitter_factor
        self._running = False

    def _next_interval(self) -> float:
        jitter = self.base * self.jitter_factor
        return self.base + random.uniform(-jitter, jitter)

    def poll_loop(self, poll_fn, callback) -> None:
        """
        Blocking loop: calls poll_fn(), passes results to callback.

        poll_fn: callable returning list of messages
        callback: callable(messages) for each batch
        """
        self._running = True
        while self._running:
            messages = poll_fn()
            if messages:
                callback(messages)
            time.sleep(self._next_interval())

    def stop(self) -> None:
        self._running = False
