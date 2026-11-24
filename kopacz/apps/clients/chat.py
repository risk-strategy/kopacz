"""
Messaging client — register, send, and receive E2E encrypted messages.

Wraps TunnelClient with the 0x03 app-ID prefix and provides
high-level send_message / receive_messages API.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ...client.tunnel import TunnelClient
from ..messaging import (
    E2ECrypto,
    HANDLE_SIZE,
    PUBKEY_SIZE,
    MSG_REGISTER,
    MSG_SEND,
    _pad_handle,
    _unpad_handle,
)


class MessageClient:
    """Client-side messaging over DNS tunnel."""

    APP_ID = 0x03

    def __init__(
        self,
        tunnel: TunnelClient,
        handle: str,
        crypto: E2ECrypto | None = None,
        known_keys: Dict[str, bytes] | None = None,
    ):
        self.tunnel = tunnel
        self.handle = handle
        self.crypto = crypto or E2ECrypto()
        self.known_keys: Dict[str, bytes] = dict(known_keys) if known_keys else {}
        self._inbox: List[bytes] = []

    def register(self) -> List[bytes]:
        """Send REGISTER with our handle and E2E public key. Returns any piggybacked downstream."""
        payload = (
            bytes([self.APP_ID, MSG_REGISTER])
            + _pad_handle(self.handle)
            + self.crypto.public_key_bytes
        )
        downstream = self.tunnel.send(payload)
        self._inbox.extend(downstream)
        return downstream

    def send_message(
        self, recipient_handle: str, plaintext: bytes, recipient_pubkey: bytes
    ) -> List[bytes]:
        """E2E encrypt and send a message. Returns any piggybacked downstream."""
        self.known_keys.setdefault(recipient_handle, recipient_pubkey)
        encrypted = self.crypto.encrypt(plaintext, recipient_pubkey)
        payload = (
            bytes([self.APP_ID, MSG_SEND])
            + _pad_handle(recipient_handle)
            + self.crypto.public_key_bytes
            + encrypted
        )
        downstream = self.tunnel.send(payload)
        self._inbox.extend(downstream)
        return downstream

    def receive_messages(self) -> List[Tuple[str, bytes]]:
        """
        Poll for incoming messages. Decrypt and return list of
        (sender_handle, plaintext) tuples.
        """
        raw_messages = list(self._inbox)
        self._inbox.clear()
        raw_messages.extend(self.tunnel.poll_all())
        results = []
        for raw in raw_messages:
            parsed = self._parse_incoming(raw)
            if parsed is not None:
                results.append(parsed)
        return results

    def _parse_incoming(self, raw: bytes) -> Optional[Tuple[str, bytes]]:
        """Parse a delivery envelope and decrypt."""
        min_size = 1 + HANDLE_SIZE + PUBKEY_SIZE
        if len(raw) < min_size or raw[0] != MSG_SEND:
            return None

        sender_handle = _unpad_handle(raw[1:1 + HANDLE_SIZE])
        sender_pubkey = raw[1 + HANDLE_SIZE:1 + HANDLE_SIZE + PUBKEY_SIZE]
        encrypted = raw[1 + HANDLE_SIZE + PUBKEY_SIZE:]

        pinned = self.known_keys.get(sender_handle)
        if pinned is not None and pinned != sender_pubkey:
            return None

        try:
            plaintext = self.crypto.decrypt(encrypted, sender_pubkey)
        except (ValueError, Exception):
            return None

        self.known_keys.setdefault(sender_handle, sender_pubkey)
        return (sender_handle, plaintext)
