"""Tests for messaging: E2ECrypto, MessageRelay, and full E2E."""

import os
import pytest

from kopacz.apps.messaging import (
    E2ECrypto,
    MessageRelay,
    StealthPoller,
    _pad_handle,
    _unpad_handle,
    MSG_REGISTER,
    MSG_SEND,
    HANDLE_SIZE,
    PUBKEY_SIZE,
)
from kopacz.apps.dispatch import AppDispatcher
from kopacz.apps.clients.chat import MessageClient
from kopacz.client.tunnel import TunnelClient
from kopacz.protocol.crypto import derive_pubkey
from kopacz.relay.server import RelayHandler
from kopacz.relay.switch import Switch

SERVER_PRIV = b"\x42" * 32
PSK = derive_pubkey(SERVER_PRIV)
DOMAIN = "msg.example.com"


class MockResolver:
    def __init__(self, handler: RelayHandler):
        self.handler = handler

    def query(self, qname: str) -> str | None:
        txt = self.handler.build_response(qname)
        return txt if txt else None


# ── E2ECrypto ─────────────────────────────────────────────────

class TestE2ECrypto:
    def test_roundtrip(self):
        alice = E2ECrypto()
        bob = E2ECrypto()

        ct = alice.encrypt(b"hello bob", bob.public_key_bytes)
        pt = bob.decrypt(ct, alice.public_key_bytes)
        assert pt == b"hello bob"

    def test_roundtrip_reverse(self):
        alice = E2ECrypto()
        bob = E2ECrypto()

        ct = bob.encrypt(b"hello alice", alice.public_key_bytes)
        pt = alice.decrypt(ct, bob.public_key_bytes)
        assert pt == b"hello alice"

    def test_wrong_key_fails(self):
        alice = E2ECrypto()
        bob = E2ECrypto()
        eve = E2ECrypto()

        ct = alice.encrypt(b"secret", bob.public_key_bytes)
        with pytest.raises(ValueError):
            eve.decrypt(ct, alice.public_key_bytes)

    def test_tampered_ciphertext_fails(self):
        alice = E2ECrypto()
        bob = E2ECrypto()

        ct = alice.encrypt(b"important", bob.public_key_bytes)
        tampered = bytearray(ct)
        tampered[len(ct) // 2] ^= 0xFF
        with pytest.raises(ValueError):
            bob.decrypt(bytes(tampered), alice.public_key_bytes)

    def test_empty_plaintext(self):
        alice = E2ECrypto()
        bob = E2ECrypto()

        ct = alice.encrypt(b"", bob.public_key_bytes)
        pt = bob.decrypt(ct, alice.public_key_bytes)
        assert pt == b""

    def test_large_plaintext(self):
        alice = E2ECrypto()
        bob = E2ECrypto()

        data = os.urandom(4096)
        ct = alice.encrypt(data, bob.public_key_bytes)
        pt = bob.decrypt(ct, alice.public_key_bytes)
        assert pt == data

    def test_nonce_increments(self):
        alice = E2ECrypto()
        bob = E2ECrypto()

        ct1 = alice.encrypt(b"msg1", bob.public_key_bytes)
        ct2 = alice.encrypt(b"msg2", bob.public_key_bytes)
        # Different nonces → different ciphertexts (even if same plaintext)
        assert ct1 != ct2
        # Both decrypt correctly
        assert bob.decrypt(ct1, alice.public_key_bytes) == b"msg1"
        assert bob.decrypt(ct2, alice.public_key_bytes) == b"msg2"

    def test_blob_too_short(self):
        alice = E2ECrypto()
        bob = E2ECrypto()
        with pytest.raises(ValueError):
            bob.decrypt(b"\x00" * 10, alice.public_key_bytes)


# ── Handle encoding ───────────────────────────────────────────

class TestHandleEncoding:
    def test_pad_unpad_roundtrip(self):
        assert _unpad_handle(_pad_handle("alice")) == "alice"

    def test_pad_exact_size(self):
        assert len(_pad_handle("alice")) == HANDLE_SIZE

    def test_truncates_long_handle(self):
        long_handle = "a" * 32
        padded = _pad_handle(long_handle)
        assert len(padded) == HANDLE_SIZE

    def test_empty_handle(self):
        assert _unpad_handle(_pad_handle("")) == ""


# ── MessageRelay ──────────────────────────────────────────────

class TestMessageRelay:
    def test_register_maps_handle(self):
        switch = Switch()
        relay = MessageRelay(switch)
        switch.register("alice-tag")

        payload = bytes([MSG_REGISTER]) + _pad_handle("alice")
        relay.on_data("alice-tag", payload)

        assert relay._handle_to_tag[_pad_handle("alice")] == "alice-tag"

    def test_route_to_online_recipient(self):
        switch = Switch()
        relay = MessageRelay(switch)
        switch.register("alice-tag")
        switch.register("bob-tag")

        # Register both
        relay.on_data("alice-tag", bytes([MSG_REGISTER]) + _pad_handle("alice"))
        relay.on_data("bob-tag", bytes([MSG_REGISTER]) + _pad_handle("bob"))

        # Alice sends to Bob
        sender_pub = os.urandom(PUBKEY_SIZE)
        encrypted = b"encrypted-message"
        send_payload = (
            bytes([MSG_SEND])
            + _pad_handle("bob")
            + sender_pub
            + encrypted
        )
        relay.on_data("alice-tag", send_payload)

        # Bob should have a message downstream
        msg = switch.poll_downstream("bob-tag")
        assert msg is not None
        assert msg[0] == MSG_SEND
        sender_handle = msg[1:1 + HANDLE_SIZE]
        assert _unpad_handle(sender_handle) == "alice"

    def test_dead_drop_for_offline(self):
        switch = Switch()
        relay = MessageRelay(switch)
        switch.register("alice-tag")

        # Register alice
        relay.on_data("alice-tag", bytes([MSG_REGISTER]) + _pad_handle("alice"))

        # Alice sends to offline Bob
        sender_pub = os.urandom(PUBKEY_SIZE)
        send_payload = (
            bytes([MSG_SEND])
            + _pad_handle("bob")
            + sender_pub
            + b"offline-msg"
        )
        relay.on_data("alice-tag", send_payload)

        # Message in dead-drop
        assert _pad_handle("bob") in relay._dead_drop
        assert len(relay._dead_drop[_pad_handle("bob")]) == 1

    def test_dead_drop_flush_on_register(self):
        switch = Switch()
        relay = MessageRelay(switch)
        switch.register("alice-tag")

        # Register alice
        relay.on_data("alice-tag", bytes([MSG_REGISTER]) + _pad_handle("alice"))

        # Alice sends to offline Bob
        sender_pub = os.urandom(PUBKEY_SIZE)
        send_payload = (
            bytes([MSG_SEND])
            + _pad_handle("bob")
            + sender_pub
            + b"waiting-msg"
        )
        relay.on_data("alice-tag", send_payload)

        # Bob comes online
        switch.register("bob-tag")
        relay.on_data("bob-tag", bytes([MSG_REGISTER]) + _pad_handle("bob"))

        # Dead-drop should be flushed
        assert _pad_handle("bob") not in relay._dead_drop

        # Bob gets the message from switch
        msg = switch.poll_downstream("bob-tag")
        assert msg is not None
        assert b"waiting-msg" in msg

    def test_empty_payload_safe(self):
        switch = Switch()
        relay = MessageRelay(switch)
        assert relay.on_data("x", b"") is None

    def test_unknown_msg_type_safe(self):
        switch = Switch()
        relay = MessageRelay(switch)
        assert relay.on_data("x", b"\xff" + b"data") is None


# ── StealthPoller ─────────────────────────────────────────────

class TestStealthPoller:
    def test_jitter_range(self):
        poller = StealthPoller(base=10.0, jitter_factor=0.3)
        intervals = [poller._next_interval() for _ in range(1000)]
        assert all(7.0 <= i <= 13.0 for i in intervals)

    def test_stop(self):
        poller = StealthPoller()
        poller.stop()
        assert poller._running is False


# ── Full E2E through tunnel ───────────────────────────────────

class TestE2EMessaging:
    def test_two_clients_exchange_messages(self):
        """Two TunnelClients exchange E2E encrypted messages through relay."""
        dispatcher = AppDispatcher()
        handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=dispatcher.on_data)
        messenger = MessageRelay(handler.switch)
        dispatcher.register(0x03, messenger.on_data)

        # Create two tunnel clients
        r1 = MockResolver(handler)
        r2 = MockResolver(handler)
        t1 = TunnelClient(DOMAIN, PSK, r1, tag="alice-sess")
        t2 = TunnelClient(DOMAIN, PSK, r2, tag="bob-sess")
        t1.connect()
        t2.connect()

        alice_crypto = E2ECrypto()
        bob_crypto = E2ECrypto()

        alice = MessageClient(t1, "alice", alice_crypto)
        bob = MessageClient(t2, "bob", bob_crypto)

        # Register both
        alice.register()
        bob.register()

        # Alice sends to Bob
        alice.send_message("bob", b"hello bob!", bob_crypto.public_key_bytes)

        # Bob receives
        msgs = bob.receive_messages()
        assert len(msgs) == 1
        sender, plaintext = msgs[0]
        assert sender == "alice"
        assert plaintext == b"hello bob!"

    def test_bidirectional_exchange(self):
        """Both directions work."""
        dispatcher = AppDispatcher()
        handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=dispatcher.on_data)
        messenger = MessageRelay(handler.switch)
        dispatcher.register(0x03, messenger.on_data)

        r1 = MockResolver(handler)
        r2 = MockResolver(handler)
        t1 = TunnelClient(DOMAIN, PSK, r1, tag="alice2")
        t2 = TunnelClient(DOMAIN, PSK, r2, tag="bob2")
        t1.connect()
        t2.connect()

        alice_crypto = E2ECrypto()
        bob_crypto = E2ECrypto()

        alice = MessageClient(t1, "alice", alice_crypto)
        bob = MessageClient(t2, "bob", bob_crypto)

        alice.register()
        bob.register()

        # Alice → Bob
        alice.send_message("bob", b"hi bob", bob_crypto.public_key_bytes)
        msgs = bob.receive_messages()
        assert len(msgs) == 1
        assert msgs[0] == ("alice", b"hi bob")

        # Bob → Alice
        bob.send_message("alice", b"hi alice", alice_crypto.public_key_bytes)
        msgs = alice.receive_messages()
        assert len(msgs) == 1
        assert msgs[0] == ("bob", b"hi alice")

    def test_relay_never_sees_plaintext(self):
        """Verify relay only handles encrypted blobs."""
        relay_data = []

        dispatcher = AppDispatcher()
        handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=dispatcher.on_data)

        # Intercept what the relay sees
        original_messenger = MessageRelay(handler.switch)

        def intercepting_handler(tag, data):
            relay_data.append(data)
            return original_messenger.on_data(tag, data)

        dispatcher.register(0x03, intercepting_handler)

        r1 = MockResolver(handler)
        r2 = MockResolver(handler)
        t1 = TunnelClient(DOMAIN, PSK, r1, tag="a-spy")
        t2 = TunnelClient(DOMAIN, PSK, r2, tag="b-spy")
        t1.connect()
        t2.connect()

        alice_crypto = E2ECrypto()
        bob_crypto = E2ECrypto()
        alice = MessageClient(t1, "alice", alice_crypto)
        bob = MessageClient(t2, "bob", bob_crypto)

        alice.register()
        bob.register()

        secret = b"TOP SECRET MESSAGE"
        alice.send_message("bob", secret, bob_crypto.public_key_bytes)

        # Relay saw SEND payloads — none should contain the plaintext
        for data in relay_data:
            if data[0:1] == bytes([MSG_SEND]):
                assert secret not in data

        # But Bob can decrypt it
        msgs = bob.receive_messages()
        assert len(msgs) == 1
        assert msgs[0][1] == secret

    def test_dead_drop_delivery(self):
        """Message sent to offline recipient, delivered when they register."""
        dispatcher = AppDispatcher()
        handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=dispatcher.on_data)
        messenger = MessageRelay(handler.switch)
        dispatcher.register(0x03, messenger.on_data)

        r1 = MockResolver(handler)
        t1 = TunnelClient(DOMAIN, PSK, r1, tag="alice-dd")
        t1.connect()

        alice_crypto = E2ECrypto()
        bob_crypto = E2ECrypto()
        alice = MessageClient(t1, "alice", alice_crypto)

        # Alice registers and sends to offline Bob
        alice.register()
        alice.send_message("bob", b"are you there?", bob_crypto.public_key_bytes)

        # Bob comes online later
        r2 = MockResolver(handler)
        t2 = TunnelClient(DOMAIN, PSK, r2, tag="bob-dd")
        t2.connect()
        bob = MessageClient(t2, "bob", bob_crypto)
        bob.register()

        # Bob should receive the dead-drop message
        msgs = bob.receive_messages()
        assert len(msgs) == 1
        assert msgs[0] == ("alice", b"are you there?")
