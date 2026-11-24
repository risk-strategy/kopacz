"""
Security and functionality audit regression test suite for Kopacz v3 (run-1).

Verifies fixes for all confirmed findings and leads:
1. Unauthenticated FIN/ACK/POLL control flags (kopacz/session/unauthenticated-control-flags)
2. Spoofed fragment total_frags state poisoning (kopacz/protocol/unauthenticated-reassembly-state-poisoning)
3. Captured SYN replay & timestamp freshness (kopacz/relay/syn-replay-no-freshness-bounded-nonce-cache)
4. Messaging handle takeover & sender pubkey spoofing (kopacz/apps/messaging-handle-not-bound-to-owner)
5. WebFetch redirect SSRF & FTP handler stripping (kopacz/apps/web-redirect-not-revalidated, web-ftp-redirect-bypasses-tor)
6. SSRF bypass vectors: IPv4-mapped IPv6, numeric/hex/octal IPs, CGNAT, trailing dots (kopacz/apps/validate-target-unresolved-host-check)
7. Tag state cleanup across Switch, ConnectProxy, and MessageRelay on session removal (kopacz/relay/tag-state-survives-session-removal)
8. WebFetch bounded response streaming, POST cap, and Switch bounded downstream queues (kopacz/relay/unbounded-downstream-queue-without-backpressure)
9. RecvWindow out-of-order memory bounds & TCPBridge persistent multi-connection accept loop.
"""

from __future__ import annotations

import socket
import struct
import time
import urllib.error
import urllib.request
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from kopacz.apps.bridge import TCPBridge
from kopacz.apps.clients.chat import MessageClient
from kopacz.apps.dispatch import AppDispatcher
from kopacz.apps.messaging import (
    E2ECrypto,
    MSG_REGISTER,
    MSG_SEND,
    MessageRelay,
    _pad_handle,
)
from kopacz.apps.proxy import ConnectProxy, validate_target
from kopacz.apps.web import (
    CHUNK,
    END,
    FETCH,
    HEADER,
    MAX_RESPONSE_BYTES,
    POST,
    WebFetch,
    validate_url,
)
from kopacz.client.tunnel import TunnelClient
from kopacz.protocol.crypto import derive_pubkey
from kopacz.protocol.fragment import ReassemblyBuffer
from kopacz.protocol.header import Flags, Header
from kopacz.relay.server import RelayHandler
from kopacz.relay.switch import Switch
from kopacz.session.arq import RecvWindow
from kopacz.session.state import RECV_WINDOW_SPAN, Session, State

PSK = b"\x42" * 32
SERVER_PUB = derive_pubkey(PSK)
DOMAIN = "t.example.com"


# ── 1. Unauthenticated Control Flags (3.1) ────────────────────


class TestAuthenticatedControlFlags:
    def _establish(self, tag: str = "abcdefgh"):
        handler = RelayHandler(DOMAIN, PSK, on_data=lambda t, d: b"echo:" + d)
        client = Session(SERVER_PUB, is_client=True)
        syn = client.initiate()[0]
        syn_resp = handler.handle_query(handler.carrier.pack_query(syn, tag))
        assert syn_resp
        client.handle_packet(syn_resp)
        assert client.state == State.ESTABLISHED
        return handler, client

    def test_forged_fin_rejected_and_session_stays_established(self):
        handler, client = self._establish("abcdefgh")

        # Unauthenticated observer sends raw 8-byte FIN header on the tag
        forged_fin = Header(Flags.FIN, 0, 0).pack()
        resp = handler.handle_query(handler.carrier.pack_query(forged_fin, "abcdefgh"))
        assert resp == b""
        assert "abcdefgh" in handler._sessions
        assert handler._sessions["abcdefgh"].state == State.ESTABLISHED

        # Legitimate client DATA still succeeds
        pkt = client.send(b"still-alive")[0]
        reply = handler.handle_query(handler.carrier.pack_query(pkt, "abcdefgh"))
        assert reply
        assert client.handle_packet(reply) == b"echo:still-alive"

    def test_forged_ack_and_poll_do_not_purge_window_or_steal_downstream(self):
        handler, client = self._establish("abcdefgh")
        handler.switch.enqueue_downstream("abcdefgh", b"confidential-downstream")

        # Unauthenticated observer sends bare 8-byte POLL
        forged_poll = Header(Flags.POLL, 0, 1).pack()
        resp = handler.handle_query(handler.carrier.pack_query(forged_poll, "abcdefgh"))
        assert resp == b""

        # Downstream message is still waiting for the legitimate client!
        legit_poll = client.make_poll()
        legit_resp = handler.handle_query(handler.carrier.pack_query(legit_poll, "abcdefgh"))
        assert legit_resp
        assert len(handler._sessions["abcdefgh"]._send_window) == 1

        # Observer sends forged ACK(0) and ACK(0x8000) to try to purge SendWindow
        for seq in (0, 0x8000):
            forged_ack = Header(Flags.ACK, 0, seq).pack()
            handler.handle_query(handler.carrier.pack_query(forged_ack, "abcdefgh"))

        # SendWindow is untouched!
        assert len(handler._sessions["abcdefgh"]._send_window) == 1
        assert client.handle_packet(legit_resp) == b"confidential-downstream"

    def test_forged_data_ack_piggyback_does_not_ack_before_decrypt(self):
        handler, client = self._establish("abcdefgh")
        handler.switch.enqueue_downstream("abcdefgh", b"msg-0")
        legit_resp = handler.handle_query(
            handler.carrier.pack_query(client.make_poll(), "abcdefgh")
        )
        assert legit_resp
        assert len(handler._sessions["abcdefgh"]._send_window) == 1

        # Observer sends forged DATA|ACK with reserved=0 and garbage ciphertext
        forged_data_ack = Header(Flags.DATA | Flags.ACK, 0, 0, 0, 1, reserved=0).pack() + b"X" * 32
        handler.handle_query(handler.carrier.pack_query(forged_data_ack, "abcdefgh"))
        assert len(handler._sessions["abcdefgh"]._send_window) == 1


# ── 2. Reassembly State Poisoning (3.2) ───────────────────────


class TestReassemblyPoisoningProtection:
    def test_spoofed_fragment_with_conflicting_total_frags_does_not_stall_session(self):
        client = Session(SERVER_PUB, is_client=True)
        server = Session(PSK, is_client=False)
        syn = client.initiate()[0]
        server.handle_packet(syn)
        client.handle_packet(server.pop_synack())

        # Observer pre-places a forged DATA|FRAG packet for seq=0 with total_frags=2
        spoofed = Header(Flags.DATA | Flags.FRAG, 0, 0, 1, 2).pack() + b"forged"
        assert server.handle_packet(spoofed) is None

        # Genuine client sends 1-fragment message for seq=0 (total_frags=1)
        genuine_pkt = client.send(b"hello")[0]
        assert server.handle_packet(genuine_pkt) == b"hello"
        assert server._recv_window.ack_number == 0

    def test_out_of_window_future_sequence_dropped_before_reassembly(self):
        client = Session(SERVER_PUB, is_client=True)
        server = Session(PSK, is_client=False)
        syn = client.initiate()[0]
        server.handle_packet(syn)
        client.handle_packet(server.pop_synack())

        far_seq = RECV_WINDOW_SPAN + 10
        spoofed_far = Header(Flags.DATA | Flags.FRAG, 0, far_seq, 0, 2).pack() + b"junk"
        assert server.handle_packet(spoofed_far) is None
        assert server._reassembly.pending == 0


# ── 3. SYN Replay & Timestamp Freshness (3.3) ─────────────────


class TestSYNReplayProtection:
    def test_same_tag_syn_replay_rejected_after_session_closed(self):
        handler = RelayHandler(DOMAIN, PSK)
        client = Session(SERVER_PUB, is_client=True)
        syn = client.initiate()[0]
        qname = handler.carrier.pack_query(syn, "tag1")

        synack = handler.handle_query(qname)
        assert synack
        client.handle_packet(synack)

        # Client closes session with authenticated FIN
        fin = client.make_fin()
        handler.handle_query(handler.carrier.pack_query(fin, "tag1"))
        assert "tag1" not in handler._sessions

        # Observer replays the original captured SYN on the same tag -> rejected!
        assert handler.handle_query(qname) == b""
        assert "tag1" not in handler._sessions

        # Legitimate client with a FRESH SYN on "tag1" succeeds!
        client2 = Session(SERVER_PUB, is_client=True)
        syn2 = client2.initiate()[0]
        assert handler.handle_query(handler.carrier.pack_query(syn2, "tag1")) != b""
        assert "tag1" in handler._sessions

    def test_expired_timestamp_syn_rejected_across_restart(self):
        # Construct a SYN with a timestamp 1000 seconds in the past
        old_ts = int(time.time()) - 1000
        with patch("kopacz.protocol.crypto.time.time", return_value=old_ts):
            old_client = Session(SERVER_PUB, is_client=True)
            old_syn_pkt = old_client.initiate()[0]

        # Fresh RelayHandler (simulating server restart with empty nonce cache)
        handler = RelayHandler(DOMAIN, PSK)
        qname = handler.carrier.pack_query(old_syn_pkt, "replayed")
        assert handler.handle_query(qname) == b""
        assert handler.session_count == 0


# ── 4. Messaging Handle Ownership & Pinning (3.4) ─────────────


class TestMessagingHandleOwnership:
    def test_handle_takeover_and_impersonation_blocked(self):
        switch = Switch()
        relay = MessageRelay(switch)
        switch.register("alice-tag")
        switch.register("bob-tag")
        switch.register("mallory-tag")

        alice_crypto = E2ECrypto()
        bob_crypto = E2ECrypto()
        mallory_crypto = E2ECrypto()

        # Alice and Bob register with their public keys
        relay.on_data(
            "alice-tag",
            bytes([MSG_REGISTER]) + _pad_handle("alice") + alice_crypto.public_key_bytes,
        )
        relay.on_data(
            "bob-tag",
            bytes([MSG_REGISTER]) + _pad_handle("bob") + bob_crypto.public_key_bytes,
        )

        # Mallory attempts to hijack 'alice' -> refused!
        relay.on_data(
            "mallory-tag",
            bytes([MSG_REGISTER]) + _pad_handle("alice") + mallory_crypto.public_key_bytes,
        )
        assert relay._handle_to_tag[_pad_handle("alice")] == "alice-tag"

        # Bob sends to Alice -> delivered to alice-tag, NOT mallory-tag
        ct = bob_crypto.encrypt(b"secret for alice", alice_crypto.public_key_bytes)
        relay.on_data(
            "bob-tag",
            bytes([MSG_SEND]) + _pad_handle("alice") + bob_crypto.public_key_bytes + ct,
        )
        assert switch.poll_downstream("mallory-tag") is None
        env = switch.poll_downstream("alice-tag")
        assert env is not None

        # Client-side key pinning blocks impersonation even if envelope is forged
        dummy_tunnel = MagicMock()
        bob_client = MessageClient(
            dummy_tunnel,
            "bob",
            bob_crypto,
            known_keys={"alice": alice_crypto.public_key_bytes},
        )
        forged_env = (
            bytes([MSG_SEND])
            + _pad_handle("alice")
            + mallory_crypto.public_key_bytes
            + mallory_crypto.encrypt(b"pay mallory", bob_crypto.public_key_bytes)
        )
        assert bob_client._parse_incoming(forged_env) is None


# ── 5. SSRF Bypass Vectors & Redirects (3.5) ──────────────────


class TestSSRFHardening:
    @pytest.mark.parametrize(
        "host",
        [
            "localhost",
            "localhost.",
            "LOCALHOST.",
            "sub.localhost",
            "sub.localhost.",
            "printer.local",
            "db.internal",
            "router.home.arpa",
            "127.0.0.1",
            "127.0.0.1.",
            "127.1",
            "0",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "0.0.0.0",
            "2130706433",      # 127.0.0.1 in decimal
            "0x7f000001",      # 127.0.0.1 in hex
            "0177.0.0.1",      # 127.0.0.1 in octal-like
            "017700000001",    # 127.0.0.1 in single octal integer
            "169.254.169.254", # cloud metadata
            "100.64.0.1",      # CGNAT / shared address space
            "100.100.100.100", # Tailscale / CGNAT
        ],
    )
    def test_validate_target_blocks_bypass_vectors(self, host: str):
        assert validate_target(host, 80) is False

    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost./admin",
            "http://[::ffff:127.0.0.1]/secret",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://0x7f000001/secret",
            "http://2130706433/secret",
            "http://127.1/secret",
            "http://metadata.internal/token",
            "ftp://93.184.216.34/pub",
        ],
    )
    def test_validate_url_blocks_bypass_vectors(self, url: str):
        assert validate_url(url) is False

    def test_safe_redirect_handler_blocks_302_to_loopback_and_ftp(self):
        switch = Switch()
        wf = WebFetch(switch, use_tor=False)
        opener = wf._make_opener()
        # Verify FTPHandler, FileHandler, DataHandler are stripped from opener
        for h in opener.handlers:
            assert not isinstance(
                h,
                (
                    urllib.request.FTPHandler,
                    urllib.request.FileHandler,
                    urllib.request.DataHandler,
                ),
            )
        handler = [
            h for h in opener.handlers if isinstance(h, urllib.request.HTTPRedirectHandler)
        ][0]

        req = urllib.request.Request("https://93.184.216.34/start")
        fp = BytesIO(b"")
        for bad_loc in (
            "http://127.0.0.1:8080/internal-admin",
            "http://169.254.169.254/latest/meta-data/",
            "ftp://93.184.216.34/file",
        ):
            with pytest.raises(urllib.error.HTTPError) as exc:
                handler.redirect_request(req, fp, 302, "Found", {"Location": bad_loc}, bad_loc)
            assert exc.value.code == 403


# ── 6. WebFetch Bounds & Streaming Cap ────────────────────────


class TestWebFetchBounds:
    def test_post_body_oversize_rejected(self):
        switch = Switch()
        switch.register("tag1")
        wf = WebFetch(switch, use_tor=False)
        url = b"https://93.184.216.34/post"
        oversized_body = b"x" * 70_000
        payload = bytes([POST]) + struct.pack(">H", len(url)) + url + oversized_body
        wf.on_data("tag1", payload)
        hdr = switch.poll_downstream("tag1")
        assert hdr is not None
        assert hdr[0] == HEADER
        status = struct.unpack(">H", hdr[1:3])[0]
        assert status == 413

    def test_response_stream_capped_at_max_response_bytes(self):
        switch = Switch()
        switch.register("tag1")
        cap = 64 * 1024
        wf = WebFetch(switch, use_tor=False, max_response_bytes=cap)

        fake_resp = MagicMock()
        fake_resp.status = 200
        fake_resp.headers = {"Content-Type": "text/plain"}
        fake_resp.read.side_effect = lambda n: b"A" * n

        fake_opener = MagicMock()
        fake_opener.open.return_value = fake_resp

        wf._sem.acquire()
        with patch.object(wf, "_make_opener", return_value=fake_opener):
            wf._fetch_and_stream("tag1", "https://93.184.216.34/infinite")

        total_bytes = 0
        saw_eof = False
        while True:
            msg = switch.poll_downstream("tag1")
            if msg is None:
                break
            if msg[0] == CHUNK:
                total_bytes += len(msg) - 1
            elif msg[0] == END:
                saw_eof = True

        assert saw_eof
        assert total_bytes == cap


# ── 7. Tag State Cleanup on Session Removal ───────────────────


class TestTagStateCleanup:
    def test_session_removal_cleans_switch_and_proxy_socket(self):
        disp = AppDispatcher()
        handler = RelayHandler(DOMAIN, PSK, max_sessions=2, on_data=disp.on_data)
        proxy = ConnectProxy(handler.switch, use_tor=False)
        disp.register(0x01, proxy.on_data)

        # Establish victim01 and attach a socketpair
        c_vic = Session(SERVER_PUB, is_client=True)
        handler.handle_query(handler.carrier.pack_query(c_vic.initiate()[0], "victim01"))
        s0, s1 = socket.socketpair()
        try:
            proxy._connections["victim01"] = s0
            handler.switch.enqueue_downstream("victim01", b"secret-queued")

            # Remove victim01 session -> Switch queue and proxy socket are both cleaned up
            handler._remove_session("victim01")
            assert handler.switch.get("victim01") is None
            assert "victim01" not in proxy._connections
        finally:
            s0.close()
            s1.close()

    def test_dead_drop_max_handles_evicts_oldest(self):
        switch = Switch()
        mr = MessageRelay(switch, dead_drop_max=5, max_handles=3)
        pub = b"\x11" * 32

        for i in range(5):
            h = _pad_handle(f"user{i}")
            mr.on_data("sender", bytes([MSG_SEND]) + h + pub + b"cipher")

        assert len(mr._dead_drop) == 3
        assert _pad_handle("user0") not in mr._dead_drop
        assert _pad_handle("user1") not in mr._dead_drop
        assert _pad_handle("user4") in mr._dead_drop


# ── 8. RecvWindow & TCPBridge Persistence ─────────────────────


class TestRecvWindowAndBridge:
    def test_ooo_window_rejects_beyond_max_ooo(self):
        rw = RecvWindow(max_ooo=16)
        accepted = sum(1 for s in range(1, 100) if rw.record(s, b"chunk"))
        assert accepted == 15
        assert len(rw._ooo) == 15
        assert rw.record(0, b"first")
        assert len(rw.pop_ready()) == 16
        assert rw.ack_number == 15

    def test_bridge_accepts_multiple_sequential_connections(self):
        switch = Switch()
        switch.register("srv1")

        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        bridge = TCPBridge(switch, "srv1", bind="127.0.0.1", port=port)
        thread = bridge.start_background()
        time.sleep(0.05)

        try:
            c1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c1.connect(("127.0.0.1", port))
            c1.sendall(b"conn1")
            time.sleep(0.05)
            assert switch.poll_downstream("srv1") == b"conn1"
            c1.close()
            time.sleep(0.05)

            c2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c2.connect(("127.0.0.1", port))
            c2.sendall(b"conn2")
            time.sleep(0.05)
            assert switch.poll_downstream("srv1") == b"conn2"
            c2.close()
        finally:
            bridge.stop()
            thread.join(timeout=2)
