"""
Session state machine.

Lifecycle:  IDLE → HANDSHAKE → ESTABLISHED → CLOSED

Full data pipeline:
    send:  data → conditional compress → encrypt(once, with header AAD) → fragment → packets
    recv:  packets → dedup → reassemble → decrypt(with AAD + anti-replay) → decompress → ordered data

ARQ:
    SendWindow tracks outbound messages. RecvWindow orders inbound messages and generates ACKs.
    Retransmission is caller-driven (call retransmit_due()).
"""

import struct
from enum import Enum, auto
from typing import List, Optional

from ..protocol.header import Header, Flags, HEADER_SIZE
from ..protocol.crypto import CryptoState
from ..protocol.fragment import fragment, ReassemblyBuffer
from ..protocol.compress import compress_if_smaller, decompress
from .arq import SendWindow, RecvWindow


class State(Enum):
    IDLE = auto()
    HANDSHAKE_SENT = auto()
    ESTABLISHED = auto()
    CLOSED = auto()


def _data_aad(stream_id: int, sequence: int, compressed: bool) -> bytes:
    """5-byte Associated Data binding stream_id, sequence, and compression flag."""
    return struct.pack(">BHH", 1 if compressed else 0, stream_id & 0xFFFF, sequence & 0xFFFF)


RECV_WINDOW_SPAN = 64


class Session:
    """
    One endpoint of a tunnel session.

    Owns the crypto state, sequence counters, fragment reassembly,
    ARQ windows, and the compress→encrypt→fragment pipeline.
    """

    def __init__(
        self,
        psk: bytes,
        is_client: bool,
        stream_id: int = 0,
        max_frag_payload: int = 120,
        cwnd: int = 10,
        rto: float = 0.5,
        in_order_delivery: bool = True,
        requested_down_mtu: Optional[int] = None,
    ):
        self.crypto = CryptoState(psk, is_client)
        self.is_client = is_client
        self.stream_id = stream_id
        self.max_frag_payload = max_frag_payload
        self.requested_down_mtu = requested_down_mtu
        self.in_order_delivery = in_order_delivery

        self.state = State.IDLE
        self._seq: int = 0
        self._poll_seq: int = 0
        self._reassembly = ReassemblyBuffer(max_pending=RECV_WINDOW_SPAN)
        self._pending_ready: List[bytes] = []
        self._synack: Optional[bytes] = None
        self._last_syn_payload: Optional[bytes] = None
        self._cached_synack: Optional[bytes] = None
        self.peer_has_more: bool = False
        self.peer_pending_frags: int = 0
        self.last_packet_authenticated: bool = False

        # ARQ
        self._send_window = SendWindow(cwnd=cwnd, rto=rto)
        self._recv_window = RecvWindow()

    def _next_seq(self) -> int:
        s = self._seq
        self._seq = (self._seq + 1) & 0xFFFF
        return s

    def _next_poll_seq(self) -> int:
        s = self._poll_seq
        self._poll_seq = (self._poll_seq + 1) & 0xFFFF
        return s

    # ── handshake ───────────────────────────────────────────────

    def initiate(self, requested_down_mtu: Optional[int] = None) -> List[bytes]:
        """Client: produce SYN packet(s), optionally negotiating downstream MTU."""
        if self.state != State.IDLE or not self.is_client:
            raise RuntimeError("initiate() requires client session in IDLE state")
        mtu = requested_down_mtu if requested_down_mtu is not None else self.requested_down_mtu
        rsv = 0
        if mtu is not None and mtu > 0:
            rsv = min(128, max(4, mtu // 8)) & 0xFF
        payload = self.crypto.client_hello()
        hdr = Header(Flags.SYN, self.stream_id, 0, 0, 1, rsv)
        self.state = State.HANDSHAKE_SENT
        return [hdr.pack() + payload]

    def handle_packet(self, raw: bytes) -> Optional[bytes]:
        """
        Process one incoming packet.

        Returns application data when a complete message is ready.
        Returns None for control packets, duplicates, or incomplete fragments.
        May raise on crypto/parse failure.
        """
        self.last_packet_authenticated = False
        if len(raw) < HEADER_SIZE:
            return None
        hdr = Header.unpack(raw)
        hdr_bytes = raw[:HEADER_SIZE]
        payload = raw[HEADER_SIZE:]

        # Defensive protocol checks: reject illegal flag combinations
        if (hdr.flags & Flags.SYN) and (hdr.flags & Flags.FIN):
            return None
        if (hdr.flags & (Flags.SYN | Flags.FIN)) and (hdr.flags & Flags.DATA):
            return None

        # ── SYN (server receives) ──────────────────────────────
        if hdr.flags & Flags.SYN and not (hdr.flags & Flags.ACK):
            if self.is_client:
                return None
            if hdr.frag_index != 0 or hdr.total_frags != 1 or (hdr.flags & Flags.FRAG):
                return None
            # Idempotent SYN retry: if initial SYN-ACK was lost in transit
            if (
                self.state == State.ESTABLISHED
                and self._recv_window.total_received == 0
                and self._last_syn_payload == payload
                and self._cached_synack is not None
            ):
                self._synack = self._cached_synack
                self.last_packet_authenticated = True
                return None
            if self.state != State.IDLE:
                return None
            synack_payload = self.crypto.server_hello(payload)
            if hdr.reserved > 0:
                self.max_frag_payload = min(1024, max(32, hdr.reserved * 8))
            self.state = State.ESTABLISHED
            synack_pkt = (
                Header(
                    Flags.SYN | Flags.ACK,
                    self.stream_id,
                    0,
                    0,
                    1,
                    min(128, max(4, self.max_frag_payload // 8)) & 0xFF,
                ).pack()
                + synack_payload
            )
            self._last_syn_payload = payload
            self._cached_synack = synack_pkt
            self._synack = synack_pkt
            self.last_packet_authenticated = True
            return None

        # ── SYN-ACK (client receives) ──────────────────────────
        if hdr.flags & Flags.SYN and hdr.flags & Flags.ACK:
            if self.state != State.HANDSHAKE_SENT or not self.is_client:
                return None
            if hdr.frag_index != 0 or hdr.total_frags != 1 or (hdr.flags & Flags.FRAG):
                return None
            self.crypto.client_finish(payload)
            self.state = State.ESTABLISHED
            self.last_packet_authenticated = True
            return None

        # ── DATA ────────────────────────────────────────────────
        if hdr.flags & Flags.DATA and self.state == State.ESTABLISHED:
            self.peer_has_more = bool(hdr.flags & Flags.MORE)
            # Drop duplicate or out-of-window sequence numbers before reassembly
            if self._recv_window.is_duplicate(hdr.sequence):
                return None
            if not self._recv_window.in_window(hdr.sequence, RECV_WINDOW_SPAN):
                return None
            encrypted = self._reassembly.add(hdr, payload)
            if encrypted is None:
                self.peer_pending_frags = max(0, hdr.total_frags - hdr.frag_index - 1)
                return None
            self.peer_pending_frags = 0
            is_comp = bool(hdr.flags & Flags.COMP)
            aad = _data_aad(hdr.stream_id, hdr.sequence, is_comp)
            decrypted = self.crypto.decrypt(encrypted, aad=aad)
            self.last_packet_authenticated = True
            # Process piggybacked ACK only AFTER AEAD decryption succeeds
            if hdr.flags & Flags.ACK:
                self._send_window.ack_low8(hdr.reserved)
            data = decompress(decrypted) if is_comp else decrypted
            # Record AFTER successful decrypt (don't ACK broken messages)
            if not self._recv_window.record(
                hdr.sequence, data if self.in_order_delivery else None
            ):
                return None
            if not self.in_order_delivery:
                return data
            ready = self._recv_window.pop_ready()
            if not ready:
                return None
            if len(ready) > 1:
                self._pending_ready.extend(ready[1:])
            return ready[0]

        # ── Control packets (ACK, FIN, POLL) require control MAC ──
        if self.state == State.ESTABLISHED and self.crypto.established:
            # Strip Flags.MORE when verifying if RelayHandler set it on a packet, or verify exact hdr_bytes
            if not self.crypto.verify_control(hdr_bytes, payload):
                alt_hdr = bytes([hdr_bytes[0] & ~Flags.MORE]) + hdr_bytes[1:]
                if not self.crypto.verify_control(alt_hdr, payload):
                    raise ValueError("Unauthenticated control packet")
            self.last_packet_authenticated = True
            self.peer_has_more = bool(hdr.flags & Flags.MORE)

            if hdr.flags & Flags.ACK:
                self._send_window.ack(hdr.sequence)
                self.peer_pending_frags = 0
                if not (hdr.flags & (Flags.FIN | Flags.POLL)):
                    return None

            if hdr.flags & Flags.FIN:
                self.state = State.CLOSED
                return None

        return None

    def drain_received(self) -> List[bytes]:
        """Drain any additional in-order messages unlocked when a sequence gap filled."""
        if not self._pending_ready:
            return []
        out = list(self._pending_ready)
        self._pending_ready.clear()
        return out

    def pop_synack(self) -> Optional[bytes]:
        """Server: retrieve pending SYN-ACK (call after handle_packet on SYN)."""
        pkt = self._synack
        self._synack = None
        return pkt

    # ── data path ───────────────────────────────────────────────

    def send(self, data: bytes, now: float | None = None) -> List[bytes]:
        """
        Full send pipeline:
            data → compress_if_smaller → encrypt(with AAD) → fragment → [packets]

        Tracks in send window for retransmission.
        Returns list of raw packets (header + payload) to transmit.
        """
        assert self.state == State.ESTABLISHED
        payload_to_encrypt, is_comp = compress_if_smaller(data)
        seq = self._next_seq()
        aad = _data_aad(self.stream_id, seq, is_comp)
        encrypted = self.crypto.encrypt(payload_to_encrypt, aad=aad)

        ack_num = self._recv_window.ack_number
        extra_flags = (Flags.COMP if is_comp else 0) | (
            Flags.ACK if ack_num is not None else 0
        )
        reserved = (ack_num & 0xFF) if ack_num is not None else 0

        pkts = fragment(
            encrypted,
            self.stream_id,
            seq,
            self.max_frag_payload,
            extra_flags=extra_flags,
            reserved=reserved,
        )
        self._send_window.track(seq, pkts, now)
        return pkts

    # ── ARQ ─────────────────────────────────────────────────────

    def make_ack(self) -> Optional[bytes]:
        """Generate authenticated ACK packet if we have something to acknowledge."""
        ack_num = self._recv_window.ack_number
        if ack_num is None:
            return None
        hdr_bytes = Header(Flags.ACK, self.stream_id, ack_num).pack()
        if self.crypto.established:
            return hdr_bytes + self.crypto.sign_control(hdr_bytes)
        return hdr_bytes

    @property
    def send_window_full(self) -> bool:
        return self._send_window.full

    def retransmit_due(self, now: float | None = None) -> List[List[bytes]]:
        """Return lists of packets needing retransmission."""
        return [entry.packets for entry in self._send_window.retransmit_due(now)]

    # ── control ─────────────────────────────────────────────────

    def make_poll(self) -> bytes:
        """Create an authenticated POLL packet for requesting downstream data."""
        poll_seq = self._next_poll_seq()
        ack_num = self._recv_window.ack_number
        if ack_num is not None:
            hdr_bytes = Header(
                Flags.POLL | Flags.ACK,
                self.stream_id,
                ack_num,
                frag_index=(poll_seq >> 8) & 0xFF,
                total_frags=1,
                reserved=poll_seq & 0xFF,
            ).pack()
        else:
            hdr_bytes = Header(Flags.POLL, self.stream_id, poll_seq).pack()
        if self.crypto.established:
            return hdr_bytes + self.crypto.sign_control(hdr_bytes)
        return hdr_bytes

    def make_fin(self) -> bytes:
        """Create an authenticated FIN packet."""
        poll_seq = self._next_poll_seq()
        self.state = State.CLOSED
        hdr_bytes = Header(Flags.FIN, self.stream_id, poll_seq).pack()
        if self.crypto.established:
            return hdr_bytes + self.crypto.sign_control(hdr_bytes)
        return hdr_bytes
