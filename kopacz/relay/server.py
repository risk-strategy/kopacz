"""
Relay DNS server.

RelayHandler: pure protocol logic, no I/O. Testable.
RelayServer:  UDP/53 socket wrapper using dnslib.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from typing import Callable, List, Optional

from ..protocol.header import Header, Flags, HEADER_SIZE
from ..protocol.crypto import NONCE_SIZE
from ..session.state import Session, State
from ..transport.carrier import Carrier
from ..transport.encoding import Encoder
from .switch import Switch

log = logging.getLogger(__name__)

MAX_SYN_NONCE_CACHE = 4096


class RelayHandler:
    """
    Processes DNS tunnel queries. Pure logic, no I/O.

    For each query QNAME:
      1. Carrier.unpack_query → (session_tag, packet_bytes)
      2. Route through Session (handshake / data / control)
      3. Return response bytes for TXT RDATA

    Application callback: on_data(tag, data) → Optional[bytes]
      Called when a complete message is received. Return value
      (if any) is queued for downstream delivery.
    """

    def __init__(
        self,
        domain: str,
        psk: bytes,
        encoder: Encoder | None = None,
        on_data: Callable[[str, bytes], Optional[bytes]] | None = None,
        max_frag_payload: int = 120,
        session_ttl: float = 600.0,
        max_sessions: int = 4096,
    ):
        self.carrier = Carrier(domain, encoder)
        self.switch = Switch()
        self.psk = psk
        self.max_frag = max_frag_payload
        self.session_ttl = session_ttl
        self.max_sessions = max_sessions
        self._sessions: dict[str, Session] = {}
        self._last_seen: dict[str, float] = {}
        self._seen_syn_nonces: OrderedDict[bytes, str] = OrderedDict()
        self._last_cleanup: float = time.monotonic()
        self._on_data = on_data
        # Protocol-level outbox: tag → queued response packets
        self._outbox: dict[str, list[bytes]] = {}

    def _authenticate_new_session(self, tag: str, packet: bytes) -> Optional[Session]:
        """
        Validate an incoming SYN packet before allocating session state.
        Rejects non-SYN packets, any replayed SYN nonce, and invalid PSKs.
        """
        if len(packet) < HEADER_SIZE + NONCE_SIZE:
            return None
        hdr = Header.unpack(packet)
        if not (hdr.flags & Flags.SYN) or (hdr.flags & Flags.ACK):
            return None

        syn_nonce = packet[HEADER_SIZE : HEADER_SIZE + NONCE_SIZE]
        if syn_nonce in self._seen_syn_nonces:
            log.warning("[%s] Rejected replayed SYN nonce", tag)
            return None

        candidate = Session(
            self.psk,
            is_client=False,
            max_frag_payload=self.max_frag,
        )
        try:
            candidate.handle_packet(packet)
        except Exception as e:
            log.debug("[%s] SYN authentication failed: %s", tag, e)
            return None

        if candidate.state != State.ESTABLISHED:
            return None

        # Evict oldest session if at capacity
        if len(self._sessions) >= self.max_sessions:
            self.cleanup_sessions()
            if len(self._sessions) >= self.max_sessions:
                oldest_tag = min(self._last_seen, key=self._last_seen.get)  # type: ignore[arg-type]
                self._remove_session(oldest_tag)

        self._seen_syn_nonces[syn_nonce] = tag
        if len(self._seen_syn_nonces) > MAX_SYN_NONCE_CACHE:
            self._seen_syn_nonces.popitem(last=False)

        self._sessions[tag] = candidate
        self._last_seen[tag] = time.monotonic()
        self.switch.register(tag)
        return candidate

    def _remove_session(self, tag: str) -> None:
        self._sessions.pop(tag, None)
        self._last_seen.pop(tag, None)
        self._outbox.pop(tag, None)
        self.switch.unregister(tag)

    def cleanup_sessions(self, now: float | None = None) -> int:
        """Evict closed or expired sessions. Returns number of sessions removed."""
        if now is None:
            now = time.monotonic()
        expired = [
            tag
            for tag, ts in self._last_seen.items()
            if (now - ts >= self.session_ttl)
            or (tag in self._sessions and self._sessions[tag].state == State.CLOSED)
        ]
        for tag in expired:
            self._remove_session(tag)
        return len(expired)

    def handle_query(self, qname: str) -> bytes:
        """
        Process one DNS query QNAME. Returns raw bytes for TXT response.

        Empty bytes means "nothing to say" — caller should return
        a dummy A record (1.2.3.4) or empty TXT to avoid NXDOMAIN caching.
        """
        try:
            tag, packet = self.carrier.unpack_query(qname)
        except Exception as e:
            log.debug("unpack_query failed: %s (qname=%s)", e, qname[:60])
            return b""

        if len(packet) < HEADER_SIZE:
            return b""

        hdr = Header.unpack(packet)
        is_poll = bool(hdr.flags & Flags.POLL)
        now = time.monotonic()

        # Periodic session cleanup (every 30s)
        if now - self._last_cleanup >= 30.0:
            self._last_cleanup = now
            self.cleanup_sessions(now=now)

        # Allow a fresh SYN to re-establish a tag whose previous session is CLOSED or expired
        if tag in self._sessions:
            existing = self._sessions[tag]
            last_ts = self._last_seen.get(tag, now)
            if existing.state == State.CLOSED or (now - last_ts >= self.session_ttl):
                self._remove_session(tag)

        if tag not in self._sessions:
            session = self._authenticate_new_session(tag, packet)
            if session is None:
                return b""
            synack = session.pop_synack()
            return synack if synack is not None else b""

        session = self._sessions[tag]

        if hdr.flags & Flags.SYN and not (hdr.flags & Flags.ACK):
            pkt_type = "SYN"
        elif hdr.flags & Flags.DATA:
            pkt_type = "DATA"
        elif is_poll:
            pkt_type = "POLL"
        elif hdr.flags & Flags.FIN:
            pkt_type = "FIN"
        else:
            pkt_type = f"flags={hdr.flags:#x}"

        log.info("[%s] %s pkt=%d bytes state=%s", tag, pkt_type, len(packet), session.state.name)

        # Process packet through session (including POLL|ACK to advance SendWindow)
        delivered_messages: List[bytes] = []
        try:
            first_msg = session.handle_packet(packet)
            if first_msg is not None:
                delivered_messages.append(first_msg)
            delivered_messages.extend(session.drain_received())
        except Exception as e:
            log.warning("[%s] handle_packet failed: %s", tag, e)
            return b""

        if session.last_packet_authenticated:
            self._last_seen[tag] = now

        # SYN-ACK takes priority (e.g. idempotent SYN retry)
        synack = session.pop_synack()
        if synack is not None:
            return synack

        if session.state == State.CLOSED:
            self._remove_session(tag)
            return b""

        # Do not release downstream data or ACKs to unauthenticated packets or partial fragments
        if not session.last_packet_authenticated:
            return b""

        # Application data received — route all in-order messages to callback
        if delivered_messages and self._on_data:
            for msg in delivered_messages:
                response = self._on_data(tag, msg)
                if response is not None:
                    self.switch.enqueue_downstream(tag, response)

        # Check outbox for pending protocol packets (previous fragments)
        if tag in self._outbox and self._outbox[tag]:
            pkt = self._outbox[tag].pop(0)
            if self._outbox.get(tag) or self.switch.has_pending(tag):
                pkt = bytes([pkt[0] | Flags.MORE]) + pkt[1:]
            return pkt

        # Check for timed-out downstream messages needing retransmission
        if session.state == State.ESTABLISHED:
            retransmits = session.retransmit_due()
            if retransmits:
                for retry_pkts in retransmits:
                    self._outbox.setdefault(tag, []).extend(retry_pkts)
                if self._outbox.get(tag):
                    pkt = self._outbox[tag].pop(0)
                    if self._outbox.get(tag) or self.switch.has_pending(tag):
                        pkt = bytes([pkt[0] | Flags.MORE]) + pkt[1:]
                    return pkt

        # Check switch for downstream app data → encrypt → fragment
        downstream = self.switch.poll_downstream(tag)
        if downstream is not None and session.state == State.ESTABLISHED:
            pkts = session.send(downstream)
            if len(pkts) > 1:
                self._outbox.setdefault(tag, []).extend(pkts[1:])
            if pkts:
                pkt = pkts[0]
                if self._outbox.get(tag) or self.switch.has_pending(tag):
                    pkt = bytes([pkt[0] | Flags.MORE]) + pkt[1:]
                return pkt

        # Nothing downstream — send standalone ACK only when needed (not on empty POLL)
        if session.state == State.ESTABLISHED and not is_poll:
            ack = session.make_ack()
            if ack is not None:
                return ack

        return b""

    def build_response(self, qname: str) -> str:
        """Process query and return encoded TXT response string."""
        raw = self.handle_query(qname)
        if not raw:
            return ""
        return self.carrier.pack_response(raw)

    def build_aaaa_response(self, qname: str) -> List[str]:
        """Process query and return list of IPv6 address strings for QTYPE=AAAA."""
        raw = self.handle_query(qname)
        if not raw:
            return []
        return self.carrier.pack_aaaa_response(raw)

    @property
    def session_count(self) -> int:
        return len(self._sessions)


class RelayServer:
    """UDP/53 DNS server wrapping RelayHandler."""

    def __init__(
        self,
        handler: RelayHandler,
        bind: str = "0.0.0.0",
        port: int = 53,
    ):
        self.handler = handler
        self.bind = bind
        self.port = port

    def run(self) -> None:
        """Blocking event loop. Ctrl-C to stop."""
        import socket

        try:
            from dnslib import DNSRecord, RR, QTYPE, TXT, A, AAAA
        except ImportError:
            raise RuntimeError("dnslib required: pip install 'kopacz[server]'")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.bind, self.port))
        log.info("Relay listening on %s:%d", self.bind, self.port)

        try:
            while True:
                data, addr = sock.recvfrom(4096)
                try:
                    request = DNSRecord.parse(data)
                    qname = str(request.q.qname).rstrip(".")
                    reply = request.reply()

                    if request.q.qtype == QTYPE.AAAA:
                        addrs = self.handler.build_aaaa_response(qname)
                        for ipv6 in addrs:
                            reply.add_answer(RR(
                                request.q.qname, QTYPE.AAAA,
                                rdata=AAAA(ipv6), ttl=0,
                            ))
                    elif request.q.qtype == QTYPE.TXT:
                        txt = self.handler.build_response(qname)
                        if txt:
                            chunks = [
                                txt[i : i + 255].encode("ascii")
                                for i in range(0, len(txt), 255)
                            ]
                            reply.add_answer(RR(
                                request.q.qname, QTYPE.TXT,
                                rdata=TXT(chunks), ttl=0,
                            ))
                        else:
                            reply.add_answer(RR(
                                request.q.qname, QTYPE.TXT,
                                rdata=TXT(""), ttl=0,
                            ))
                    else:
                        # Non-carrier QTYPE (e.g. RFC 9156 QNAME-minimisation A/NS probe):
                        # return stateless NOERROR answer without mutating tunnel session state.
                        reply.add_answer(RR(
                            request.q.qname, QTYPE.A,
                            rdata=A("1.2.3.4"), ttl=0,
                        ))

                    sock.sendto(reply.pack(), addr)
                except Exception as e:
                    log.debug("Error processing %s: %s", addr, e)
        finally:
            sock.close()
