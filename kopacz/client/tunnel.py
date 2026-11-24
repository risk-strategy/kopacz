"""
Tunnel client — drives the DNS query/response cycle.

TunnelClient: orchestrates Session + Carrier + Resolver.
Resolver:     protocol for DNS transport (UDP, DoH, DoT, mock).
UDPResolver:  raw UDP/53 queries to a recursive resolver.
"""

from __future__ import annotations

import os
import random
import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Protocol, Union, runtime_checkable

from ..protocol.header import Header, Flags, HEADER_SIZE
from ..session.state import Session, State
from ..transport.carrier import Carrier, Posture, POSTURES
from ..transport.encoding import Encoder

log = logging.getLogger(__name__)


@runtime_checkable
class Resolver(Protocol):
    def query(self, qname: str) -> Optional[str]:
        """Send DNS TXT query, return decoded TXT string or None on timeout."""
        ...


class TunnelClient:
    """
    Client endpoint of the DNS tunnel.

    Drives the query/response cycle:
      connect()  — 1-RTT handshake
      send()     — upstream data, returns any piggybacked downstream
      poll()     — request downstream data
      close()    — FIN

    Every method is synchronous and blocking. Async wrapper is
    someone else's problem.
    """

    def __init__(
        self,
        domain: str,
        psk: bytes,
        resolver: Resolver,
        tag: Optional[str] = None,
        encoder: Optional[Encoder] = None,
        max_frag_payload: Optional[int] = None,
        max_query_retries: int = 2,
        posture: Optional[Union[str, Posture]] = None,
        requested_down_mtu: Optional[int] = None,
        max_in_flight: Optional[int] = None,
        jitter: Optional[tuple[float, float]] = None,
    ):
        resolved_posture: Optional[Posture] = None
        if isinstance(posture, str):
            if posture not in POSTURES:
                raise ValueError(f"Unknown posture {posture!r} (choose from {list(POSTURES)})")
            resolved_posture = POSTURES[posture]
        elif isinstance(posture, Posture):
            resolved_posture = posture

        self.posture = resolved_posture
        max_label = resolved_posture.max_label_len if resolved_posture else 63
        self.carrier = Carrier(domain, encoder, max_label_len=max_label)
        self.tag = tag or _random_tag()

        up_cap = resolved_posture.up_mtu if resolved_posture else 120
        if max_frag_payload is None:
            auto_max = max(24, self.carrier.max_query_bytes(self.tag) - HEADER_SIZE)
            max_frag_payload = min(auto_max, up_cap)

        down_mtu = (
            requested_down_mtu
            if requested_down_mtu is not None
            else (resolved_posture.down_mtu if resolved_posture else None)
        )
        self.session = Session(
            psk,
            is_client=True,
            max_frag_payload=max_frag_payload,
            requested_down_mtu=down_mtu,
        )
        self.resolver = resolver
        if resolved_posture is not None and hasattr(self.resolver, "qtype"):
            self.resolver.qtype = resolved_posture.qtype
        self.max_query_retries = max_query_retries
        self.max_in_flight = (
            max_in_flight
            if max_in_flight is not None
            else (resolved_posture.max_in_flight if resolved_posture else 1)
        )
        if jitter is not None:
            self.jitter_min, self.jitter_max = jitter
        elif resolved_posture is not None:
            self.jitter_min, self.jitter_max = (
                resolved_posture.jitter_min,
                resolved_posture.jitter_max,
            )
        else:
            self.jitter_min, self.jitter_max = 0.0, 0.0
        self._lock = threading.RLock()

    @property
    def connected(self) -> bool:
        return self.session.state == State.ESTABLISHED

    def _apply_jitter(self) -> None:
        if self.jitter_max > 0:
            delay = random.uniform(self.jitter_min, self.jitter_max)
            if delay > 0:
                time.sleep(delay)

    def _ingest_raw(self, raw: bytes) -> List[bytes]:
        """Pass raw response packet to Session and collect all unlocked in-order messages."""
        out: List[bytes] = []
        r = self.session.handle_packet(raw)
        if r is not None:
            out.append(r)
        out.extend(self.session.drain_received())
        return out

    def connect(self) -> None:
        """Perform 1-RTT handshake (with retry if SYN or SYN-ACK is dropped). Raises on failure."""
        with self._lock:
            syn_pkts = self.session.initiate()
            qname = self.carrier.pack_query(syn_pkts[0], self.tag)
            txt = None
            for _ in range(max(1, self.max_query_retries)):
                self._apply_jitter()
                txt = self.resolver.query(qname)
                if txt:
                    break
            if not txt:
                raise ConnectionError("No response to SYN")
            raw = self.carrier.unpack_response(txt)
            self.session.handle_packet(raw)
            if self.session.state != State.ESTABLISHED:
                raise ConnectionError("Handshake failed")

    def _resend_due(self) -> List[bytes]:
        """Resend upstream DATA whose RTO expired (caller holds self._lock)."""
        downstream: List[bytes] = []
        for pkts in self.session.retransmit_due():
            for pkt in pkts:
                self._apply_jitter()
                qname = self.carrier.pack_query(pkt, self.tag)
                txt = self.resolver.query(qname)
                if txt:
                    downstream.extend(
                        self._ingest_raw(self.carrier.unpack_response(txt))
                    )
        return downstream

    def send(self, data: bytes) -> List[bytes]:
        """
        Send data upstream. Returns list of any downstream
        data received in the responses (may be empty).

        Each fragment becomes one DNS query. Each response
        is processed for downstream data. If the final fragment
        received no reply (empty TXT), retries the final fragment
        up to max_query_retries so multi-fragment messages are
        reliably reassembled on the relay over lossy UDP links.
        """
        with self._lock:
            downstream: List[bytes] = self._resend_due()
            pkts = self.session.send(data)
            last_txt: Optional[str] = None
            for pkt in pkts:
                self._apply_jitter()
                qname = self.carrier.pack_query(pkt, self.tag)
                last_txt = self.resolver.query(qname)
                if last_txt:
                    downstream.extend(
                        self._ingest_raw(self.carrier.unpack_response(last_txt))
                    )
            if pkts and not last_txt:
                last_qname = self.carrier.pack_query(pkts[-1], self.tag)
                for _ in range(self.max_query_retries):
                    self._apply_jitter()
                    last_txt = self.resolver.query(last_qname)
                    if last_txt:
                        downstream.extend(
                            self._ingest_raw(self.carrier.unpack_response(last_txt))
                        )
                        break
            return downstream

    def poll(self) -> Optional[bytes]:
        """Poll for downstream data. Returns data or None."""
        with self._lock:
            self._apply_jitter()
            qname = self.carrier.pack_query(self.session.make_poll(), self.tag)
            txt = self.resolver.query(qname)
            if not txt:
                return None
            msgs = self._ingest_raw(self.carrier.unpack_response(txt))
            return msgs[0] if msgs else None

    def poll_all(
        self,
        max_polls: int = 50,
        retry_delay: float = 0.0,
        max_empty: int = 0,
    ) -> List[bytes]:
        """Poll until server has nothing left. Returns all received messages.

        Self-clocking pipeline: when the relay reports remaining fragments
        (peer_pending_frags > 0 or peer_has_more) and max_in_flight > 1,
        dispatches up to max_in_flight concurrent POLL queries in a wave.
        """
        with self._lock:
            results: List[bytes] = self._resend_due()
            empty_count = 0
            polls_sent = 0
            while polls_sent < max_polls:
                results.extend(self._resend_due())
                self._apply_jitter()
                # Determine self-clocked batch size
                pending_hint = self.session.peer_pending_frags
                if self.session.peer_has_more and pending_hint < 2:
                    pending_hint = 2
                batch_size = 1
                if self.max_in_flight > 1 and pending_hint > 1:
                    batch_size = min(
                        self.max_in_flight,
                        pending_hint,
                        max_polls - polls_sent,
                    )

                qnames = [
                    self.carrier.pack_query(self.session.make_poll(), self.tag)
                    for _ in range(batch_size)
                ]
                polls_sent += batch_size

                if batch_size == 1:
                    txts = [self.resolver.query(qnames[0])]
                else:
                    with ThreadPoolExecutor(max_workers=batch_size) as pool:
                        txts = list(pool.map(self.resolver.query, qnames))

                got_any_data = False
                should_stop = False
                for txt in txts:
                    if txt is None:
                        should_stop = True
                        break
                    if txt == "":
                        continue
                    raw = self.carrier.unpack_response(txt)
                    if len(raw) >= HEADER_SIZE:
                        hdr = Header.unpack(raw)
                        if (hdr.flags & Flags.ACK) and not (hdr.flags & Flags.DATA):
                            self.session.handle_packet(raw)
                            continue
                    got_any_data = True
                    results.extend(self._ingest_raw(raw))

                if should_stop:
                    break
                if not got_any_data:
                    if retry_delay > 0 and empty_count < max_empty:
                        empty_count += 1
                        time.sleep(retry_delay)
                        continue
                    break
                empty_count = 0
            return results

    def close(self) -> None:
        """Send FIN. Session is dead after this."""
        with self._lock:
            if self.session.state != State.ESTABLISHED:
                return
            fin = self.session.make_fin()
            qname = self.carrier.pack_query(fin, self.tag)
            self.resolver.query(qname)


class UDPResolver:
    """Raw UDP/53 queries to a recursive resolver (supports TXT and AAAA carriers)."""

    def __init__(
        self,
        nameserver: str = "8.8.8.8",
        port: int = 53,
        timeout: float = 5.0,
        qtype: str = "TXT",
        encoder: Optional[Encoder] = None,
    ):
        self.nameserver = nameserver
        self.port = port
        self.timeout = timeout
        self.qtype = qtype.upper()
        from ..transport.encoding import Base32Encoder
        self._encoder = encoder or Base32Encoder()

    def query(self, qname: str) -> Optional[str]:
        import socket

        try:
            from dnslib import DNSRecord, QTYPE
        except ImportError:
            raise RuntimeError("dnslib required: pip install 'kopacz[server]'")

        q = DNSRecord.question(qname, self.qtype)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(q.pack(), (self.nameserver, self.port))
            data, _ = sock.recvfrom(4096)
            response = DNSRecord.parse(data)
            if self.qtype == "AAAA":
                addrs = [
                    str(rr.rdata)
                    for rr in response.rr
                    if rr.rtype == QTYPE.AAAA
                ]
                if not addrs:
                    return ""
                raw = Carrier.unpack_aaaa_response(addrs)
                return self._encoder.encode(raw)

            for rr in response.rr:
                if rr.rtype == QTYPE.TXT:
                    parts = []
                    for seg in rr.rdata.data:
                        parts.append(
                            seg.decode("ascii") if isinstance(seg, bytes) else str(seg)
                        )
                    return "".join(parts)
            return None
        except socket.timeout:
            log.debug("DNS query timeout for %s", qname)
            return None
        finally:
            sock.close()


def _random_tag(length: int = 8) -> str:
    """Generate a random session tag that looks like a CDN token."""
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    raw = os.urandom(length)
    return "".join(alphabet[b % 36] for b in raw)
