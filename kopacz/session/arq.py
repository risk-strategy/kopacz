"""
Automatic Repeat reQuest — Selective Repeat over DNS.

SendWindow: tracks outbound unacked messages, retransmission timing.
RecvWindow: tracks inbound sequences, buffers out-of-order messages,
            and generates cumulative ACK.

Message-level, not fragment-level. Sequence numbers are 16-bit with wrapping.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List, Optional


def seq_le(a: int, b: int) -> bool:
    """a <= b with 16-bit unsigned wrapping.

    Half the sequence space (32768) is 'ahead', half is 'behind'.
    """
    return a == b or ((b - a) & 0xFFFF) < 0x8000


@dataclass(slots=True)
class TxEntry:
    """One outbound unacked message."""

    seq: int
    packets: List[bytes]
    sent_at: float
    retries: int = 0


class SendWindow:
    """
    Sliding window of unacknowledged outbound messages.

    cwnd limits outstanding messages. Cumulative ACK advances
    the window. RTO triggers retransmission.

    Invariant: len(self) <= cwnd at all times.
    """

    def __init__(self, cwnd: int = 10, rto: float = 0.5):
        self.cwnd = cwnd
        self.rto = rto
        self._entries: dict[int, TxEntry] = {}

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def full(self) -> bool:
        return len(self._entries) >= self.cwnd

    def track(self, seq: int, packets: List[bytes], now: float | None = None) -> None:
        """Register outbound message for retransmission tracking."""
        self._entries[seq] = TxEntry(seq, packets, now if now is not None else time.monotonic())

    def ack(self, ack_seq: int) -> int:
        """Cumulative ACK: remove entries with seq <= ack_seq. Returns count removed."""
        to_remove = [s for s in self._entries if seq_le(s, ack_seq)]
        for s in to_remove:
            del self._entries[s]
        return len(to_remove)

    def ack_low8(self, low8: int) -> int:
        """Acknowledge using the low 8 bits of ack_seq (piggybacked on DATA|ACK)."""
        matches = [s for s in self._entries if (s & 0xFF) == (low8 & 0xFF)]
        if not matches:
            return 0
        # Pick the highest matching sequence in the window
        target = matches[0]
        for s in matches[1:]:
            if seq_le(target, s):
                target = s
        return self.ack(target)

    def retransmit_due(self, now: float | None = None) -> List[TxEntry]:
        """Return entries past RTO, sorted by seq. Updates their sent_at and retries."""
        if now is None:
            now = time.monotonic()
        due = []
        for entry in self._entries.values():
            if now - entry.sent_at >= self.rto:
                entry.sent_at = now
                entry.retries += 1
                due.append(entry)
        return sorted(due, key=lambda e: e.seq)

    @property
    def pending(self) -> List[int]:
        """Sequence numbers of all pending (unacked) messages."""
        return sorted(self._entries.keys())


class RecvWindow:
    """
    Tracks received sequence numbers, buffers out-of-order payloads,
    and generates cumulative ACK.

    Out-of-order packets are buffered. The ACK number and ready payloads
    advance only when contiguous sequences (starting from 0) are received.

    Property: ack_number == N iff seqs {0, 1, ..., N} all received.
    """

    def __init__(self, max_ooo: int = 128):
        self._ooo: set[int] = set()
        self._ooo_data: Dict[int, bytes] = {}
        self._ready_data: List[bytes] = []
        self._next_expected: int = 0
        self._count: int = 0
        self._has_contiguous: bool = False
        self._max_ooo: int = max_ooo

    def is_duplicate(self, seq: int) -> bool:
        """Return True if seq has already been received."""
        if self._has_contiguous and seq_le(seq, (self._next_expected - 1) & 0xFFFF):
            return True
        return seq in self._ooo

    def in_window(self, seq: int, span: int = 64) -> bool:
        """Return True if seq lies in [next_expected, next_expected + span)."""
        return ((seq - self._next_expected) & 0xFFFF) < span

    def record(self, seq: int, data: Optional[bytes] = None) -> bool:
        """Record receipt of seq (and optional payload). Returns True if new, False if duplicate or out-of-window."""
        if self.is_duplicate(seq):
            return False

        # Bound out-of-order distance and buffer size to prevent memory exhaustion
        if seq != self._next_expected:
            distance = (seq - self._next_expected) & 0xFFFF
            if distance >= self._max_ooo or len(self._ooo) >= self._max_ooo:
                return False

        self._ooo.add(seq)
        if data is not None:
            self._ooo_data[seq] = data
        self._count += 1

        # Advance contiguous frontier
        while self._next_expected in self._ooo:
            self._ooo.discard(self._next_expected)
            if self._next_expected in self._ooo_data:
                self._ready_data.append(self._ooo_data.pop(self._next_expected))
            self._next_expected = (self._next_expected + 1) & 0xFFFF
            self._has_contiguous = True

        return True

    def pop_ready(self) -> List[bytes]:
        """Pop all newly contiguous payloads in strict sequence order."""
        if not self._ready_data:
            return []
        out = list(self._ready_data)
        self._ready_data.clear()
        return out

    @property
    def ack_number(self) -> Optional[int]:
        """Highest contiguous seq received. None if no contiguous data yet."""
        if not self._has_contiguous:
            return None
        return (self._next_expected - 1) & 0xFFFF

    @property
    def next_expected(self) -> int:
        return self._next_expected

    @property
    def total_received(self) -> int:
        return self._count
