"""
ARQ primitive tests.

Covers: seq_le wrapping, SendWindow tracking/ack/retransmit,
RecvWindow cumulative ACK/duplicates/out-of-order, property tests.
"""

import pytest
from hypothesis import given, strategies as st, settings

from kopacz.session.arq import seq_le, SendWindow, RecvWindow


# ── seq_le ───────────────────────────────────────────────────

class TestSeqLE:
    def test_equal(self):
        assert seq_le(0, 0)
        assert seq_le(1000, 1000)
        assert seq_le(65535, 65535)

    def test_simple_order(self):
        assert seq_le(0, 1)
        assert seq_le(5, 10)
        assert seq_le(0, 32767)

    def test_not_greater(self):
        assert not seq_le(10, 5)
        assert not seq_le(100, 0)

    def test_wrapping(self):
        # 65535 is "just before" 0 in circular space
        assert seq_le(65535, 0)
        assert seq_le(65530, 5)
        assert seq_le(65000, 200)

    def test_half_range_boundary(self):
        # Exactly half the space apart: ambiguous, but convention says NOT less
        assert not seq_le(0, 32768)
        assert not seq_le(32768, 0)

    @settings(max_examples=500)
    @given(st.integers(0, 0xFFFF))
    def test_prop_reflexive(self, x):
        assert seq_le(x, x)

    @settings(max_examples=500)
    @given(
        a=st.integers(0, 0xFFFF),
        delta=st.integers(1, 0x7FFF),
    )
    def test_prop_small_delta_is_le(self, a, delta):
        b = (a + delta) & 0xFFFF
        assert seq_le(a, b)
        assert not seq_le(b, a)


# ── SendWindow ───────────────────────────────────────────────

class TestSendWindow:
    def test_empty(self):
        sw = SendWindow()
        assert len(sw) == 0
        assert not sw.full
        assert sw.pending == []

    def test_track_and_full(self):
        sw = SendWindow(cwnd=3)
        sw.track(0, [b"a"], now=0.0)
        sw.track(1, [b"b"], now=0.0)
        assert not sw.full
        sw.track(2, [b"c"], now=0.0)
        assert sw.full

    def test_ack_removes(self):
        sw = SendWindow(cwnd=5)
        for i in range(5):
            sw.track(i, [bytes([i])], now=0.0)
        removed = sw.ack(2)
        assert removed == 3  # seqs 0, 1, 2
        assert len(sw) == 2
        assert sw.pending == [3, 4]

    def test_ack_idempotent(self):
        sw = SendWindow()
        sw.track(0, [b"x"], now=0.0)
        sw.ack(0)
        assert sw.ack(0) == 0  # already removed

    def test_retransmit_before_rto(self):
        sw = SendWindow(rto=1.0)
        sw.track(0, [b"x"], now=0.0)
        assert sw.retransmit_due(now=0.5) == []

    def test_retransmit_after_rto(self):
        sw = SendWindow(rto=1.0)
        sw.track(0, [b"x"], now=0.0)
        due = sw.retransmit_due(now=1.5)
        assert len(due) == 1
        assert due[0].seq == 0
        assert due[0].retries == 1

    def test_retransmit_updates_sent_at(self):
        sw = SendWindow(rto=1.0)
        sw.track(0, [b"x"], now=0.0)
        sw.retransmit_due(now=1.5)
        # Now RTO resets — shouldn't be due again at 2.0
        assert sw.retransmit_due(now=2.0) == []
        # But should be due at 2.5+
        due = sw.retransmit_due(now=2.6)
        assert len(due) == 1
        assert due[0].retries == 2

    def test_ack_with_wrapping(self):
        sw = SendWindow()
        sw.track(65534, [b"a"], now=0.0)
        sw.track(65535, [b"b"], now=0.0)
        sw.track(0, [b"c"], now=0.0)
        # ACK 0 should remove 65534, 65535, and 0
        removed = sw.ack(0)
        assert removed == 3


# ── RecvWindow ───────────────────────────────────────────────

class TestRecvWindow:
    def test_empty(self):
        rw = RecvWindow()
        assert rw.ack_number is None
        assert rw.total_received == 0

    def test_sequential(self):
        rw = RecvWindow()
        assert rw.record(0)
        assert rw.ack_number == 0
        assert rw.record(1)
        assert rw.ack_number == 1
        assert rw.record(2)
        assert rw.ack_number == 2

    def test_duplicate_rejected(self):
        rw = RecvWindow()
        assert rw.record(0)
        assert not rw.record(0)
        assert rw.total_received == 1

    def test_out_of_order_no_contiguous(self):
        rw = RecvWindow()
        assert rw.record(2)
        # Received seq 2 but not 0 or 1 — no contiguous ack
        assert rw.ack_number is None
        assert rw.total_received == 1

    def test_out_of_order_fills_gap(self):
        rw = RecvWindow()
        rw.record(2)
        rw.record(0)
        assert rw.ack_number == 0  # contiguous: only 0
        rw.record(1)
        assert rw.ack_number == 2  # contiguous: 0, 1, 2

    def test_reverse_order(self):
        rw = RecvWindow()
        for i in reversed(range(5)):
            rw.record(i)
        assert rw.ack_number == 4

    def test_already_processed_is_duplicate(self):
        rw = RecvWindow()
        rw.record(0)
        rw.record(1)
        rw.record(2)
        # Seq 0 was processed contiguously — should be duplicate
        assert not rw.record(0)
        assert not rw.record(1)

    @settings(max_examples=200)
    @given(st.permutations(list(range(20))))
    def test_prop_any_permutation_yields_correct_ack(self, perm):
        """Any permutation of 0..19 results in ack_number == 19."""
        rw = RecvWindow()
        for seq in perm:
            rw.record(seq)
        assert rw.ack_number == 19
        assert rw.total_received == 20

    @settings(max_examples=200)
    @given(st.permutations(list(range(10))))
    def test_prop_all_new(self, perm):
        """Every element in a unique permutation is recorded as new."""
        rw = RecvWindow()
        results = [rw.record(seq) for seq in perm]
        assert all(results)
        assert rw.total_received == 10

    @settings(max_examples=200)
    @given(st.permutations(list(range(10))))
    def test_prop_second_pass_all_duplicate(self, perm):
        """Recording the same permutation twice: second pass all duplicates."""
        rw = RecvWindow()
        for seq in perm:
            rw.record(seq)
        for seq in perm:
            assert not rw.record(seq)
