import random
import pytest
from hypothesis import given, strategies as st, settings

from kopacz.protocol.header import Header, Flags, HEADER_SIZE
from kopacz.protocol.fragment import fragment, ReassemblyBuffer


@settings(max_examples=500)
@given(
    data=st.binary(min_size=1, max_size=5000),
    max_payload=st.integers(min_value=1, max_value=500),
)
def test_prop_fragment_reassemble(data, max_payload):
    """reassemble(fragment(D)) == D for all D."""
    pkts = fragment(data, stream_id=1, sequence=42, max_payload=max_payload)
    buf = ReassemblyBuffer()
    result = None
    for pkt in pkts:
        hdr = Header.unpack(pkt)
        result = buf.add(hdr, pkt[HEADER_SIZE:])
    assert result == data


@settings(max_examples=500)
@given(
    data=st.binary(min_size=1, max_size=5000),
    max_payload=st.integers(min_value=1, max_value=500),
    seed=st.integers(min_value=0, max_value=2**32),
)
def test_prop_order_independent(data, max_payload, seed):
    """reassemble(shuffle(fragment(D))) == D."""
    pkts = fragment(data, stream_id=1, sequence=42, max_payload=max_payload)
    rng = random.Random(seed)
    shuffled = list(pkts)
    rng.shuffle(shuffled)

    buf = ReassemblyBuffer()
    result = None
    for pkt in shuffled:
        hdr = Header.unpack(pkt)
        r = buf.add(hdr, pkt[HEADER_SIZE:])
        if r is not None:
            result = r
    assert result == data


def test_single_fragment():
    pkts = fragment(b"hello", 0, 0, max_payload=100)
    assert len(pkts) == 1
    hdr = Header.unpack(pkts[0])
    assert hdr.total_frags == 1
    assert hdr.frag_index == 0
    assert hdr.flags & Flags.DATA
    assert not (hdr.flags & Flags.FRAG)


def test_multi_fragment_flag():
    pkts = fragment(b"x" * 100, 0, 0, max_payload=30)
    assert len(pkts) == 4
    for pkt in pkts:
        hdr = Header.unpack(pkt)
        assert hdr.flags & Flags.FRAG
        assert hdr.total_frags == 4


def test_max_255_fragments():
    with pytest.raises(ValueError, match="255"):
        fragment(b"x" * 256, 0, 0, max_payload=1)


def test_empty_data():
    pkts = fragment(b"", 0, 0, max_payload=100)
    assert len(pkts) == 1
    assert len(pkts[0]) == HEADER_SIZE


def test_reassembly_pending_count():
    pkts = fragment(b"x" * 100, 0, 0, max_payload=30)
    buf = ReassemblyBuffer()
    # Feed all but last
    for pkt in pkts[:-1]:
        hdr = Header.unpack(pkt)
        assert buf.add(hdr, pkt[HEADER_SIZE:]) is None
    assert buf.pending == 1
    # Feed last
    hdr = Header.unpack(pkts[-1])
    assert buf.add(hdr, pkts[-1][HEADER_SIZE:]) == b"x" * 100
    assert buf.pending == 0


def test_reassembly_rejects_zero_total_frags():
    buf = ReassemblyBuffer()
    hdr = Header(Flags.DATA, stream_id=1, sequence=0, frag_index=0, total_frags=0)
    with pytest.raises(ValueError, match="Invalid total_frags"):
        buf.add(hdr, b"abc")
    assert buf.pending == 0


def test_reassembly_rejects_frag_index_out_of_bounds():
    buf = ReassemblyBuffer()
    hdr = Header(Flags.DATA | Flags.FRAG, stream_id=1, sequence=0, frag_index=2, total_frags=2)
    with pytest.raises(ValueError, match="frag_index"):
        buf.add(hdr, b"abc")
    assert buf.pending == 0


def test_reassembly_restarts_on_inconsistent_total_frags():
    """Forged fragment with conflicting total_frags is discarded so genuine message completes."""
    buf = ReassemblyBuffer()
    forged = Header(Flags.DATA | Flags.FRAG, stream_id=1, sequence=5, frag_index=1, total_frags=2)
    assert buf.add(forged, b"forged") is None
    assert buf.pending == 1

    genuine = Header(Flags.DATA, stream_id=1, sequence=5, frag_index=0, total_frags=1)
    assert buf.add(genuine, b"genuine") == b"genuine"
    assert buf.pending == 0

