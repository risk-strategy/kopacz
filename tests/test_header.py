import pytest
from hypothesis import given, strategies as st, settings

from kopacz.protocol.header import Header, Flags, HEADER_SIZE


def test_size_is_8():
    assert HEADER_SIZE == 8


def test_flag_values():
    assert Flags.SYN  == 0x80
    assert Flags.FIN  == 0x40
    assert Flags.ACK  == 0x20
    assert Flags.DATA == 0x10
    assert Flags.POLL == 0x08
    assert Flags.FRAG == 0x04
    assert Flags.CFG  == 0x02


@settings(max_examples=1000)
@given(
    flags=st.integers(0, 0xFF),
    stream_id=st.integers(0, 0xFFFF),
    seq=st.integers(0, 0xFFFF),
    fidx=st.integers(0, 0xFF),
    ftot=st.integers(0, 0xFF),
)
def test_prop_roundtrip(flags, stream_id, seq, fidx, ftot):
    """pack(unpack(pack(h))) == pack(h) for all valid headers."""
    h = Header(flags, stream_id, seq, fidx, ftot)
    raw = h.pack()
    assert len(raw) == HEADER_SIZE
    h2 = Header.unpack(raw)
    assert h2 == h
    assert h2.pack() == raw


def test_unpack_rejects_short():
    with pytest.raises(ValueError):
        Header.unpack(b"\x00" * 7)


def test_unpack_ignores_trailing():
    h = Header(Flags.DATA, 1, 42, 0, 1)
    h2 = Header.unpack(h.pack() + b"\xff" * 10)
    assert h2 == h


def test_repr():
    h = Header(Flags.SYN | Flags.ACK, 5, 100, 2, 3)
    r = repr(h)
    assert "SYN" in r
    assert "ACK" in r
