import pytest
from hypothesis import given, strategies as st, settings
from kopacz.protocol.compress import compress, decompress, compress_if_smaller


@settings(max_examples=500)
@given(st.binary(min_size=0, max_size=10000))
def test_prop_roundtrip(data):
    assert decompress(compress(data)) == data


def test_compressible_data_shrinks():
    data = b"AAAA" * 1000
    assert len(compress(data)) < len(data) // 2


def test_empty():
    assert compress(b"") == b""
    assert decompress(b"") == b""


def test_compress_if_smaller_skips_incompressible():
    raw = b"short msg"
    payload, is_comp = compress_if_smaller(raw)
    assert is_comp is False
    assert payload == raw


def test_compress_if_smaller_compresses_repetitive():
    raw = b"ABCD" * 500
    payload, is_comp = compress_if_smaller(raw)
    assert is_comp is True
    assert len(payload) < len(raw)
    assert decompress(payload) == raw


def test_decompression_bomb_rejected():
    bomb = compress(b"\x00" * 100_000)
    with pytest.raises(ValueError, match="Decompressed size exceeds limit"):
        decompress(bomb, max_size=4096)

