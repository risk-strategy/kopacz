import pytest
from hypothesis import given, strategies as st, settings

from kopacz.transport.encoding import Base32Encoder, Base64Encoder, Base36Encoder


@settings(max_examples=500)
@given(st.binary(min_size=0, max_size=500))
def test_prop_base32_roundtrip(data):
    enc = Base32Encoder()
    assert enc.decode(enc.encode(data)) == data


@settings(max_examples=500)
@given(st.binary(min_size=0, max_size=500))
def test_prop_base64_roundtrip(data):
    enc = Base64Encoder()
    assert enc.decode(enc.encode(data)) == data


@settings(max_examples=500)
@given(st.binary(min_size=1, max_size=500))
def test_prop_base36_roundtrip(data):
    enc = Base36Encoder()
    assert enc.decode(enc.encode(data)) == data


def test_base36_empty():
    enc = Base36Encoder()
    assert enc.encode(b"") == ""
    assert enc.decode("") == b""


def test_base32_empty():
    enc = Base32Encoder()
    assert enc.encode(b"") == ""
    assert enc.decode("") == b""


def test_base64_empty():
    enc = Base64Encoder()
    assert enc.encode(b"") == ""
    assert enc.decode("") == b""


def test_all_dns_safe():
    """Encoded output must contain only DNS-safe characters."""
    data = bytes(range(256))
    for EncClass in [Base32Encoder, Base64Encoder, Base36Encoder]:
        enc = EncClass()
        encoded = enc.encode(data)
        for c in encoded:
            assert c.isalnum() or c in "-_", (
                f"{EncClass.__name__} produced {c!r}"
            )


def test_label_limits():
    """bytes_per_label bytes must encode to ≤63 chars."""
    for EncClass in [Base32Encoder, Base64Encoder, Base36Encoder]:
        enc = EncClass()
        data = b"\xff" * enc.bytes_per_label()
        encoded = enc.encode(data)
        assert len(encoded) <= 63, (
            f"{EncClass.__name__}: {enc.bytes_per_label()} bytes → "
            f"{len(encoded)} chars (>63)"
        )
