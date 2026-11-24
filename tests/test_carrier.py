import pytest
from hypothesis import given, strategies as st, settings, assume

from kopacz.transport.carrier import Carrier
from kopacz.transport.encoding import Base32Encoder, Base36Encoder

DNS_TAG = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789"),
    min_size=4,
    max_size=12,
)


@settings(max_examples=300)
@given(data=st.binary(min_size=1, max_size=80), tag=DNS_TAG)
def test_prop_query_roundtrip(data, tag):
    """unpack(pack(data, tag)) == (tag, data)."""
    carrier = Carrier("example.com")
    try:
        qname = carrier.pack_query(data, tag)
    except ValueError:
        return  # too long for FQDN — skip
    got_tag, got_data = carrier.unpack_query(qname)
    assert got_tag == tag
    assert got_data == data


@settings(max_examples=300)
@given(data=st.binary(min_size=1, max_size=200))
def test_prop_response_roundtrip(data):
    carrier = Carrier("example.com")
    assert carrier.unpack_response(carrier.pack_response(data)) == data


def test_fqdn_within_limit():
    carrier = Carrier("example.com")
    data = b"x" * 80
    qname = carrier.pack_query(data, "sess1")
    assert len(qname) <= 253


def test_multi_part_domain():
    carrier = Carrier("corp.sig.it.com")
    data = b"test"
    qname = carrier.pack_query(data, "mysess")
    tag, decoded = carrier.unpack_query(qname)
    assert tag == "mysess"
    assert decoded == data


def test_max_query_bytes_positive():
    carrier = Carrier("corporate.sig.it.com")
    assert carrier.max_query_bytes("session1") > 0


def test_rejects_oversized():
    carrier = Carrier("example.com")
    with pytest.raises(ValueError, match="253"):
        carrier.pack_query(b"x" * 500, "sess")


def test_base36_carrier():
    carrier = Carrier("example.com", Base36Encoder())
    data = b"hello world"
    qname = carrier.pack_query(data, "s1")
    tag, decoded = carrier.unpack_query(qname)
    assert tag == "s1"
    assert decoded == data
