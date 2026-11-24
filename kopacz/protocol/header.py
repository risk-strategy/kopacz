"""
AS-DNS Protocol Header — 8 bytes, big-endian.

Wire format:
  Byte 0:    Flags (8 bits)
  Byte 1-2:  Stream ID (16 bits)
  Byte 3-4:  Sequence (16 bits)
  Byte 5:    Fragment Index (8 bits)
  Byte 6:    Total Fragments (8 bits)
  Byte 7:    Reserved / Aux (8 bits: piggybacked ACK low-8 or POLL nonce)
"""

import struct
from enum import IntFlag


class Flags(IntFlag):
    SYN  = 0x80   # Handshake initiation
    FIN  = 0x40   # Session teardown
    ACK  = 0x20   # Acknowledge receipt
    DATA = 0x10   # Contains payload
    POLL = 0x08   # Heartbeat / request downstream
    FRAG = 0x04   # Fragmented packet
    CFG  = 0x02   # Configuration / More-Data indicator
    MORE = 0x02   # Relay has additional downstream packets queued
    COMP = 0x01   # Payload is LZ4-compressed
    RSV  = 0x01   # Alias for backward compatibility


_FMT = ">BHHBBB"
HEADER_SIZE = struct.calcsize(_FMT)
assert HEADER_SIZE == 8


class Header:
    __slots__ = (
        "flags",
        "stream_id",
        "sequence",
        "frag_index",
        "total_frags",
        "reserved",
    )

    def __init__(
        self,
        flags: int = 0,
        stream_id: int = 0,
        sequence: int = 0,
        frag_index: int = 0,
        total_frags: int = 1,
        reserved: int = 0,
    ):
        self.flags = flags & 0xFF
        self.stream_id = stream_id & 0xFFFF
        self.sequence = sequence & 0xFFFF
        self.frag_index = frag_index & 0xFF
        self.total_frags = total_frags & 0xFF
        self.reserved = reserved & 0xFF

    def pack(self) -> bytes:
        return struct.pack(
            _FMT,
            self.flags,
            self.stream_id,
            self.sequence,
            self.frag_index,
            self.total_frags,
            self.reserved,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "Header":
        if len(data) < HEADER_SIZE:
            raise ValueError(f"Need {HEADER_SIZE} bytes, got {len(data)}")
        flags, sid, seq, fidx, ftot, rsv = struct.unpack(_FMT, data[:HEADER_SIZE])
        return cls(flags, sid, seq, fidx, ftot, rsv)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Header):
            return NotImplemented
        return (
            self.flags == other.flags
            and self.stream_id == other.stream_id
            and self.sequence == other.sequence
            and self.frag_index == other.frag_index
            and self.total_frags == other.total_frags
            and self.reserved == other.reserved
        )

    def __repr__(self) -> str:
        names = "|".join(f.name for f in Flags if f.name != "RSV" and (self.flags & f)) or "0"
        return (
            f"Header({names} stream={self.stream_id} "
            f"seq={self.sequence} frag={self.frag_index}/{self.total_frags})"
        )
