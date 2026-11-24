"""
Fragmentation and reassembly.

Splits an encrypted blob into header+fragment packets sized for DNS.
Reassembles fragments back into the complete blob regardless of arrival order.
"""

from typing import Dict, List, Optional, Tuple

from .header import Header, Flags, HEADER_SIZE

MAX_REASSEMBLED_SIZE = 65536  # 64 KB hard ceiling per reassembled ciphertext blob


def fragment(
    data: bytes,
    stream_id: int,
    sequence: int,
    max_payload: int,
    extra_flags: int = 0,
    reserved: int = 0,
) -> List[bytes]:
    """
    Split *data* into packets: Header(8) + chunk.

    max_payload : max bytes of encrypted data per fragment (excludes header).
    Returns a list of raw packets ready for carrier encoding.
    """
    if max_payload <= 0:
        raise ValueError("max_payload must be positive")

    if not data:
        hdr = Header(Flags.DATA | extra_flags, stream_id, sequence, 0, 1, reserved)
        return [hdr.pack()]

    chunks = [data[i : i + max_payload] for i in range(0, len(data), max_payload)]
    total = len(chunks)
    if total > 255:
        raise ValueError(f"Data needs {total} fragments (max 255)")

    base_flags = Flags.DATA | extra_flags | (Flags.FRAG if total > 1 else 0)

    return [
        Header(base_flags, stream_id, sequence, idx, total, reserved).pack() + chunk
        for idx, chunk in enumerate(chunks)
    ]


class ReassemblyBuffer:
    """
    Collects fragments keyed by (stream_id, sequence).
    Returns the reassembled blob once all fragments arrive.

    Formal property:
        For all D, reassemble(shuffle(fragment(D))) == D
    """

    def __init__(self, max_pending: int = 256):
        self._max = max_pending
        self._frags: Dict[Tuple[int, int], Dict[int, bytes]] = {}
        self._totals: Dict[Tuple[int, int], int] = {}

    def add(self, header: Header, payload: bytes) -> Optional[bytes]:
        if header.total_frags < 1:
            raise ValueError(f"Invalid total_frags: {header.total_frags}")
        if header.frag_index >= header.total_frags:
            raise ValueError(
                f"frag_index {header.frag_index} >= total_frags {header.total_frags}"
            )
        if len(payload) > MAX_REASSEMBLED_SIZE:
            raise ValueError(f"Fragment payload {len(payload)} exceeds maximum {MAX_REASSEMBLED_SIZE}")

        key = (header.stream_id, header.sequence)

        # Headers are unauthenticated prior to reassembly completion: if total_frags
        # conflicts with stored partial state, discard the stale partial entry so a
        # genuine (re)transmission is never permanently blocked by a forged fragment.
        if key in self._frags and header.total_frags != self._totals[key]:
            del self._frags[key]
            del self._totals[key]

        if key not in self._frags:
            if len(self._frags) >= self._max:
                oldest = next(iter(self._frags))
                del self._frags[oldest]
                del self._totals[oldest]
            self._frags[key] = {}
            self._totals[key] = header.total_frags

        self._frags[key][header.frag_index] = payload
        current_size = sum(len(p) for p in self._frags[key].values())
        if current_size > MAX_REASSEMBLED_SIZE:
            del self._frags[key]
            del self._totals[key]
            raise ValueError(
                f"Reassembled size {current_size} exceeds maximum {MAX_REASSEMBLED_SIZE}"
            )

        if len(self._frags[key]) == self._totals[key]:
            parts = self._frags.pop(key)
            total = self._totals.pop(key)
            return b"".join(parts[i] for i in range(total))

        return None

    @property
    def pending(self) -> int:
        return len(self._frags)
