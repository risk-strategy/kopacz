"""
DNS carrier — packs/unpacks binary data into DNS FQDNs and TXT records.

Upstream  (client→server):  [label].[label]...[session_tag].[domain]
Downstream (server→client):  base-encoded TXT RDATA
"""

import ipaddress
import math
from dataclasses import dataclass
from typing import List, Tuple

from .encoding import Encoder, Base32Encoder, Base64Encoder, Base36Encoder

MAX_LABEL = 63
MAX_FQDN = 253
MAX_AAAA_PAYLOAD = 223  # 14 bytes in record 0 + 14 * 15 bytes in records 1..14


@dataclass(frozen=True, slots=True)
class Posture:
    """
    Transport posture controlling wire shape, MTU, and pacing.

    TURBO    : Captive-portal / DoH mode — max MTU (480B down / 120B up),
               63-char labels, QTYPE=TXT, up to 6 concurrent polls, 0ms jitter.
    BALANCED : General CLI default — single-string TXT (160B down / 96B up),
               48-char labels, up to 2 concurrent polls, light jitter.
    COVERT   : HRD / DPI-evasion mode — QTYPE=AAAA (zero TXT records),
               short <=24-char labels (36B up / 64B down), 1 query in flight,
               human/browser-like randomized jitter (200-800ms).
    """

    name: str
    qtype: str = "TXT"
    max_label_len: int = 63
    up_mtu: int = 120
    down_mtu: int = 120
    max_in_flight: int = 1
    jitter_min: float = 0.0
    jitter_max: float = 0.0


POSTURE_TURBO = Posture(
    name="turbo",
    qtype="TXT",
    max_label_len=63,
    up_mtu=120,
    down_mtu=480,
    max_in_flight=6,
    jitter_min=0.0,
    jitter_max=0.0,
)

POSTURE_BALANCED = Posture(
    name="balanced",
    qtype="TXT",
    max_label_len=48,
    up_mtu=96,
    down_mtu=160,
    max_in_flight=2,
    jitter_min=0.01,
    jitter_max=0.05,
)

POSTURE_COVERT = Posture(
    name="covert",
    qtype="AAAA",
    max_label_len=24,
    up_mtu=36,
    down_mtu=64,
    max_in_flight=1,
    jitter_min=0.20,
    jitter_max=0.80,
)

POSTURES = {
    "turbo": POSTURE_TURBO,
    "balanced": POSTURE_BALANCED,
    "covert": POSTURE_COVERT,
}


class Carrier:
    def __init__(
        self,
        domain: str,
        encoder: Encoder | None = None,
        response_encoder: Encoder | None = None,
        max_label_len: int = MAX_LABEL,
    ):
        domain_clean = domain.strip().rstrip(".")
        if not domain_clean:
            raise ValueError("Domain must not be empty")
        if not (4 <= max_label_len <= MAX_LABEL):
            raise ValueError(f"max_label_len must be in [4, {MAX_LABEL}]")
        self.domain = domain_clean
        self.encoder = encoder or Base32Encoder()
        self.response_encoder = response_encoder or self.encoder
        self.max_label_len = max_label_len
        self._dom_depth = len(self.domain.split("."))

    # ── upstream (QNAME) ────────────────────────────────────────

    def pack_query(self, data: bytes, session_tag: str) -> str:
        """Encode packet bytes into an FQDN for a DNS query."""
        if not session_tag or "." in session_tag or len(session_tag) > MAX_LABEL:
            raise ValueError(f"Invalid session_tag: {session_tag!r}")
        encoded = self.encoder.encode(data)
        if not encoded:
            raise ValueError("Cannot pack empty query data")
        step = self.max_label_len
        labels: list[str] = [
            encoded[i : i + step] for i in range(0, len(encoded), step)
        ]

        fqdn = ".".join(labels) + f".{session_tag}.{self.domain}"
        if len(fqdn) > MAX_FQDN:
            raise ValueError(f"FQDN {len(fqdn)} chars exceeds {MAX_FQDN}")
        return fqdn

    def unpack_query(self, qname: str) -> Tuple[str, bytes]:
        """Decode FQDN → (session_tag, packet_bytes).

        Case is normalised to lower because recursive resolvers
        (notably Google DNS) use 0x20 case randomisation for
        anti-spoofing — the same logical QNAME arrives with
        different capitalisation on every query.
        """
        cleaned = qname.strip().rstrip(".")
        if len(cleaned) > MAX_FQDN:
            raise ValueError(f"QNAME {len(cleaned)} chars exceeds {MAX_FQDN}")
        parts = cleaned.lower().split(".")
        suffix_len = 1 + self._dom_depth          # session_tag + domain parts
        if len(parts) <= suffix_len:
            raise ValueError("QNAME too short")
        # Verify domain suffix matches
        if ".".join(parts[-self._dom_depth:]) != self.domain.lower():
            raise ValueError("QNAME domain mismatch")
        session_tag = parts[-suffix_len]
        if not session_tag:
            raise ValueError("Empty session_tag")
        data_labels = parts[:-suffix_len]
        if any(not lbl or len(lbl) > MAX_LABEL for lbl in data_labels):
            raise ValueError("Invalid label in QNAME")
        encoded = "".join(data_labels)
        return session_tag, self.encoder.decode(encoded)

    # ── downstream (TXT RDATA & AAAA RDATA) ─────────────────────

    def pack_response(self, data: bytes) -> str:
        return self.response_encoder.encode(data)

    def unpack_response(self, txt: str) -> bytes:
        return self.response_encoder.decode(txt)

    @staticmethod
    def pack_aaaa_response(data: bytes) -> List[str]:
        """
        Encode raw downstream packet bytes into a list of IANA Global Unicast
        IPv6 addresses (2000::/3) for QTYPE=AAAA covert transport.

        Survives recursive resolver RRset shuffling by embedding the 4-bit
        record index in byte 0 (0x20 | idx) and total byte length in record 0 byte 1.
        """
        if not data:
            return []
        if len(data) > MAX_AAAA_PAYLOAD:
            raise ValueError(
                f"AAAA payload {len(data)} bytes exceeds max {MAX_AAAA_PAYLOAD}"
            )

        records: List[str] = []
        # Record 0: [0x20, total_len, up to 14 payload bytes]
        chunk0 = data[:14].ljust(14, b"\x00")
        rec0 = bytes([0x20, len(data)]) + chunk0
        records.append(str(ipaddress.IPv6Address(rec0)))

        offset = 14
        idx = 1
        while offset < len(data):
            chunk = data[offset : offset + 15].ljust(15, b"\x00")
            rec = bytes([0x20 | (idx & 0x0F)]) + chunk
            records.append(str(ipaddress.IPv6Address(rec)))
            offset += 15
            idx += 1

        return records

    @staticmethod
    def unpack_aaaa_response(ipv6_addrs: List[str]) -> bytes:
        """
        Reconstruct raw downstream packet bytes from (potentially shuffled)
        AAAA IPv6 address strings.
        """
        if not ipv6_addrs:
            return b""
        parsed: dict[int, bytes] = {}
        for addr in ipv6_addrs:
            raw16 = ipaddress.IPv6Address(addr).packed
            if (raw16[0] & 0xF0) != 0x20:
                raise ValueError(f"Invalid AAAA carrier prefix in {addr}")
            idx = raw16[0] & 0x0F
            parsed[idx] = raw16

        if 0 not in parsed:
            raise ValueError("Missing AAAA record 0")
        for i in range(len(parsed)):
            if i not in parsed:
                raise ValueError(f"Missing AAAA record index {i}")

        total_len = parsed[0][1]
        if total_len == 0 or total_len > MAX_AAAA_PAYLOAD:
            raise ValueError(f"Invalid AAAA total_len {total_len}")

        buf = bytearray(parsed[0][2:])
        for i in range(1, len(parsed)):
            buf.extend(parsed[i][1:])

        if len(buf) < total_len:
            raise ValueError(
                f"Truncated AAAA response: got {len(buf)} bytes, need {total_len}"
            )
        return bytes(buf[:total_len])

    # ── capacity ────────────────────────────────────────────────

    def max_query_bytes(self, session_tag: str) -> int:
        """Max raw bytes that fit in one query FQDN (respecting max_label_len)."""
        suffix = f".{session_tag}.{self.domain}"
        avail = MAX_FQDN - len(suffix)
        if avail <= 0:
            return 0
        lbl = self.max_label_len
        max_encoded_chars = avail - math.ceil(avail / (lbl + 1)) + 1
        while max_encoded_chars + max(0, math.ceil(max_encoded_chars / lbl) - 1) > avail:
            max_encoded_chars -= 1

        if isinstance(self.encoder, Base32Encoder):
            return (max_encoded_chars * 5) // 8
        if isinstance(self.encoder, Base64Encoder):
            return (max_encoded_chars * 3) // 4
        if isinstance(self.encoder, Base36Encoder):
            # Sentinel byte + data must fit in 36^max_encoded_chars
            return max(1, ((max_encoded_chars * 516) // 800) - 1)

        n_labels = max(1, avail // (lbl + 1))
        return self.encoder.bytes_per_label() * n_labels
