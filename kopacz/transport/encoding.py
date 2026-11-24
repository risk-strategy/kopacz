"""
DNS-safe binary encodings.

Base32  — standard, good firewall traversal (a-z, 2-7)
Base64url — max bandwidth for TXT records (A-Z, a-z, 0-9, -, _)
Base36  — compact, looks like CDN cache tokens (0-9, a-z)
"""

import base64
import string
from typing import Protocol, runtime_checkable


@runtime_checkable
class Encoder(Protocol):
    def encode(self, data: bytes) -> str: ...
    def decode(self, s: str) -> bytes: ...
    def bytes_per_label(self) -> int: ...


class Base32Encoder:
    """5 bits/char.  DNS-safe lowercase."""

    def encode(self, data: bytes) -> str:
        if not data:
            return ""
        return base64.b32encode(data).decode("ascii").lower().rstrip("=")

    def decode(self, s: str) -> bytes:
        if not s:
            return b""
        s = s.upper()
        s += "=" * ((8 - len(s) % 8) % 8)
        return base64.b32decode(s)

    def bytes_per_label(self) -> int:
        # 63 chars  →  floor(63/8)*5 = 35 bytes  (conservative, avoids padding edge)
        return 35


class Base64Encoder:
    """6 bits/char.  URL-safe alphabet for TXT records."""

    def encode(self, data: bytes) -> str:
        if not data:
            return ""
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

    def decode(self, s: str) -> bytes:
        if not s:
            return b""
        s += "=" * ((4 - len(s) % 4) % 4)
        return base64.urlsafe_b64decode(s)

    def bytes_per_label(self) -> int:
        # 63 chars  →  floor(63/4)*3 = 45 bytes
        return 45


class Base36Encoder:
    """~5.17 bits/char.  Looks like CDN/analytics tokens."""

    ALPHABET = string.digits + string.ascii_lowercase

    def encode(self, data: bytes) -> str:
        if not data:
            return ""
        n = int.from_bytes(b"\x01" + data, "big")  # sentinel preserves leading zeros
        out: list[str] = []
        while n:
            n, r = divmod(n, 36)
            out.append(self.ALPHABET[r])
        return "".join(reversed(out))

    def decode(self, s: str) -> bytes:
        if not s:
            return b""
        n = 0
        for c in s.lower():
            n = n * 36 + self.ALPHABET.index(c)
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return raw[1:]  # strip sentinel

    def bytes_per_label(self) -> int:
        # 63 chars * log2(36)/8 ≈ 40.7  →  38 conservative
        return 38
