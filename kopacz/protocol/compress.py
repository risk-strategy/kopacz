"""
LZ4 frame compression with decompression bomb protection.

Uses python-lz4 (`lz4.frame`) when available, with an automatic
ctypes fallback to the system `liblz4.so.1` shared library.
"""

from __future__ import annotations

import ctypes
from typing import Tuple

MAX_DECOMPRESSED_SIZE = 65536  # 64 KB default safety cap per frame

try:
    import lz4.frame as _lz4_frame
except ImportError:
    _lz4_frame = None


class _CLZ4Frame:
    """Thin ctypes wrapper around system liblz4.so.1 LZ4F frame API."""

    def __init__(self) -> None:
        self._lib = ctypes.CDLL("liblz4.so.1")

        self._lib.LZ4F_isError.argtypes = [ctypes.c_size_t]
        self._lib.LZ4F_isError.restype = ctypes.c_uint

        self._lib.LZ4F_getErrorName.argtypes = [ctypes.c_size_t]
        self._lib.LZ4F_getErrorName.restype = ctypes.c_char_p

        self._lib.LZ4F_compressFrameBound.argtypes = [ctypes.c_size_t, ctypes.c_void_p]
        self._lib.LZ4F_compressFrameBound.restype = ctypes.c_size_t

        self._lib.LZ4F_compressFrame.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
        ]
        self._lib.LZ4F_compressFrame.restype = ctypes.c_size_t

        self._lib.LZ4F_createDecompressionContext.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_uint,
        ]
        self._lib.LZ4F_createDecompressionContext.restype = ctypes.c_size_t

        self._lib.LZ4F_freeDecompressionContext.argtypes = [ctypes.c_void_p]
        self._lib.LZ4F_freeDecompressionContext.restype = ctypes.c_size_t

        self._lib.LZ4F_decompress.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p,
        ]
        self._lib.LZ4F_decompress.restype = ctypes.c_size_t

    def _check(self, code: int) -> None:
        if self._lib.LZ4F_isError(code):
            name = self._lib.LZ4F_getErrorName(code)
            msg = name.decode("ascii", errors="replace") if name else str(code)
            raise ValueError(f"LZ4 frame error: {msg}")

    def compress(self, data: bytes) -> bytes:
        bound = self._lib.LZ4F_compressFrameBound(len(data), None)
        dst = ctypes.create_string_buffer(bound)
        written = self._lib.LZ4F_compressFrame(dst, bound, data, len(data), None)
        self._check(written)
        return dst.raw[:written]

    def decompress(self, data: bytes, max_size: int = MAX_DECOMPRESSED_SIZE) -> bytes:
        dctx = ctypes.c_void_p()
        err = self._lib.LZ4F_createDecompressionContext(ctypes.byref(dctx), 100)
        self._check(err)
        try:
            src_buf = ctypes.create_string_buffer(data, len(data))
            src_pos = 0
            src_total = len(data)
            out_chunks: list[bytes] = []
            total_out = 0
            chunk_cap = min(max(len(data) * 4, 4096), 65536)
            dst_buf = ctypes.create_string_buffer(chunk_cap)

            hint = 1
            while src_pos < src_total or hint != 0:
                if src_pos >= src_total and hint != 0:
                    raise ValueError("Truncated LZ4 frame")
                src_rem = ctypes.c_size_t(src_total - src_pos)
                dst_cap = ctypes.c_size_t(chunk_cap)
                src_ptr = ctypes.byref(src_buf, src_pos)
                hint = self._lib.LZ4F_decompress(
                    dctx,
                    dst_buf,
                    ctypes.byref(dst_cap),
                    src_ptr,
                    ctypes.byref(src_rem),
                    None,
                )
                self._check(hint)
                if src_rem.value == 0 and dst_cap.value == 0 and hint != 0:
                    raise ValueError("Truncated or corrupt LZ4 frame")
                src_pos += src_rem.value
                if dst_cap.value > 0:
                    total_out += dst_cap.value
                    if max_size and total_out > max_size:
                        raise ValueError(
                            f"Decompressed size exceeds limit ({max_size} bytes)"
                        )
                    out_chunks.append(dst_buf.raw[: dst_cap.value])
                if hint == 0 and src_pos >= src_total:
                    break

            return b"".join(out_chunks)
        finally:
            self._lib.LZ4F_freeDecompressionContext(dctx)


_c_lz4 = _CLZ4Frame() if _lz4_frame is None else None


def compress(data: bytes) -> bytes:
    """Compress *data* into an LZ4 frame."""
    if not data:
        return data
    if _lz4_frame is not None:
        return _lz4_frame.compress(data)
    assert _c_lz4 is not None
    return _c_lz4.compress(data)


def decompress(data: bytes, max_size: int = MAX_DECOMPRESSED_SIZE) -> bytes:
    """Decompress an LZ4 frame, enforcing *max_size* to prevent decompression bombs."""
    if not data:
        return data
    if _lz4_frame is not None:
        out = _lz4_frame.decompress(data)
        if max_size and len(out) > max_size:
            raise ValueError(f"Decompressed size exceeds limit ({max_size} bytes)")
        return out
    assert _c_lz4 is not None
    return _c_lz4.decompress(data, max_size=max_size)


def compress_if_smaller(data: bytes) -> Tuple[bytes, bool]:
    """
    Compress *data* with LZ4 only if it strictly reduces byte size.
    Returns (payload_bytes, is_compressed).
    """
    if len(data) < 20:
        # LZ4 frame header+footer is 11-15 bytes; <20B cannot shrink meaningfully
        return data, False
    compressed = compress(data)
    if len(compressed) < len(data):
        return compressed, True
    return data, False
