"""Planted content, built by the tests from literal definitions. Nothing here is malicious: the PE is a
header with no code, the PDF and PNG are minimal valid documents."""

import hashlib
import random
import struct
import zlib


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha1(data: bytes) -> str:
    # SHA-1 is a reported identifier (spec §14), not a security check.
    return hashlib.sha1(data, usedforsecurity=False).hexdigest()


def text_bytes(tag: str) -> bytes:
    """A short UTF-8 text, unique per tag."""
    return f"Ostia acceptance test file: {tag}\n".encode()


def seeded_bytes(seed: int, size: int) -> bytes:
    """Deterministic pseudo-random bytes (incompressible)."""
    return random.Random(seed).randbytes(size)


def _png_chunk(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


def png_bytes(tag: str) -> bytes:
    """A valid 1x1 greyscale PNG carrying `tag` in a tEXt chunk."""
    header = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", header)
        + _png_chunk(b"tEXt", b"Comment\x00" + tag.encode())
        + _png_chunk(b"IDAT", zlib.compress(b"\x00\x00"))
        + _png_chunk(b"IEND", b"")
    )


def pdf_bytes(tag: str) -> bytes:
    """A minimal one-page PDF whose title is `tag`."""
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
        b"<< /Title (" + tag.encode() + b") >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R /Info 4 0 R >>\n" % (len(objects) + 1)
    out += b"startxref\n%d\n%%%%EOF\n" % xref
    return bytes(out)


def pe_bytes(tag: str) -> bytes:
    """Headers of a 32-bit PE image with no section and no code, followed by `tag`: typed as `pe`, never
    executable."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x80)
    # COFF header: i386, 0 sections, timestamp 0, no symbols, optional header 0xE0 bytes, executable image.
    coff = struct.pack("<HHIIIHH", 0x014C, 0, 0, 0, 0, 0xE0, 0x0102)
    optional = bytearray(0xE0)
    optional[0:2] = struct.pack("<H", 0x010B)
    return bytes(dos) + b"PE\x00\x00" + coff + bytes(optional) + tag.encode()
