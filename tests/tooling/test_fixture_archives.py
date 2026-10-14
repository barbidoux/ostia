"""Self-tests of the archive builder `tests/fixtures/archives.py` (WP-1.9), whose contract is the locked
`tests/acceptance/common/archives.py`: an archive of each format holding exactly the planted entries, built
from the standard library only; an unknown format is refused.

Expected values are the literal plants of this file. They are read back without the builder: libmagic
(`file`) and blkid identify each format; the standard library decodes the 7z LZMA2 stream and the cabinet's
deflate blocks; the RAR5 header checksums, the ISO 9660 directory tree and the compound file's directory are
walked from their published layouts. The extraction worker's tests read the same archives with independent
readers (sevenz-rust2, rars, cfb, lzxd).
"""

import importlib
import lzma
import struct
import subprocess
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from tooling_support import REPO, run

# Loaded by the name the acceptance helpers use (tests/acceptance/common/archives.py).
BUILDER = importlib.import_module("tests.fixtures.archives")
build_archive: Callable[[str, list[tuple[str, bytes]]], bytes] = BUILDER.build_archive
ArchiveRequestError: type[ValueError] = BUILDER.ArchiveRequestError

A = b"Ostia archive builder: entry a\n"
B = bytes(range(256)) * 16  # 4096 bytes
ENTRIES = [("a.txt", A), ("dir/b.bin", B)]
SBIN_BLKID = "/usr/sbin/blkid"


def magic(data: bytes) -> str:
    result = subprocess.run(["file", "-b", "-"], input=data, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    return result.stdout.decode().strip()


@pytest.mark.req("TOOLING")
def test_unknown_format_is_refused() -> None:
    with pytest.raises(ArchiveRequestError, match="unknown archive format 'arj'"):
        build_archive("arj", ENTRIES)


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("fmt", "expected"),
    [
        ("7z", "7-zip archive data, version 0.4"),
        ("rar", "RAR archive data, v5"),
        ("cab", "Microsoft Cabinet archive data"),
        ("iso", "ISO 9660 CD-ROM filesystem data 'OSTIA'"),
        ("msi", "Composite Document File V2 Document"),
    ],
)
def test_libmagic_identifies_each_format(fmt: str, expected: str) -> None:
    assert magic(build_archive(fmt, ENTRIES)).startswith(expected)


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize("fmt", ["7z", "rar", "cab", "iso", "msi"])
def test_archives_are_deterministic(fmt: str) -> None:
    assert build_archive(fmt, ENTRIES) == build_archive(fmt, ENTRIES)


@pytest.mark.req("TOOLING")
def test_seven_zip_stream_decodes_to_the_entries() -> None:
    data = build_archive("7z", ENTRIES)
    assert data[:8] == b"7z\xbc\xaf\x27\x1c\x00\x04"
    (start_crc,) = struct.unpack_from("<I", data, 8)
    assert zlib.crc32(data[12:32]) == start_crc
    offset, size, header_crc = struct.unpack_from("<QQI", data, 12)
    header = data[32 + offset : 32 + offset + size]
    assert len(header) == size and zlib.crc32(header) == header_crc
    filters = [{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 20}]
    decoded = lzma.decompress(data[32 : 32 + offset], format=lzma.FORMAT_RAW, filters=filters)
    assert decoded == A + B
    # Names as UTF-16LE in the header, the directory first.
    assert "dir\0a.txt\0dir/b.bin\0".encode("utf-16-le") in header


@pytest.mark.req("TOOLING")
def test_cab_blocks_inflate_to_the_entries() -> None:
    data = build_archive("cab", ENTRIES)
    total, files_at = struct.unpack_from("<I", data, 8)[0], struct.unpack_from("<I", data, 16)[0]
    folders, files = struct.unpack_from("<HH", data, 26)
    assert (total, folders, files, files_at) == (len(data), 1, 2, 44)
    data_at, blocks, compression = struct.unpack_from("<IHH", data, 36)
    assert compression == 1  # MSZIP
    names = []
    at = files_at
    for _ in range(files):
        size, offset = struct.unpack_from("<II", data, at)
        end = data.index(b"\0", at + 16)
        names.append((data[at + 16 : end], size, offset))
        at = end + 1
    assert names == [(b"a.txt", len(A), 0), (b"dir\\b.bin", len(B), len(A))]
    out = b""
    at = data_at
    for _ in range(blocks):
        checksum, packed, unpacked = struct.unpack_from("<IHH", data, at)
        body = data[at + 8 : at + 8 + packed]
        assert body[:2] == b"CK"
        block = zlib.decompress(body[2:], -15)
        assert len(block) == unpacked
        assert checksum != 0
        out += block
        at += 8 + packed
    assert out == A + B and at == len(data)


def rar_headers(data: bytes) -> list[tuple[int, bytes, bytes]]:
    """(type, header, data area) of every RAR5 header, each checksum verified."""

    def vint(at: int) -> tuple[int, int]:
        value, shift = 0, 0
        while True:
            byte = data[at]
            value |= (byte & 0x7F) << shift
            at += 1
            shift += 7
            if not byte & 0x80:
                return value, at

    assert data[:8] == b"Rar!\x1a\x07\x01\x00"
    found = []
    at = 8
    while at < len(data):
        (crc,) = struct.unpack_from("<I", data, at)
        size, body = vint(at + 4)
        assert zlib.crc32(data[at + 4 : body + size]) == crc
        kind, cursor = vint(body)
        flags, cursor = vint(cursor)
        if flags & 0x01:
            _, cursor = vint(cursor)
        payload = 0
        if flags & 0x02:
            payload, cursor = vint(cursor)
        end = body + size
        found.append((kind, data[body:end], data[end : end + payload]))
        at = end + payload
    return found


@pytest.mark.req("TOOLING")
def test_rar_headers_are_valid_and_entries_stored() -> None:
    headers = rar_headers(build_archive("rar", ENTRIES))
    assert [kind for kind, _, _ in headers] == [1, 2, 2, 2, 5]
    assert headers[1][1].endswith(b"dir") and headers[1][2] == b""
    assert headers[2][1].endswith(b"a.txt") and headers[2][2] == A
    assert headers[3][1].endswith(b"dir/b.bin") and headers[3][2] == B


def iso_tree(data: bytes, descriptor: int) -> dict[bytes, bytes]:
    """Files of the tree whose volume descriptor is at sector `descriptor`, by path of identifiers."""

    def records(location: int, size: int) -> list[tuple[bytes, int, int, bool]]:
        out = []
        at = location * 2048
        end = at + size
        while at < end:
            length = data[at]
            if length == 0:
                at = (at // 2048 + 1) * 2048
                continue
            extent = struct.unpack_from("<I", data, at + 2)[0]
            extent_size = struct.unpack_from("<I", data, at + 10)[0]
            flags = data[at + 25]
            name = data[at + 33 : at + 33 + data[at + 32]]
            out.append((name, extent, extent_size, bool(flags & 0x02)))
            at += length
        return out

    root = data[descriptor * 2048 + 156 :]
    found: dict[bytes, bytes] = {}
    pending = [(b"", struct.unpack_from("<I", root, 2)[0], struct.unpack_from("<I", root, 10)[0])]
    while pending:
        prefix, location, size = pending.pop()
        for name, extent, extent_size, directory in records(location, size):
            if name in (b"\0", b"\1"):
                continue
            if directory:
                pending.append((prefix + name + b"/", extent, extent_size))
            else:
                found[prefix + name] = data[extent * 2048 : extent * 2048 + extent_size]
    return found


@pytest.mark.req("TOOLING")
def test_iso_primary_and_joliet_trees_hold_the_entries() -> None:
    data = build_archive("iso", ENTRIES)
    assert data[16 * 2048 : 16 * 2048 + 6] == b"\x01CD001"
    assert data[17 * 2048 : 17 * 2048 + 6] == b"\x02CD001"
    assert data[17 * 2048 + 88 : 17 * 2048 + 91] == b"%/E"
    assert data[18 * 2048 : 18 * 2048 + 6] == b"\xffCD001"
    assert iso_tree(data, 16) == {b"A.TXT;1": A, b"DIR/B.BIN;1": B}
    joliet = {name.replace(b"\0/", b"/"): content for name, content in iso_tree(data, 17).items()}
    assert joliet == {
        "a.txt;1".encode("utf-16-be"): A,
        "dir".encode("utf-16-be") + b"/" + "b.bin;1".encode("utf-16-be"): B,
    }


@pytest.mark.req("TOOLING")
def test_iso_blkid_sees_a_joliet_volume(tmp_path: Path) -> None:
    image = tmp_path / "bundle.iso"
    image.write_bytes(build_archive("iso", ENTRIES))
    result = run([SBIN_BLKID, "-p", "-o", "export", str(image)], cwd=REPO)
    fields = dict(line.split("=", 1) for line in result.stdout.splitlines())
    # `-o export` escapes spaces.
    assert (fields["TYPE"], fields["LABEL"], fields["VERSION"]) == (
        "iso9660",
        "OSTIA",
        "Joliet\\ Extension",
    )


def cfb_directory(data: bytes) -> list[dict[str, Any]]:
    """Entries of the compound file's directory (its chain read through the FAT)."""
    assert data[:8] == bytes.fromhex("d0cf11e0a1b11ae1")
    shift, mini_shift = struct.unpack_from("<HH", data, 30)
    assert (shift, mini_shift) == (9, 6)
    fat_count, first_directory = struct.unpack_from("<II", data, 44)
    fat_sectors = struct.unpack_from(f"<{fat_count}I", data, 76)
    fat: list[int] = []
    for sector in fat_sectors:
        fat += struct.unpack_from("<128I", data, (sector + 1) * 512)
    chain = []
    sector = first_directory
    while sector != 0xFFFFFFFE:
        chain.append(sector)
        sector = fat[sector]
    directory = b"".join(data[(s + 1) * 512 : (s + 2) * 512] for s in chain)
    entries = []
    for at in range(0, len(directory), 128):
        length, kind = struct.unpack_from("<HB", directory, at + 64)
        if kind == 0:
            continue
        entries.append(
            {
                "name": directory[at : at + length - 2].decode("utf-16-le"),
                "kind": kind,
                "clsid": directory[at + 80 : at + 96],
                "size": struct.unpack_from("<Q", directory, at + 120)[0],
            }
        )
    return entries


@pytest.mark.req("TOOLING")
def test_msi_root_carries_the_installer_class_and_its_streams() -> None:
    entries = cfb_directory(build_archive("msi", ENTRIES))
    root, *streams = entries
    assert (root["name"], root["kind"]) == ("Root Entry", 5)
    assert root["clsid"] == bytes.fromhex("84100c0000000000c000000000000046")
    by_name = {s["name"]: s for s in streams}
    # MSI stream names as Windows Installer writes them: U+4840 marks a table, then packed characters.
    string_pool = "".join(map(chr, [0x4840, 0x3F3F, 0x4577, 0x446C, 0x3E6A, 0x44B2, 0x482F]))
    string_data = "".join(map(chr, [0x4840, 0x3F3F, 0x4577, 0x446C, 0x3B6A, 0x45E4, 0x4824]))
    cabinet = "".join(map(chr, [0x4573, 0x41F2, 0x41B8, 0x47B7, 0x4126, 0x4825]))  # product.cab
    assert set(by_name) == {string_pool, string_data, cabinet}
    assert (by_name[string_pool]["size"], by_name[string_data]["size"]) == (4, 0)
    assert by_name[cabinet]["size"] == len(build_archive("cab", ENTRIES))
