"""Archive builder for the formats of FR-06 beyond zip, tar and gzip (WP-1.9). Contract:
tests/acceptance/common/archives.py.

`build_archive(fmt, entries)` returns the bytes of an archive of format `fmt` (`7z`, `rar`, `cab`, `iso`, `msi`)
holding `entries`, a list of (`/`-separated path, content); extracting it yields exactly these bytes. Any other
format is refused with `ArchiveRequestError`. Only the standard library is used (Q-63), and every archive is
deterministic: fixed times (1980-01-01T00:00:00Z), no random fields.

Each format also has its own builder with keyword options, used by the extraction worker's tests to plant
what a well-behaved archiver never writes:
- `seven_zip`: one LZMA2 folder holding every non-empty entry (a solid archive; `solid=False`: one folder
  per entry), directories as empty-stream items, modification times; `coder` declares another coder (`copy`,
  `aes`, `ppmd`, `bzip2`) whose bytes are the plain contents.
- `rar`: RAR5 with stored entries and directory headers; `encrypted` adds a file encryption record.
- `cab`: one folder, compressed with `mszip` (deflate blocks behind `CK`), `lzx` (uncompressed LZX blocks),
  `none`, or declared `quantum`; names use the cabinet's `\\` separator; data blocks carry checksums.
- `iso`: ISO 9660 with level-2 primary names and, with `joliet`, a Joliet tree holding the given names.
- `msi`: a compound file (version 3) whose root carries the Windows Installer class id, holding the tables
  `_StringPool` and `_StringData` and an embedded cabinet `product.cab` (a `cab` of the entries), each under
  its MSI-encoded stream name.
"""

import lzma
import struct
import zlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

Entries = Sequence[tuple[str, bytes]]

# 1980-01-01T00:00:00Z.
EPOCH_1980 = 315_532_800
FORMATS = ("7z", "rar", "cab", "iso", "msi")


class ArchiveRequestError(ValueError):
    """A request the builder cannot honour."""


def build_archive(fmt: str, entries: Entries) -> bytes:
    """An archive of format `fmt` holding `entries`."""
    if fmt == "7z":
        return seven_zip(entries)
    if fmt == "rar":
        return rar(entries)
    if fmt == "cab":
        return cab(entries)
    if fmt == "iso":
        return iso(entries)
    if fmt == "msi":
        return msi(entries)
    raise ArchiveRequestError(f"unknown archive format {fmt!r}; known: {', '.join(FORMATS)}")


def _directories(entries: Entries) -> list[str]:
    """Every parent directory of the entries, parents first."""
    found: dict[str, None] = {}
    for path, _ in entries:
        parts = path.split("/")[:-1]
        for depth in range(1, len(parts) + 1):
            found["/".join(parts[:depth])] = None
    return sorted(found, key=lambda d: (d.count("/"), d))


# --- 7z ----------------------------------------------------------------------------------------------

SEVEN_ZIP_SIGNATURE = b"7z\xbc\xaf\x27\x1c"
# Coder id and properties. LZMA2 property 16: a 1 MiB dictionary.
SEVEN_ZIP_CODERS: dict[str, tuple[bytes, bytes]] = {
    "lzma2": (b"\x21", b"\x10"),
    "copy": (b"\x00", b""),
    "aes": (b"\x06\xf1\x07\x01", b""),
    "ppmd": (b"\x03\x04\x01", b"\x06\x00\x00\x00\x01"),
    "bzip2": (b"\x04\x02\x02", b""),
}
LZMA2_DICTIONARY = 1 << 20
# 1980-01-01 as a Windows FILETIME (100 ns since 1601-01-01).
FILETIME_1980 = (EPOCH_1980 + 11_644_473_600) * 10_000_000


def _number(value: int) -> bytes:
    """A 7z variable-length number: as many leading one bits in the first byte as extra bytes follow."""
    for extra in range(8):
        if value < 1 << (7 * (extra + 1)):
            first = ((0xFF00 >> extra) & 0xFF) | (value >> (8 * extra))
            return bytes([first]) + (value & ((1 << (8 * extra)) - 1)).to_bytes(extra, "little")
    return b"\xff" + value.to_bytes(8, "little")


def _bits(flags: Sequence[bool]) -> bytes:
    """A 7z bit vector, most significant bit first."""
    out = bytearray((len(flags) + 7) // 8)
    for index, flag in enumerate(flags):
        if flag:
            out[index // 8] |= 0x80 >> (index % 8)
    return bytes(out)


def _seven_zip_pack(data: bytes, coder: str) -> bytes:
    if coder == "lzma2":
        filters = [{"id": lzma.FILTER_LZMA2, "dict_size": LZMA2_DICTIONARY}]
        return lzma.compress(data, format=lzma.FORMAT_RAW, filters=filters)
    return data


def seven_zip(
    entries: Entries,
    *,
    coder: str = "lzma2",
    solid: bool = True,
    extra_substreams: int = 0,
    lzma2_property: int | None = None,
) -> bytes:
    """A 7z archive of `entries`, one folder for all (`solid`) or one per non-empty entry (see the module
    docstring). Also: the last folder declaring `extra_substreams` empty sub-streams no file takes; the LZMA2
    dictionary property byte declared as `lzma2_property` (the stream is still coded with 1 MiB)."""
    if coder not in SEVEN_ZIP_CODERS:
        raise ArchiveRequestError(f"unknown 7z coder {coder!r}")
    coder_id, properties = SEVEN_ZIP_CODERS[coder]
    if lzma2_property is not None:
        properties = bytes([lzma2_property])
    items: list[tuple[str, bytes | None]] = [(d, None) for d in _directories(entries)]
    items += [(path, content) for path, content in entries]
    streams = [content for _, content in items if content]
    folders = ([streams] if streams else []) if solid else [[s] for s in streams]
    packs = [_seven_zip_pack(b"".join(folder), coder) for folder in folders]
    packed = b"".join(packs)

    header = bytearray(b"\x01")  # Header
    if streams:
        header += b"\x04"  # MainStreamsInfo
        header += b"\x06" + _number(0) + _number(len(packs)) + b"\x09"
        header += b"".join(_number(len(p)) for p in packs) + b"\x00"
        flag = len(coder_id) | (0x20 if properties else 0)
        folder = _number(1) + bytes([flag]) + coder_id
        if properties:
            folder += _number(len(properties)) + properties
        header += b"\x07\x0b" + _number(len(folders)) + b"\x00" + folder * len(folders)
        header += b"\x0c" + b"".join(_number(sum(map(len, f))) for f in folders) + b"\x00"
        counts = [len(f) for f in folders]
        counts[-1] += extra_substreams
        header += b"\x08\x0d" + b"".join(_number(c) for c in counts)
        # Each folder lists all its sub-stream sizes but the last, which is what remains.
        listed = [
            size
            for f, c in zip(folders, counts, strict=True)
            for size in ([len(s) for s in f] + [0] * (c - len(f)))[:-1]
        ]
        if listed:
            header += b"\x09" + b"".join(_number(size) for size in listed)
        crcs = [zlib.crc32(s) for s in streams] + [0] * extra_substreams
        header += b"\x0a\x01" + b"".join(struct.pack("<I", crc) for crc in crcs)
        header += b"\x00\x00"  # end of SubStreamsInfo, of MainStreamsInfo
    header += b"\x05" + _number(len(items))  # FilesInfo
    empty = [not content for _, content in items]
    if any(empty):
        vector = _bits(empty)
        header += b"\x0e" + _number(len(vector)) + vector
        files = _bits([content is not None for _, content in items if not content])
        header += b"\x0f" + _number(len(files)) + files
    names = b"\x00" + b"".join(path.encode("utf-16-le") + b"\x00\x00" for path, _ in items)
    header += b"\x11" + _number(len(names)) + names
    times = b"\x01\x00" + struct.pack("<Q", FILETIME_1980) * len(items)
    header += b"\x14" + _number(len(times)) + times
    header += b"\x00\x00"  # end of FilesInfo, of Header

    start = struct.pack("<QQI", len(packed), len(header), zlib.crc32(header))
    return (
        SEVEN_ZIP_SIGNATURE
        + b"\x00\x04"
        + struct.pack("<I", zlib.crc32(start))
        + start
        + packed
        + bytes(header)
    )


# --- RAR5 --------------------------------------------------------------------------------------------

RAR5_SIGNATURE = b"Rar!\x1a\x07\x01\x00"


def _vint(value: int) -> bytes:
    """A RAR5 variable-length integer: seven bits per byte, low bits first, high bit set on all but the last."""
    out = bytearray()
    while True:
        low, value = value & 0x7F, value >> 7
        out.append(low | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _rar_header(
    kind: int, body: bytes, *, extra: bytes = b"", data: int | None = None, flags: int = 0
) -> bytes:
    """A RAR5 header block: CRC32, size, type, flags, extra area size, data size, body, extra area."""
    flags |= (0x01 if extra else 0) | (0x02 if data is not None else 0)
    fields = _vint(kind) + _vint(flags)
    if extra:
        fields += _vint(len(extra))
    if data is not None:
        fields += _vint(data)
    content = fields + body + extra
    sized = _vint(len(content)) + content
    return struct.pack("<I", zlib.crc32(sized)) + sized


def _rar_stored(kind: int, name: bytes, content: bytes, *, flags: int = 0) -> bytes:
    """A stored file (2) or service (3) header with its CRC and its data."""
    body = _vint(0x04) + _vint(len(content)) + _vint(0o100644)
    body += struct.pack("<I", zlib.crc32(content))
    body += _vint(0) + _vint(1) + _vint(len(name)) + name
    return _rar_header(kind, body, data=len(content), flags=flags) + content


def rar(
    entries: Entries,
    *,
    encrypted: bool = False,
    directory_data: bytes = b"",
    links: Sequence[tuple[str, str]] = (),
    link_data: bytes = b"",
    services: Sequence[tuple[str, bytes]] = (),
    file_services: Sequence[tuple[str, bytes]] = (),
    split: bool = False,
) -> bytes:
    """A RAR5 archive of `entries`, stored (see the module docstring). Also: `directory_data` in each
    directory header's data area; `links` (name, target) as Unix symbolic link members (redirection records),
    carrying `link_data`; `services` (name, data) as service headers before the files, `file_services` after
    the first file; with `split`, the last file continues in a next volume."""
    out = bytearray(RAR5_SIGNATURE)
    out += _rar_header(1, _vint(0))  # main archive header
    unix = 1
    for service, data in services:
        out += _rar_stored(3, service.encode(), data)
    for directory in _directories(entries):
        name = directory.encode()
        body = _vint(0x01 | 0x02) + _vint(0) + _vint(0o40755) + struct.pack("<I", EPOCH_1980)
        body += _vint(0) + _vint(unix) + _vint(len(name)) + name
        out += _rar_header(2, body, data=len(directory_data) if directory_data else None)
        out += directory_data
    for link, target in links:
        name = link.encode()
        body = _vint(0) + _vint(0) + _vint(0o120777) + _vint(0) + _vint(unix)
        body += _vint(len(name)) + name
        record = _vint(0x05) + _vint(1) + _vint(0) + _vint(len(target.encode())) + target.encode()
        extra = _vint(len(record)) + record
        out += _rar_header(2, body, extra=extra, data=len(link_data) if link_data else None)
        out += link_data
    for index, (path, content) in enumerate(entries):
        if split and index == len(entries) - 1:
            out += _rar_stored(2, path.encode(), content, flags=0x10)
            continue
        name = path.encode()
        body = _vint(0x02 | 0x04) + _vint(len(content)) + _vint(0o100644)
        body += struct.pack("<II", EPOCH_1980, zlib.crc32(content))
        body += _vint(0) + _vint(unix) + _vint(len(name)) + name  # compression 0: stored
        extra = b""
        payload = content
        if encrypted:
            record = _vint(0x01) + _vint(0) + _vint(0) + bytes([15]) + bytes(16) + bytes(16)
            extra = _vint(len(record)) + record
            payload = content + bytes(-len(content) % 16)
        out += _rar_header(2, body, extra=extra, data=len(payload)) + payload
        if index == 0:
            for service, data in file_services:
                out += _rar_stored(3, service.encode(), data)
    out += _rar_header(5, _vint(0))  # end of archive
    return bytes(out)


# --- cab ---------------------------------------------------------------------------------------------

CAB_FRAME = 32_768
# typeCompress of CFFOLDER: none, MSZIP, Quantum level 7 memory 20, LZX with a 64 KiB window.
CAB_COMPRESSION = {"none": 0x0000, "mszip": 0x0001, "quantum": 0x1472, "lzx": 0x1003}
DOS_DATE_1980 = (0 << 9) | (1 << 5) | 1


def cab_checksum(data: bytes, seed: int = 0) -> int:
    """The cabinet checksum (MS-CAB 2.4): XOR of little-endian 32-bit words, a short tail taken big first."""
    checksum = seed
    whole = len(data) // 4 * 4
    for offset in range(0, whole, 4):
        checksum ^= int.from_bytes(data[offset : offset + 4], "little")
    tail = 0
    for byte in data[whole:]:
        tail = (tail << 8) | byte
    return checksum ^ tail


def _lzx_frame(chunk: bytes, first: bool) -> bytes:
    """One LZX frame holding one uncompressed block: header bits (E8 flag on the first frame, type 3, 24-bit
    size), padding to a 16-bit word, R0 R1 R2, then the bytes. Bits fill 16-bit little-endian words, high first."""
    bits = ("0" if first else "") + "011" + format(len(chunk), "024b")
    bits += "0" * (-len(bits) % 16)
    words = b"".join(
        int(bits[i : i + 16], 2).to_bytes(2, "little") for i in range(0, len(bits), 16)
    )
    return words + struct.pack("<III", 1, 1, 1) + chunk + bytes(len(chunk) % 2)


def _cab_block(chunk: bytes, compression: str, first: bool) -> bytes:
    if compression == "mszip":
        deflater = zlib.compressobj(9, zlib.DEFLATED, -15)
        return b"CK" + deflater.compress(chunk) + deflater.flush()
    if compression == "lzx":
        return _lzx_frame(chunk, first)
    return chunk


def cab(entries: Entries, *, compression: str = "mszip", folder_per_entry: bool = False) -> bytes:
    """A cabinet of `entries` in one folder, or one folder per entry (see the module docstring)."""
    if compression not in CAB_COMPRESSION:
        raise ArchiveRequestError(f"unknown cab compression {compression!r}")
    groups = [[entry] for entry in entries] if folder_per_entry else [list(entries)]
    files = bytearray()
    for index, group in enumerate(groups):
        offset = 0
        for path, content in group:
            name = path.replace("/", "\\").encode()
            attributes = 0x20 | (0x80 if not name.isascii() else 0)
            files += struct.pack(
                "<IIHHHH", len(content), offset, index, DOS_DATE_1980, 0, attributes
            )
            files += name + b"\x00"
            offset += len(content)
    files_at = 36 + 8 * len(groups)
    data_at = files_at + len(files)
    folders = bytearray()
    blocks = bytearray()
    for group in groups:
        data = b"".join(content for _, content in group)
        count = 0
        first = data_at + len(blocks)
        for start in range(0, len(data), CAB_FRAME):
            chunk = data[start : start + CAB_FRAME]
            packed = _cab_block(chunk, compression, start == 0)
            sizes = struct.pack("<HH", len(packed), len(chunk))
            checksum = cab_checksum(sizes, cab_checksum(packed))
            blocks += struct.pack("<I", checksum) + sizes + packed
            count += 1
        folders += struct.pack("<IHH", first, count, CAB_COMPRESSION[compression])
    total = data_at + len(blocks)
    header = b"MSCF" + struct.pack(
        "<IIIIIBBHHHHH", 0, total, 0, files_at, 0, 3, 1, len(groups), len(entries), 0, 0x05A1, 0
    )
    return header + bytes(folders) + bytes(files) + bytes(blocks)


# --- ISO 9660 ----------------------------------------------------------------------------------------

SECTOR = 2048
DATE_1980 = bytes([80, 1, 1, 0, 0, 0, 0])
UNUSED_DATE = b"0" * 16 + b"\x00"


def _both16(value: int) -> bytes:
    return value.to_bytes(2, "little") + value.to_bytes(2, "big")


def _both32(value: int) -> bytes:
    return value.to_bytes(4, "little") + value.to_bytes(4, "big")


def _sectors(size: int) -> int:
    return (size + SECTOR - 1) // SECTOR


@dataclass
class _Node:
    """A directory of the image being built."""

    name: str
    parent: "_Node | None" = None
    children: dict[str, "_Node"] = field(default_factory=dict)
    files: dict[str, bytes] = field(default_factory=dict)
    location: dict[bool, int] = field(default_factory=dict)  # per tree (Joliet or not)
    size: dict[bool, int] = field(default_factory=dict)


def _primary_name(name: str, directory: bool) -> bytes:
    """A level-2 ISO 9660 identifier: upper-case d-characters, `.` before an extension, `;1` on files."""
    stem, dot, extension = name.upper().rpartition(".") if "." in name else (name.upper(), "", "")
    clean = "".join(c if c.isascii() and (c.isalnum() or c == "_") else "_" for c in stem)
    clean_ext = "".join(c if c.isascii() and (c.isalnum() or c == "_") else "_" for c in extension)
    if directory:
        return (clean + ("_" + clean_ext if dot else ""))[:31].encode()
    return (clean[:26] + "." + clean_ext[:3] + ";1").encode()


def _identifier(name: str, directory: bool, joliet: bool) -> bytes:
    if joliet:
        return (name if directory else name + ";1").encode("utf-16-be")
    return _primary_name(name, directory)


def _record(identifier: bytes, location: int, size: int, directory: bool) -> bytes:
    length = 33 + len(identifier)
    pad = length % 2
    return (
        bytes([length + pad, 0])
        + _both32(location)
        + _both32(size)
        + DATE_1980
        + bytes([0x02 if directory else 0x00, 0, 0])
        + _both16(1)
        + bytes([len(identifier)])
        + identifier
        + bytes(pad)
    )


def _directory_extent(node: _Node, joliet: bool, files_at: dict[tuple[int, str], int]) -> bytes:
    """A directory's records: `.`, `..`, then children by identifier; none crosses a sector boundary."""
    parent = node.parent or node
    records = [
        _record(b"\x00", node.location.get(joliet, 0), node.size.get(joliet, 0), True),
        _record(b"\x01", parent.location.get(joliet, 0), parent.size.get(joliet, 0), True),
    ]
    children: list[tuple[bytes, bytes]] = []
    for name, child in node.children.items():
        identifier = _identifier(name, True, joliet)
        children.append(
            (
                identifier,
                _record(identifier, child.location.get(joliet, 0), child.size.get(joliet, 0), True),
            )
        )
    for name, content in node.files.items():
        identifier = _identifier(name, False, joliet)
        location = files_at.get((id(node), name), 0)
        children.append((identifier, _record(identifier, location, len(content), False)))
    records += [record for _, record in sorted(children)]
    out = bytearray()
    for record in records:
        if len(out) % SECTOR + len(record) > SECTOR:
            out += bytes(-len(out) % SECTOR)
        out += record
    out += bytes(-len(out) % SECTOR)
    return bytes(out)


def _walk(root: _Node) -> list[_Node]:
    """Directories level by level, children by name: the path table order."""
    order = [root]
    for node in order:
        order += [node.children[name] for name in sorted(node.children)]
    return order


def _path_table(order: list[_Node], joliet: bool, big_endian: bool) -> bytes:
    numbers = {id(node): index + 1 for index, node in enumerate(order)}
    endian: Literal["big", "little"] = "big" if big_endian else "little"
    out = bytearray()
    for node in order:
        identifier = b"\x00" if node.parent is None else _identifier(node.name, True, joliet)
        parent = numbers[id(node.parent or node)]
        out += bytes([len(identifier), 0]) + node.location[joliet].to_bytes(4, endian)
        out += parent.to_bytes(2, endian) + identifier + bytes(len(identifier) % 2)
    return bytes(out)


def _descriptor(
    kind: int, root: _Node, joliet: bool, tables: tuple[int, int, int], total: int
) -> bytes:
    size, little, big = tables
    out = bytearray(SECTOR)
    out[0:7] = bytes([kind]) + b"CD001\x01"
    out[8:40] = _padded("OSTIA", 32, joliet)
    out[40:72] = _padded("OSTIA", 32, joliet)
    out[80:88] = _both32(total)
    if joliet:
        out[88:91] = b"%/E"
    out[120:124] = _both16(1)
    out[124:128] = _both16(1)
    out[128:132] = _both16(SECTOR)
    out[132:140] = _both32(size)
    out[140:144] = little.to_bytes(4, "little")
    out[148:152] = big.to_bytes(4, "big")
    out[156:190] = _record(b"\x00", root.location[joliet], root.size[joliet], True)
    out[190:702] = _padded("", 512, joliet)  # volume set, publisher, preparer, application
    out[702:813] = b" " * 111  # copyright, abstract and bibliographic file names
    for at in (813, 830, 847, 864):
        out[at : at + 17] = UNUSED_DATE
    out[881] = 1
    return bytes(out)


def _padded(value: str, size: int, joliet: bool) -> bytes:
    """A descriptor identifier: a-characters padded with spaces, or (Joliet) UCS-2 padded with UCS-2 spaces."""
    if joliet:
        return (value + " " * size).encode("utf-16-be")[:size]
    return value.encode().ljust(size, b" ")


def iso(
    entries: Entries, *, joliet: bool = True, boot_record: bool = False, udf: bool = False
) -> bytes:
    """An ISO 9660 image of `entries` (see the module docstring); `boot_record` adds an El Torito boot record
    descriptor, `udf` a UDF volume recognition sequence (BEA01, NSR02, TEA01) after the terminator."""
    root = _Node("")
    for path, content in entries:
        node = root
        *parents, name = path.split("/")
        for part in parents:
            node = node.children.setdefault(part, _Node(part, node))
        node.files[name] = content
    order = _walk(root)
    trees = [False, True] if joliet else [False]

    descriptors = 1 + len(trees) + boot_record  # PVD, SVD, boot record, terminator
    recognition = [b"BEA01", b"NSR02", b"TEA01"] if udf else []
    cursor = 16 + descriptors + len(recognition)
    tables: dict[bool, tuple[int, int, int]] = {}
    for tree in trees:
        for node in order:
            node.location[tree] = 0  # sizes of path tables do not depend on locations
        size = len(_path_table(order, tree, False))
        tables[tree] = (size, cursor, cursor + _sectors(size))
        cursor += 2 * _sectors(size)
    for tree in trees:
        for node in order:
            node.size[tree] = len(_directory_extent(node, tree, {}))
            node.location[tree] = cursor
            cursor += node.size[tree] // SECTOR
    files_at: dict[tuple[int, str], int] = {}
    contents: list[bytes] = []
    for node in order:
        for name, content in node.files.items():
            files_at[(id(node), name)] = cursor if content else 0
            contents.append(content)
            cursor += _sectors(len(content))
    total = cursor

    image = bytearray(16 * SECTOR)
    image += _descriptor(1, root, False, tables[False], total)
    if joliet:
        image += _descriptor(2, root, True, tables[True], total)
    if boot_record:
        system = b"EL TORITO SPECIFICATION".ljust(32, b"\x00")
        image += (bytes([0]) + b"CD001\x01" + system + bytes(32)).ljust(SECTOR, b"\x00")
    image += bytes([255]) + b"CD001\x01" + bytes(SECTOR - 7)
    for identifier in recognition:
        image += (bytes([0]) + identifier + b"\x01").ljust(SECTOR, b"\x00")
    for tree in trees:
        size = tables[tree][0]
        image += _path_table(order, tree, False).ljust(_sectors(size) * SECTOR, b"\x00")
        image += _path_table(order, tree, True).ljust(_sectors(size) * SECTOR, b"\x00")
    for tree in trees:
        for node in order:
            image += _directory_extent(node, tree, files_at)
    for content in contents:
        image += content + bytes(-len(content) % SECTOR)
    if len(image) != total * SECTOR:
        raise ArchiveRequestError("iso layout error")  # a builder bug, never a request error
    return bytes(image)


# --- msi (compound file) -----------------------------------------------------------------------------

COMPOUND_FILE = bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
# {000C1084-0000-0000-C000-000000000046}, as stored.
MSI_CLSID = bytes.fromhex("84100c0000000000c000000000000046")
CFB_SECTOR = 512
MINI_SECTOR = 64
MINI_CUTOFF = 4096
FREESECT, ENDOFCHAIN, FATSECT, NOSTREAM = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF
MIME = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"


def msi_stream_name(name: str, *, table: bool = False) -> str:
    """The MSI encoding of a stream name: pairs of [0-9A-Za-z._] packed in U+3800..U+47FF, single ones in
    U+4800..U+483F, a table name behind U+4840."""
    out = ["䡀"] if table else []
    index = 0
    while index < len(name):
        first = MIME.find(name[index])
        second = MIME.find(name[index + 1]) if index + 1 < len(name) else -1
        if first >= 0 and second >= 0:
            out.append(chr(0x3800 + first + (second << 6)))
            index += 2
        elif first >= 0:
            out.append(chr(0x4800 + first))
            index += 1
        else:
            out.append(name[index])
            index += 1
    return "".join(out)


def _cfb_key(name: str) -> tuple[int, str]:
    """Sibling order of a compound file: shorter names first, then by upper-case UTF-16."""
    return (len(name.encode("utf-16-le")), name.upper())


def compound_file(streams: Sequence[tuple[str, bytes]], clsid: bytes = MSI_CLSID) -> bytes:
    """A version 3 compound file whose root (class id `clsid`) holds `streams`; streams under 4096 bytes go
    to the mini stream."""
    sectors: list[bytes] = []
    fat: list[int] = []

    def place(data: bytes, size: int) -> int:
        count = (len(data) + size - 1) // size
        if count == 0:
            return ENDOFCHAIN
        start = len(sectors)
        for index in range(count):
            sectors.append(data[index * size : (index + 1) * size].ljust(size, b"\x00"))
            fat.append(start + index + 1 if index + 1 < count else ENDOFCHAIN)
        return start

    mini = bytearray()
    mini_fat: list[int] = []
    placed: list[tuple[str, int, int]] = []
    big: list[tuple[int, bytes]] = []
    for name, data in streams:
        if len(data) >= MINI_CUTOFF:
            placed.append((name, -1, len(data)))
            big.append((len(placed) - 1, data))
            continue
        count = (len(data) + MINI_SECTOR - 1) // MINI_SECTOR
        start = len(mini) // MINI_SECTOR if count else ENDOFCHAIN
        for index in range(count):
            mini_fat.append(start + index + 1 if index + 1 < count else ENDOFCHAIN)
        mini += data.ljust(count * MINI_SECTOR, b"\x00")
        placed.append((name, start, len(data)))

    # Directory: root, then streams as a balanced binary tree in sibling order.
    order = sorted(range(len(placed)), key=lambda i: _cfb_key(placed[i][0]))
    left = [NOSTREAM] * len(placed)
    right = [NOSTREAM] * len(placed)

    def tree(lo: int, hi: int) -> int:
        if lo >= hi:
            return NOSTREAM
        middle = (lo + hi) // 2
        node = order[middle]
        left[node] = tree(lo, middle)
        right[node] = tree(middle + 1, hi)
        return node + 1

    top = tree(0, len(order))
    entries_count = 1 + len(placed)
    directory_sectors = (entries_count * 128 + CFB_SECTOR - 1) // CFB_SECTOR
    first_directory = place(bytes(directory_sectors * CFB_SECTOR), CFB_SECTOR)
    first_mini_fat = place(b"".join(struct.pack("<I", e) for e in mini_fat), CFB_SECTOR)
    mini_fat_sectors = (len(mini_fat) * 4 + CFB_SECTOR - 1) // CFB_SECTOR
    mini_start = place(bytes(mini), CFB_SECTOR)
    starts = {index: place(data, CFB_SECTOR) for index, data in big}

    def entry(
        name: str,
        kind: int,
        left_id: int,
        right_id: int,
        child: int,
        start: int,
        size: int,
        klass: bytes = bytes(16),
    ) -> bytes:
        encoded = name.encode("utf-16-le") + b"\x00\x00"
        if len(encoded) > 64:
            raise ArchiveRequestError(f"compound file name too long: {name!r}")
        return (
            encoded.ljust(64, b"\x00")
            + struct.pack("<HBB", len(encoded), kind, 1)
            + struct.pack("<III", left_id, right_id, child)
            + klass
            + bytes(4 + 16)
            + struct.pack("<IQ", start, size)
        )

    directory = entry("Root Entry", 5, NOSTREAM, NOSTREAM, top, mini_start, len(mini), clsid)
    for index, (name, start, size) in enumerate(placed):
        start = starts.get(index, start)
        directory += entry(name, 2, left[index], right[index], NOSTREAM, start, size)
    unused = (
        bytes(64) + struct.pack("<HBB", 0, 0, 0) + struct.pack("<III", NOSTREAM, NOSTREAM, NOSTREAM)
    )
    unused += bytes(128 - len(unused))
    directory += unused * (directory_sectors * 4 - entries_count)
    for index in range(directory_sectors):
        sectors[first_directory + index] = directory[index * CFB_SECTOR : (index + 1) * CFB_SECTOR]

    fat_sectors = 1
    while len(sectors) + fat_sectors > fat_sectors * (CFB_SECTOR // 4):
        fat_sectors += 1
    if fat_sectors > 109:
        raise ArchiveRequestError("compound file too large for a header-only DIFAT")
    fat_at = list(range(len(sectors), len(sectors) + fat_sectors))
    fat += [FATSECT] * fat_sectors
    fat += [FREESECT] * (fat_sectors * (CFB_SECTOR // 4) - len(fat))
    table = b"".join(struct.pack("<I", e) for e in fat)
    sectors += [table[i * CFB_SECTOR : (i + 1) * CFB_SECTOR] for i in range(fat_sectors)]

    header = (
        COMPOUND_FILE + bytes(16) + struct.pack("<HHHHH", 0x003E, 0x0003, 0xFFFE, 9, 6) + bytes(6)
    )
    header += struct.pack(
        "<IIIIIIIII",
        0,
        fat_sectors,
        first_directory,
        0,
        MINI_CUTOFF,
        first_mini_fat,
        mini_fat_sectors,
        ENDOFCHAIN,
        0,
    )
    difat = [*fat_at, *[FREESECT] * (109 - fat_sectors)]
    header += b"".join(struct.pack("<I", s) for s in difat)
    return header + b"".join(sectors)


def msi(entries: Entries) -> bytes:
    """A Windows Installer package holding `entries` in an embedded cabinet (see the module docstring)."""
    streams = [
        (msi_stream_name("_StringPool", table=True), struct.pack("<HH", 1252, 0)),
        (msi_stream_name("_StringData", table=True), b""),
        (msi_stream_name("product.cab"), cab(entries)),
    ]
    return compound_file(streams)
