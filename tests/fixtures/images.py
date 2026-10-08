"""Disk-image fixture generator (WP-1.3). Contract: tests/acceptance/common/images.py.

`build_image(fs, files)` returns a regular file under `<repo>/target/fixtures/` holding only a file system of
type `fs` (no partition table) with the planted `files`, or raises `ImageRequestError` for a request the file
system cannot honour. Nothing is approximated: a name, attribute, stream or time the file system cannot hold
exactly is refused, by the checks below or by the file-system driver itself.

How each file system is populated (no block device is ever touched):
- ext2, ext3, ext4: the files are laid out in a staging directory (names, bytes, times, `user.*` extended
  attributes, symbolic links as given) and `mkfs.<fs> -d` copies it into the image; no root needed.
- fat12, fat16, fat32, exfat, ntfs: `tools/dev/mkimage.sh` creates the file system, then the development
  helper `tools/dev/loopmount.sh rw-image` mounts it (through `sudo -n` and the root-owned copy, or directly
  when running as root as in CI) and the files are written through the driver. FAT attributes are set with
  FAT_IOCTL_SET_ATTRIBUTES, NTFS attributes with the `system.ntfs_attrib_be` attribute of ntfs-3g and NTFS
  alternate data streams as `user.<stream>` attributes of ntfs-3g. No exFAT driver sets attributes, so after
  unmounting the generator sets the bits in the file's directory entry set and recomputes its checksum.
- Every image is checked with the file system's `fsck` in no-change mode before it is returned.

Times: `modified` is `YYYY-MM-DDTHH:MM:SSZ` with even seconds (FAT holds two-second steps), from
1980-01-01T00:00:00Z to 2037-12-31T23:59:58Z on every file system.

Each image has a manifest next to it, `<image>.manifest.json`: the file system, the image name and, per
planted file, its path, size, SHA-256, SHA-1, attributes, time, streams and extended attributes (size and
SHA-256 each) and link target. Images are cached by a hash of the request and of the generator and helper
scripts: the same request returns the same file, which callers never modify.
"""

import errno
import fcntl
import filecmp
import hashlib
import itertools
import json
import os
import re
import shutil
import struct
import subprocess
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "target" / "fixtures"
MKIMAGE = REPO / "tools" / "dev" / "mkimage.sh"
LOOPMOUNT = REPO / "tools" / "dev" / "loopmount.sh"
INSTALLED_HELPER = Path("/usr/local/sbin/ostia-loopmount")
MOUNT_BASE = Path("/run/ostia-loopmount")
SBIN_PATH = f"{os.environ.get('PATH', '')}:/usr/sbin:/sbin"

FILE_SYSTEMS = ("fat12", "fat16", "fat32", "exfat", "ntfs", "ext2", "ext3", "ext4")
FAT = ("fat12", "fat16", "fat32")
EXT = ("ext2", "ext3", "ext4")
WITH_ATTRIBUTES = (*FAT, "exfat", "ntfs")
CASE_INSENSITIVE = (*FAT, "exfat")
KEYS = frozenset(
    {"path", "content", "hidden", "read_only", "modified", "streams", "xattrs", "symlink"}
)
MANIFEST_SCHEMA = "ostia.fixture-image.v1"

TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
TIME_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
EARLIEST = datetime(1980, 1, 1, tzinfo=UTC)
LATEST = datetime(2037, 12, 31, 23, 59, 58, tzinfo=UTC)
NAME_UNITS = 255  # longest name component: UTF-8 bytes on ext, UTF-16 code units elsewhere

MIB = 1 << 20
MIN_MIB = {
    "fat12": 4,
    "fat16": 16,
    "fat32": 64,
    "exfat": 8,
    "ntfs": 8,
    "ext2": 8,
    "ext3": 8,
    "ext4": 8,
}
SLACK_PER_FILE = 16 * 1024  # cluster rounding, directory entries, MFT records, inodes
FAT12_MAX_MIB = 16

HIDDEN, READ_ONLY = 0x02, 0x01  # the same bits in FAT, exFAT and NTFS
FAT_IOCTL_GET_ATTRIBUTES = 0x80047210
FAT_IOCTL_SET_ATTRIBUTES = 0x40047211
NTFS_ATTRIBUTES = "system.ntfs_attrib_be"
# Errors of the driver when it creates a name it cannot hold (fuse-exfat answers ENOENT for control
# characters, vfat EINVAL, a case-insensitive collision EEXIST).
NAME_ERRORS = frozenset(
    {errno.EINVAL, errno.EEXIST, errno.ENAMETOOLONG, errno.EILSEQ, errno.ENOENT}
)

_mount_names = itertools.count()


class ImageRequestError(ValueError):
    """A request the file system cannot honour: refused, never approximated."""


@dataclass(frozen=True)
class _Plant:
    path: str
    content: bytes
    hidden: bool
    read_only: bool
    modified: str | None
    streams: dict[str, bytes]
    xattrs: dict[str, bytes]
    symlink: str | None

    @property
    def epoch(self) -> int | None:
        if self.modified is None:
            return None
        return int(datetime.strptime(self.modified, TIME_FORMAT).replace(tzinfo=UTC).timestamp())

    @property
    def attribute_bits(self) -> int:
        return (HIDDEN if self.hidden else 0) | (READ_ONLY if self.read_only else 0)

    def manifest_entry(self) -> dict[str, object]:
        return {
            "path": self.path,
            "size": len(self.content),
            "sha256": hashlib.sha256(self.content).hexdigest(),
            "sha1": hashlib.sha1(self.content).hexdigest(),
            "hidden": self.hidden,
            "read_only": self.read_only,
            "modified": self.modified,
            "streams": _digests(self.streams),
            "xattrs": _digests(self.xattrs),
            "symlink": self.symlink,
        }


def _digests(values: Mapping[str, bytes]) -> dict[str, dict[str, object]]:
    return {
        name: {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        for name, data in values.items()
    }


def build_image(fs: str, files: Sequence[Mapping[str, object]]) -> Path:
    """An image of file system `fs` holding `files` (see the module docstring and the contract)."""
    plants = _validate(fs, files)
    stem = f"{fs}-{_cache_key(fs, plants)[:16]}"
    image = FIXTURES / f"{stem}.img"
    manifest = image.with_suffix(".manifest.json")
    if image.is_file() and manifest.is_file():
        return image
    FIXTURES.mkdir(parents=True, exist_ok=True)
    partial = FIXTURES / f"{stem}.{os.getpid()}.partial.img"
    partial_manifest = FIXTURES / f"{stem}.{os.getpid()}.partial.json"
    try:
        if fs in EXT:
            _build_ext(fs, plants, partial)
        else:
            _build_mounted(fs, plants, partial)
        _fsck(fs, partial)
        partial_manifest.write_text(
            json.dumps(
                {
                    "schema": MANIFEST_SCHEMA,
                    "fs": fs,
                    "image": image.name,
                    "files": [plant.manifest_entry() for plant in plants],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        os.replace(partial_manifest, manifest)
        os.replace(partial, image)
    finally:
        partial.unlink(missing_ok=True)
        partial_manifest.unlink(missing_ok=True)
    return image


# --- request validation ---------------------------------------------------------------------------


def _refuse(message: str) -> ImageRequestError:
    return ImageRequestError(message)


def _validate(fs: object, files: object) -> list[_Plant]:
    if not isinstance(fs, str) or fs not in FILE_SYSTEMS:
        raise _refuse(f"unknown file system {fs!r} (one of {', '.join(FILE_SYSTEMS)})")
    if isinstance(files, str | bytes) or not isinstance(files, Sequence):
        raise _refuse(f"files must be a list of dicts, got {type(files).__name__}")
    plants = [_validate_file(fs, spec) for spec in files]
    _validate_tree(fs, plants)
    return plants


def _validate_file(fs: str, spec: object) -> _Plant:
    if not isinstance(spec, Mapping):
        raise _refuse(f"each file must be a dict, got {type(spec).__name__}")
    keys = set(spec)
    if keys != KEYS:
        raise _refuse(
            f"file keys must be exactly {sorted(KEYS)}: missing {sorted(KEYS - keys)}, "
            f"unknown {sorted(map(repr, keys - KEYS))}"
        )
    path, content, symlink = spec["path"], spec["content"], spec["symlink"]
    hidden, read_only, modified = spec["hidden"], spec["read_only"], spec["modified"]
    if not isinstance(path, str):
        raise _refuse(f"path must be a str, got {type(path).__name__}")
    _validate_path(fs, path)
    if type(content) is not bytes:
        raise _refuse(f"{path!r}: content must be bytes, got {type(content).__name__}")
    if type(hidden) is not bool or type(read_only) is not bool:
        raise _refuse(f"{path!r}: hidden and read_only must be bool")
    if (hidden or read_only) and fs not in WITH_ATTRIBUTES:
        raise _refuse(f"{path!r}: {fs} has no hidden or read-only attribute")
    time = None if modified is None else _validate_time(path, modified)
    streams = _named_bytes(path, "streams", spec["streams"])
    xattrs = _named_bytes(path, "xattrs", spec["xattrs"])
    _validate_streams(fs, path, streams)
    _validate_xattrs(fs, path, xattrs)
    target = None if symlink is None else _validate_symlink(fs, path, symlink, content, xattrs)
    return _Plant(path, content, hidden, read_only, time, streams, xattrs, target)


def _validate_path(fs: str, path: str) -> None:
    if "\0" in path:
        raise _refuse(f"{path!r}: NUL in a path")
    for part in path.split("/"):
        if part in ("", ".", ".."):
            raise _refuse(f"{path!r}: paths are relative, '/'-separated, without '.', '..' or ''")
        units = len(part.encode()) if fs in EXT else len(part.encode("utf-16-le")) // 2
        if units > NAME_UNITS:
            raise _refuse(f"{path!r}: a name of {fs} holds at most {NAME_UNITS} units")


def _validate_time(path: str, modified: object) -> str:
    if not isinstance(modified, str) or not TIME_PATTERN.fullmatch(modified):
        raise _refuse(f"{path!r}: modified must be YYYY-MM-DDTHH:MM:SSZ or None, got {modified!r}")
    try:
        moment = datetime.strptime(modified, TIME_FORMAT).replace(tzinfo=UTC)
    except ValueError as error:
        raise _refuse(f"{path!r}: modified {modified!r} is not a date") from error
    if moment.second % 2:
        raise _refuse(
            f"{path!r}: modified {modified!r} has odd seconds (FAT holds two-second steps)"
        )
    if not EARLIEST <= moment <= LATEST:
        raise _refuse(f"{path!r}: modified {modified!r} is outside 1980-01-01 .. 2037-12-31")
    return modified


def _named_bytes(path: str, key: str, value: object) -> dict[str, bytes]:
    if not isinstance(value, Mapping):
        raise _refuse(f"{path!r}: {key} must be a dict of name to bytes")
    for name, data in value.items():
        if not isinstance(name, str) or type(data) is not bytes:
            raise _refuse(f"{path!r}: {key} must be a dict of str to bytes")
    return dict(value)


def _validate_streams(fs: str, path: str, streams: Mapping[str, bytes]) -> None:
    if streams and fs != "ntfs":
        raise _refuse(f"{path!r}: alternate data streams exist on ntfs only")
    for name in streams:
        if name == "" or any(c in name for c in "/:\0"):
            raise _refuse(f"{path!r}: invalid stream name {name!r}")


def _validate_xattrs(fs: str, path: str, xattrs: Mapping[str, bytes]) -> None:
    if xattrs and fs not in EXT:
        raise _refuse(f"{path!r}: extended attributes are planted on ext2/3/4 only")
    for name in xattrs:
        if not name.startswith("user.") or name == "user." or "\0" in name:
            raise _refuse(f"{path!r}: extended attribute {name!r} is not a user.* name")


def _validate_symlink(
    fs: str, path: str, symlink: object, content: bytes, xattrs: Mapping[str, bytes]
) -> str:
    if fs not in EXT:
        raise _refuse(f"{path!r}: symbolic links are planted on ext2/3/4 only")
    if not isinstance(symlink, str) or symlink == "" or "\0" in symlink:
        raise _refuse(f"{path!r}: a link target is a non-empty str")
    if content:
        raise _refuse(f"{path!r}: a symbolic link has no content")
    if xattrs:
        raise _refuse(f"{path!r}: Linux keeps no user.* attribute on a symbolic link")
    return symlink


def _validate_tree(fs: str, plants: Sequence[_Plant]) -> None:
    paths = [plant.path for plant in plants]
    if len(set(paths)) != len(paths):
        raise _refuse(f"duplicate paths: {sorted({p for p in paths if paths.count(p) > 1})}")
    directories = {"/".join(p.split("/")[:n]) for p in paths for n in range(1, p.count("/") + 1)}
    clash = sorted(set(paths) & directories)
    if clash:
        raise _refuse(f"{clash[0]!r} is both a file and a directory")
    if fs in CASE_INSENSITIVE:
        seen: dict[str, str] = {}
        for name in sorted(set(paths) | directories):
            other = seen.setdefault(name.upper(), name)
            if other != name:
                raise _refuse(f"{other!r} and {name!r} are the same name on {fs}")


def _cache_key(fs: str, plants: Sequence[_Plant]) -> str:
    digest = hashlib.sha256()
    for source in (Path(__file__), MKIMAGE, LOOPMOUNT):
        digest.update(hashlib.sha256(source.read_bytes()).digest())
    request = {"fs": fs, "files": [plant.manifest_entry() for plant in plants]}
    digest.update(json.dumps(request, sort_keys=True).encode())
    return digest.hexdigest()


def _size_mib(fs: str, plants: Sequence[_Plant]) -> int:
    payload = sum(len(p.content) + sum(map(len, p.streams.values())) for p in plants)
    needed = payload + payload // 4 + SLACK_PER_FILE * len(plants)
    size = MIN_MIB[fs] + -(-needed // MIB)
    if fs == "fat12" and size > FAT12_MAX_MIB:
        raise _refuse(f"{payload} bytes do not fit a FAT12 image of at most {FAT12_MAX_MIB} MiB")
    return size


# --- ext: staging directory and mkfs -d -----------------------------------------------------------


def _build_ext(fs: str, plants: Sequence[_Plant], image: Path) -> None:
    staging = FIXTURES / f".staging-{os.getpid()}-{next(_mount_names)}"
    staging.mkdir(mode=0o755)
    try:
        for plant in plants:
            _stage(staging, plant)
        mkfs = shutil.which(f"mkfs.{fs}", path=SBIN_PATH)
        if mkfs is None:
            raise RuntimeError(f"mkfs.{fs} not found: install e2fsprogs (tools/dev/packages.txt)")
        with image.open("xb") as created:
            created.truncate(_size_mib(fs, plants) * MIB)
        owner = f"root_owner={os.getuid()}:{os.getgid()}"
        result = subprocess.run(
            [mkfs, "-q", "-F", "-L", "OSTIA", "-E", owner, "-d", str(staging), str(image)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"mkfs.{fs} -d failed: {result.stderr.strip()}")
    finally:
        shutil.rmtree(staging)


def _stage(root: Path, plant: _Plant) -> None:
    target = root / plant.path
    target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if plant.symlink is not None:
        os.symlink(plant.symlink, target)
    else:
        with open(target, "xb") as out:
            out.write(plant.content)
        for name, value in plant.xattrs.items():
            os.setxattr(target, name, value)
    if plant.epoch is not None:
        os.utime(target, (plant.epoch, plant.epoch), follow_symlinks=False)


# --- FAT, exFAT, NTFS: written through the driver on a rw-image mount -------------------------------


def _helper(*args: str) -> None:
    if os.geteuid() == 0:
        command = ["bash", str(LOOPMOUNT), *args]
    else:
        if not INSTALLED_HELPER.is_file():
            raise RuntimeError(
                f"{INSTALLED_HELPER} is not installed: run `sudo tools/dev/setup-debian.sh --install`"
            )
        if not filecmp.cmp(INSTALLED_HELPER, LOOPMOUNT, shallow=False):
            raise RuntimeError(
                f"{INSTALLED_HELPER} differs from tools/dev/loopmount.sh: run "
                "`sudo tools/dev/setup-debian.sh --install` again"
            )
        command = ["sudo", "-n", str(INSTALLED_HELPER), *args]
    result = subprocess.run(command, capture_output=True, text=True, cwd=REPO, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"loopmount {args[0]} failed: {result.stderr.strip()}")


@contextmanager
def _rw_mount(image: Path) -> Iterator[Path]:
    name = f"fixture-{os.getpid()}-{next(_mount_names)}"
    _helper("rw-image", str(image), name)
    try:
        yield MOUNT_BASE / str(os.getuid()) / name
    finally:
        _helper("umount", name)


def _build_mounted(fs: str, plants: Sequence[_Plant], image: Path) -> None:
    created = subprocess.run(
        ["bash", str(MKIMAGE), fs, str(_size_mib(fs, plants)), str(image)],
        capture_output=True,
        text=True,
        cwd=REPO,
        check=False,
    )
    if created.returncode != 0:
        raise RuntimeError(f"mkimage {fs} failed: {created.stderr.strip()}")
    with _rw_mount(image) as root:
        for plant in plants:
            _write(fs, root, plant)
    if fs == "exfat":
        _exfat_set_attributes(image, {p.path: p.attribute_bits for p in plants if p.attribute_bits})


@contextmanager
def _naming(fs: str, path: str) -> Iterator[None]:
    """A name the driver refuses to create is a refused request."""
    try:
        yield
    except OSError as error:
        if error.errno in NAME_ERRORS:
            raise _refuse(f"{fs} cannot hold {path!r}: {error.strerror}") from error
        raise


def _write(fs: str, root: Path, plant: _Plant) -> None:
    parts = plant.path.split("/")
    target = root.joinpath(*parts)
    with _naming(fs, plant.path):
        for depth in range(1, len(parts)):
            directory = root.joinpath(*parts[:depth])
            if not directory.is_dir():
                directory.mkdir()
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o644)
    with os.fdopen(descriptor, "wb") as out:
        out.write(plant.content)
    for name, data in plant.streams.items():
        os.setxattr(target, f"user.{name}", data)
    if plant.epoch is not None:
        os.utime(target, (plant.epoch, plant.epoch))
    if plant.attribute_bits and fs in FAT:
        _fat_add_attributes(target, plant.attribute_bits)
    if plant.attribute_bits and fs == "ntfs":
        current = int.from_bytes(os.getxattr(target, NTFS_ATTRIBUTES), "big")
        os.setxattr(target, NTFS_ATTRIBUTES, (current | plant.attribute_bits).to_bytes(4, "big"))
    if plant.epoch is not None and os.stat(target).st_mtime != plant.epoch:
        raise RuntimeError(f"{fs}: the time of {plant.path!r} did not hold")


def _fat_add_attributes(path: Path, bits: int) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        (current,) = struct.unpack("I", fcntl.ioctl(descriptor, FAT_IOCTL_GET_ATTRIBUTES, bytes(4)))
        fcntl.ioctl(descriptor, FAT_IOCTL_SET_ATTRIBUTES, struct.pack("I", current | bits))
    finally:
        os.close(descriptor)


# --- exFAT attributes, set in the directory entry sets --------------------------------------------

EXFAT_FILE, EXFAT_STREAM, EXFAT_NAME, EXFAT_END = 0x85, 0xC0, 0xC1, 0x00
EXFAT_NO_FAT_CHAIN = 0x02
ENTRY = 32


class _Exfat:
    """Just enough of exFAT to find a file's directory entry set by path: boot sector, FAT chains,
    directory entries (exFAT specification §3, §4, §6, §7)."""

    def __init__(self, data: bytearray) -> None:
        if data[3:11] != b"EXFAT   ":
            raise RuntimeError("not an exFAT boot sector")
        self.data = data
        sector = 1 << data[108]
        self.cluster = sector << data[109]
        self.fat = self._u32(80) * sector
        self.heap = self._u32(88) * sector
        self.root = self._u32(96)
        self.count = self._u32(92)

    def _u32(self, offset: int) -> int:
        return int.from_bytes(self.data[offset : offset + 4], "little")

    def _clusters(self, first: int, length: int, contiguous: bool) -> list[int]:
        if contiguous:
            return list(range(first, first + -(-length // self.cluster)))
        chain: list[int] = []
        cluster = first
        while 2 <= cluster < self.count + 2:
            if len(chain) > self.count:
                raise RuntimeError("exFAT: FAT chain loops")
            chain.append(cluster)
            cluster = self._u32(self.fat + 4 * cluster)
        return chain

    def _entries(self, clusters: Sequence[int]) -> list[int]:
        return [
            self.heap + (cluster - 2) * self.cluster + index * ENTRY
            for cluster in clusters
            for index in range(self.cluster // ENTRY)
        ]

    def _lookup(self, entries: Sequence[int], name: str) -> list[int]:
        index = 0
        while index < len(entries) and self.data[entries[index]] != EXFAT_END:
            if self.data[entries[index]] != EXFAT_FILE:
                index += 1
                continue
            entry_set = list(entries[index : index + self.data[entries[index] + 1] + 1])
            stream = entry_set[1] if len(entry_set) > 1 else None
            if stream is not None and self.data[stream] == EXFAT_STREAM:
                units = self.data[stream + 3]
                encoded = b"".join(
                    bytes(self.data[e + 2 : e + ENTRY])
                    for e in entry_set[2:]
                    if self.data[e] == EXFAT_NAME
                )
                if encoded[: 2 * units].decode("utf-16-le", "surrogatepass") == name:
                    return entry_set
            index += len(entry_set)
        raise RuntimeError(f"exFAT: no directory entry for {name!r}")

    def entry_set(self, path: str) -> list[int]:
        clusters = self._clusters(self.root, 0, contiguous=False)
        parts = path.split("/")
        for part in parts[:-1]:
            stream = self._lookup(self._entries(clusters), part)[1]
            first = self._u32(stream + 20)
            length = int.from_bytes(self.data[stream + 24 : stream + 32], "little")
            clusters = self._clusters(
                first, length, bool(self.data[stream + 1] & EXFAT_NO_FAT_CHAIN)
            )
        return self._lookup(self._entries(clusters), parts[-1])

    def set_checksum(self, entry_set: Sequence[int]) -> int:
        checksum = 0
        for position, offset in enumerate(entry_set):
            for index in range(ENTRY):
                if position == 0 and index in (2, 3):
                    continue
                rotated = (checksum >> 1) | ((checksum & 1) << 15)
                checksum = (rotated + self.data[offset + index]) & 0xFFFF
        return checksum


def _exfat_set_attributes(image: Path, wanted: Mapping[str, int]) -> None:
    if not wanted:
        return
    with image.open("r+b") as disk:
        data = bytearray(disk.read())
        volume = _Exfat(data)
        for path, bits in wanted.items():
            entry_set = volume.entry_set(path)
            file_entry = entry_set[0]
            attributes = int.from_bytes(data[file_entry + 4 : file_entry + 6], "little") | bits
            data[file_entry + 4 : file_entry + 6] = attributes.to_bytes(2, "little")
            data[file_entry + 2 : file_entry + 4] = volume.set_checksum(entry_set).to_bytes(
                2, "little"
            )
        disk.seek(0)
        disk.write(data)


# --- consistency ----------------------------------------------------------------------------------

FSCK = {
    "fat12": ["fsck.vfat", "-n"],
    "fat16": ["fsck.vfat", "-n"],
    "fat32": ["fsck.vfat", "-n"],
    "exfat": ["fsck.exfat", "-n"],
    "ntfs": ["ntfsfix", "--no-action"],
    "ext2": ["e2fsck", "-f", "-n"],
    "ext3": ["e2fsck", "-f", "-n"],
    "ext4": ["e2fsck", "-f", "-n"],
}


def _fsck(fs: str, image: Path) -> None:
    command, *args = FSCK[fs]
    found = shutil.which(command, path=SBIN_PATH)
    if found is None:
        raise RuntimeError(f"{command} not found (tools/dev/packages.txt)")
    result = subprocess.run([found, *args, str(image)], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{command} found errors in the {fs} image: {result.stdout.strip()}")
