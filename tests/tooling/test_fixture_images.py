"""Self-tests of the disk-image generator `tests/fixtures/images.py` (WP-1.3), whose contract is the locked
`tests/acceptance/common/images.py`: every image is a bare file system of the requested type under
target/fixtures/, mounts read-only through the development helper and holds exactly the planted content;
the generator's manifest lists the same; a request the file system cannot honour is refused.

Expected values are the literal plants of this file. They are read back without the generator: through the
kernel or FUSE driver on a read-only mount (names, bytes, times, extended attributes, links),
FAT_IOCTL_GET_ATTRIBUTES (FAT attributes), ntfsinfo and ntfscat (NTFS attributes and streams), a scan of the
raw exFAT directory entries (exFAT attributes), blkid and fsck. Mounting needs the helper of
docs/dev-setup.md, as in test_dev_images.py.
"""

import fcntl
import filecmp
import hashlib
import importlib
import json
import os
import stat
import struct
import subprocess
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import pytest

from tooling_support import REPO, run

# Loaded by the name the acceptance helpers use (tests/acceptance/common/images.py); `tests/` is not a
# package, so a static import would give the module a second name for mypy.
GENERATOR = importlib.import_module("tests.fixtures.images")
build_image: Callable[[str, list[dict[str, Any]]], str | Path] = GENERATOR.build_image
ImageRequestError: type[ValueError] = GENERATOR.ImageRequestError

LOOPMOUNT = REPO / "tools" / "dev" / "loopmount.sh"
INSTALLED_HELPER = Path("/usr/local/sbin/ostia-loopmount")
MOUNT_BASE = Path("/run/ostia-loopmount") / str(os.getuid())
FIXTURES = REPO / "target" / "fixtures"
SBIN_PATH = f"{os.environ.get('PATH', '')}:/usr/sbin:/sbin"

FAT = ("fat12", "fat16", "fat32")
EXT = ("ext2", "ext3", "ext4")
ALL = (*FAT, "exfat", "ntfs", *EXT)
# blkid -p TYPE and VERSION of each requested file system (VERSION where it tells the variants apart).
BLKID = {
    "fat12": ("vfat", "FAT12"),
    "fat16": ("vfat", "FAT16"),
    "fat32": ("vfat", "FAT32"),
    "exfat": ("exfat", None),
    "ntfs": ("ntfs", None),
    "ext2": ("ext2", None),
    "ext3": ("ext3", None),
    "ext4": ("ext4", None),
}
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

MODIFIED = "2024-03-01T10:20:30Z"
LATER = "2031-12-24T23:58:58Z"
EPOCH = {MODIFIED: 1_709_288_430, LATER: 1_955_923_138}
RLO = chr(0x202E)  # RIGHT-TO-LEFT OVERRIDE: "invoice<RLO>fdp.exe" displays as "invoiceexe.pdf"
BEL = chr(0x07)
HIDDEN, READ_ONLY = 0x02, 0x01  # FAT and exFAT attribute bits
FAT_IOCTL_GET_ATTRIBUTES = 0x80047210


@dataclass(frozen=True)
class Plant:
    path: str
    content: bytes = b""
    hidden: bool = False
    read_only: bool = False
    modified: str | None = MODIFIED
    streams: dict[str, bytes] = field(default_factory=dict)
    xattrs: dict[str, bytes] = field(default_factory=dict)
    symlink: str | None = None

    def spec(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "content": self.content,
            "hidden": self.hidden,
            "read_only": self.read_only,
            "modified": self.modified,
            "streams": dict(self.streams),
            "xattrs": dict(self.xattrs),
            "symlink": self.symlink,
        }

    def attribute_bits(self) -> int:
        return (HIDDEN if self.hidden else 0) | (READ_ONLY if self.read_only else 0)


BIG = (bytes(range(251)) * 4178)[
    : 1_048_576 + 3
]  # more than 1 MiB, not a multiple of any block size
ZONE = b"[ZoneTransfer]\r\nZoneId=3\r\n"
ATTRIBUTES = [
    Plant("hid.txt", b"hidden attribute", hidden=True),
    Plant("ro.txt", b"read-only attribute", read_only=True),
    Plant("both.txt", b"hidden and read-only", hidden=True, read_only=True),
    Plant("plain.txt", b"no attribute"),
]
STREAMS = [
    Plant("host.txt", b"host of streams", streams={"Zone.Identifier": ZONE, "bin": b"\0\1\2"}),
    Plant("docs/carrier.txt", b"nested host", streams={"payload": b"MZ in a stream"}),
]
XATTRS = [
    Plant("tagged.txt", b"host of attributes", xattrs={"user.comment": b"planted"}),
    Plant("docs/two.txt", b"two", xattrs={"user.a": b"1", "user.b": b"\0\xff"}),
]
LINKS = [
    Plant("escape-absolute", symlink="/etc/hostname"),
    Plant("escape-relative", symlink="../../../etc/hostname"),
    Plant("docs/inside", symlink="../readme.txt"),
    Plant("dangling", symlink="missing/target", modified=LATER),
]


def plants(fs: str) -> list[Plant]:
    files = [
        Plant("readme.txt", b"readme\n"),
        Plant("docs/deep/nested/report.pdf", b"%PDF-1.4 nested\n"),
        Plant("empty.dat", b""),
        Plant("big.bin", BIG),
        Plant("photo.jpg.exe", b"MZ double extension"),
        Plant(".dotfile", b"dot file\n", modified=LATER),
        Plant("n" * 200 + ".txt", b"long name"),
        Plant(f"invoice{RLO}fdp.exe", b"trapped name"),
        Plant("caf\N{LATIN SMALL LETTER E WITH ACUTE}.txt", b"accent"),
    ]
    if fs in EXT:
        return files + XATTRS + LINKS + [Plant(f"bell{BEL}.txt", b"control character")]
    if fs == "ntfs":
        return files + ATTRIBUTES + STREAMS + [Plant(f"bell{BEL}.txt", b"control character")]
    return files + ATTRIBUTES


def loopmount(*args: str) -> subprocess.CompletedProcess[str]:
    if os.geteuid() == 0:
        return run(["bash", str(LOOPMOUNT), *args], cwd=REPO)
    assert INSTALLED_HELPER.is_file(), (
        f"{INSTALLED_HELPER} is not installed: run `sudo tools/dev/setup-debian.sh --install`"
    )
    assert filecmp.cmp(INSTALLED_HELPER, LOOPMOUNT, shallow=False), (
        f"{INSTALLED_HELPER} differs from tools/dev/loopmount.sh: run "
        "`sudo tools/dev/setup-debian.sh --install` again"
    )
    return run(["sudo", "-n", str(INSTALLED_HELPER), *args], cwd=REPO)


@pytest.fixture
def mounted() -> Iterator[list[str]]:
    """Mount names used by a test; whatever is still mounted at the end is unmounted."""
    names: list[str] = []
    yield names
    for name in names:
        if os.path.ismount(MOUNT_BASE / name):
            loopmount("umount", name)


def mount_ro(image: Path, names: list[str]) -> Path:
    name = f"selftest-{os.getpid()}-{len(names)}"
    names.append(name)
    result = loopmount("ro", str(image), name)
    assert result.returncode == 0, result.stdout + result.stderr
    return MOUNT_BASE / name


def listing(root: Path) -> dict[str, os.stat_result]:
    """Every entry under root that is not a directory, by relative path, links not followed."""
    found: dict[str, os.stat_result] = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        links = [d for d in dirs if os.path.islink(os.path.join(directory, d))]
        for entry in [*files, *links]:
            path = os.path.join(directory, entry)
            found[os.path.relpath(path, root)] = os.lstat(path)
    return found


def tool(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        args, capture_output=True, env={**os.environ, "PATH": SBIN_PATH}, check=False
    )


Built = tuple[list[Plant], Path]


@pytest.fixture(scope="module")
def image_of() -> Callable[[str], Built]:
    """The image of `plants(fs)`, built once per file system for the whole module."""
    built: dict[str, Built] = {}

    def get(fs: str) -> Built:
        if fs not in built:
            files = plants(fs)
            built[fs] = (files, Path(build_image(fs, [p.spec() for p in files])))
        return built[fs]

    return get


@pytest.mark.req("TOOLING")
@pytest.mark.slow
@pytest.mark.parametrize("fs", ALL)
def test_image_is_a_bare_clean_file_system_of_the_requested_type(
    image_of: Callable[[str], Built], fs: str
) -> None:
    _, image = image_of(fs)
    assert image.is_file() and not image.is_symlink()
    assert image.parent == FIXTURES
    fs_type, version = BLKID[fs]
    probe = tool("blkid", "-p", "-o", "export", str(image))
    fields = dict(line.split("=", 1) for line in probe.stdout.decode().split())
    assert fields["TYPE"] == fs_type, fields
    assert "PTTYPE" not in fields, fields
    if version is not None:
        assert fields["VERSION"] == version, fields
    checked = tool(*FSCK[fs], str(image))
    assert checked.returncode == 0, checked.stdout.decode() + checked.stderr.decode()


@pytest.mark.req("TOOLING")
@pytest.mark.slow
@pytest.mark.parametrize("fs", ALL)
def test_image_mounts_and_holds_exactly_the_planted_files(
    image_of: Callable[[str], Built], mounted: list[str], fs: str
) -> None:
    files, image = image_of(fs)
    root = mount_ro(image, mounted)
    found = listing(root)
    assert sorted(found) == sorted(p.path for p in files)
    for plant in files:
        entry = found[plant.path]
        if plant.symlink is None:
            assert stat.S_ISREG(entry.st_mode), plant.path
            assert (root / plant.path).read_bytes() == plant.content, plant.path
        else:
            assert stat.S_ISLNK(entry.st_mode), plant.path
            assert os.readlink(root / plant.path) == plant.symlink, plant.path
        assert plant.modified is not None
        assert entry.st_mtime == EPOCH[plant.modified], plant.path


@pytest.mark.req("TOOLING")
@pytest.mark.slow
@pytest.mark.parametrize("fs", FAT)
def test_fat_attributes_are_planted(
    image_of: Callable[[str], Built], mounted: list[str], fs: str
) -> None:
    files, image = image_of(fs)
    root = mount_ro(image, mounted)
    for plant in files:
        fd = os.open(root / plant.path, os.O_RDONLY)
        try:
            (bits,) = struct.unpack("I", fcntl.ioctl(fd, FAT_IOCTL_GET_ATTRIBUTES, b"\0" * 4))
        finally:
            os.close(fd)
        assert bits & (HIDDEN | READ_ONLY) == plant.attribute_bits(), plant.path


def exfat_attributes(image: Path, name: str) -> int:
    """FileAttributes of the file entry whose name entry holds `name` (at most 15 characters, unique in the
    image): the file entry is two entries before its first name entry."""
    data = image.read_bytes()
    needle = bytes([0xC1, 0x00]) + name.encode("utf-16-le")
    entries = []
    start = 0
    while (found := data.find(needle, start)) != -1:
        if found % 32 == 0 and data[found - 64] == 0x85 and data[found - 32] == 0xC0:
            entries.append(found - 64)
        start = found + 1
    assert len(entries) == 1, f"{name}: {len(entries)} file entries"
    return int.from_bytes(data[entries[0] + 4 : entries[0] + 6], "little")


@pytest.mark.req("TOOLING")
@pytest.mark.slow
def test_exfat_attributes_are_planted(image_of: Callable[[str], Built]) -> None:
    files, image = image_of("exfat")
    short = [plant for plant in files if len(plant.path) <= 15]
    assert {p.path for p in ATTRIBUTES} <= {p.path for p in short}
    for plant in short:
        bits = exfat_attributes(image, plant.path)
        assert bits & (HIDDEN | READ_ONLY) == plant.attribute_bits(), plant.path


def ntfs_info(image: Path, path: str) -> str:
    info = tool("ntfsinfo", "-F", "/" + path, str(image))
    assert info.returncode == 0, info.stderr.decode()
    return info.stdout.decode()


def ntfs_flags(image: Path, path: str) -> set[str]:
    """The flags of the file's $STANDARD_INFORMATION, as ntfsinfo names them."""
    section = ntfs_info(image, path).split("$STANDARD_INFORMATION", 1)[1].split("Dumping", 1)[0]
    line = next(line for line in section.splitlines() if "File attributes:" in line)
    return set(line.split(":", 1)[1].split("(")[0].split())


def ntfs_streams(image: Path, path: str) -> dict[str, bytes]:
    """Named $DATA streams of a file: names from ntfsinfo, bytes from ntfscat."""
    names = []
    for section in ntfs_info(image, path).split("Dumping attribute $DATA")[1:]:
        for line in section.split("Dumping", 1)[0].splitlines():
            if line.strip().startswith("Attribute name:"):
                names.append(line.split("'")[1])
    streams = {}
    for name in names:
        cat = tool("ntfscat", "-a", "0x80", "-n", name, str(image), "/" + path)
        assert cat.returncode == 0, cat.stderr.decode()
        streams[name] = cat.stdout
    return streams


@pytest.mark.req("TOOLING")
@pytest.mark.slow
def test_ntfs_attributes_are_planted(image_of: Callable[[str], Built]) -> None:
    files, image = image_of("ntfs")
    for plant in files:
        flags = ntfs_flags(image, plant.path)
        assert ("HIDDEN" in flags, "READONLY" in flags) == (plant.hidden, plant.read_only), (
            plant.path,
            flags,
        )


@pytest.mark.req("TOOLING")
@pytest.mark.slow
def test_ntfs_alternate_data_streams_are_planted(image_of: Callable[[str], Built]) -> None:
    _, image = image_of("ntfs")
    assert ntfs_streams(image, "host.txt") == {"Zone.Identifier": ZONE, "bin": b"\0\1\2"}
    assert ntfs_streams(image, "docs/carrier.txt") == {"payload": b"MZ in a stream"}
    assert ntfs_streams(image, "readme.txt") == {}


def ext_user_xattrs(image: Path, path: str, scratch: Path) -> dict[str, bytes]:
    """The user.* attributes of a file, read with debugfs: no mount, since a kernel ext2 driver built
    without xattr support (the WSL2 kernel's) hides them."""
    listed = tool("debugfs", "-R", f"ea_list /{path}", str(image))
    assert listed.returncode == 0, listed.stderr.decode()
    names = [
        line.split(" (", 1)[0].strip()
        for line in listed.stdout.decode().splitlines()
        if line.startswith("  user.")
    ]
    values = {}
    for name in names:
        out = scratch / "value"
        got = tool("debugfs", "-R", f"ea_get -f {out} /{path} {name}", str(image))
        assert got.returncode == 0, got.stderr.decode()
        values[name] = out.read_bytes()
    return values


@pytest.mark.req("TOOLING")
@pytest.mark.slow
@pytest.mark.parametrize("fs", EXT)
def test_ext_extended_attributes_are_planted(
    image_of: Callable[[str], Built], tmp_path: Path, fs: str
) -> None:
    files, image = image_of(fs)
    for plant in (p for p in files if p.symlink is None):
        assert ext_user_xattrs(image, plant.path, tmp_path) == plant.xattrs, plant.path


@pytest.mark.req("TOOLING")
@pytest.mark.slow
@pytest.mark.parametrize("fs", ALL)
def test_manifest_lists_exactly_the_planted_content(
    image_of: Callable[[str], Built], fs: str
) -> None:
    files, image = image_of(fs)
    manifest = json.loads(image.with_suffix(".manifest.json").read_text())
    assert (manifest["fs"], manifest["image"]) == (fs, image.name)
    listed = {entry["path"]: entry for entry in manifest["files"]}
    assert sorted(listed) == sorted(p.path for p in files)
    for plant in files:
        entry = listed[plant.path]
        assert entry["size"] == len(plant.content)
        assert entry["sha256"] == hashlib.sha256(plant.content).hexdigest()
        assert entry["sha1"] == hashlib.sha1(plant.content).hexdigest()
        assert (entry["hidden"], entry["read_only"]) == (plant.hidden, plant.read_only)
        assert (entry["modified"], entry["symlink"]) == (plant.modified, plant.symlink)
        for key, planted in (("streams", plant.streams), ("xattrs", plant.xattrs)):
            assert entry[key] == {
                name: {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                for name, data in planted.items()
            }


def specs(*files: Plant) -> list[dict[str, Any]]:
    return [p.spec() for p in files]


A = Plant("a.txt", b"a")


@pytest.mark.req("TOOLING")
def test_same_request_is_served_from_the_cache() -> None:
    first = Path(build_image("ext4", specs(A)))
    before = first.stat()
    again = Path(build_image("ext4", specs(A)))
    assert again == first
    assert (again.stat().st_ino, again.stat().st_mtime_ns) == (before.st_ino, before.st_mtime_ns)


@pytest.mark.req("TOOLING")
def test_different_requests_give_different_images() -> None:
    images = {
        Path(build_image("ext4", specs(A))),
        Path(build_image("ext4", specs(A, Plant("b.txt", b"b")))),
        Path(build_image("ext4", specs(Plant("a.txt", b"A")))),
        Path(build_image("ext4", specs(Plant("a.txt", b"a", modified=LATER)))),
        Path(build_image("ext4", specs(Plant("a.txt", b"a", xattrs={"user.c": b"x"})))),
        Path(build_image("ext2", specs(A))),
    }
    assert len(images) == 6


def with_key(key: str, value: object) -> list[dict[str, Any]]:
    spec = A.spec()
    spec[key] = value
    return [spec]


def without_key(key: str) -> list[dict[str, Any]]:
    spec = A.spec()
    del spec[key]
    return [spec]


# (id, file system, request): each is refused with ImageRequestError and leaves nothing behind.
REFUSED: list[tuple[str, str, Any]] = [
    ("unknown-fs", "hfsplus", specs(A)),
    ("files-not-a-list", "ext4", "a.txt"),
    ("file-not-a-dict", "ext4", ["a.txt"]),
    ("missing-key", "ext4", without_key("symlink")),
    ("extra-key", "ext4", with_key("mode", 0o644)),
    ("content-str", "ext4", with_key("content", "a")),
    ("content-bytearray", "ext4", with_key("content", bytearray(b"a"))),
    ("path-bytes", "ext4", with_key("path", b"a.txt")),
    ("hidden-int", "fat16", with_key("hidden", 1)),
    ("read-only-none", "fat16", with_key("read_only", None)),
    ("streams-list", "ntfs", with_key("streams", [("s", b"x")])),
    ("stream-value-str", "ntfs", with_key("streams", {"s": "x"})),
    ("xattrs-none", "ext4", with_key("xattrs", None)),
    ("symlink-bytes", "ext4", with_key("symlink", b"a")),
    ("modified-int", "ext4", with_key("modified", 1_709_288_430)),
    ("absolute-path", "ext4", specs(Plant("/etc/a.txt", b"a"))),
    ("dot-dot", "ext4", specs(Plant("docs/../a.txt", b"a"))),
    ("dot", "ext4", specs(Plant("./a.txt", b"a"))),
    ("empty-path", "ext4", specs(Plant("", b"a"))),
    ("empty-component", "ext4", specs(Plant("docs//a.txt", b"a"))),
    ("trailing-slash", "ext4", specs(Plant("docs/", b"a"))),
    ("nul-in-path", "ext4", specs(Plant("a\0.txt", b"a"))),
    ("duplicate-path", "ext4", specs(A, Plant("a.txt", b"b"))),
    ("file-under-file", "ext4", specs(Plant("a", b"a"), Plant("a/b", b"b"))),
    ("hidden-on-ext", "ext4", specs(Plant("a.txt", b"a", hidden=True))),
    ("read-only-on-ext", "ext3", specs(Plant("a.txt", b"a", read_only=True))),
    ("stream-on-ext", "ext4", specs(Plant("a.txt", b"a", streams={"s": b"x"}))),
    ("stream-on-fat", "fat32", specs(Plant("a.txt", b"a", streams={"s": b"x"}))),
    ("stream-on-exfat", "exfat", specs(Plant("a.txt", b"a", streams={"s": b"x"}))),
    ("stream-name-colon", "ntfs", specs(Plant("a.txt", b"a", streams={"s:t": b"x"}))),
    ("stream-name-empty", "ntfs", specs(Plant("a.txt", b"a", streams={"": b"x"}))),
    ("xattr-on-ntfs", "ntfs", specs(Plant("a.txt", b"a", xattrs={"user.c": b"x"}))),
    ("xattr-on-fat", "fat16", specs(Plant("a.txt", b"a", xattrs={"user.c": b"x"}))),
    ("xattr-not-user", "ext4", specs(Plant("a.txt", b"a", xattrs={"trusted.c": b"x"}))),
    ("xattr-empty-name", "ext4", specs(Plant("a.txt", b"a", xattrs={"user.": b"x"}))),
    ("symlink-on-ntfs", "ntfs", specs(Plant("l", symlink="a.txt"))),
    ("symlink-on-fat", "fat12", specs(Plant("l", symlink="a.txt"))),
    ("symlink-with-content", "ext4", specs(Plant("l", b"x", symlink="a.txt"))),
    ("symlink-with-xattr", "ext4", specs(Plant("l", symlink="a.txt", xattrs={"user.c": b"x"}))),
    ("symlink-empty", "ext4", specs(Plant("l", symlink=""))),
    ("odd-seconds", "fat16", specs(Plant("a.txt", b"a", modified="2024-03-01T10:20:31Z"))),
    ("offset", "ext4", specs(Plant("a.txt", b"a", modified="2024-03-01T10:20:30+01:00"))),
    ("fraction", "ext4", specs(Plant("a.txt", b"a", modified="2024-03-01T10:20:30.5Z"))),
    ("before-1980", "ext4", specs(Plant("a.txt", b"a", modified="1979-12-31T23:59:58Z"))),
    ("after-2037", "ext4", specs(Plant("a.txt", b"a", modified="2038-01-01T00:00:00Z"))),
    ("not-a-date", "ext4", specs(Plant("a.txt", b"a", modified="2024-02-30T10:20:30Z"))),
    ("control-on-fat", "fat16", specs(Plant(f"bell{BEL}.txt", b"a"))),
    ("control-on-exfat", "exfat", specs(Plant(f"bell{BEL}.txt", b"a"))),
    ("reserved-on-fat", "fat32", specs(Plant("what?.txt", b"a"))),
    ("case-collision-fat", "fat16", specs(Plant("A.txt", b"a"), A)),
    ("case-collision-exfat", "exfat", specs(Plant("A.txt", b"a"), A)),
    ("case-collision-dir", "fat32", specs(Plant("Docs/a.txt", b"a"), Plant("docs/b.txt", b"b"))),
    ("name-too-long", "ext4", specs(Plant("n" * 256, b"a"))),
]


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(("fs", "files"), [r[1:] for r in REFUSED], ids=[r[0] for r in REFUSED])
def test_request_the_file_system_cannot_honour_is_refused(fs: str, files: object) -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    before = set(FIXTURES.iterdir())
    mounts_before = set(MOUNT_BASE.iterdir()) if MOUNT_BASE.is_dir() else set()
    with pytest.raises(ImageRequestError):
        build_image(fs, cast("list[dict[str, Any]]", files))
    assert set(FIXTURES.iterdir()) == before
    mounts_after = set(MOUNT_BASE.iterdir()) if MOUNT_BASE.is_dir() else set()
    assert mounts_after == mounts_before


@pytest.mark.req("TOOLING")
def test_a_name_the_driver_refuses_is_a_refusal_naming_the_path() -> None:
    with pytest.raises(ImageRequestError) as refused:
        build_image("fat16", specs(Plant(f"bell{BEL}.txt", b"a")))
    assert repr(f"bell{BEL}.txt") in str(refused.value)
