"""Disk images for `ostia scan --image`.

`build_image` is the contract of the disk-image generator that WP-1.3 writes in `tests/fixtures/images.py`:

    build_image(fs: str, files: list[dict]) -> str | Path

- `fs`: one of FILE_SYSTEMS.
- `files`: one dict per planted file, with exactly these keys:
  `path` (str, `/`-separated, relative), `content` (bytes), `hidden` and `read_only` (bool: the file-system
  hidden and read-only attributes; only on fat12/16/32, exfat, ntfs), `modified` (RFC 3339 UTC string with whole even seconds, or None),
  `streams` (dict name -> bytes: NTFS alternate data streams; ntfs only), `xattrs` (dict name -> bytes:
  `user.*` extended attributes; ext2/3/4 only), `symlink` (str or None: when set, the entry is a symbolic link
  to this target, written as given and never resolved, `content` is empty; ext2/3/4 only). A request the file
  system cannot honour is refused with an exception, never approximated. Directories are created as needed.
- Returns the path of a regular image file holding only that file system (no partition table), under
  `<repo>/target/fixtures/` (where the development mount helper accepts images). The generator may cache
  images keyed by the request; callers never modify the file.
"""

import importlib
import subprocess
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from common.ostia import REPO

FILE_SYSTEMS = ("fat12", "fat16", "fat32", "exfat", "ntfs", "ext2", "ext3", "ext4")
GENERATOR = "tests.fixtures.images"
FIXTURES = REPO / "target" / "fixtures"


@dataclass(frozen=True)
class Planted:
    """One file planted in an image, declared by the test."""

    path: str
    content: bytes
    hidden: bool = False
    read_only: bool = False
    modified: datetime | None = None
    streams: Mapping[str, bytes] = field(default_factory=dict)
    xattrs: Mapping[str, bytes] = field(default_factory=dict)
    symlink: str | None = None

    def spec(self) -> dict[str, Any]:
        modified = None
        if self.modified is not None:
            modified = self.modified.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {
            "path": self.path,
            "content": self.content,
            "hidden": self.hidden,
            "read_only": self.read_only,
            "modified": modified,
            "streams": dict(self.streams),
            "xattrs": dict(self.xattrs),
            "symlink": self.symlink,
        }


def build_image(fs: str, files: Sequence[Planted]) -> Path:
    """An image of file system `fs` holding `files`, from the WP-1.3 generator."""
    assert fs in FILE_SYSTEMS, f"unknown file system {fs!r}"
    try:
        generator = importlib.import_module(GENERATOR)
    except ModuleNotFoundError as error:
        if error.name in ("tests.fixtures", GENERATOR):
            raise AssertionError(
                "disk-image generator tests/fixtures/images.py is not implemented (WP-1.3)"
            ) from error
        raise
    image = Path(generator.build_image(fs, [planted.spec() for planted in files]))
    assert image.is_file(), f"the generator returned {image}, which is not a file"
    return image


def _unique(stem: str) -> Path:
    """A new file name under target/fixtures/ (where the mount helper accepts images), unique per call."""
    FIXTURES.mkdir(parents=True, exist_ok=True)
    return FIXTURES / f"acceptance-{stem}-{uuid.uuid4().hex[:12]}.img"


def _fresh(stem: str, size_mib: int) -> Path:
    path = _unique(stem)
    with path.open("wb") as image:
        image.truncate(size_mib * 1024 * 1024)
    return path


def blank_image(size_mib: int = 4) -> Path:
    """An image of zeros: no file system at all."""
    return _fresh("blank", size_mib)


def minix_image(size_mib: int = 4) -> Path:
    """A valid MINIX v3 file system, outside FR-03's list (mkfs.minix, util-linux, on a regular file)."""
    path = _fresh("minix", size_mib)
    subprocess.run(["mkfs.minix", "-3", str(path)], check=True, capture_output=True)
    return path


def damaged_copy(image: Path, start: int, length: int) -> Path:
    """A copy of `image` with `length` bytes zeroed from offset `start` (the original, maybe cached, is kept)."""
    path = _unique("damaged")
    data = bytearray(image.read_bytes())
    assert start + length <= len(data), "the damaged range is outside the image"
    data[start : start + length] = bytes(length)
    path.write_bytes(bytes(data))
    return path
