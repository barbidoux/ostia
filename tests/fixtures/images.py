"""Disk-image fixture generator (WP-1.3). Contract: tests/acceptance/common/images.py."""

from collections.abc import Mapping, Sequence
from pathlib import Path

FILE_SYSTEMS = ("fat12", "fat16", "fat32", "exfat", "ntfs", "ext2", "ext3", "ext4")


class ImageRequestError(ValueError):
    """A request the file system cannot honour: refused, never approximated."""


def build_image(fs: str, files: Sequence[Mapping[str, object]]) -> Path:
    """An image of file system `fs` holding `files`."""
    raise NotImplementedError("WP-1.3: disk-image generator")
