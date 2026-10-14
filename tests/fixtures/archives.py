"""Archive builder for the formats of FR-06 beyond zip, tar and gzip (WP-1.9). Contract:
tests/acceptance/common/archives.py. Not implemented yet.
"""

from collections.abc import Sequence

Entries = Sequence[tuple[str, bytes]]


class ArchiveRequestError(ValueError):
    """A request the builder cannot honour."""


def build_archive(fmt: str, entries: Entries) -> bytes:
    """An archive of format `fmt` holding `entries`."""
    raise NotImplementedError(f"archive builder: {fmt}")
