"""Archives built at test time. zip, tar and gzip come from the standard library; the other formats of
FR-06 come from the archive builder that WP-1.9 writes in `tests/fixtures/archives.py`:

    build_archive(fmt: str, entries: list[tuple[str, bytes]]) -> bytes

with `fmt` in `7z`, `rar`, `cab`, `iso`, `msi`; entries are (`/`-separated path, content); every entry's
content is stored so that extracting the archive yields exactly these bytes (names may follow the format's
conventions, for example a flat name in a cab). A format it cannot build is refused with an exception.
"""

import gzip
import importlib
import io
import tarfile
import zipfile
from collections.abc import Sequence

GENERATOR = "tests.fixtures.archives"
EPOCH_1980 = (1980, 1, 1, 0, 0, 0)


def zip_bytes(
    entries: Sequence[tuple[str, bytes]], *, compression: int = zipfile.ZIP_DEFLATED
) -> bytes:
    """A zip archive with fixed timestamps (deterministic)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in entries:
            info = zipfile.ZipInfo(name, date_time=EPOCH_1980)
            info.compress_type = compression
            archive.writestr(
                info, content, compresslevel=9 if compression == zipfile.ZIP_DEFLATED else None
            )
    return buffer.getvalue()


def tar_bytes(entries: Sequence[tuple[str, bytes]]) -> bytes:
    """A ustar archive with fixed metadata."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, content in entries:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mtime = 0
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def gzip_bytes(name: str, content: bytes) -> bytes:
    """A gzip member whose header carries `name` (FNAME) and mtime 0."""
    buffer = io.BytesIO()
    with gzip.GzipFile(
        filename=name, mode="wb", fileobj=buffer, mtime=0, compresslevel=9
    ) as member:
        member.write(content)
    return buffer.getvalue()


def build_archive(fmt: str, entries: Sequence[tuple[str, bytes]]) -> bytes:
    """An archive of format `fmt` holding `entries`."""
    if fmt == "zip":
        return zip_bytes(entries)
    if fmt == "tar":
        return tar_bytes(entries)
    try:
        generator = importlib.import_module(GENERATOR)
    except ModuleNotFoundError as error:
        if error.name in ("tests.fixtures", GENERATOR):
            raise AssertionError(
                f"archive builder tests/fixtures/archives.py is not implemented (WP-1.9): {fmt}"
            ) from error
        raise
    data = generator.build_archive(fmt, list(entries))
    assert isinstance(data, bytes) and data, f"the archive builder returned no {fmt} bytes"
    return data
