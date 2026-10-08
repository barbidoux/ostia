"""FR-06 and FR-08: archives are extracted recursively and every extracted object is analysed; any breach of
the policy's limits on depth, compression ratio, total size or entry count makes the archive UNSCANNABLE, and
a malformed archive is UNSCANNABLE without stopping the scan. Bombs are a few KiB built at test time."""

import struct
import zipfile
from pathlib import Path
from typing import Any

import pytest
from common import (
    Planted,
    Scan,
    build_archive,
    build_image,
    fake_engine_config,
    gzip_bytes,
    policy_document,
    scan,
    seeded_bytes,
    sha256,
    tar_bytes,
    text_bytes,
    write_signed_policy,
    zip_bytes,
)

ENGINES = {
    "fake-av": {"role": "detector", "trusted_alone": False},
    "fake-av-2": {"role": "detector", "trusted_alone": False},
}

ONE, TWO, THREE = text_bytes("level one"), text_bytes("level two"), text_bytes("level three")
NESTED = zip_bytes(
    [
        ("one.txt", ONE),
        (
            "inner.zip",
            zip_bytes([("two.txt", TWO), ("core.tar", tar_bytes([("three.txt", THREE)]))]),
        ),
    ]
)
TAR_A, TAR_B = text_bytes("tar entry"), seeded_bytes(2, 70_000)
LETTER = text_bytes("gzip member")
VALID_FOR_DAMAGE = zip_bytes([("x.bin", seeded_bytes(3, 5_000))], compression=zipfile.ZIP_STORED)
DEFLATED_FOR_DAMAGE = zip_bytes([("y.txt", text_bytes("corrupted deflate stream") * 200)])


ZEROS = bytes(16 * 1024 * 1024)


def corrupted(archive: bytes) -> bytes:
    """Flip bytes inside the compressed data of the first entry (local header is 30 bytes + name)."""
    data = bytearray(archive)
    for offset in range(40, 60):
        data[offset] ^= 0xFF
    return bytes(data)


def central_entry(archive: bytes) -> int:
    offset = archive.find(b"PK\x01\x02")
    assert offset > 0, "no central directory entry"
    return offset


def lying_sizes(archive: bytes, declared: int) -> bytes:
    """Declare `declared` uncompressed bytes for the first entry, in its local and central headers."""
    data = bytearray(archive)
    data[22:26] = struct.pack("<I", declared)
    central = central_entry(archive)
    data[central + 24 : central + 28] = struct.pack("<I", declared)
    return bytes(data)


def encrypted_flag(archive: bytes) -> bytes:
    """Set the 'encrypted' general-purpose flag (bit 0) of the first entry, in both headers."""
    data = bytearray(archive)
    data[6] |= 0x01
    data[central_entry(archive) + 8] |= 0x01
    return bytes(data)


STDLIB_FILES = [
    Planted("nested.zip", NESTED),
    Planted("plain.tar", tar_bytes([("a.txt", TAR_A), ("dir/b.bin", TAR_B)])),
    Planted("letter.gz", gzip_bytes("letter.txt", LETTER)),
]
WITNESS = Planted("witness.txt", text_bytes("clean file next to malformed archives"))
MALFORMED = {
    # Central directory cut off.
    "truncated.zip": VALID_FOR_DAMAGE[: len(VALID_FOR_DAMAGE) * 6 // 10],
    "corrupt.zip": corrupted(DEFLATED_FOR_DAMAGE),
    # Headers declare 1000 bytes; the stream inflates to 16 MiB.
    "lying-sizes.zip": lying_sizes(zip_bytes([("zeros.bin", ZEROS)]), 1000),
    "encrypted.zip": encrypted_flag(
        zip_bytes([("secret.bin", seeded_bytes(4, 2_000))], compression=zipfile.ZIP_STORED)
    ),
    "slip-parent.zip": zip_bytes([("../escape.txt", text_bytes("outside the container"))]),
    "slip-absolute.zip": zip_bytes([("/etc/escape.txt", text_bytes("absolute entry"))]),
}


def run(work: Path, files: list[Planted], limits: dict[str, int] | None = None) -> Scan:
    image = build_image("ext4", files)
    engines = [fake_engine_config(work, engine_id) for engine_id in ENGINES]
    policy = write_signed_policy(work / "policy", policy_document(ENGINES, limits=limits))
    return scan(work / "scan", image, policy, engines)


@pytest.fixture(scope="module")
def stdlib(tmp_path_factory: pytest.TempPathFactory) -> Scan:
    return run(tmp_path_factory.mktemp("extraction"), STDLIB_FILES)


def shape(obj: dict[str, Any]) -> tuple[str, int, str | None]:
    return (obj["origin"], obj["depth"], obj["sha256"])


@pytest.mark.req("FR-06")
def test_nested_archives_within_limits_are_fully_listed(stdlib: Scan) -> None:
    top = stdlib.file("nested.zip")
    assert sorted(o["path"] for o in stdlib.children(top)) == ["inner.zip", "one.txt"]
    inner = stdlib.child(top, "inner.zip")
    assert sorted(o["path"] for o in stdlib.children(inner)) == ["core.tar", "two.txt"]
    core = stdlib.child(inner, "core.tar")
    assert [o["path"] for o in stdlib.children(core)] == ["three.txt"]
    assert shape(stdlib.child(top, "one.txt")) == ("EXTRACTED", 1, sha256(ONE))
    assert shape(stdlib.child(inner, "two.txt")) == ("EXTRACTED", 2, sha256(TWO))
    assert shape(stdlib.child(core, "three.txt")) == ("EXTRACTED", 3, sha256(THREE))
    assert (inner["depth"], core["depth"]) == (1, 2)
    assert len(stdlib.descendants(top)) == 5


@pytest.mark.req("FR-06", "FR-10")
def test_clean_archive_tree_is_transferable_as_its_container(stdlib: Scan) -> None:
    top = stdlib.file("nested.zip")
    assert {o["verdict"] for o in stdlib.descendants(top)} == {"CLEAN"}
    assert top["verdict"] == "CLEAN"
    assert top["transferable"] is True
    assert all(o["transferable"] is False for o in stdlib.descendants(top))


@pytest.mark.req("FR-06", "FR-10")
def test_containers_travel_and_their_entries_do_not(stdlib: Scan) -> None:
    assert stdlib.output_files() == {p.path: p.content for p in STDLIB_FILES}


@pytest.mark.req("FR-06")
def test_tar_entries_are_extracted(stdlib: Scan) -> None:
    top = stdlib.file("plain.tar")
    assert stdlib.child(top, "a.txt")["sha256"] == sha256(TAR_A)
    assert stdlib.child(top, "dir/b.bin")["sha256"] == sha256(TAR_B)
    assert len(stdlib.children(top)) == 2


@pytest.mark.req("FR-06")
def test_gzip_member_is_extracted_under_its_header_name(stdlib: Scan) -> None:
    member = stdlib.child(stdlib.file("letter.gz"), "letter.txt")
    assert member["sha256"] == sha256(LETTER)


@pytest.mark.req("FR-08")
def test_extracted_objects_are_analysed_by_every_engine(stdlib: Scan) -> None:
    extracted = [
        obj
        for name in ("nested.zip", "plain.tar", "letter.gz")
        for obj in stdlib.descendants(stdlib.file(name))
    ]
    assert len(extracted) == 8  # nested.zip 5, plain.tar 2, letter.gz 1
    for obj in extracted:
        for engine_id in ENGINES:
            assert stdlib.engine_result(obj, engine_id)["status"] == "OK", obj["path"]


@pytest.fixture(scope="module")
def malformed(tmp_path_factory: pytest.TempPathFactory) -> Scan:
    files = [WITNESS] + [Planted(name, data) for name, data in MALFORMED.items()]
    return run(tmp_path_factory.mktemp("malformed"), files)


@pytest.mark.req("FR-06", "NFR-05")
@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_malformed_archive_is_unscannable_and_the_scan_completes(
    malformed: Scan, name: str
) -> None:
    # Truncated, corrupt, lying sizes, encrypted entry, entry path leaving the container: R1 (policy.md).
    listed = malformed.file(name)
    assert (listed["verdict"], listed["rule"]) == ("UNSCANNABLE", "R1")
    assert malformed.file(WITNESS.path)["verdict"] == "CLEAN"


@pytest.mark.req("FR-06", "FR-10")
def test_malformed_archives_block_the_medium(malformed: Scan) -> None:
    assert malformed.report["medium_verdict"]["blocked"] is True
    assert malformed.output_files() == {}


# --- formats built by the WP-1.9 archive builder ----------------------------------------------------

FORMATS = {"7z": "7z", "rar": "rar", "cab": "cab", "iso": "iso9660", "msi": "msi"}


@pytest.fixture(scope="module", params=sorted(FORMATS))
def archive_format(
    request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory
) -> tuple[str, list[bytes], Scan]:
    fmt: str = request.param
    contents = [text_bytes(f"{fmt} entry a"), seeded_bytes(len(fmt) * 7, 4_096)]
    archive = build_archive(fmt, [("a.txt", contents[0]), ("dir/b.bin", contents[1])])
    work = tmp_path_factory.mktemp(f"format-{fmt}")
    return fmt, contents, run(work, [Planted(f"bundle.{fmt}", archive)])


@pytest.mark.req("FR-06")
def test_archive_format_is_identified(archive_format: tuple[str, list[bytes], Scan]) -> None:
    fmt, _, found = archive_format
    assert found.file(f"bundle.{fmt}")["detected_type"] == FORMATS[fmt]


@pytest.mark.req("FR-06")
def test_archive_format_is_extracted(archive_format: tuple[str, list[bytes], Scan]) -> None:
    fmt, contents, found = archive_format
    extracted = {o["sha256"] for o in found.descendants(found.file(f"bundle.{fmt}"))}
    # Every planted entry is found among the descendants (an msi also yields its own tables and
    # cabinet, an iso its directory structure): containment, not equality.
    assert {sha256(content) for content in contents} <= extracted


@pytest.mark.req("FR-06")
def test_archive_format_tree_is_clean(archive_format: tuple[str, list[bytes], Scan]) -> None:
    fmt, _, found = archive_format
    top = found.file(f"bundle.{fmt}")
    assert top["verdict"] == "CLEAN"
    assert {o["verdict"] for o in found.descendants(top)} == {"CLEAN"}


# --- limits -----------------------------------------------------------------------------------------


def nest(levels: int) -> bytes:
    """l0.zip holds l1.zip ... holds l<levels-1>.zip, which holds leaf.txt."""
    archive = zip_bytes([("leaf.txt", text_bytes("leaf"))])
    for level in range(levels - 1, 0, -1):
        archive = zip_bytes([(f"l{level}.zip", archive)])
    return archive


@pytest.fixture(scope="module")
def too_deep(tmp_path_factory: pytest.TempPathFactory) -> Scan:
    # Depths: l0.zip 0, l1.zip 1, l2.zip 2, l3.zip 3, l4.zip would be 4 > max_depth 3.
    files = [Planted("l0.zip", nest(5)), Planted("clean.txt", text_bytes("clean"))]
    return run(tmp_path_factory.mktemp("too-deep"), files, {"max_depth": 3})


@pytest.mark.req("FR-06")
def test_too_deep_archive_is_unscannable(too_deep: Scan) -> None:
    level = too_deep.file("l0.zip")
    for name in ("l1.zip", "l2.zip", "l3.zip"):
        level = too_deep.child(level, name)
    assert (level["verdict"], level["rule"], level["limit"]) == ("UNSCANNABLE", "R1", "depth")


@pytest.mark.req("FR-06")
def test_no_object_is_deeper_than_the_depth_limit(too_deep: Scan) -> None:
    assert max(o["depth"] for o in too_deep.objects) == 3


@pytest.mark.req("FR-06", "FR-10")
def test_too_deep_archive_blocks_the_medium(too_deep: Scan) -> None:
    assert too_deep.report["medium_verdict"]["blocked"] is True
    assert too_deep.file("clean.txt")["transferable"] is False
    assert too_deep.output_files() == {}


@pytest.fixture(scope="module")
def too_dense(tmp_path_factory: pytest.TempPathFactory) -> Scan:
    # 16 MiB of zeros compress about 1000:1; the ratio limit is 100 and the size limit far away.
    files = [
        Planted("bomb.zip", zip_bytes([("zeros.bin", ZEROS)])),
        Planted("zeros.gz", gzip_bytes("zeros.bin", ZEROS)),
    ]
    limits = {"max_ratio": 100, "max_total_bytes": 1024 * 1024 * 1024}
    return run(tmp_path_factory.mktemp("too-dense"), files, limits)


@pytest.mark.req("FR-06")
@pytest.mark.parametrize("name", ["bomb.zip", "zeros.gz"])
def test_too_dense_archive_is_unscannable(too_dense: Scan, name: str) -> None:
    listed = too_dense.file(name)
    assert (listed["verdict"], listed["rule"], listed["limit"]) == ("UNSCANNABLE", "R1", "ratio")


@pytest.mark.req("FR-06")
def test_too_large_archive_is_unscannable(tmp_path: Path) -> None:
    # Three incompressible 512 KiB entries (ratio about 1) against a 1 MiB total.
    entries = [(f"part{i}.bin", seeded_bytes(10 + i, 512 * 1024)) for i in range(3)]
    files = [Planted("big.zip", zip_bytes(entries, compression=zipfile.ZIP_STORED))]
    found = run(tmp_path, files, {"max_total_bytes": 1024 * 1024, "max_ratio": 100})
    listed = found.file("big.zip")
    assert (listed["verdict"], listed["rule"], listed["limit"]) == (
        "UNSCANNABLE",
        "R1",
        "total_size",
    )


@pytest.mark.req("FR-06")
def test_archive_with_too_many_entries_is_unscannable(tmp_path: Path) -> None:
    entries = [(f"f{i:02d}.txt", b"x") for i in range(30)]
    files = [Planted("many.zip", zip_bytes(entries, compression=zipfile.ZIP_STORED))]
    found = run(tmp_path, files, {"max_entries": 20})
    listed = found.file("many.zip")
    assert (listed["verdict"], listed["rule"], listed["limit"]) == (
        "UNSCANNABLE",
        "R1",
        "entry_count",
    )


MIB = 1024 * 1024
TIGHT = {"max_entries": 20, "max_total_bytes": MIB, "max_ratio": 100, "max_path_length": 64}
# About 50:1 once deflated: random kibibyte plus zeros.
DENSE_BUT_ALLOWED = seeded_bytes(5, 1024) + bytes(54_000)
AT_LIMIT = [
    Planted("twenty.zip", zip_bytes([(f"f{i:02d}.txt", b"x") for i in range(20)])),
    Planted(
        "exact.zip", zip_bytes([("mib.bin", seeded_bytes(6, MIB))], compression=zipfile.ZIP_STORED)
    ),
    Planted("dense-but-allowed.zip", zip_bytes([("mixed.bin", DENSE_BUT_ALLOWED)])),
]


@pytest.fixture(scope="module")
def at_limit(tmp_path_factory: pytest.TempPathFactory) -> Scan:
    return run(tmp_path_factory.mktemp("at-limit"), AT_LIMIT, TIGHT)


@pytest.mark.req("FR-06")
@pytest.mark.parametrize("name", [p.path for p in AT_LIMIT])
def test_archive_at_the_limits_is_extracted_and_clean(at_limit: Scan, name: str) -> None:
    top = at_limit.file(name)
    assert (top["verdict"], top["limit"]) == ("CLEAN", None)
    assert top["transferable"] is True


def inner(entries: list[tuple[str, bytes]]) -> bytes:
    return zip_bytes(entries, compression=zipfile.ZIP_STORED)


CUMULATIVE = [
    # Two levels of 2 + 15 + 15 entries: each archive is under 20, the tree is not.
    Planted(
        "deep-count.zip",
        inner(
            [(f"in{n}.zip", inner([(f"f{i:02d}.txt", b"x") for i in range(15)])) for n in (1, 2)]
        ),
    ),
    # 800 KiB at the first level, 800 KiB more at the second: over 1 MiB only in total.
    Planted(
        "deep-size.zip",
        inner(
            [
                (f"in{n}.zip", inner([("part.bin", seeded_bytes(20 + n, 400 * 1024))]))
                for n in (1, 2)
            ]
        ),
    ),
    Planted("long-name.zip", zip_bytes([("d/" + "n" * 100 + ".txt", text_bytes("long name"))])),
]


@pytest.fixture(scope="module")
def cumulative(tmp_path_factory: pytest.TempPathFactory) -> Scan:
    return run(tmp_path_factory.mktemp("cumulative"), CUMULATIVE, TIGHT)


@pytest.mark.req("FR-06")
@pytest.mark.parametrize(
    ("name", "limit"),
    [
        ("deep-count.zip", "entry_count"),
        ("deep-size.zip", "total_size"),
        ("long-name.zip", "path_length"),
    ],
)
def test_limits_count_the_whole_tree(cumulative: Scan, name: str, limit: str) -> None:
    top = cumulative.file(name)
    tree = [top, *cumulative.descendants(top)]
    # The limit is reported on whichever container was being extracted when it was reached.
    breached = [o for o in tree if o["limit"] == limit]
    assert len(breached) >= 1, [o["limit"] for o in tree]
    assert all(o["verdict"] == "UNSCANNABLE" for o in breached)
    assert top["transferable"] is False
