"""FR-03, FR-04, SEC-10 and the P1 exit criterion: every supported file system is scanned end to end from a
generated disk image, without USB hardware; any other file system is refused cleanly (exit 4)."""

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from common import (
    FILE_SYSTEMS,
    Planted,
    Scan,
    blank_image,
    build_image,
    damaged_copy,
    fake_engine_config,
    load_report,
    minix_image,
    pdf_bytes,
    png_bytes,
    policy_document,
    run_ostia,
    scan,
    seeded_bytes,
    sha1,
    sha256,
    text_bytes,
    write_signed_policy,
)

EXT = ("ext2", "ext3", "ext4")
MODIFIED = datetime(2024, 3, 1, 10, 20, 30, tzinfo=UTC)
DETECTOR = {"fake-av": {"role": "detector", "trusted_alone": False}}


def planted(fs: str) -> list[Planted]:
    files = [
        Planted("readme.txt", text_bytes("readme"), modified=MODIFIED),
        Planted("docs/report.pdf", pdf_bytes("report"), modified=MODIFIED),
        Planted("docs/deep/nested/photo.png", png_bytes("photo"), modified=MODIFIED),
        Planted("empty.dat", b"", modified=MODIFIED),
        # Larger than any read buffer: the hashes cover every chunk.
        Planted("big.bin", seeded_bytes(1, 1_048_576 + 3), modified=MODIFIED),
        Planted(".dotfile", text_bytes("dot file"), modified=MODIFIED),
    ]
    if fs not in EXT:
        files += [
            Planted(
                "attrib-hidden.txt", text_bytes("hidden attribute"), hidden=True, modified=MODIFIED
            ),
            Planted(
                "attrib-readonly.txt",
                text_bytes("read-only attribute"),
                read_only=True,
                modified=MODIFIED,
            ),
        ]
    return files


@dataclass
class FsScan:
    fs: str
    files: list[Planted]
    scan: Scan


@pytest.fixture(scope="module", params=FILE_SYSTEMS)
def fs_scan(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory) -> FsScan:
    fs: str = request.param
    files = planted(fs)
    image = build_image(fs, files)
    work = tmp_path_factory.mktemp(f"fs-{fs}")
    engine = fake_engine_config(work, "fake-av")
    policy = write_signed_policy(work / "policy", policy_document(DETECTOR))
    return FsScan(fs, files, scan(work / "scan", image, policy, [engine]))


@pytest.mark.req("FR-03")
def test_supported_file_system_is_scanned_end_to_end(fs_scan: FsScan) -> None:
    report = fs_scan.scan.report
    assert report["refusal"] is None
    assert report["medium"]["file_system"] == fs_scan.fs


@pytest.mark.req("FR-04")
def test_every_planted_file_is_inventoried(fs_scan: FsScan) -> None:
    listed = sorted(o["path"] for o in fs_scan.scan.files())
    assert listed == sorted(p.path for p in fs_scan.files)
    assert {o["kind"] for o in fs_scan.scan.files()} == {"file"}


@pytest.mark.req("FR-04", "SEC-10")
def test_sizes_and_hashes_match_the_planted_content(fs_scan: FsScan) -> None:
    for planted_file in fs_scan.files:
        listed = fs_scan.scan.file(planted_file.path)
        assert listed["size"] == len(planted_file.content), planted_file.path
        assert listed["sha256"] == sha256(planted_file.content), planted_file.path
        assert listed["sha1"] == sha1(planted_file.content), planted_file.path


@pytest.mark.req("FR-04")
def test_modification_time_is_reported(fs_scan: FsScan) -> None:
    for planted_file in fs_scan.files:
        modified = fs_scan.scan.file(planted_file.path)["modified"]
        assert modified is not None, planted_file.path
        assert datetime.fromisoformat(modified) == MODIFIED, planted_file.path


@pytest.mark.req("FR-04")
def test_hidden_files_are_marked_hidden(fs_scan: FsScan) -> None:
    hidden = {o["path"] for o in fs_scan.scan.files() if "hidden" in o["attributes"]}
    expected = {".dotfile"} if fs_scan.fs in EXT else {".dotfile", "attrib-hidden.txt"}
    assert hidden == expected


@pytest.mark.req("FR-04")
def test_read_only_attribute_is_reported(fs_scan: FsScan) -> None:
    read_only = {o["path"] for o in fs_scan.scan.files() if "read_only" in o["attributes"]}
    assert read_only == (set() if fs_scan.fs in EXT else {"attrib-readonly.txt"})


@pytest.mark.req("FR-08", "SEC-10")
def test_every_object_is_analysed_by_the_engine(fs_scan: FsScan) -> None:
    # The fake engine answers ERROR when the bytes on fd 3 do not hash to the request's SHA-256: an OK
    # result means the engine analysed the very bytes that were hashed.
    assert len(fs_scan.scan.files()) == len(fs_scan.files)
    for obj in fs_scan.scan.objects:
        assert fs_scan.scan.engine_result(obj, "fake-av")["status"] == "OK", obj["path"]


@pytest.mark.req("SEC-10", "FR-10")
def test_clean_medium_transfers_the_scanned_copies(fs_scan: FsScan) -> None:
    verdict = fs_scan.scan.report["medium_verdict"]
    assert (verdict["verdict"], verdict["blocked"]) == ("CLEAN", False)
    assert fs_scan.scan.output_files() == {p.path: p.content for p in fs_scan.files}


@pytest.fixture(params=["blank", "minix"])
def unsupported_image(request: pytest.FixtureRequest) -> Path:
    return blank_image() if request.param == "blank" else minix_image()


def refused_scan(work: Path, image: Path) -> tuple[int, str, Path, Path]:
    policy = write_signed_policy(work / "policy", policy_document(DETECTOR))
    engine = fake_engine_config(work, "fake-av")
    report, output = work / "report.json", work / "output"
    result = run_ostia(
        "scan",
        "--image",
        image,
        "--report",
        report,
        "--output",
        output,
        *policy.args(),
        "--dev-engine",
        engine,
    )
    return result.returncode, result.stderr, report, output


@pytest.mark.req("FR-03")
def test_unsupported_file_system_exits_4_with_a_clear_message(
    tmp_path: Path, unsupported_image: Path
) -> None:
    code, stderr, _, _ = refused_scan(tmp_path, unsupported_image)
    assert code == 4, stderr
    assert "unsupported file system" in stderr.lower()


@pytest.mark.req("FR-03")
def test_unsupported_file_system_report_says_why_and_nothing_is_transferred(
    tmp_path: Path, unsupported_image: Path
) -> None:
    code, stderr, report_path, output = refused_scan(tmp_path, unsupported_image)
    assert code == 4, stderr
    report = load_report(report_path)
    assert report["refusal"]["code"] == "unsupported_file_system"
    assert report["medium"]["file_system"] is None
    assert report["objects"] == []
    assert report["medium_verdict"]["verdict"] == "UNSCANNABLE"
    assert report["medium_verdict"]["blocked"] is True
    assert not output.exists() or not any(output.iterdir())


@pytest.mark.req("FR-03", "NFR-05")
def test_damaged_file_system_is_never_transferred(tmp_path: Path) -> None:
    # The ext4 superblock (bytes 1024-2047) stays; the 512 KiB after it, group descriptors included, are
    # zeroed. Exit 4, 5, or 0 with the unreadable objects UNSCANNABLE: never a transfer (cli.md).
    image = build_image("ext4", [Planted("data.txt", text_bytes("behind broken metadata"))])
    code, stderr, report_path, output = refused_scan(
        tmp_path, damaged_copy(image, 2048, 512 * 1024)
    )
    assert code in (0, 4, 5), stderr
    if code in (0, 4):
        assert load_report(report_path)["medium_verdict"]["blocked"] is True
    assert not output.exists() or not any(output.iterdir())


REAL = Planted("real.txt", text_bytes("target of a link"))
LINKS = {
    "escape-absolute": "/etc/hostname",
    "escape-relative": "../../../etc/hostname",
    "inside": "real.txt",
}


@pytest.fixture(scope="module")
def links(tmp_path_factory: pytest.TempPathFactory) -> Scan:
    files = [REAL] + [Planted(name, b"", symlink=target) for name, target in LINKS.items()]
    work = tmp_path_factory.mktemp("symlinks")
    engine = fake_engine_config(work, "fake-av")
    policy = write_signed_policy(work / "policy", policy_document(DETECTOR))
    return scan(work / "scan", build_image("ext4", files), policy, [engine])


@pytest.mark.req("FR-04", "SEC-10")
@pytest.mark.parametrize("name", sorted(LINKS))
def test_symbolic_link_is_listed_and_never_followed(links: Scan, name: str) -> None:
    link = links.file(name)
    assert (link["kind"], link["size"], link["sha256"], link["sha1"]) == ("symlink", 0, None, None)
    assert link["engine_results"] == []


@pytest.mark.req("FR-04", "FR-10")
@pytest.mark.parametrize("name", sorted(LINKS))
def test_symbolic_link_is_unscannable_and_never_transferred(links: Scan, name: str) -> None:
    link = links.file(name)
    assert (link["verdict"], link["rule"], link["transferable"]) == ("UNSCANNABLE", "R1", False)


@pytest.mark.req("FR-10")
def test_medium_with_a_symbolic_link_transfers_nothing(links: Scan) -> None:
    assert links.file("real.txt")["sha256"] == sha256(REAL.content)
    assert links.report["medium_verdict"]["blocked"] is True
    assert links.output_files() == {}
