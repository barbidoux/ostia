"""FR-04 and DEEP-05: NTFS alternate data streams and ext4 extended attributes are listed in the inventory
and scanned, and never copied to the output."""

import os
from pathlib import Path

import pytest
from common import (
    Planted,
    Scan,
    build_image,
    fake_engine_config,
    on_sha256,
    policy_document,
    scan,
    sha1,
    sha256,
    text_bytes,
    write_signed_policy,
)

ZONE = b"[ZoneTransfer]\r\nZoneId=3\r\n"
HOST = Planted("readme.txt", text_bytes("host of a stream"), streams={"Zone.Identifier": ZONE})
PLAIN = Planted("clean.txt", text_bytes("no stream"))
XATTR = b"planted extended attribute"
TAGGED = Planted("tagged.txt", text_bytes("host of an attribute"), xattrs={"user.comment": XATTR})
ENGINES = {"fake-av": {"role": "detector", "trusted_alone": True}}


def run(work: Path, fs: str, files: list[Planted], rules: list[dict[str, object]]) -> Scan:
    image = build_image(fs, files)
    engine = fake_engine_config(work, "fake-av", rules=rules)
    policy = write_signed_policy(work / "policy", policy_document(ENGINES))
    return scan(work / "scan", image, policy, [engine])


@pytest.fixture(scope="module")
def ntfs(tmp_path_factory: pytest.TempPathFactory) -> Scan:
    return run(tmp_path_factory.mktemp("ntfs-streams"), "ntfs", [HOST, PLAIN], [])


@pytest.fixture(scope="module")
def ext4(tmp_path_factory: pytest.TempPathFactory) -> Scan:
    return run(tmp_path_factory.mktemp("ext4-xattrs"), "ext4", [TAGGED, PLAIN], [])


@pytest.mark.req("FR-04", "DEEP-05")
def test_alternate_data_stream_is_listed(ntfs: Scan) -> None:
    stream = ntfs.stream("readme.txt", "Zone.Identifier", "ALT_STREAM")
    assert stream["parent_id"] == ntfs.file("readme.txt")["id"]
    assert stream["depth"] == 1
    assert stream["size"] == len(ZONE)
    assert stream["sha256"] == sha256(ZONE)
    assert stream["sha1"] == sha1(ZONE)


@pytest.mark.req("DEEP-05", "FR-08")
def test_alternate_data_stream_is_scanned(ntfs: Scan) -> None:
    stream = ntfs.stream("readme.txt", "Zone.Identifier", "ALT_STREAM")
    assert ntfs.engine_result(stream, "fake-av")["status"] == "OK"


@pytest.mark.req("DEEP-05")
def test_alternate_data_stream_is_never_transferable(ntfs: Scan) -> None:
    assert ntfs.stream("readme.txt", "Zone.Identifier", "ALT_STREAM")["transferable"] is False
    assert ntfs.file("readme.txt")["transferable"] is True


@pytest.mark.req("DEEP-05", "SEC-10")
def test_alternate_data_stream_is_not_copied_to_the_output(ntfs: Scan) -> None:
    assert ntfs.output_files() == {HOST.path: HOST.content, PLAIN.path: PLAIN.content}
    copy = ntfs.output / HOST.path
    assert [name for name in os.listxattr(copy) if "Zone.Identifier" in name] == []


@pytest.mark.req("DEEP-05", "FR-10")
def test_malicious_stream_blocks_the_medium(tmp_path: Path) -> None:
    flagged = run(tmp_path, "ntfs", [HOST, PLAIN], [on_sha256(sha256(ZONE), hint="MALICIOUS")])
    stream = flagged.stream("readme.txt", "Zone.Identifier", "ALT_STREAM")
    assert (stream["verdict"], stream["rule"]) == ("MALICIOUS", "R2")
    assert flagged.report["medium_verdict"]["blocked"] is True
    assert flagged.report["medium_verdict"]["blocking_objects"] == [stream["id"]]
    assert flagged.output_files() == {}


@pytest.mark.req("FR-04", "DEEP-05")
def test_extended_attribute_is_listed(ext4: Scan) -> None:
    attribute = ext4.stream("tagged.txt", "user.comment", "XATTR")
    assert attribute["parent_id"] == ext4.file("tagged.txt")["id"]
    assert attribute["depth"] == 1
    assert attribute["size"] == len(XATTR)
    assert attribute["sha256"] == sha256(XATTR)


@pytest.mark.req("DEEP-05", "FR-08")
def test_extended_attribute_is_scanned(ext4: Scan) -> None:
    attribute = ext4.stream("tagged.txt", "user.comment", "XATTR")
    assert ext4.engine_result(attribute, "fake-av")["status"] == "OK"


@pytest.mark.req("DEEP-05")
def test_extended_attribute_is_never_copied(ext4: Scan) -> None:
    assert ext4.stream("tagged.txt", "user.comment", "XATTR")["transferable"] is False
    assert ext4.output_files() == {TAGGED.path: TAGGED.content, PLAIN.path: PLAIN.content}
    assert "user.comment" not in os.listxattr(ext4.output / TAGGED.path)
