"""Golden vectors of the ostia.engine.v1 framing, shared by the Rust and Python test suites.

Usage: gen_vectors.py [--out DIR] [--check]

Writes one complete frame per vector (`<name>.bin`) and a manifest (`vectors.json`: message type, expected
outcome — "ok" or the error kind — and the message fields in Protobuf JSON) to DIR (default proto/testdata),
encoding with the Python framing. With --check, compares instead of writing. The vectors are written once:
changing an existing one is a contract change (CTR-04).
"""

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from google.protobuf import json_format
from google.protobuf.message import Message

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "workers-py" / "common" / "src"))

from ostia_common.engine_v1 import engine_pb2
from ostia_common.framing import encode_frame

DEFAULT_OUT = REPO / "proto" / "testdata"


@dataclass
class Vector:
    name: str
    message: str
    expect: str
    description: str
    frame: bytes
    fields: Message | None


def changed[M: (engine_pb2.AnalyzeRequest, engine_pb2.AnalyzeResponse)](
    message: M, **changes: object
) -> M:
    """`message` with fields replaced; `version=None` removes the version."""
    for name, value in changes.items():
        if name != "version":
            setattr(message, name, value)
        elif isinstance(value, engine_pb2.ContractVersion):
            message.version.CopyFrom(value)
        else:
            message.ClearField("version")
    return message


def request_pdf() -> engine_pb2.AnalyzeRequest:
    return engine_pb2.AnalyzeRequest(
        session_id="session-0001",
        object_id="object-0001",
        sha256=bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        detected_type="application/pdf",
        size=0,
        origin=engine_pb2.FILE,
        limits=engine_pb2.Limits(memory_bytes=268_435_456, duration_ms=30_000, write_bytes=0),
        version=engine_pb2.ContractVersion(major=1, minor=0),
    )


def response_clean(minor: int = 0) -> engine_pb2.AnalyzeResponse:
    return engine_pb2.AnalyzeResponse(
        engine_id="clamav",
        engine_version="1.4.3",
        content_version="daily-27500",
        status=engine_pb2.OK,
        hint=engine_pb2.CLEAN,
        duration_ms=12,
        version=engine_pb2.ContractVersion(major=1, minor=minor),
    )


def response_typed() -> engine_pb2.AnalyzeResponse:
    """The triage worker's answer: the type found in the content (minor 1, Q-54)."""
    return engine_pb2.AnalyzeResponse(
        engine_id="ostia-triage",
        engine_version="0.0.0",
        content_version="magic-1",
        status=engine_pb2.OK,
        hint=engine_pb2.NONE,
        duration_ms=1,
        detected_type="png",
        version=engine_pb2.ContractVersion(major=1, minor=1),
    )


def request_extract() -> engine_pb2.AnalyzeRequest:
    """A request to the extraction worker, with the tree's remaining budget (minor 2, ADR-18)."""
    return engine_pb2.AnalyzeRequest(
        session_id="session-0001",
        object_id="object-0002",
        sha256=bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        detected_type="zip",
        size=22,
        origin=engine_pb2.FILE,
        limits=engine_pb2.Limits(memory_bytes=268_435_456, duration_ms=30_000, write_bytes=0),
        extraction=engine_pb2.ExtractionBudget(
            max_ratio=200,
            remaining_bytes=4_294_967_296,
            remaining_entries=100_000,
            max_path_length=4096,
        ),
        version=engine_pb2.ContractVersion(major=1, minor=2),
    )


def extract_entry(
    path: bytes = b"dir/b.bin",
    kind: engine_pb2.EntryKind.ValueType = engine_pb2.REGULAR,
    size: int = 3,
    major: int = 1,
) -> engine_pb2.ExtractFrame:
    return engine_pb2.ExtractFrame(
        entry=engine_pb2.Entry(path=path, kind=kind, size=size, modified=315_532_800),
        version=engine_pb2.ContractVersion(major=major, minor=2),
    )


def extract_data(data: bytes = b"abc") -> engine_pb2.ExtractFrame:
    return engine_pb2.ExtractFrame(data=data, version=engine_pb2.ContractVersion(major=1, minor=2))


def extract_done(**changes: object) -> engine_pb2.ExtractFrame:
    """The end of an extraction stopped by the ratio limit."""
    done = engine_pb2.AnalyzeResponse(
        engine_id="ostia-extract",
        engine_version="0.0.0",
        content_version="formats-1",
        status=engine_pb2.ERROR,
        hint=engine_pb2.NONE,
        duration_ms=1,
        limit="ratio",
        version=engine_pb2.ContractVersion(major=1, minor=2),
    )
    return engine_pb2.ExtractFrame(
        done=changed(done, **changes), version=engine_pb2.ContractVersion(major=1, minor=2)
    )


def response_scored() -> engine_pb2.AnalyzeResponse:
    return engine_pb2.AnalyzeResponse(
        engine_id="ember",
        engine_version="2024.1",
        content_version="model-2024-09",
        status=engine_pb2.OK,
        hint=engine_pb2.SUSPICIOUS,
        score=0.875,
        findings=[
            engine_pb2.Finding(
                id="EMBER-SCORE",
                title="PE model score above threshold",
                severity=3,
                evidence="score=0.875 threshold=0.8",
                attack_ids=["T1204.002"],
            )
        ],
        duration_ms=840,
        version=engine_pb2.ContractVersion(major=1, minor=0),
    )


def clean_with(**changes: object) -> engine_pb2.AnalyzeResponse:
    return changed(response_clean(), **changes)


def message_vector(name: str, expect: str, description: str, message: Message) -> Vector:
    kind = message.DESCRIPTOR.name
    return Vector(name, kind, expect, description, encode_frame(message), message)


def frame_vector(name: str, expect: str, description: str, frame: bytes) -> Vector:
    return Vector(name, "AnalyzeResponse", expect, description, frame, None)


def body_vector(name: str, expect: str, description: str, body: bytes) -> Vector:
    """A response body built byte by byte (described in `description`), framed."""
    return Vector(
        name, "AnalyzeResponse", expect, description, len(body).to_bytes(4, "big") + body, None
    )


def vectors() -> list[Vector]:
    clean_frame = encode_frame(response_clean())
    clean_body = response_clean().SerializeToString()
    major_2 = engine_pb2.ContractVersion(major=2, minor=0)
    minor_3 = engine_pb2.ContractVersion(major=1, minor=3)
    no_frame = engine_pb2.ExtractFrame(version=engine_pb2.ContractVersion(major=1, minor=2))
    severity_5 = response_scored()
    severity_5.findings[0].severity = 5
    return [
        message_vector("request_pdf", "ok", "a valid request", request_pdf()),
        message_vector("response_clean", "ok", "a valid response", response_clean()),
        message_vector("response_scored", "ok", "score and finding", response_scored()),
        message_vector("response_typed", "ok", "type from the triage worker", response_typed()),
        message_vector("response_newer_minor", "ok", "minor 7 is accepted", response_clean(7)),
        message_vector("request_extract", "ok", "a request with a budget", request_extract()),
        message_vector("extract_entry", "ok", "an entry of 3 bytes", extract_entry()),
        message_vector("extract_data", "ok", "3 bytes of the entry", extract_data()),
        message_vector("extract_done", "ok", "stopped by the ratio limit", extract_done()),
        message_vector(
            "extract_link",
            "ok",
            "a link entry, no bytes",
            extract_entry(path=b"link", kind=engine_pb2.LINK, size=0),
        ),
        frame_vector("frame_empty", "empty", "zero length", b"\x00\x00\x00\x00"),
        frame_vector("frame_oversized", "oversized", "16 MiB + 1 announced", b"\x01\x00\x00\x01"),
        frame_vector(
            "frame_truncated_header", "truncated_header", "3-byte prefix", b"\x00\x00\x01"
        ),
        frame_vector("frame_truncated_body", "truncated_body", "last byte cut", clean_frame[:-1]),
        frame_vector(
            "frame_trailing_bytes", "trailing_bytes", "one extra byte", clean_frame + b"\0"
        ),
        frame_vector(
            "response_malformed",
            "malformed",
            "field 1 announces 5 bytes, 2 follow",
            b"\x00\x00\x00\x04\x0a\x05ab",
        ),
        message_vector(
            "response_major_2", "unsupported_major", "major 2", clean_with(version=major_2)
        ),
        message_vector(
            "response_no_version", "unsupported_major", "no version", clean_with(version=None)
        ),
        message_vector(
            "response_no_engine_id",
            "missing_engine_identity",
            "empty engine_id",
            clean_with(engine_id=""),
        ),
        message_vector(
            "response_no_engine_version",
            "missing_engine_identity",
            "empty engine_version",
            clean_with(engine_version=""),
        ),
        message_vector(
            "response_no_content_version",
            "missing_engine_identity",
            "empty content_version",
            clean_with(content_version=""),
        ),
        message_vector(
            "response_score_above_one", "invalid_score", "score 1.5", clean_with(score=1.5)
        ),
        message_vector(
            "response_score_nan", "invalid_score", "score NaN", clean_with(score=float("nan"))
        ),
        message_vector(
            "response_status_unspecified",
            "invalid_response",
            "status 0",
            clean_with(status=engine_pb2.STATUS_UNSPECIFIED),
        ),
        message_vector(
            "request_major_2",
            "unsupported_major",
            "request with major 2",
            changed(request_pdf(), version=major_2),
        ),
        message_vector(
            "request_short_sha256",
            "invalid_request",
            "31-byte sha256",
            changed(request_pdf(), sha256=bytes(31)),
        ),
        body_vector(
            "response_wrong_wire_type",
            "malformed",
            "status (field 4) sent length-delimited: 22 00 appended",
            clean_body + b"\x22\x00",
        ),
        body_vector(
            "response_version_as_varint",
            "malformed",
            "version (field 15) sent as a varint: 78 01 appended",
            clean_body + b"\x78\x01",
        ),
        body_vector(
            "response_finding_id_as_varint",
            "malformed",
            "a finding whose id (field 1) is a varint: 3a 02 08 01 appended",
            clean_body + b"\x3a\x02\x08\x01",
        ),
        body_vector(
            "response_varint_overflow",
            "malformed",
            "duration_ms (field 8) as a 10-byte varint overflowing 64 bits",
            clean_body + b"\x40" + b"\xff" * 9 + b"\x7f",
        ),
        body_vector(
            "response_engine_id_bad_utf8",
            "malformed",
            "engine_id holding the invalid UTF-8 bytes ff fe",
            changed(response_clean(), engine_id="").SerializeToString() + b"\x0a\x02\xff\xfe",
        ),
        message_vector("response_hint_unknown", "invalid_response", "hint 99", clean_with(hint=99)),
        message_vector(
            "response_severity_5",
            "invalid_response",
            "a finding with severity 5",
            severity_5,
        ),
        message_vector(
            "response_two_faults",
            "unsupported_major",
            "major 2 and an empty engine_id: the version is checked first",
            clean_with(version=major_2, engine_id=""),
        ),
        body_vector(
            "response_unknown_group",
            "ok",
            "two nested unknown groups (field 100): a3 06 a3 06 a4 06 a4 06 appended",
            clean_body + b"\xa3\x06\xa3\x06\xa4\x06\xa4\x06",
        ),
        body_vector(
            "response_unterminated_group",
            "malformed",
            "a nested unknown group left open: a3 06 a3 06 a4 06 appended",
            clean_body + b"\xa3\x06\xa3\x06\xa4\x06",
        ),
        body_vector(
            "response_mismatched_group",
            "malformed",
            "group 100 closed by an end tag of field 101: a3 06 ac 06 appended",
            clean_body + b"\xa3\x06\xac\x06",
        ),
        body_vector(
            "response_minor_3_extra_field",
            "ok",
            "minor 3 (newer than this decoder) with field 99 (unknown to it) appended: ignored",
            changed(response_clean(), version=minor_3).SerializeToString() + b"\x9a\x06\x01x",
        ),
        message_vector(
            "extract_no_frame", "invalid_response", "neither entry, data nor done", no_frame
        ),
        message_vector("extract_major_2", "unsupported_major", "major 2", extract_entry(major=2)),
        message_vector(
            "extract_kind_unspecified",
            "invalid_response",
            "entry kind 0",
            extract_entry(kind=engine_pb2.ENTRY_KIND_UNSPECIFIED),
        ),
        message_vector(
            "extract_kind_unknown",
            "invalid_response",
            "entry kind 9",
            extract_entry(kind=engine_pb2.EntryKind.ValueType(9)),
        ),
        message_vector(
            "extract_link_with_size",
            "invalid_response",
            "a link announcing 5 bytes",
            extract_entry(path=b"link", kind=engine_pb2.LINK, size=5),
        ),
        message_vector(
            "extract_special_with_size",
            "invalid_response",
            "a special entry announcing 1 byte",
            extract_entry(path=b"fifo", kind=engine_pb2.SPECIAL, size=1),
        ),
        message_vector(
            "extract_no_path", "invalid_response", "an empty path", extract_entry(path=b"")
        ),
        message_vector("extract_empty_data", "invalid_response", "empty data", extract_data(b"")),
        message_vector(
            "extract_done_no_engine_id",
            "missing_engine_identity",
            "a done without engine_id",
            extract_done(engine_id=""),
        ),
        message_vector(
            "extract_done_major_2",
            "unsupported_major",
            "a done whose own version is major 2",
            extract_done(version=major_2),
        ),
    ]


def render() -> dict[str, bytes]:
    """Every file of the vector set, by name."""
    entries = []
    files: dict[str, bytes] = {}
    for vector in vectors():
        fields = None
        if vector.fields is not None:
            fields = json_format.MessageToDict(vector.fields, preserving_proto_field_name=True)
        entries.append(
            {
                "name": vector.name,
                "message": vector.message,
                "expect": vector.expect,
                "description": vector.description,
                "fields": fields,
            }
        )
        files[f"{vector.name}.bin"] = vector.frame
    manifest = {
        "comment": "Written by tools/contracts/gen_vectors.py; each <name>.bin is one complete frame.",
        "vectors": entries,
    }
    files["vectors.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    return files


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Golden vectors of the ostia.engine.v1 framing")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    out: Path = args.out
    files = render()
    if args.check:
        stale = []
        for name, content in files.items():
            if not (out / name).is_file():
                stale.append(f"{name} is missing: run `just vectors`")
            elif (out / name).read_bytes() != content:
                stale.append(f"{name} is out of date: run `just vectors`")
        for path in sorted(out.glob("*.bin")):
            if path.name not in files:
                stale.append(f"{path.name} is not a vector: run `just vectors`")
        for line in stale:
            print(line)
        if stale:
            return 1
        print(f"golden vectors are up to date ({len(files) - 1} vectors)")
        return 0
    out.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (out / name).write_bytes(content)
    print(f"wrote {len(files) - 1} vectors and vectors.json to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
