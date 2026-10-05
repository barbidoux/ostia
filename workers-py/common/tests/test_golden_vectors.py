"""Golden vectors shared with the Rust framing (proto/testdata, CTR-01 to CTR-04).

Mirrors crates/contracts/tests/golden.rs: the valid messages are written out here, independently of the
generator; each must encode to the committed bytes and decode back, and each invalid frame must be refused
with the expected kind.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ostia_common.engine_v1 import engine_pb2
from ostia_common.framing import (
    ContractError,
    decode_frame,
    decode_request,
    decode_response,
    encode_frame,
)

TESTDATA = Path(__file__).resolve().parents[3] / "proto" / "testdata"


def vector(name: str) -> bytes:
    return (TESTDATA / f"{name}.bin").read_bytes()


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


def response_clean(minor: int) -> engine_pb2.AnalyzeResponse:
    return engine_pb2.AnalyzeResponse(
        engine_id="clamav",
        engine_version="1.4.3",
        content_version="daily-27500",
        status=engine_pb2.OK,
        hint=engine_pb2.CLEAN,
        duration_ms=12,
        version=engine_pb2.ContractVersion(major=1, minor=minor),
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


VALID_RESPONSES = {
    "response_clean": response_clean(0),
    "response_scored": response_scored(),
    "response_newer_minor": response_clean(7),
}
VALID_DECODE_ONLY = ["response_minor_1_extra_field", "response_unknown_group"]

INVALID = [
    ("frame_empty", "response", "empty"),
    ("frame_oversized", "response", "oversized"),
    ("frame_truncated_header", "response", "truncated_header"),
    ("frame_truncated_body", "response", "truncated_body"),
    ("frame_trailing_bytes", "response", "trailing_bytes"),
    ("response_malformed", "response", "malformed"),
    ("response_major_2", "response", "unsupported_major"),
    ("response_no_version", "response", "unsupported_major"),
    ("response_no_engine_id", "response", "missing_engine_identity"),
    ("response_no_engine_version", "response", "missing_engine_identity"),
    ("response_no_content_version", "response", "missing_engine_identity"),
    ("response_score_above_one", "response", "invalid_score"),
    ("response_score_nan", "response", "invalid_score"),
    ("response_status_unspecified", "response", "invalid_response"),
    ("request_major_2", "request", "unsupported_major"),
    ("request_short_sha256", "request", "invalid_request"),
    ("response_wrong_wire_type", "response", "malformed"),
    ("response_version_as_varint", "response", "malformed"),
    ("response_finding_id_as_varint", "response", "malformed"),
    ("response_varint_overflow", "response", "malformed"),
    ("response_engine_id_bad_utf8", "response", "malformed"),
    ("response_hint_unknown", "response", "invalid_response"),
    ("response_severity_5", "response", "invalid_response"),
    ("response_two_faults", "response", "unsupported_major"),
    ("response_unterminated_group", "response", "malformed"),
    ("response_mismatched_group", "response", "malformed"),
]

# Run by a pure-Python protobuf runtime: every vector must give the same outcome as with upb.
PURE_PYTHON_SCRIPT = """
import json, sys
from pathlib import Path
from google.protobuf.internal import api_implementation
from ostia_common.framing import ContractError, decode_frame, decode_request, decode_response
assert api_implementation.Type() == "python", api_implementation.Type()
testdata = Path(sys.argv[1])
for vector in json.loads((testdata / "vectors.json").read_text())["vectors"]:
    decode = decode_request if vector["message"] == "AnalyzeRequest" else decode_response
    try:
        decode(decode_frame((testdata / (vector["name"] + ".bin")).read_bytes()))
        outcome = "ok"
    except ContractError as error:
        outcome = error.kind
    print(vector["name"], outcome)
"""


@pytest.mark.req("CTR-01", "CTR-03")
def test_python_encodes_the_valid_vectors_to_the_committed_bytes() -> None:
    assert encode_frame(request_pdf()) == vector("request_pdf")
    for name, message in VALID_RESPONSES.items():
        assert encode_frame(message) == vector(name), name


@pytest.mark.req("CTR-01")
def test_response_clean_is_the_hand_decoded_frame() -> None:
    # Written out field by field from engine.proto, independently of both encoders.
    expected = bytes.fromhex(
        "00000026  0a06636c616d6176  1205312e342e33  1a0b6461696c792d3237353030  "
        "2001  2802  400c  7a020801"
    )
    assert vector("response_clean") == expected
    assert encode_frame(response_clean(0)) == expected


@pytest.mark.req("CTR-01", "CTR-03", "CTR-04")
def test_python_decodes_the_valid_vectors() -> None:
    assert decode_request(decode_frame(vector("request_pdf"))) == request_pdf()
    for name, message in VALID_RESPONSES.items():
        assert decode_response(decode_frame(vector(name))) == message, name


@pytest.mark.req("CTR-04")
def test_a_newer_minor_with_an_unknown_field_is_accepted() -> None:
    decoded = decode_response(decode_frame(vector("response_minor_1_extra_field")))
    decoded.DiscardUnknownFields()
    assert decoded == response_clean(1)
    grouped = decode_response(decode_frame(vector("response_unknown_group")))
    grouped.DiscardUnknownFields()
    assert grouped == response_clean(0)


@pytest.mark.req("CTR-02")
def test_the_pure_python_protobuf_runtime_gives_the_same_outcomes() -> None:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
        "PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION": "python",
    }
    command = [sys.executable, "-c", PURE_PYTHON_SCRIPT, str(TESTDATA)]
    result = subprocess.run(command, capture_output=True, text=True, env=env, check=False)
    assert result.returncode == 0, result.stderr
    outcomes = dict(line.split(" ", 1) for line in result.stdout.splitlines())
    manifest = json.loads((TESTDATA / "vectors.json").read_text())
    assert outcomes == {v["name"]: v["expect"] for v in manifest["vectors"]}


@pytest.mark.req("CTR-02", "CTR-03", "CTR-04")
@pytest.mark.parametrize(("name", "message", "kind"), INVALID, ids=[v[0] for v in INVALID])
def test_python_refuses_the_invalid_vectors_with_the_same_kind(
    name: str, message: str, kind: str
) -> None:
    decode = decode_request if message == "request" else decode_response
    with pytest.raises(ContractError) as error:
        decode(decode_frame(vector(name)))
    assert error.value.kind == kind


@pytest.mark.req("TOOLING")
def test_the_manifest_lists_the_same_vectors_and_expectations() -> None:
    manifest = json.loads((TESTDATA / "vectors.json").read_text())
    listed = {v["name"]: v["expect"] for v in manifest["vectors"]}
    expected = {"request_pdf": "ok", **dict.fromkeys(VALID_RESPONSES, "ok")}
    expected.update(dict.fromkeys(VALID_DECODE_ONLY, "ok"))
    expected.update({name: kind for name, _, kind in INVALID})
    assert listed == expected
    assert sorted(p.stem for p in TESTDATA.glob("*.bin")) == sorted(expected)
