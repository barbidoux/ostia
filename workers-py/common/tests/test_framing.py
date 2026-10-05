"""Framing and validated decoding of ostia.engine.v1 messages in Python (CTR-01 to CTR-04).

Mirrors crates/contracts/tests/framing.rs: same frames, same error kinds.
"""

import io
import math
from collections.abc import Callable

import pytest
from hypothesis import given, seed, settings
from hypothesis import strategies as st

from ostia_common.engine_v1 import engine_pb2
from ostia_common.framing import (
    DEFAULT_MAX_FRAME,
    MAJOR,
    MINOR,
    ByteReader,
    ByteWriter,
    ContractError,
    current_version,
    decode_frame,
    decode_request,
    decode_response,
    encode_frame,
    read_frame,
    write_frame,
)

SHA256_EMPTY = bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")


def apply(
    message: engine_pb2.AnalyzeRequest | engine_pb2.AnalyzeResponse, changes: dict[str, object]
) -> None:
    """Set fields of `message`; `version=None` removes the version."""
    for name, value in changes.items():
        if name != "version":
            setattr(message, name, value)
        elif isinstance(value, engine_pb2.ContractVersion):
            message.version.CopyFrom(value)
        else:
            message.ClearField("version")


def request(**changes: object) -> engine_pb2.AnalyzeRequest:
    message = engine_pb2.AnalyzeRequest(
        session_id="session-0001",
        object_id="object-0001",
        sha256=SHA256_EMPTY,
        detected_type="application/pdf",
        size=0,
        origin=engine_pb2.FILE,
        limits=engine_pb2.Limits(memory_bytes=268_435_456, duration_ms=30_000, write_bytes=0),
        version=engine_pb2.ContractVersion(major=1, minor=0),
    )
    apply(message, changes)
    return message


def response(**changes: object) -> engine_pb2.AnalyzeResponse:
    message = engine_pb2.AnalyzeResponse(
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
    apply(message, changes)
    return message


def refused(call: object, *args: object) -> ContractError:
    assert callable(call)
    with pytest.raises(ContractError) as error:
        call(*args)
    return error.value


@pytest.mark.req("CTR-04")
def test_messages_carry_contract_version_one_zero() -> None:
    assert (MAJOR, MINOR) == (1, 0)
    assert current_version() == engine_pb2.ContractVersion(major=1, minor=0)


@pytest.mark.req("CTR-01")
def test_frame_is_a_big_endian_length_then_the_message() -> None:
    small = engine_pb2.ContractVersion(major=1, minor=0)
    assert encode_frame(small) == bytes([0x00, 0x00, 0x00, 0x02, 0x08, 0x01])
    big = engine_pb2.ContractVersion(major=1, minor=300)
    assert encode_frame(big) == bytes([0x00, 0x00, 0x00, 0x05, 0x08, 0x01, 0x10, 0xAC, 0x02])


@pytest.mark.req("CTR-01")
def test_request_round_trips_through_a_frame() -> None:
    assert decode_request(decode_frame(encode_frame(request()))) == request()


@pytest.mark.req("CTR-01", "CTR-03")
def test_response_round_trips_through_a_frame() -> None:
    assert decode_response(decode_frame(encode_frame(response()))) == response()


@pytest.mark.req("CTR-01")
def test_frames_round_trip_through_a_stream() -> None:
    stream = io.BytesIO()
    write_frame(stream, request())
    write_frame(stream, response())
    stream.seek(0)
    assert decode_request(read_frame(stream)) == request()
    assert decode_response(read_frame(stream)) == response()
    assert refused(read_frame, stream).kind == "truncated_header"


@pytest.mark.req("CTR-02")
@pytest.mark.parametrize(
    ("frame", "kind"),
    [
        (b"\x00\x00\x00\x00", "empty"),
        (b"", "truncated_header"),
        (b"\x00\x00\x01", "truncated_header"),
        (b"\x00\x00\x00\x04\x01\x02\x03", "truncated_body"),
        (b"\x00\x00\x00\x01\x01\x02", "trailing_bytes"),
        (b"\x01\x00\x00\x01", "oversized"),
        (b"\xff\xff\xff\xff", "oversized"),
    ],
)
def test_malformed_frames_are_rejected_with_their_kind(frame: bytes, kind: str) -> None:
    assert refused(decode_frame, frame).kind == kind


@pytest.mark.req("CTR-02")
def test_the_cap_is_configurable() -> None:
    assert DEFAULT_MAX_FRAME == 16 * 1024 * 1024
    frame = b"\x00\x00\x00\x05\x01\x02\x03\x04\x05"
    assert decode_frame(frame, 5) == b"\x01\x02\x03\x04\x05"
    assert refused(decode_frame, frame, 4).kind == "oversized"
    assert refused(encode_frame, response(), 16).kind == "oversized"


class Announcing:
    """An unbuffered stream that announces a 4 GiB frame and counts the bytes asked for after it."""

    def __init__(self) -> None:
        self.header = io.BytesIO(b"\xff\xff\xff\xff")
        self.requested_after_header = 0

    def read(self, size: int, /) -> bytes:
        chunk = self.header.read(size)
        if chunk:
            return chunk
        self.requested_after_header += size
        return bytes(size)


@pytest.mark.req("CTR-02")
def test_the_cap_is_checked_before_reading_the_body() -> None:
    stream = Announcing()
    assert refused(read_frame, stream).kind == "oversized"
    assert stream.requested_after_header == 0


@pytest.mark.req("CTR-02")
def test_a_stream_that_ends_early_is_truncated() -> None:
    frame = encode_frame(response())
    assert refused(read_frame, io.BytesIO(frame[:2])).kind == "truncated_header"
    assert refused(read_frame, io.BytesIO(frame[:-1])).kind == "truncated_body"
    assert refused(read_frame, io.BytesIO(b"\x00\x00\x00\x00")).kind == "empty"


@pytest.mark.req("CTR-02")
def test_bytes_that_are_not_protobuf_are_malformed() -> None:
    body = b"\x0a\x05ab"  # field 1 announces 5 bytes and only 2 follow
    assert refused(decode_response, body).kind == "malformed"
    assert refused(decode_request, body).kind == "malformed"


@pytest.mark.req("CTR-02", "CTR-04")
@pytest.mark.parametrize(
    ("version", "expected"),
    [
        (None, "unsupported_major"),
        (engine_pb2.ContractVersion(major=0, minor=9), "unsupported_major"),
        (engine_pb2.ContractVersion(major=2, minor=0), "unsupported_major"),
        (engine_pb2.ContractVersion(major=1, minor=7), None),
    ],
    ids=["missing", "major 0", "major 2", "newer minor"],
)
def test_other_majors_are_refused_and_newer_minors_accepted(
    version: engine_pb2.ContractVersion | None, expected: str | None
) -> None:
    response_body = decode_frame(encode_frame(response(version=version)))
    request_body = decode_frame(encode_frame(request(version=version)))
    if expected is None:
        assert decode_response(response_body).version.minor == 7
        assert decode_request(request_body).version.minor == 7
    else:
        assert refused(decode_response, response_body).kind == expected
        assert refused(decode_request, request_body).kind == expected


@pytest.mark.req("CTR-03")
@pytest.mark.parametrize("field", ["engine_id", "engine_version", "content_version"])
def test_responses_without_engine_identity_are_refused(field: str) -> None:
    error = refused(decode_response, decode_frame(encode_frame(response(**{field: ""}))))
    assert error.kind == "missing_engine_identity"
    assert error.detail == field


@pytest.mark.req("CTR-02")
@pytest.mark.parametrize("score", [-0.001, 1.5, math.nan, math.inf])
def test_scores_outside_zero_one_are_refused(score: float) -> None:
    body = decode_frame(encode_frame(response(score=score)))
    assert refused(decode_response, body).kind == "invalid_score"


@pytest.mark.req("CTR-02")
@pytest.mark.parametrize("score", [0.0, 1.0])
def test_scores_at_the_bounds_are_accepted(score: float) -> None:
    assert decode_response(decode_frame(encode_frame(response(score=score)))).score == score


@pytest.mark.req("CTR-02")
@pytest.mark.parametrize(
    ("changes", "detail"),
    [
        ({"sha256": SHA256_EMPTY[:31]}, "sha256"),
        ({"origin": 0}, "origin"),
        ({"origin": 99}, "origin"),
    ],
    ids=["short sha256", "unspecified origin", "unknown origin"],
)
def test_invalid_request_fields_are_refused(changes: dict[str, object], detail: str) -> None:
    error = refused(decode_request, decode_frame(encode_frame(request(**changes))))
    assert (error.kind, error.detail) == ("invalid_request", detail)


@pytest.mark.req("CTR-02")
@pytest.mark.parametrize("status", [0, 99])
def test_unknown_statuses_are_refused(status: int) -> None:
    error = refused(decode_response, decode_frame(encode_frame(response(status=status))))
    assert (error.kind, error.detail) == ("invalid_response", "status")


@pytest.mark.req("CTR-02")
@pytest.mark.parametrize("hint", [-1, 5, 99])
def test_unknown_hints_are_refused(hint: int) -> None:
    error = refused(decode_response, decode_frame(encode_frame(response(hint=hint))))
    assert (error.kind, error.detail) == ("invalid_response", "hint")


@pytest.mark.req("CTR-02")
def test_unspecified_hint_is_accepted_and_severity_above_four_refused() -> None:
    assert decode_response(decode_frame(encode_frame(response(hint=0)))).hint == 0
    severe = response()
    severe.findings[0].severity = 5
    error = refused(decode_response, decode_frame(encode_frame(severe)))
    assert (error.kind, error.detail) == ("invalid_response", "severity")


@pytest.mark.req("CTR-02")
def test_encoding_honours_the_cap_exactly() -> None:
    message = engine_pb2.ContractVersion(major=1, minor=0)
    assert encode_frame(message, 2) == b"\x00\x00\x00\x02\x08\x01"
    assert refused(encode_frame, message, 1).kind == "oversized"
    assert refused(encode_frame, engine_pb2.ContractVersion()).kind == "empty"
    # A cap above what 32 bits can announce: the longest announced frame is merely truncated.
    assert refused(decode_frame, b"\xff\xff\xff\xff", 2**64).kind == "truncated_body"


class Trickle:
    """A stream that hands out one byte per call."""

    def __init__(self, data: bytes) -> None:
        self.data = io.BytesIO(data)

    def read(self, size: int, /) -> bytes:
        return self.data.read(min(size, 1))


class Generous:
    """A broken stream that returns more bytes than asked for."""

    def read(self, size: int, /) -> bytes:
        return bytes(size + 1)


class Failing:
    def __init__(self, error: Exception) -> None:
        self.error = error

    def read(self, size: int, /) -> bytes:
        raise self.error

    def write(self, data: bytes, /) -> int:
        raise self.error


class Recording:
    """A writer that accepts one byte per call (or none, like a full non-blocking pipe)."""

    def __init__(self, accept: int | None = 1) -> None:
        self.accept = accept
        self.data = bytearray()
        self.flushes = 0

    def write(self, data: bytes, /) -> int | None:
        if self.accept is None:
            return None
        self.data += data[: self.accept]
        return min(len(data), self.accept)

    def flush(self) -> None:
        self.flushes += 1


@pytest.mark.req("CTR-01")
def test_short_reads_are_retried() -> None:
    assert decode_response(read_frame(Trickle(encode_frame(response())))) == response()


@pytest.mark.req("CTR-01", "CTR-02")
@pytest.mark.parametrize(
    "stream",
    [Generous(), Failing(PermissionError("denied")), Failing(ValueError("closed file"))],
    ids=["more than asked", "OSError", "closed stream"],
)
def test_stream_failures_are_io_errors_on_read(stream: ByteReader) -> None:
    assert refused(read_frame, stream).kind == "io"


@pytest.mark.req("CTR-01")
def test_short_writes_are_completed_and_flushed() -> None:
    writer = Recording()
    write_frame(writer, response())
    assert bytes(writer.data) == encode_frame(response())
    assert writer.flushes == 1


@pytest.mark.req("CTR-01", "CTR-02")
@pytest.mark.parametrize(
    "stream",
    [Recording(accept=None), Failing(BrokenPipeError("pipe")), Failing(ValueError("closed"))],
    ids=["nothing written", "OSError", "closed stream"],
)
def test_stream_failures_are_io_errors_on_write(stream: ByteWriter) -> None:
    assert refused(write_frame, stream, response()).kind == "io"


@pytest.mark.req("CTR-02")
@seed(0x057AC0DE)
@settings(max_examples=2000, database=None, deadline=None)
@given(st.binary(max_size=512))
def test_decoders_only_raise_contract_errors_on_random_bytes(data: bytes) -> None:
    calls: list[Callable[[], object]] = [
        lambda: decode_frame(data),
        lambda: decode_frame(data, 64),
        lambda: read_frame(io.BytesIO(data)),
        lambda: decode_request(data),
        lambda: decode_response(data),
    ]
    for call in calls:
        try:
            call()
        except ContractError:
            pass


@pytest.mark.req("CTR-02")
@seed(0x057AC0DE)
@settings(max_examples=2000, database=None, deadline=None)
@given(st.binary(min_size=1, max_size=512))
def test_framed_random_bodies_only_raise_contract_errors(body: bytes) -> None:
    frame = len(body).to_bytes(4, "big") + body
    assert decode_frame(frame) == body
    for decode in (decode_request, decode_response):
        try:
            decode(body)
        except ContractError:
            pass
