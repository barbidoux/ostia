"""Length-prefixed framing and validated decoding of ostia.engine.v1 messages (ADR-03).

Every message on a worker's standard input or output is one frame: a 4-byte big-endian length, then the
encoded message (CTR-01). Any malformed, oversized, truncated or incompatible input raises ContractError,
never another exception (CTR-02). A response must name its engine, engine version and content version
(CTR-03); every message carries a ContractVersion whose major must be MAJOR (CTR-04). The error kinds are
shared with the Rust framing (crates/contracts) and the golden vectors (proto/testdata).
"""

from typing import Protocol

from google.protobuf.descriptor import Descriptor, FieldDescriptor
from google.protobuf.message import DecodeError, Message

from ostia_common.engine_v1 import engine_pb2

DEFAULT_MAX_FRAME = 16 * 1024 * 1024
MAJOR = 1
MINOR = 0


class ByteReader(Protocol):
    """What read_frame needs from a stream (stdin.buffer, a pipe, io.BytesIO)."""

    def read(self, size: int, /) -> bytes: ...


class ByteWriter(Protocol):
    """What write_frame needs from a stream (stdout.buffer, a pipe, io.BytesIO).

    `write` may write fewer bytes than given, or none (`None`, a full non-blocking pipe). A `flush`
    method, when the stream has one, is called after each frame.
    """

    def write(self, data: bytes, /) -> int | None: ...


class ContractError(Exception):
    """A frame or a message was refused; `kind` names why (shared with the Rust framing)."""

    def __init__(self, kind: str, detail: str = "") -> None:
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind = kind
        self.detail = detail


def current_version() -> engine_pb2.ContractVersion:
    """The version written into every message: {MAJOR, MINOR}."""
    return engine_pb2.ContractVersion(major=MAJOR, minor=MINOR)


def _effective_cap(cap: int) -> int:
    """The largest message length a frame can carry under `cap` (the prefix is 32 bits)."""
    return min(cap, 0xFFFFFFFF)


def _announced_length(header: bytes, cap: int) -> int:
    length = int.from_bytes(header, "big")
    if length == 0:
        raise ContractError("empty")
    if length > _effective_cap(cap):
        raise ContractError("oversized", f"{length} bytes, cap {cap}")
    return length


def encode_frame(message: Message, cap: int = DEFAULT_MAX_FRAME) -> bytes:
    """One frame holding `message`."""
    body = message.SerializeToString()
    if not body:
        raise ContractError("empty")
    if len(body) > _effective_cap(cap):
        raise ContractError("oversized", f"{len(body)} bytes, cap {cap}")
    return len(body).to_bytes(4, "big") + body


def decode_frame(buf: bytes, cap: int = DEFAULT_MAX_FRAME) -> bytes:
    """The message bytes of `buf`, which must hold exactly one frame."""
    if len(buf) < 4:
        raise ContractError("truncated_header")
    length = _announced_length(buf[:4], cap)
    body = buf[4:]
    if len(body) < length:
        raise ContractError("truncated_body")
    if len(body) > length:
        raise ContractError("trailing_bytes")
    return body


def _read_exactly(stream: ByteReader, size: int) -> bytes:
    """Up to `size` bytes; fewer only when the stream ends."""
    chunks = []
    remaining = size
    while remaining:
        try:
            chunk = stream.read(remaining)
        except (OSError, ValueError) as error:
            raise ContractError("io", str(error)) from error
        if not chunk:
            break
        if len(chunk) > remaining:
            raise ContractError("io", f"stream returned {len(chunk)} bytes for {remaining}")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(stream: ByteReader, cap: int = DEFAULT_MAX_FRAME) -> bytes:
    """Read one frame from `stream`; the cap is checked before any message byte is read."""
    header = _read_exactly(stream, 4)
    if len(header) < 4:
        raise ContractError("truncated_header")
    length = _announced_length(header, cap)
    body = _read_exactly(stream, length)
    if len(body) < length:
        raise ContractError("truncated_body")
    return body


def write_frame(stream: ByteWriter, message: Message, cap: int = DEFAULT_MAX_FRAME) -> None:
    """Write `message` to `stream` as one frame."""
    frame = memoryview(encode_frame(message, cap))
    written = 0
    try:
        while written < len(frame):
            count = stream.write(bytes(frame[written:]))
            if not count:
                raise ContractError("io", "the stream accepted no bytes")
            written += count
        flush = getattr(stream, "flush", None)
        if callable(flush):
            flush()
    except (OSError, ValueError) as error:
        raise ContractError("io", str(error)) from error


def _check_version(message: engine_pb2.AnalyzeRequest | engine_pb2.AnalyzeResponse) -> None:
    """A missing version reads as major 0; any major other than MAJOR is refused."""
    major = message.version.major if message.HasField("version") else 0
    if major != MAJOR:
        raise ContractError("unsupported_major", str(major))


def _parse[M: Message](message: M, descriptor: Descriptor, body: bytes) -> M:
    """Parse `body`, then hold it to the wire rules prost (the Rust decoder) enforces."""
    try:
        message.ParseFromString(body)
    except (DecodeError, ValueError, RecursionError) as error:
        # ValueError: UnicodeDecodeError from the pure-Python runtime on invalid UTF-8.
        raise ContractError("malformed", str(error)) from error
    _check_wire(memoryview(body), 0, len(body), descriptor, 0, 0)
    return message


# Wire types (protobuf encoding).
_VARINT, _I64, _LEN, _SGROUP, _EGROUP, _I32 = 0, 1, 2, 3, 4, 5
_I64_TYPES = {
    FieldDescriptor.TYPE_DOUBLE,
    FieldDescriptor.TYPE_FIXED64,
    FieldDescriptor.TYPE_SFIXED64,
}
_I32_TYPES = {
    FieldDescriptor.TYPE_FLOAT,
    FieldDescriptor.TYPE_FIXED32,
    FieldDescriptor.TYPE_SFIXED32,
}
_LEN_TYPES = {FieldDescriptor.TYPE_STRING, FieldDescriptor.TYPE_BYTES, FieldDescriptor.TYPE_MESSAGE}
_MAX_DEPTH = 100


def _varint(buf: memoryview, pos: int, end: int) -> tuple[int, int]:
    """A varint at `pos`: at most 10 bytes, the 10th at most 1 (no 64-bit overflow), as prost."""
    value = 0
    for index in range(10):
        if pos + index >= end:
            raise ContractError("malformed", "truncated varint")
        byte = buf[pos + index]
        if index == 9 and byte > 1:
            raise ContractError("malformed", "varint overflows 64 bits")
        value |= (byte & 0x7F) << (7 * index)
        if byte < 0x80:
            return value, pos + index + 1
    raise ContractError("malformed", "varint longer than 10 bytes")


def _wire_type(field: FieldDescriptor) -> int:
    """The wire type of a known field. v1 has no repeated scalar field, so packed encoding never
    applies; a future one must accept it here (prost does)."""
    if field.type in _I64_TYPES:
        return _I64
    if field.type in _I32_TYPES:
        return _I32
    if field.type in _LEN_TYPES:
        return _LEN
    if field.type == FieldDescriptor.TYPE_GROUP:
        return _SGROUP
    return _VARINT


def _check_wire(
    buf: memoryview, start: int, end: int, descriptor: Descriptor | None, group: int, depth: int
) -> int:
    """Walk buf[start:end] without copying: a message body, or (`group` > 0) a group body that must end
    with that group's end tag. Returns the position after the body.

    A known field must use its own wire type, recursively in known sub-messages; every varint, also in
    unknown fields, must fit 64 bits; keys must fit 32 bits with a non-zero field number.
    """
    if depth > _MAX_DEPTH:
        raise ContractError("malformed", "nested too deeply")
    pos = start
    while pos < end:
        key, pos = _varint(buf, pos, end)
        number, wire = key >> 3, key & 7
        if key > 0xFFFFFFFF or number == 0:
            raise ContractError("malformed", f"invalid key {key}")
        if wire == _EGROUP:
            if number != group:
                raise ContractError("malformed", f"unexpected end of group {number}")
            return pos
        field = descriptor.fields_by_number.get(number) if descriptor is not None else None
        if field is not None and wire != _wire_type(field):
            raise ContractError("malformed", f"field {field.name} sent with wire type {wire}")
        if wire == _VARINT:
            _, pos = _varint(buf, pos, end)
        elif wire == _I64:
            pos += 8
        elif wire == _I32:
            pos += 4
        elif wire == _LEN:
            length, pos = _varint(buf, pos, end)
            if pos + length > end:
                raise ContractError("malformed", "truncated field")
            if field is not None and field.message_type is not None:
                _check_wire(buf, pos, pos + length, field.message_type, 0, depth + 1)
            pos += length
        elif wire == _SGROUP:
            pos = _check_wire(buf, pos, end, None, number, depth + 1)
        else:
            raise ContractError("malformed", f"invalid wire type {wire}")
        if pos > end:
            raise ContractError("malformed", "truncated field")
    if group:
        raise ContractError("malformed", f"group {group} is not closed")
    return pos


def decode_request(body: bytes) -> engine_pb2.AnalyzeRequest:
    """Decode and validate a request: contract major, 32-byte SHA-256, known origin."""
    request = _parse(engine_pb2.AnalyzeRequest(), engine_pb2.AnalyzeRequest.DESCRIPTOR, body)
    _check_version(request)
    if len(request.sha256) != 32:
        raise ContractError("invalid_request", "sha256")
    if request.origin not in _KNOWN_ORIGINS:
        raise ContractError("invalid_request", "origin")
    return request


def decode_response(body: bytes) -> engine_pb2.AnalyzeResponse:
    """Decode and validate a response: major, engine identity, known status and hint, severity up to
    4, score in [0, 1]."""
    response = _parse(engine_pb2.AnalyzeResponse(), engine_pb2.AnalyzeResponse.DESCRIPTOR, body)
    _check_version(response)
    for field, value in (
        ("engine_id", response.engine_id),
        ("engine_version", response.engine_version),
        ("content_version", response.content_version),
    ):
        if not value:
            raise ContractError("missing_engine_identity", field)
    if response.status not in _KNOWN_STATUSES:
        raise ContractError("invalid_response", "status")
    if response.hint not in _KNOWN_HINTS:
        raise ContractError("invalid_response", "hint")
    if any(finding.severity > _MAX_SEVERITY for finding in response.findings):
        raise ContractError("invalid_response", "severity")
    if response.HasField("score") and not 0.0 <= response.score <= 1.0:
        raise ContractError("invalid_score", str(response.score))
    return response


_KNOWN_ORIGINS = frozenset(engine_pb2.Origin.values()) - {engine_pb2.ORIGIN_UNSPECIFIED}
_KNOWN_STATUSES = frozenset(engine_pb2.Status.values()) - {engine_pb2.STATUS_UNSPECIFIED}
_KNOWN_HINTS = frozenset(engine_pb2.Hint.values())
_MAX_SEVERITY = 4
