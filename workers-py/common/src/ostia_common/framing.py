"""Length-prefixed framing and validated decoding of ostia.engine.v1 messages (ADR-03).

Every message on a worker's standard input or output is one frame: a 4-byte big-endian length, then the
encoded message (CTR-01). Any malformed, oversized, truncated or incompatible input raises ContractError,
never another exception (CTR-02). A response must name its engine, engine version and content version
(CTR-03); every message carries a ContractVersion whose major must be MAJOR (CTR-04). The error kinds are
shared with the Rust framing (crates/contracts) and the golden vectors (proto/testdata).
"""

from typing import Protocol

from google.protobuf.message import DecodeError, Message

from ostia_common.engine_v1 import engine_pb2

DEFAULT_MAX_FRAME = 16 * 1024 * 1024
MAJOR = 1
MINOR = 0


class ByteReader(Protocol):
    """What read_frame needs from a stream (stdin.buffer, a pipe, io.BytesIO)."""

    def read(self, size: int, /) -> bytes: ...


class ByteWriter(Protocol):
    """What write_frame needs from a stream (stdout.buffer, a pipe, io.BytesIO)."""

    def write(self, data: bytes, /) -> int: ...


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
        except OSError as error:
            raise ContractError("io", str(error)) from error
        if not chunk:
            break
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
    frame = encode_frame(message, cap)
    try:
        stream.write(frame)
    except OSError as error:
        raise ContractError("io", str(error)) from error


def _check_version(message: engine_pb2.AnalyzeRequest | engine_pb2.AnalyzeResponse) -> None:
    """A missing version reads as major 0; any major other than MAJOR is refused."""
    major = message.version.major if message.HasField("version") else 0
    if major != MAJOR:
        raise ContractError("unsupported_major", str(major))


def _parse[M: Message](message: M, body: bytes) -> M:
    try:
        message.ParseFromString(body)
    except DecodeError as error:
        raise ContractError("malformed", str(error)) from error
    return message


def decode_request(body: bytes) -> engine_pb2.AnalyzeRequest:
    """Decode and validate a request: contract major, 32-byte SHA-256, known origin."""
    request = _parse(engine_pb2.AnalyzeRequest(), body)
    _check_version(request)
    if len(request.sha256) != 32:
        raise ContractError("invalid_request", "sha256")
    if request.origin not in _KNOWN_ORIGINS:
        raise ContractError("invalid_request", "origin")
    return request


def decode_response(body: bytes) -> engine_pb2.AnalyzeResponse:
    """Decode and validate a response: major, engine identity, known status, score in [0, 1]."""
    response = _parse(engine_pb2.AnalyzeResponse(), body)
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
    if response.HasField("score") and not 0.0 <= response.score <= 1.0:
        raise ContractError("invalid_score", str(response.score))
    return response


_KNOWN_ORIGINS = frozenset(engine_pb2.Origin.values()) - {engine_pb2.ORIGIN_UNSPECIFIED}
_KNOWN_STATUSES = frozenset(engine_pb2.Status.values()) - {engine_pb2.STATUS_UNSPECIFIED}
