"""Length-prefixed framing and validated decoding of ostia.engine.v1 messages (ADR-03).

Every message on a worker's standard input or output is one frame: a 4-byte big-endian length, then the
encoded message (CTR-01). Any malformed, oversized, truncated or incompatible input raises ContractError,
never another exception (CTR-02). A response must name its engine, engine version and content version
(CTR-03); every message carries a ContractVersion whose major must be MAJOR (CTR-04). The error kinds are
shared with the Rust framing (crates/contracts) and the golden vectors (proto/testdata).
"""

from typing import Protocol

from google.protobuf.message import Message

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
    raise NotImplementedError


def encode_frame(message: Message, cap: int = DEFAULT_MAX_FRAME) -> bytes:
    """One frame holding `message`."""
    raise NotImplementedError


def decode_frame(buf: bytes, cap: int = DEFAULT_MAX_FRAME) -> bytes:
    """The message bytes of `buf`, which must hold exactly one frame."""
    raise NotImplementedError


def read_frame(stream: ByteReader, cap: int = DEFAULT_MAX_FRAME) -> bytes:
    """Read one frame from `stream`; the cap is checked before any message byte is read."""
    raise NotImplementedError


def write_frame(stream: ByteWriter, message: Message, cap: int = DEFAULT_MAX_FRAME) -> None:
    """Write `message` to `stream` as one frame."""
    raise NotImplementedError


def decode_request(body: bytes) -> engine_pb2.AnalyzeRequest:
    """Decode and validate a request: contract major, 32-byte SHA-256, known origin."""
    raise NotImplementedError


def decode_response(body: bytes) -> engine_pb2.AnalyzeResponse:
    """Decode and validate a response: major, engine identity, known status, score in [0, 1]."""
    raise NotImplementedError
