"""The fake engine (tests/fakes/fake_engine.py): a worker process speaking the real framing.

It reads one framed AnalyzeRequest on stdin and the object on file descriptor 3, and answers one framed
AnalyzeResponse on stdout, as configured by a JSON file (`--config` or OSTIA_FAKE_ENGINE_CONFIG): a default
answer and rules matched by sha256, object_id glob or detected_type (first match wins), each answering,
waiting, crashing, killing itself or writing garbage.
"""

import hashlib
import io
import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Mapping
from pathlib import Path

import pytest

from ostia_common.engine_v1 import engine_pb2
from ostia_common.framing import decode_response, encode_frame, read_frame
from tooling_support import REPO

FAKE = REPO / "tests" / "fakes" / "fake_engine.py"
ENGINE = {"id": "fake", "version": "1.0.0", "content_version": "rules-1"}
DEFAULT = {"status": "OK", "hint": "CLEAN", "duration_ms": 7}
EVIL = b"evil payload"
PLANTED = {
    "id": "FAKE-1",
    "title": "planted marker",
    "severity": 4,
    "evidence": "marker at offset 0",
    "attack_ids": ["T1204"],
}


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def request(
    data: bytes, object_id: str = "object-0001", detected_type: str = "application/pdf"
) -> engine_pb2.AnalyzeRequest:
    return engine_pb2.AnalyzeRequest(
        session_id="session-0001",
        object_id=object_id,
        sha256=sha256(data),
        detected_type=detected_type,
        size=len(data),
        origin=engine_pb2.FILE,
        version=engine_pb2.ContractVersion(major=1, minor=0),
    )


def run_engine(
    tmp_path: Path,
    config: dict[str, object],
    stdin: bytes,
    fd3: bytes | None,
    use_env: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    config_path = tmp_path / "engine.json"
    config_path.write_text(json.dumps(config))
    env = {"PATH": os.environ["PATH"]}
    args = [sys.executable, str(FAKE)]
    if use_env:
        env["OSTIA_FAKE_ENGINE_CONFIG"] = str(config_path)
    else:
        args += ["--config", str(config_path)]
    if fd3 is None:
        command = args
    else:
        object_path = tmp_path / "object.bin"
        object_path.write_bytes(fd3)
        command = ["bash", "-c", 'exec "$@" 3<"$OBJECT"', "bash", *args]
        env["OBJECT"] = str(object_path)
    return subprocess.run(
        command, input=stdin, capture_output=True, env=env, timeout=60, check=False
    )


def answer(result: subprocess.CompletedProcess[bytes]) -> engine_pb2.AnalyzeResponse:
    assert result.returncode == 0, result.stderr.decode()
    stream = io.BytesIO(result.stdout)
    response = decode_response(read_frame(stream))
    assert stream.read() == b"", "more than one frame on stdout"
    return response


def config(*rules: Mapping[str, object]) -> dict[str, object]:
    return {"engine": ENGINE, "default": DEFAULT, "rules": list(rules)}


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize("use_env", [False, True], ids=["--config", "environment"])
def test_the_default_answer_carries_the_configured_engine(tmp_path: Path, use_env: bool) -> None:
    data = b"harmless"
    result = run_engine(tmp_path, config(), encode_frame(request(data)), data, use_env)
    assert answer(result) == engine_pb2.AnalyzeResponse(
        engine_id="fake",
        engine_version="1.0.0",
        content_version="rules-1",
        status=engine_pb2.OK,
        hint=engine_pb2.CLEAN,
        duration_ms=7,
        version=engine_pb2.ContractVersion(major=1, minor=0),
    )


RULES = (
    {
        "match": {"sha256": sha256(EVIL).hex()},
        "respond": {"hint": "MALICIOUS", "score": 0.99, "findings": [PLANTED]},
    },
    {"match": {"object_id": "suspect-*"}, "respond": {"hint": "SUSPICIOUS", "score": 0.6}},
    {
        "match": {"detected_type": "application/x-dosexec"},
        "respond": {"status": "UNSUPPORTED", "hint": "NONE"},
    },
)


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("data", "object_id", "detected_type", "status", "hint", "score", "findings"),
    [
        (EVIL, "object-0001", "application/pdf", "OK", "MALICIOUS", 0.99, [PLANTED]),
        (b"x", "suspect-7", "application/pdf", "OK", "SUSPICIOUS", 0.6, []),
        (b"x", "object-0002", "application/x-dosexec", "UNSUPPORTED", "NONE", None, []),
        (EVIL, "suspect-7", "application/x-dosexec", "OK", "MALICIOUS", 0.99, [PLANTED]),
        (b"x", "object-0003", "text/plain", "OK", "CLEAN", None, []),
    ],
    ids=["by sha256", "by object_id glob", "by detected_type", "first match wins", "default"],
)
def test_rules_choose_the_answer(
    tmp_path: Path,
    data: bytes,
    object_id: str,
    detected_type: str,
    status: str,
    hint: str,
    score: float | None,
    findings: list[dict[str, object]],
) -> None:
    frame = encode_frame(request(data, object_id, detected_type))
    response = answer(run_engine(tmp_path, config(*RULES), frame, data))
    assert engine_pb2.Status.Name(response.status) == status
    assert engine_pb2.Hint.Name(response.hint) == hint
    assert (response.score if response.HasField("score") else None) == score
    assert [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "evidence": f.evidence,
            "attack_ids": list(f.attack_ids),
        }
        for f in response.findings
    ] == findings
    assert response.engine_id == "fake"


@pytest.mark.req("TOOLING")
def test_a_delay_postpones_the_answer(tmp_path: Path) -> None:
    rule = {"match": {"object_id": "*"}, "delay_ms": 300, "respond": {"hint": "NONE"}}
    started = time.monotonic()
    result = run_engine(tmp_path, config(rule), encode_frame(request(b"x")), b"x")
    assert time.monotonic() - started >= 0.3
    assert answer(result).hint == engine_pb2.NONE


@pytest.mark.req("TOOLING")
def test_a_crash_exits_with_the_configured_code_and_no_output(tmp_path: Path) -> None:
    rule = {"match": {"object_id": "*"}, "crash": {"exit_code": 3}}
    result = run_engine(tmp_path, config(rule), encode_frame(request(b"x")), b"x")
    assert result.returncode == 3
    assert result.stdout == b""


@pytest.mark.req("TOOLING")
def test_a_signal_kills_the_engine(tmp_path: Path) -> None:
    rule = {"match": {"object_id": "*"}, "signal": "SIGSEGV"}
    result = run_engine(tmp_path, config(rule), encode_frame(request(b"x")), b"x")
    assert result.returncode == -signal.SIGSEGV
    assert result.stdout == b""


@pytest.mark.req("TOOLING")
def test_garbage_replaces_the_frame(tmp_path: Path) -> None:
    rule = {"match": {"object_id": "*"}, "garbage": "deadbeef00"}
    result = run_engine(tmp_path, config(rule), encode_frame(request(b"x")), b"x")
    assert result.returncode == 0
    assert result.stdout == bytes.fromhex("deadbeef00")


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("fd3", "evidence"),
    [(b"not the object", "sha256 of fd 3 differs from the request"), (None, "fd 3 is not open")],
    ids=["other content", "no fd 3"],
)
def test_the_object_on_fd3_must_match_the_request(
    tmp_path: Path, fd3: bytes | None, evidence: str
) -> None:
    result = run_engine(tmp_path, config(), encode_frame(request(b"the object")), fd3)
    response = answer(result)
    assert response.status == engine_pb2.ERROR
    assert [(f.id, f.evidence) for f in response.findings] == [("fake-engine:fd3", evidence)]


@pytest.mark.req("TOOLING")
def test_an_invalid_request_is_refused_without_output(tmp_path: Path) -> None:
    result = run_engine(tmp_path, config(), b"\x00\x00\x00\x00", b"x")
    assert result.returncode == 2
    assert result.stdout == b""
    assert "fake engine: request refused: empty" in result.stderr.decode()


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"rules": [{"match": {"object_id": "*"}, "bogus": 1}]}, "unknown key 'bogus' in rules[0]"),
        ({"default": {"hint": "VERY_BAD"}}, "unknown hint 'VERY_BAD' in default"),
        (
            {"rules": [{"match": {"object_id": "*"}, "crash": {"exit_code": 3}, "garbage": "00"}]},
            "rules[0] needs exactly one of respond, crash, signal, garbage",
        ),
        ({"engine": {"id": "fake"}}, "engine needs id, version and content_version"),
    ],
    ids=["unknown key", "unknown hint", "two actions", "incomplete engine"],
)
def test_an_invalid_config_is_refused(
    tmp_path: Path, change: dict[str, object], message: str
) -> None:
    result = run_engine(tmp_path, {**config(), **change}, encode_frame(request(b"x")), b"x")
    assert result.returncode == 2
    assert result.stdout == b""
    assert f"fake engine: config: {message}" in result.stderr.decode()
