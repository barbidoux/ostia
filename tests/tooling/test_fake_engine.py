"""The fake engine (tests/fakes/fake_engine.py): a worker process speaking the real framing.

It reads one framed AnalyzeRequest on stdin and the object on file descriptor 3 (read-only), and answers one
framed AnalyzeResponse on stdout, as configured by a JSON file (`--config` or OSTIA_FAKE_ENGINE_CONFIG): a
default answer and rules matched by sha256, object_id glob and detected_type (all keys of a rule must match;
the first matching rule in list order wins), each answering (fields override the default), waiting,
crashing, killing itself or writing garbage. Every config mistake is refused at start (exit 2, nothing on
stdout), so a later test can never pass because the fake crashed for an unrelated reason.
"""

import hashlib
import io
import json
import os
import resource
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


def no_core_dumps() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run_engine(
    tmp_path: Path,
    config: Mapping[str, object] | str,
    stdin: bytes,
    fd3: bytes | None,
    use_env: bool = False,
    fd3_mode: str = "<",
) -> subprocess.CompletedProcess[bytes]:
    config_path = tmp_path / "engine.json"
    config_path.write_text(config if isinstance(config, str) else json.dumps(config))
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
        command = ["bash", "-c", f'exec "$@" 3{fd3_mode}"$OBJECT"', "bash", *args]
        env["OBJECT"] = str(object_path)
    return subprocess.run(
        command,
        input=stdin,
        capture_output=True,
        env=env,
        cwd=tmp_path,
        timeout=60,
        check=False,
        preexec_fn=no_core_dumps,
    )


def answer(result: subprocess.CompletedProcess[bytes]) -> engine_pb2.AnalyzeResponse:
    assert result.returncode == 0, result.stderr.decode()
    stream = io.BytesIO(result.stdout)
    response = decode_response(read_frame(stream))
    assert stream.read() == b"", "more than one frame on stdout"
    return response


def config(*rules: Mapping[str, object]) -> dict[str, object]:
    return {"engine": ENGINE, "default": DEFAULT, "rules": list(rules)}


def run_rule(tmp_path: Path, rule: Mapping[str, object]) -> subprocess.CompletedProcess[bytes]:
    return run_engine(tmp_path, config(rule), encode_frame(request(b"x")), b"x")


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
        "match": {"sha256": sha256(EVIL).hex().upper()},
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
        (b"x", "object-0003", "text/plain", "OK", "CLEAN", None, []),
    ],
    ids=["by sha256 (any case)", "by object_id glob", "by detected_type", "default"],
)
def test_rules_choose_the_answer_and_override_the_default(
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
    assert response.duration_ms == 7, "fields a rule does not set come from the default"


@pytest.mark.req("TOOLING")
def test_the_first_matching_rule_in_list_order_wins(tmp_path: Path) -> None:
    # An object_id rule listed before a sha256 rule wins although sha256 is more specific.
    rules = (
        {"match": {"object_id": "suspect-*"}, "respond": {"hint": "SUSPICIOUS"}},
        {"match": {"sha256": sha256(EVIL).hex()}, "respond": {"hint": "MALICIOUS"}},
    )
    frame = encode_frame(request(EVIL, "suspect-1"))
    assert answer(run_engine(tmp_path, config(*rules), frame, EVIL)).hint == engine_pb2.SUSPICIOUS


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("object_id", "hint"),
    [("suspect-1", engine_pb2.MALICIOUS), ("object-0001", engine_pb2.CLEAN)],
    ids=["all keys match", "one key differs"],
)
def test_every_key_of_a_rule_must_match(tmp_path: Path, object_id: str, hint: int) -> None:
    rule = {
        "match": {"sha256": sha256(EVIL).hex(), "object_id": "suspect-*"},
        "respond": {"hint": "MALICIOUS"},
    }
    frame = encode_frame(request(EVIL, object_id))
    assert answer(run_engine(tmp_path, config(rule), frame, EVIL)).hint == hint


@pytest.mark.req("TOOLING")
def test_a_delay_postpones_the_answer(tmp_path: Path) -> None:
    # Compared with an undelayed run, so interpreter start-up does not count as the delay.
    started = time.monotonic()
    answer(run_rule(tmp_path, {"match": {"object_id": "*"}, "respond": {"hint": "NONE"}}))
    baseline = time.monotonic() - started
    rule = {"match": {"object_id": "*"}, "delay_ms": 1500, "respond": {"hint": "NONE"}}
    started = time.monotonic()
    result = run_rule(tmp_path, rule)
    assert time.monotonic() - started - baseline >= 1.0
    assert answer(result).hint == engine_pb2.NONE


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("crash", "code"), [({"exit_code": 3}, 3), ({}, 1)], ids=["exit code 3", "default exit code"]
)
def test_a_crash_exits_with_the_configured_code_and_no_output(
    tmp_path: Path, crash: dict[str, int], code: int
) -> None:
    result = run_rule(tmp_path, {"match": {"object_id": "*"}, "crash": crash})
    assert result.returncode == code
    assert result.stdout == b""


@pytest.mark.req("TOOLING")
def test_a_delay_then_a_crash_is_a_hang_that_dies(tmp_path: Path) -> None:
    started = time.monotonic()
    result = run_rule(
        tmp_path, {"match": {"object_id": "*"}, "delay_ms": 500, "crash": {"exit_code": 4}}
    )
    assert time.monotonic() - started >= 0.5
    assert (result.returncode, result.stdout) == (4, b"")


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize("name", ["SIGSEGV", "SIGKILL", "SIGABRT"])
def test_a_signal_kills_the_engine(tmp_path: Path, name: str) -> None:
    result = run_rule(tmp_path, {"match": {"object_id": "*"}, "signal": name})
    assert result.returncode == -getattr(signal, name), result.stderr.decode()
    assert result.stdout == b""


@pytest.mark.req("TOOLING")
def test_garbage_replaces_the_frame(tmp_path: Path) -> None:
    result = run_rule(tmp_path, {"match": {"object_id": "*"}, "garbage": "deadbeef00"})
    assert result.returncode == 0
    assert result.stdout == bytes.fromhex("deadbeef00")


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("fd3", "mode", "evidence"),
    [
        (b"not the object", "<", "sha256 of fd 3 differs from the request"),
        (None, "<", "fd 3 is not open"),
        (b"the object", "<>", "fd 3 is not read-only"),
    ],
    ids=["other content", "no fd 3", "read-write fd 3"],
)
def test_the_object_on_fd3_must_be_the_request_object_read_only(
    tmp_path: Path, fd3: bytes | None, mode: str, evidence: str
) -> None:
    frame = encode_frame(request(b"the object"))
    response = answer(run_engine(tmp_path, config(), frame, fd3, fd3_mode=mode))
    assert response.status == engine_pb2.ERROR
    assert [(f.id, f.evidence) for f in response.findings] == [("fake-engine:fd3", evidence)]


@pytest.mark.req("TOOLING")
def test_an_invalid_request_is_refused_without_output(tmp_path: Path) -> None:
    result = run_engine(tmp_path, config(), b"\x00\x00\x00\x00", b"x")
    assert result.returncode == 2
    assert result.stdout == b""
    assert "fake engine: request refused: empty" in result.stderr.decode()


def rule_with(**fields: object) -> dict[str, object]:
    return {"rules": [{"match": {"object_id": "*"}, **fields}]}


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("change", "message"),
    [
        (rule_with(respond={}, bogus=1), "unknown key 'bogus' in rules[0]"),
        ({"default": {"hint": "VERY_BAD"}}, "unknown hint 'VERY_BAD' in default"),
        ({"default": {"status": "FINE"}}, "unknown status 'FINE' in default"),
        (rule_with(crash={"exit_code": 3}, garbage="00"), "rules[0] needs exactly one of"),
        ({"engine": {"id": "fake"}}, "engine needs id, version and content_version"),
        ({"default": {"score": "high"}}, "score in default must be a number in [0, 1]"),
        ({"default": {"score": 1.5}}, "score in default must be a number in [0, 1]"),
        ({"default": {"duration_ms": -1}}, "duration_ms in default must be an integer >= 0"),
        ({"default": {"findings": 5}}, "findings in default must be a list"),
        (
            {"default": {"findings": [{"id": "F", "attack_ids": "T1"}]}},
            "attack_ids in default.findings[0] must be a list of strings",
        ),
        (
            {"default": {"findings": [{"id": "F", "severity": 5}]}},
            "severity in default.findings[0] must be an integer from 0 to 4",
        ),
        ({"default": {"findings": [{"name": "F"}]}}, "unknown key 'name' in default.findings[0]"),
        ({"rules": 5}, "rules must be a list"),
        ({"rules": [{"respond": {}}]}, "rules[0] needs a match"),
        (
            {"rules": [{"match": {"name": "*"}, "respond": {}}]},
            "unknown key 'name' in rules[0].match",
        ),
        (
            {"rules": [{"match": {"sha256": "abc"}, "respond": {}}]},
            "sha256 in rules[0].match must be 64 hex digits",
        ),
        (
            {"rules": [{"match": {"object_id": 7}, "respond": {}}]},
            "object_id in rules[0].match must be a string",
        ),
        (rule_with(respond={}, delay_ms=-1), "delay_ms in rules[0] must be an integer >= 0"),
        (rule_with(respond={}, delay_ms="5000"), "delay_ms in rules[0] must be an integer >= 0"),
        (rule_with(garbage="zz"), "garbage in rules[0] must be hex digits"),
        (rule_with(crash={"exit_code": "x"}), "exit_code in rules[0] must be from 1 to 255"),
        (rule_with(crash={"exit_code": 256}), "exit_code in rules[0] must be from 1 to 255"),
        (rule_with(crash={"exit_code": 0}), "exit_code in rules[0] must be from 1 to 255"),
        (rule_with(crash={"code": 3}), "unknown key 'code' in rules[0].crash"),
        (rule_with(signal="SIGHUP"), "unknown signal 'SIGHUP' in rules[0]"),
    ],
)
def test_an_invalid_config_is_refused(
    tmp_path: Path, change: dict[str, object], message: str
) -> None:
    result = run_engine(tmp_path, {**config(), **change}, encode_frame(request(b"x")), b"x")
    assert result.returncode == 2, result.stderr.decode()
    assert result.stdout == b""
    assert f"fake engine: config: {message}" in result.stderr.decode()


@pytest.mark.req("TOOLING")
def test_an_unreadable_or_missing_config_is_refused(tmp_path: Path) -> None:
    result = run_engine(tmp_path, "{not json", encode_frame(request(b"x")), b"x")
    assert (result.returncode, result.stdout) == (2, b"")
    assert "fake engine: config: cannot read" in result.stderr.decode()
    command = [sys.executable, str(FAKE)]
    env = {"PATH": os.environ["PATH"]}
    missing = subprocess.run(command, capture_output=True, env=env, timeout=60, check=False)
    assert (missing.returncode, missing.stdout) == (2, b"")
    expected = "fake engine: config: no --config and no OSTIA_FAKE_ENGINE_CONFIG"
    assert expected in missing.stderr.decode()
