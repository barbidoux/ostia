"""Fake engine: a worker speaking the ostia.engine.v1 framing, answering as a JSON config says.

Usage: fake_engine.py [--config FILE]   (or OSTIA_FAKE_ENGINE_CONFIG=FILE)

Reads one framed AnalyzeRequest on stdin and the object on file descriptor 3, then answers one framed
AnalyzeResponse on stdout. Config:

    {
      "engine": {"id": "fake", "version": "1.0.0", "content_version": "rules-1"},
      "default": {"status": "OK", "hint": "CLEAN", "score": 0.1, "findings": [...], "duration_ms": 5},
      "rules": [
        {"match": {"sha256": "<hex>" | "object_id": "<glob>" | "detected_type": "<type>"},
         "delay_ms": 200,                           (optional, before acting)
         one of: "respond": {fields as "default", overriding it}
                 "crash": {"exit_code": 3}          (exit without output)
                 "signal": "SIGSEGV"                (kill itself)
                 "garbage": "<hex>"                 (write these bytes instead of a frame)}
      ]
    }

The first matching rule wins (all keys of its `match` must match); otherwise the default answers. If fd 3 is
missing or its SHA-256 differs from the request, the answer is status ERROR with finding "fake-engine:fd3".
A request or config that cannot be used exits 2 with a message on stderr and nothing on stdout.
"""

import argparse
import fnmatch
import hashlib
import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "workers-py" / "common" / "src"))

from ostia_common.engine_v1 import engine_pb2
from ostia_common.framing import (
    ContractError,
    current_version,
    decode_request,
    read_frame,
    write_frame,
)

ACTIONS = ("respond", "crash", "signal", "garbage")
RULE_KEYS = {"match", "delay_ms", *ACTIONS}
MATCH_KEYS = {"sha256", "object_id", "detected_type"}
ANSWER_KEYS = {"status", "hint", "score", "findings", "duration_ms"}
FINDING_KEYS = {"id", "title", "severity", "evidence", "attack_ids"}
STATUSES = frozenset(engine_pb2.Status.keys())
HINTS = frozenset(engine_pb2.Hint.keys())
SIGNALS = {"SIGSEGV": signal.SIGSEGV, "SIGKILL": signal.SIGKILL, "SIGABRT": signal.SIGABRT}


class ConfigError(Exception):
    """The config cannot be used."""


def check_keys(value: object, allowed: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{where} must be an object")
    for key in value:
        if key not in allowed:
            raise ConfigError(f"unknown key {key!r} in {where}")
    return value


def check_answer(value: object, where: str) -> dict[str, Any]:
    answer = check_keys(value, ANSWER_KEYS, where)
    if "status" in answer and answer["status"] not in STATUSES:
        raise ConfigError(f"unknown status {answer['status']!r} in {where}")
    if "hint" in answer and answer["hint"] not in HINTS:
        raise ConfigError(f"unknown hint {answer['hint']!r} in {where}")
    for index, finding in enumerate(answer.get("findings", [])):
        check_keys(finding, FINDING_KEYS, f"{where}.findings[{index}]")
    return answer


def load_config(path: Path) -> dict[str, Any]:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ConfigError(f"cannot read {path}: {error}") from error
    config = check_keys(config, {"engine", "default", "rules"}, "the config")
    identity = ("id", "version", "content_version")
    engine = check_keys(config.get("engine"), set(identity), "engine")
    if not all(isinstance(engine.get(key), str) and engine[key] for key in identity):
        raise ConfigError("engine needs id, version and content_version")
    check_answer(config.get("default", {}), "default")
    for index, rule in enumerate(config.get("rules", [])):
        where = f"rules[{index}]"
        rule = check_keys(rule, RULE_KEYS, where)
        check_keys(rule.get("match"), MATCH_KEYS, f"{where}.match")
        if sum(action in rule for action in ACTIONS) != 1:
            raise ConfigError(f"{where} needs exactly one of {', '.join(ACTIONS)}")
        if "respond" in rule:
            check_answer(rule["respond"], f"{where}.respond")
        if "signal" in rule and rule["signal"] not in SIGNALS:
            raise ConfigError(f"unknown signal {rule['signal']!r} in {where}")
    return config


def matches(rule: dict[str, Any], request: engine_pb2.AnalyzeRequest) -> bool:
    conditions = rule["match"]
    if "sha256" in conditions and request.sha256.hex() != conditions["sha256"].lower():
        return False
    if "object_id" in conditions and not fnmatch.fnmatchcase(
        request.object_id, conditions["object_id"]
    ):
        return False
    return "detected_type" not in conditions or request.detected_type == conditions["detected_type"]


def build_response(config: dict[str, Any], answer: dict[str, Any]) -> engine_pb2.AnalyzeResponse:
    engine = config["engine"]
    response = engine_pb2.AnalyzeResponse(
        engine_id=engine["id"],
        engine_version=engine["version"],
        content_version=engine["content_version"],
        status=engine_pb2.Status.Value(answer.get("status", "OK")),
        hint=engine_pb2.Hint.Value(answer.get("hint", "NONE")),
        duration_ms=answer.get("duration_ms", 0),
        version=current_version(),
    )
    if "score" in answer:
        response.score = answer["score"]
    for finding in answer.get("findings", []):
        response.findings.add(**finding)
    return response


def object_problem(request: engine_pb2.AnalyzeRequest) -> str | None:
    """Why the object on fd 3 cannot be the one the request describes, or None."""
    try:
        with os.fdopen(3, "rb") as stream:
            digest = hashlib.sha256(stream.read()).digest()
    except OSError:
        return "fd 3 is not open"
    if digest != request.sha256:
        return "sha256 of fd 3 differs from the request"
    return None


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Fake Ostia engine")
    parser.add_argument("--config", type=Path, default=os.environ.get("OSTIA_FAKE_ENGINE_CONFIG"))
    args = parser.parse_args(argv)
    if args.config is None:
        print("fake engine: config: no --config and no OSTIA_FAKE_ENGINE_CONFIG", file=sys.stderr)
        return 2
    try:
        config = load_config(Path(args.config))
    except ConfigError as error:
        print(f"fake engine: config: {error}", file=sys.stderr)
        return 2
    try:
        request = decode_request(read_frame(sys.stdin.buffer))
    except ContractError as error:
        print(f"fake engine: request refused: {error}", file=sys.stderr)
        return 2
    problem = object_problem(request)
    if problem is not None:
        answer = {"status": "ERROR", "findings": [{"id": "fake-engine:fd3", "evidence": problem}]}
        write_frame(sys.stdout.buffer, build_response(config, answer))
        return 0
    rule = next((rule for rule in config.get("rules", []) if matches(rule, request)), None)
    if rule is None:
        write_frame(sys.stdout.buffer, build_response(config, config.get("default", {})))
        return 0
    time.sleep(rule.get("delay_ms", 0) / 1000)
    if "crash" in rule:
        return int(rule["crash"].get("exit_code", 1))
    if "signal" in rule:
        sys.stdout.flush()
        signal.signal(SIGNALS[rule["signal"]], signal.SIG_DFL)
        os.kill(os.getpid(), SIGNALS[rule["signal"]])
        return 1
    if "garbage" in rule:
        sys.stdout.buffer.write(bytes.fromhex(rule["garbage"]))
        sys.stdout.buffer.flush()
        return 0
    answer = {**config.get("default", {}), **rule["respond"]}
    write_frame(sys.stdout.buffer, build_response(config, answer))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
