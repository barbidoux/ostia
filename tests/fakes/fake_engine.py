"""Fake engine: a worker speaking the ostia.engine.v1 framing, answering as a JSON config says.

Usage: fake_engine.py [--config FILE]   (or OSTIA_FAKE_ENGINE_CONFIG=FILE)

Reads one framed AnalyzeRequest on stdin and the object on file descriptor 3 (read-only), then answers one
framed AnalyzeResponse on stdout. Config:

    {
      "engine": {"id": "fake", "version": "1.0.0", "content_version": "rules-1"},
      "default": {"status": "OK", "hint": "CLEAN", "score": 0.1, "findings": [...], "duration_ms": 5},
      "rules": [
        {"match": {"sha256": "<64 hex>", "object_id": "<glob>", "detected_type": "<type>"},
         "delay_ms": 200,                           (optional, before acting)
         one of: "respond": {fields as "default", overriding it}
                 "crash": {"exit_code": 3}          (exit 1-255 without output; default 1)
                 "signal": "SIGSEGV"                (SIGSEGV, SIGKILL or SIGABRT: kill itself)
                 "garbage": "<hex>"                 (write these bytes instead of a frame)}
      ]
    }

A rule matches when every key of its `match` matches; the first matching rule in list order wins, otherwise
the default answers. Findings: {"id", "title", "severity" (0-4), "evidence", "attack_ids": [...]}.
If fd 3 is missing, writable, or its SHA-256 differs from the request, the answer is status ERROR with the
finding "fake-engine:fd3". Every config mistake is refused at start: exit 2, a message on stderr, nothing on
stdout; so is a request that is not a valid frame.

"name pattern" matching uses object_id: the request carries no file name.
"""

import argparse
import fcntl
import fnmatch
import hashlib
import json
import math
import os
import re
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
IDENTITY = ("id", "version", "content_version")
STATUSES = frozenset(engine_pb2.Status.keys())
HINTS = frozenset(engine_pb2.Hint.keys())
SIGNALS = {"SIGSEGV": signal.SIGSEGV, "SIGKILL": signal.SIGKILL, "SIGABRT": signal.SIGABRT}
SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
HEX = re.compile(r"^(?:[0-9a-fA-F]{2})*$")
CHUNK = 1 << 20


class ConfigError(Exception):
    """The config cannot be used."""


def obj(value: object, allowed: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{where} must be an object")
    for key in value:
        if key not in allowed:
            raise ConfigError(f"unknown key {key!r} in {where}")
    return value


def is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def natural(value: object, name: str, where: str) -> None:
    if not (isinstance(value, int) and not isinstance(value, bool) and value >= 0):
        raise ConfigError(f"{name} in {where} must be an integer >= 0")


def strings(value: object, name: str, where: str) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{name} in {where} must be a list of strings")


def check_finding(value: object, where: str) -> None:
    finding = obj(value, FINDING_KEYS, where)
    for key in ("id", "title", "evidence"):
        if key in finding and not isinstance(finding[key], str):
            raise ConfigError(f"{key} in {where} must be a string")
    severity = finding.get("severity", 0)
    if not is_int(severity) or not 0 <= severity <= 4:
        raise ConfigError(f"severity in {where} must be an integer from 0 to 4")
    if "attack_ids" in finding:
        strings(finding["attack_ids"], "attack_ids", where)


def check_answer(value: object, where: str) -> None:
    answer = obj(value, ANSWER_KEYS, where)
    if "status" in answer and answer["status"] not in STATUSES:
        raise ConfigError(f"unknown status {answer['status']!r} in {where}")
    if "hint" in answer and answer["hint"] not in HINTS:
        raise ConfigError(f"unknown hint {answer['hint']!r} in {where}")
    if "score" in answer:
        score = answer["score"]
        number = isinstance(score, (int, float)) and not isinstance(score, bool)
        if not number or not math.isfinite(score) or not 0 <= score <= 1:
            raise ConfigError(f"score in {where} must be a number in [0, 1]")
    if "duration_ms" in answer:
        natural(answer["duration_ms"], "duration_ms", where)
    findings = answer.get("findings", [])
    if not isinstance(findings, list):
        raise ConfigError(f"findings in {where} must be a list")
    for index, finding in enumerate(findings):
        check_finding(finding, f"{where}.findings[{index}]")


def check_rule(value: object, where: str) -> None:
    rule = obj(value, RULE_KEYS, where)
    if "match" not in rule:
        raise ConfigError(f"{where} needs a match")
    conditions = obj(rule["match"], MATCH_KEYS, f"{where}.match")
    for key, condition in conditions.items():
        if not isinstance(condition, str):
            raise ConfigError(f"{key} in {where}.match must be a string")
    if "sha256" in conditions and not SHA256.match(conditions["sha256"]):
        raise ConfigError(f"sha256 in {where}.match must be 64 hex digits")
    if "delay_ms" in rule:
        natural(rule["delay_ms"], "delay_ms", where)
    if sum(action in rule for action in ACTIONS) != 1:
        raise ConfigError(f"{where} needs exactly one of {', '.join(ACTIONS)}")
    if "respond" in rule:
        check_answer(rule["respond"], f"{where}.respond")
    if "crash" in rule:
        code = obj(rule["crash"], {"exit_code"}, f"{where}.crash").get("exit_code", 1)
        if not is_int(code) or not 1 <= code <= 255:
            raise ConfigError(f"exit_code in {where} must be from 1 to 255")
    if "signal" in rule and rule["signal"] not in SIGNALS:
        raise ConfigError(f"unknown signal {rule['signal']!r} in {where}")
    if "garbage" in rule and not (isinstance(rule["garbage"], str) and HEX.match(rule["garbage"])):
        raise ConfigError(f"garbage in {where} must be hex digits")


def load_config(path: Path) -> dict[str, Any]:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ConfigError(f"cannot read {path}: {error}") from error
    config = obj(config, {"engine", "default", "rules"}, "the config")
    engine = obj(config.get("engine"), set(IDENTITY), "engine")
    if not all(isinstance(engine.get(key), str) and engine[key] for key in IDENTITY):
        raise ConfigError("engine needs id, version and content_version")
    check_answer(config.get("default", {}), "default")
    rules = config.get("rules", [])
    if not isinstance(rules, list):
        raise ConfigError("rules must be a list")
    for index, rule in enumerate(rules):
        check_rule(rule, f"rules[{index}]")
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
        mode = fcntl.fcntl(3, fcntl.F_GETFL) & os.O_ACCMODE
    except OSError:
        return "fd 3 is not open"
    if mode != os.O_RDONLY:
        return "fd 3 is not read-only"
    digest = hashlib.sha256()
    with os.fdopen(3, "rb") as stream:
        while chunk := stream.read(CHUNK):
            digest.update(chunk)
    if digest.digest() != request.sha256:
        return "sha256 of fd 3 differs from the request"
    return None


def die(name: str) -> int:
    """Kill this process with the named signal (SIGKILL cannot have a handler, so none is reset)."""
    number = SIGNALS[name]
    sys.stdout.flush()
    if number != signal.SIGKILL:
        signal.signal(number, signal.SIG_DFL)
    os.kill(os.getpid(), number)
    return 1


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
        return die(rule["signal"])
    if "garbage" in rule:
        sys.stdout.buffer.write(bytes.fromhex(rule["garbage"]))
        sys.stdout.buffer.flush()
        return 0
    answer = {**config.get("default", {}), **rule["respond"]}
    write_frame(sys.stdout.buffer, build_response(config, answer))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
