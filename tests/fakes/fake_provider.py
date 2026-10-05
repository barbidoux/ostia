"""Fake enrichment provider (P8 skeleton): an HTTP server on loopback answering recorded responses.

Usage: fake_provider.py --recordings FILE --log FILE [--port 0]

Recordings (JSON): {"lookups": {"<sha256>": {"status": 200, "body": {...}}},
                    "unknown": {"status": 404, "body": {...}},
                    "upload": {"status": 200, "body": {...}}}

GET /files/<sha256> answers the recorded lookup or "unknown"; POST /files answers "upload"; anything else
is 404 {"error": "unknown endpoint"}. Every request is logged as one JSON line {method, path} plus, when it
carried a body, its SHA-256 and size (never its content). It never calls anything outside. The provider
contracts come with P8; recorded responses only, no live service.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from fake_http import JsonLines, QuietHandler, arguments, loopback_only, serve

LOOKUP = re.compile(r"^/files/([0-9a-f]{64})$")
LOOKUP_KEY = re.compile(r"^[0-9a-f]{64}$")


class RecordingsError(Exception):
    """The recordings cannot be used."""


def load_recordings(path: Path) -> dict[str, Any]:
    try:
        recordings = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RecordingsError(f"cannot read {path}: {error}") from error
    if not isinstance(recordings, dict):
        raise RecordingsError("must be an object")
    for key in ("lookups", "unknown", "upload"):
        if key not in recordings:
            raise RecordingsError(f"missing {key!r}")
    if not isinstance(recordings["lookups"], dict):
        raise RecordingsError("lookups must be an object")
    responses = {"unknown": recordings["unknown"], "upload": recordings["upload"]}
    for digest, response in recordings["lookups"].items():
        if not LOOKUP_KEY.match(digest):
            raise RecordingsError(f"lookup key {digest!r} must be 64 lowercase hex digits")
        responses[f"lookups.{digest}"] = response
    for name, response in responses.items():
        check_response(name, response)
    return recordings


def check_response(name: str, response: object) -> None:
    if not isinstance(response, dict) or set(response) != {"status", "body"}:
        raise RecordingsError(f"{name}: needs exactly status and body")
    status = response["status"]
    if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
        raise RecordingsError(f"{name}: status must be an integer from 100 to 599")


def handler(recordings: dict[str, Any], log: JsonLines) -> type[QuietHandler]:
    class Provider(QuietHandler):
        def answer(self, response: dict[str, Any]) -> None:
            payload = json.dumps(response["body"]).encode()
            self.reply(int(response["status"]), payload, "application/json")

        def do_GET(self) -> None:
            log.append({"method": "GET", "path": self.path})
            lookup = LOOKUP.match(self.path)
            if lookup is None:
                self.answer({"status": 404, "body": {"error": "unknown endpoint"}})
                return
            self.answer(recordings["lookups"].get(lookup.group(1), recordings["unknown"]))

        def do_POST(self) -> None:
            body = self.body()
            if body is None:
                return
            entry: dict[str, object] = {"method": "POST", "path": self.path}
            if body:
                entry["body_sha256"] = hashlib.sha256(body).hexdigest()
                entry["body_size"] = len(body)
            log.append(entry)
            if self.path != "/files":
                self.answer({"status": 404, "body": {"error": "unknown endpoint"}})
                return
            self.answer(recordings["upload"])

    return Provider


def main(argv: list[str]) -> int:
    parser = arguments(argparse.ArgumentParser(description="Fake enrichment provider"))
    parser.add_argument("--recordings", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args(argv)
    if not loopback_only("provider", args.host):
        return 2
    try:
        recordings = load_recordings(args.recordings)
    except RecordingsError as error:
        print(f"fake provider: recordings: {error}", file=sys.stderr)
        return 2
    return serve(args.host, args.port, handler(recordings, JsonLines(args.log)))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
