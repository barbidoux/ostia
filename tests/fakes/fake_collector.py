"""Fake log collector (P6 skeleton): an HTTP server on loopback recording what it receives.

Usage: fake_collector.py --record FILE [--status 200] [--delay-ms 0] [--port 0]

Prints `listening http://127.0.0.1:<port>`, then for every request (GET, HEAD, POST, PUT, PATCH, DELETE,
any path) waits --delay-ms, appends {method, path, content_type, body} as one JSON line to FILE (a body
that is not UTF-8 is recorded as `"body": null` plus `body_base64`), and answers --status with an empty
body. The forwarding contract (OCSF over HTTPS or syslog) comes with P6.
"""

import argparse
import base64
import sys
import time
from pathlib import Path

from fake_http import JsonLines, QuietHandler, arguments, loopback_only, serve


def handler(record: JsonLines, status: int, delay: float) -> type[QuietHandler]:
    class Collector(QuietHandler):
        def handle_any(self) -> None:
            body = self.body()
            if body is None:
                return
            time.sleep(delay)
            entry: dict[str, object] = {
                "method": self.command,
                "path": self.path,
                "content_type": self.headers.get("Content-Type", ""),
            }
            try:
                entry["body"] = body.decode("utf-8")
            except UnicodeDecodeError:
                entry["body"] = None
                entry["body_base64"] = base64.b64encode(body).decode("ascii")
            record.append(entry)
            self.reply(status)

        def do_GET(self) -> None:
            self.handle_any()

        def do_HEAD(self) -> None:
            self.handle_any()

        def do_POST(self) -> None:
            self.handle_any()

        def do_PUT(self) -> None:
            self.handle_any()

        def do_PATCH(self) -> None:
            self.handle_any()

        def do_DELETE(self) -> None:
            self.handle_any()

    return Collector


def main(argv: list[str]) -> int:
    parser = arguments(argparse.ArgumentParser(description="Fake log collector"))
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--status", type=int, default=200)
    parser.add_argument("--delay-ms", type=int, default=0)
    args = parser.parse_args(argv)
    if not loopback_only("collector", args.host):
        return 2
    if args.delay_ms < 0:
        print("fake collector: --delay-ms must be >= 0", file=sys.stderr)
        return 2
    collector = handler(JsonLines(args.record), args.status, args.delay_ms / 1000)
    return serve(args.host, args.port, collector)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
