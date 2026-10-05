"""Fake log collector (P6 skeleton): an HTTP server on loopback recording what it receives.

Usage: fake_collector.py --record FILE [--status 200] [--delay-ms 0] [--port 0]

Prints `listening http://127.0.0.1:<port>`, then for every request (any method, any path) waits
--delay-ms, appends {method, path, content_type, body} as one JSON line to FILE, and answers --status with
an empty body. The forwarding contract (OCSF over HTTPS or syslog) comes with P6.
"""

import argparse
import sys
import time
from pathlib import Path

from fake_http import JsonLines, QuietHandler, arguments, serve


def handler(record: JsonLines, status: int, delay: float) -> type[QuietHandler]:
    class Collector(QuietHandler):
        def handle_any(self) -> None:
            body = self.body()
            time.sleep(delay)
            record.append(
                {
                    "method": self.command,
                    "path": self.path,
                    "content_type": self.headers.get("Content-Type", ""),
                    "body": body.decode("utf-8", errors="replace"),
                }
            )
            self.reply(status)

        def do_GET(self) -> None:
            self.handle_any()

        def do_POST(self) -> None:
            self.handle_any()

        def do_PUT(self) -> None:
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
    record = JsonLines(args.record)
    collector = handler(record, args.status, args.delay_ms / 1000)
    return serve("collector", args.host, args.port, collector)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
