"""What the fake HTTP servers share: loopback only, a port chosen by the system, one JSON line per request."""

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock

LOOPBACK = "127.0.0.1"


def arguments(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("--host", default=LOOPBACK, help="must be 127.0.0.1")
    parser.add_argument("--port", type=int, default=0, help="0: chosen by the system")
    return parser


class JsonLines:
    """Appends one JSON object per line, flushed at once, safe across request threads."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = Lock()
        path.write_text("", encoding="utf-8")

    def append(self, entry: dict[str, object]) -> None:
        with self.lock, self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry) + "\n")


class QuietHandler(BaseHTTPRequestHandler):
    """A request handler that reads the body and logs nothing to stderr."""

    def body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def reply(self, status: int, payload: bytes = b"", content_type: str = "") -> None:
        self.send_response(status)
        if content_type:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(name: str, host: str, port: int, handler: type[BaseHTTPRequestHandler]) -> int:
    """Serve until killed; print `listening <url>` once bound. Refuse anything but loopback."""
    if host != LOOPBACK:
        print(f"fake {name}: listens on {LOOPBACK} only", file=sys.stderr)
        return 2
    server = ThreadingHTTPServer((host, port), handler)
    print(f"listening http://{LOOPBACK}:{server.server_address[1]}", flush=True)
    server.serve_forever()
    return 0
