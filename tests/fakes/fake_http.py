"""What the fake HTTP servers share: loopback only, a port chosen by the system, one JSON line per request.

Request bodies must carry a Content-Length: chunked bodies get 411, bodies above 16 MiB get 413, a malformed
length gets 400.
"""

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock

LOOPBACK = "127.0.0.1"
MAX_BODY = 16 * 1024 * 1024


def arguments(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("--host", default=LOOPBACK, help="must be 127.0.0.1")
    parser.add_argument("--port", type=int, default=0, help="0: chosen by the system")
    return parser


def loopback_only(name: str, host: str) -> bool:
    """Whether `host` is the loopback address; says why not on stderr."""
    if host == LOOPBACK:
        return True
    print(f"fake {name}: listens on {LOOPBACK} only", file=sys.stderr)
    return False


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
    """A request handler that reads bodies with a Content-Length only and logs nothing to stderr."""

    def body(self) -> bytes | None:
        """The request body, or None after answering 400, 411 or 413."""
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            self.reply(411)
            return None
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0:
            self.reply(400)
            return None
        if length > MAX_BODY:
            self.reply(413)
            return None
        return self.rfile.read(length) if length else b""

    def reply(self, status: int, payload: bytes = b"", content_type: str = "") -> None:
        self.send_response(status)
        if content_type:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(host: str, port: int, handler: type[BaseHTTPRequestHandler]) -> int:
    """Serve until killed; print `listening <url>` with the bound address once listening."""
    server = ThreadingHTTPServer((host, port), handler)
    bound_host, bound_port = server.server_address[:2]
    print(f"listening http://{bound_host!s}:{bound_port}", flush=True)
    server.serve_forever()
    return 0
