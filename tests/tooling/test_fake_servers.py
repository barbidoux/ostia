"""The fake collector and fake provider skeletons (tests/fakes/fake_collector.py, fake_provider.py).

Both are HTTP servers on 127.0.0.1 only (port chosen by the system), started as processes: they print
`listening http://127.0.0.1:<port>` and serve until stopped. The collector (log forwarding, P6) records
every request and answers a fixed status; the provider (enrichment, P8) answers recorded responses by
sha256 and logs what it was sent (hash and size of uploads, never their content). Full contracts come with
P6 and P8.
"""

import hashlib
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from tooling_support import REPO

COLLECTOR = REPO / "tests" / "fakes" / "fake_collector.py"
PROVIDER = REPO / "tests" / "fakes" / "fake_provider.py"
KNOWN = hashlib.sha256(b"known sample").hexdigest()
UNKNOWN = hashlib.sha256(b"unknown sample").hexdigest()


@contextmanager
def server(script: Path, *args: str) -> Iterator[str]:
    process = subprocess.Popen(
        [sys.executable, str(script), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        assert process.stderr is not None
        line = process.stdout.readline().strip()
        assert line.startswith("listening http://127.0.0.1:"), line or process.stderr.read()
        yield line.removeprefix("listening ")
    finally:
        process.terminate()
        process.wait(timeout=10)


def call(
    url: str, method: str = "GET", body: bytes | None = None, content_type: str = ""
) -> tuple[int, bytes]:
    headers = {"Content-Type": content_type} if content_type else {}
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=10) as reply:
            return reply.status, reply.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def lines(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.mark.req("TOOLING")
def test_the_collector_records_requests_and_answers_its_status(tmp_path: Path) -> None:
    record = tmp_path / "received.jsonl"
    with server(COLLECTOR, "--record", str(record), "--status", "202") as url:
        event = b'{"class_uid": 6003}'
        assert call(f"{url}/events", "POST", event, "application/json") == (202, b"")
        assert call(f"{url}/health") == (202, b"")
    assert lines(record) == [
        {
            "method": "POST",
            "path": "/events",
            "content_type": "application/json",
            "body": '{"class_uid": 6003}',
        },
        {"method": "GET", "path": "/health", "content_type": "", "body": ""},
    ]


@pytest.mark.req("TOOLING")
def test_the_collector_can_answer_slowly(tmp_path: Path) -> None:
    record = tmp_path / "received.jsonl"
    with server(COLLECTOR, "--record", str(record), "--delay-ms", "300") as url:
        started = time.monotonic()
        assert call(f"{url}/events", "POST", b"{}", "application/json")[0] == 200
        assert time.monotonic() - started >= 0.3


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("script", "name", "args"),
    [
        (COLLECTOR, "collector", ["--record", "received.jsonl"]),
        (PROVIDER, "provider", ["--recordings", "recordings.json", "--log", "sent.jsonl"]),
    ],
)
def test_servers_listen_on_loopback_only(
    tmp_path: Path, script: Path, name: str, args: list[str]
) -> None:
    (tmp_path / "recordings.json").write_text(json.dumps(RECORDINGS))
    command = [sys.executable, str(script), *args, "--host", "0.0.0.0"]
    result = subprocess.run(
        command, cwd=tmp_path, capture_output=True, text=True, timeout=30, check=False
    )
    assert result.returncode == 2
    assert f"fake {name}: listens on 127.0.0.1 only" in result.stderr


RECORDINGS = {
    "lookups": {KNOWN: {"status": 200, "body": {"verdict": "malicious", "detections": 41}}},
    "unknown": {"status": 404, "body": {"error": "NotFoundError"}},
    "upload": {"status": 200, "body": {"id": "upload-1"}},
}


@pytest.mark.req("TOOLING")
def test_the_provider_answers_recorded_responses_and_logs_what_it_was_sent(tmp_path: Path) -> None:
    recordings = tmp_path / "recordings.json"
    recordings.write_text(json.dumps(RECORDINGS))
    log = tmp_path / "sent.jsonl"
    with server(PROVIDER, "--recordings", str(recordings), "--log", str(log)) as url:
        status, body = call(f"{url}/files/{KNOWN}")
        assert (status, json.loads(body)) == (200, {"verdict": "malicious", "detections": 41})
        status, body = call(f"{url}/files/{UNKNOWN}")
        assert (status, json.loads(body)) == (404, {"error": "NotFoundError"})
        sample = b"sample bytes"
        status, body = call(f"{url}/files", "POST", sample, "application/octet-stream")
        assert (status, json.loads(body)) == (200, {"id": "upload-1"})
        status, body = call(f"{url}/elsewhere")
        assert (status, json.loads(body)) == (404, {"error": "unknown endpoint"})
    assert lines(log) == [
        {"method": "GET", "path": f"/files/{KNOWN}"},
        {"method": "GET", "path": f"/files/{UNKNOWN}"},
        {
            "method": "POST",
            "path": "/files",
            "body_sha256": hashlib.sha256(b"sample bytes").hexdigest(),
            "body_size": 12,
        },
        {"method": "GET", "path": "/elsewhere"},
    ]


@pytest.mark.req("TOOLING")
def test_the_provider_refuses_incomplete_recordings(tmp_path: Path) -> None:
    recordings = tmp_path / "recordings.json"
    recordings.write_text(json.dumps({"lookups": {}, "upload": RECORDINGS["upload"]}))
    command = [
        sys.executable,
        str(PROVIDER),
        "--recordings",
        str(recordings),
        "--log",
        str(tmp_path / "sent.jsonl"),
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 2
    assert "fake provider: recordings: missing 'unknown'" in result.stderr
