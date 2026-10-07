"""The fake collector and fake provider skeletons (tests/fakes/fake_collector.py, fake_provider.py).

Both are HTTP servers on 127.0.0.1 only (port chosen by the system), started as processes: they print
`listening http://<bound address>:<port>` and serve until stopped. The collector (log forwarding, P6)
records every request and answers a fixed status; the provider (enrichment, P8) answers recorded responses
by sha256 and logs what it was sent (hash and size of bodies, never their content). Bodies must carry a
Content-Length (chunked bodies are refused with 411). Full contracts come with P6 and P8.
"""

import base64
import hashlib
import http.client
import json
import selectors
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
STARTUP_SECONDS = 20


@contextmanager
def server(tmp_path: Path, script: Path, *args: str) -> Iterator[str]:
    """Start a fake server, yield its URL, stop it (killed if it does not stop)."""
    errors = (tmp_path / f"{script.stem}.stderr").open("w")
    with subprocess.Popen(
        [sys.executable, str(script), *args],
        stdout=subprocess.PIPE,
        stderr=errors,
        text=True,
        cwd=tmp_path,
    ) as process:
        try:
            assert process.stdout is not None
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            ready = selector.select(timeout=STARTUP_SECONDS)
            line = process.stdout.readline().strip() if ready else ""
            stderr = (tmp_path / f"{script.stem}.stderr").read_text()
            assert line.startswith("listening http://127.0.0.1:"), line or stderr
            yield line.removeprefix("listening ")
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            errors.close()


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


def chunked_post(url: str, path: str) -> int:
    host, port = url.removeprefix("http://").split(":")
    connection = http.client.HTTPConnection(host, int(port), timeout=10)
    connection.request("POST", path, body=iter([b"{}"]), encode_chunked=True)
    status = connection.getresponse().status
    connection.close()
    return status


def lines(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def run_script(tmp_path: Path, script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(script), *args]
    return subprocess.run(
        command, cwd=tmp_path, capture_output=True, text=True, timeout=30, check=False
    )


@pytest.mark.req("TOOLING")
def test_the_collector_records_requests_and_answers_its_status(tmp_path: Path) -> None:
    record = tmp_path / "received.jsonl"
    with server(tmp_path, COLLECTOR, "--record", str(record), "--status", "202") as url:
        event = b'{"class_uid": 6003}'
        assert call(f"{url}/events", "POST", event, "application/json") == (202, b"")
        assert call(f"{url}/health") == (202, b"")
        assert call(f"{url}/events", "PATCH", b"\xff\x00", "application/octet-stream")[0] == 202
        assert chunked_post(url, "/events") == 411
    assert lines(record) == [
        {
            "method": "POST",
            "path": "/events",
            "content_type": "application/json",
            "body": '{"class_uid": 6003}',
        },
        {"method": "GET", "path": "/health", "content_type": "", "body": ""},
        {
            "method": "PATCH",
            "path": "/events",
            "content_type": "application/octet-stream",
            "body": None,
            "body_base64": base64.b64encode(b"\xff\x00").decode(),
        },
    ]


@pytest.mark.req("TOOLING")
def test_the_collector_can_answer_slowly(tmp_path: Path) -> None:
    record = tmp_path / "received.jsonl"
    with server(tmp_path, COLLECTOR, "--record", str(record), "--delay-ms", "300") as url:
        started = time.monotonic()
        assert call(f"{url}/events", "POST", b"{}", "application/json")[0] == 200
        assert time.monotonic() - started >= 0.3


@pytest.mark.req("TOOLING")
def test_the_collector_refuses_a_negative_delay(tmp_path: Path) -> None:
    result = run_script(tmp_path, COLLECTOR, "--record", "received.jsonl", "--delay-ms", "-1")
    assert result.returncode == 2
    assert "fake collector: --delay-ms must be >= 0" in result.stderr


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("script", "name", "args", "output"),
    [
        (COLLECTOR, "collector", ["--record", "received.jsonl"], "received.jsonl"),
        (
            PROVIDER,
            "provider",
            ["--recordings", "recordings.json", "--log", "sent.jsonl"],
            "sent.jsonl",
        ),
    ],
)
def test_servers_listen_on_loopback_only(
    tmp_path: Path, script: Path, name: str, args: list[str], output: str
) -> None:
    (tmp_path / "recordings.json").write_text(json.dumps(RECORDINGS))
    result = run_script(tmp_path, script, *args, "--host", "0.0.0.0")
    assert result.returncode == 2
    assert f"fake {name}: listens on 127.0.0.1 only" in result.stderr
    assert not (tmp_path / output).exists(), "nothing is written before refusing"


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
    with server(tmp_path, PROVIDER, "--recordings", str(recordings), "--log", str(log)) as url:
        status, body = call(f"{url}/files/{KNOWN}")
        assert (status, json.loads(body)) == (200, {"verdict": "malicious", "detections": 41})
        status, body = call(f"{url}/files/{UNKNOWN}")
        assert (status, json.loads(body)) == (404, {"error": "NotFoundError"})
        sample = b"sample bytes"
        status, body = call(f"{url}/files", "POST", sample, "application/octet-stream")
        assert (status, json.loads(body)) == (200, {"id": "upload-1"})
        status, body = call(f"{url}/elsewhere")
        assert (status, json.loads(body)) == (404, {"error": "unknown endpoint"})
        status, body = call(f"{url}/files/{KNOWN.upper()}")
        assert (status, json.loads(body)) == (404, {"error": "unknown endpoint"})
        status, body = call(f"{url}/other", "POST", b"xyz", "application/octet-stream")
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
        {"method": "GET", "path": f"/files/{KNOWN.upper()}"},
        {
            "method": "POST",
            "path": "/other",
            "body_sha256": hashlib.sha256(b"xyz").hexdigest(),
            "body_size": 3,
        },
    ]


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("recordings", "message"),
    [
        ({"lookups": {}, "upload": RECORDINGS["upload"]}, "missing 'unknown'"),
        ({**RECORDINGS, "lookups": []}, "lookups must be an object"),
        (
            {**RECORDINGS, "lookups": {"ABC": RECORDINGS["unknown"]}},
            "lookup key 'ABC' must be 64 lowercase hex digits",
        ),
        (
            {**RECORDINGS, "upload": {"status": "200", "body": {}}},
            "upload: status must be an integer from 100 to 599",
        ),
        ({**RECORDINGS, "unknown": {"status": 404}}, "unknown: needs exactly status and body"),
    ],
    ids=["missing unknown", "lookups list", "bad lookup key", "bad status", "missing body"],
)
def test_the_provider_refuses_bad_recordings(
    tmp_path: Path, recordings: dict[str, object], message: str
) -> None:
    (tmp_path / "recordings.json").write_text(json.dumps(recordings))
    result = run_script(
        tmp_path, PROVIDER, "--recordings", "recordings.json", "--log", "sent.jsonl"
    )
    assert result.returncode == 2
    assert f"fake provider: recordings: {message}" in result.stderr
