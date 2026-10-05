# Test doubles (WP-0.7)

Black-box doubles, run as processes, usable from locked acceptance tests. Their behaviour is tested in
`tests/tooling/test_fake_engine.py`, `tests/tooling/test_fake_servers.py` and `tests/fakes/clock/tests/`.

| Double | Run | What it does |
|---|---|---|
| `fake_engine.py` | worker process: `python tests/fakes/fake_engine.py --config engine.json` (or `OSTIA_FAKE_ENGINE_CONFIG`), object on fd 3 | Answers one framed `AnalyzeRequest` (ostia.engine.v1) with the default answer or the first matching rule (sha256, `object_id` glob, `detected_type`): respond with status, hint, score and findings, after an optional delay, or crash, kill itself, or write garbage. A missing or mismatching fd 3 gives status `ERROR`. See the module docstring for the config. |
| `clock/` (crate `ostia-fake-clock`) | Rust dependency | `FakeClock` (set and advanced by the test) and `FileClock` (epoch milliseconds read from the file named by `OSTIA_FAKE_CLOCK`, for dev builds) behind the `Clock` trait of `ostia-core-domain`. |
| `fake_collector.py` | `python tests/fakes/fake_collector.py --record received.jsonl [--status 200] [--delay-ms 0]` | HTTP on 127.0.0.1 (prints `listening <url>`), records every request as a JSON line, answers a fixed status. Log-forwarding skeleton; the contract comes with P6. |
| `fake_provider.py` | `python tests/fakes/fake_provider.py --recordings recordings.json --log sent.jsonl` | HTTP on 127.0.0.1, answers recorded lookups by SHA-256, an "unknown" and an "upload" response, and logs what it was sent (hash and size, never content). Enrichment skeleton; the contract comes with P8. |

None of them touches the network beyond loopback, and none contains real malware or real API responses.
